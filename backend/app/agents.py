from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .llm import reason
from .mitre import DETECTOR_FAMILY, families_of_techniques, family_from_title, technique_conflict
from .models import EvidenceOut, HypothesisOut, ReportOut, VerifierOut
from .tools import (
    get_incident,
    get_incident_entities,
    get_incident_events,
    get_signals_for_events,
    insert_evidence,
    insert_timeline,
    query_events_for_entity,
    record_agent_run,
    search_attack_kb,
    write_report,
)

ANNOTATION_SCORE = 0.5

EVIDENCE_SYSTEM = (
    "You are the Evidence Collector in a SOC investigation pipeline. You are given "
    "network-flow events and the detector signals that fired on them. Extract DISTINCT, "
    "checkable facts. Every fact MUST cite real event_id values from the supplied data. "
    "Do not speculate about intent or attribution. Prefer a few strong facts."
)

HYPOTHESIS_SYSTEM = (
    "You are the Hypothesis & ATT&CK analyst in a SOC pipeline. Reason ONLY from grounded "
    "EVIDENCE facts. Every hypothesis MUST cite evidence_id values, map to one best-fitting "
    "MITRE ATT&CK technique from the supplied KB, and keep actions simulation-only."
)

VERIFIER_SYSTEM = (
    "You are the Verifier in a SOC pipeline — a strict adversarial fact-checker. For each "
    "hypothesis, judge ONLY the full text of the evidence it cited. supported=true only when "
    "that evidence genuinely establishes the statement. Reject weak, unrelated, or over-claimed "
    "conclusions. evidence_strength is 0..1 and must reflect only cited evidence."
)

REPORT_SYSTEM = (
    "You are the Report Writer in a SOC pipeline. You are given ONLY VERIFIED hypotheses, "
    "their evidence, and confidence assessments. Assert nothing unsupported; use inline [EV-x] "
    "citations; state confidence and basis; clearly mark annotation-only findings as not "
    "independently detector-confirmed. Actions are simulation-only."
)


def _ms() -> int:
    return int(time.time() * 1000)


def _uniq(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _keywords(text: str) -> list[str]:
    stop = {"flows", "flow", "host", "from", "with", "this", "that", "were", "made", "over", "port", "detector"}
    return _uniq([w for w in re.findall(r"[a-z]{4,}", text.lower()) if w not in stop])[:6]


def _render_evidence_data(
    incident: dict[str, Any] | None,
    entities: list[dict[str, Any]],
    events: list[dict[str, Any]],
    signals_by_event: dict[str, list[dict[str, Any]]],
) -> str:
    lines: list[str] = []
    if incident:
        lines.append(f"INCIDENT {incident.get('code')}: {incident.get('title')} (risk {incident.get('risk_score')})")
    lines.append("ENTITIES:")
    for entity in entities:
        lines.append(f"  - {entity.get('entity_type')}={entity.get('entity_value')} role={entity.get('role') or '?'}")
    lines.extend(["", f"EVENTS ({len(events)}):"])
    for event in events:
        sigs = "; ".join(
            f"{s.get('detector')}({float(s.get('score') or 0):.2f}):{s.get('reason')}"
            for s in signals_by_event.get(event["event_id"], [])
        )
        lines.append(
            f"  event_id={event['event_id']} ts={event.get('ts')} "
            f"{event.get('src_ip') or '?'}->{event.get('dst_ip') or '?'} "
            f"sev={event.get('severity')} mitre=[{','.join(event.get('mitre_tags') or [])}] "
            f"{event.get('template_text') or ''}"
            + (f"\n      signals: {sigs}" if sigs else "")
        )
    return "\n".join(lines)


async def run_evidence_collector(incident_id: str) -> dict[str, Any]:
    started = _ms()
    incident = await get_incident(incident_id)
    entities = await get_incident_entities(incident_id)

    event_index = {r["event_id"]: r for r in await get_incident_events(incident_id, 60)}
    retrieval_path = "incident-scoped"
    narrowed_from = 0

    if not event_index:
        retrieval_path = "entity-fallback"
        for entity in entities:
            if entity.get("entity_type") not in {"ip", "src_ip", "dst_ip"}:
                continue
            for row in await query_events_for_entity(entity["entity_value"], 40):
                event_index[row["event_id"]] = row

    candidates = list(event_index.values())
    candidate_signals = await get_signals_for_events([e["event_id"] for e in candidates])
    signals_by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in candidate_signals:
        signals_by_event[signal["event_id"]].append(signal)

    if retrieval_path == "entity-fallback":
        by_title = family_from_title((incident or {}).get("title"))
        families = {by_title} if by_title else families_of_techniques((incident or {}).get("mitre_techniques") or [])
        if families:
            keep = {
                e["event_id"]
                for e in candidates
                if any(
                    s.get("detector") != "label"
                    and DETECTOR_FAMILY.get(s.get("detector_ref")) in families
                    for s in signals_by_event.get(e["event_id"], [])
                )
            }
            if not keep:
                narrowed_from = len(candidates)
                event_index.clear()
            elif len(keep) < len(candidates):
                narrowed_from = len(candidates)
                event_index = {k: v for k, v in event_index.items() if k in keep}

    events = list(event_index.values())
    parsed, tokens = await reason(
        schema=EvidenceOut,
        system=EVIDENCE_SYSTEM,
        data=_render_evidence_data(incident, entities, events, signals_by_event),
        name="collect_evidence",
    )

    valid_ids = {e["event_id"] for e in events}
    kept: list[dict[str, Any]] = []
    dropped = 0
    short_code = (incident or {}).get("code") or incident_id[:8]
    for fact in parsed.evidence:
        cited = list(fact.source_event_ids)
        good = [event_id for event_id in cited if event_id in valid_ids]
        if not good or len(good) != len(cited):
            dropped += 1
            continue
        kept.append({
            "evidence_id": f"EV-{short_code}-{len(kept) + 1}",
            "kind": fact.kind,
            "fact": fact.fact,
            "source_event_ids": good,
            "confidence": fact.confidence,
        })

    await insert_evidence([{**e, "incident_id": incident_id} for e in kept])

    output: dict[str, Any] = {"evidence": kept, "retrieval_path": retrieval_path}
    if narrowed_from:
        output["fallback_narrowed_from"] = narrowed_from
        output["fallback_kept"] = len(events)

    await record_agent_run({
        "incident_id": incident_id,
        "agent": "evidence-collector",
        "tools_used": [
            "getIncidentEntities",
            "getIncidentEvents" if retrieval_path == "incident-scoped" else "queryEventsForEntity",
            "getSignalsForEvents",
            "insertEvidence",
        ],
        "citations": [event_id for e in kept for event_id in e["source_event_ids"]],
        "output": output,
        "status": "partial" if dropped else "ok",
        "unsupported_claims": [{"dropped_facts_with_bad_citations": dropped}] if dropped else [],
        "latency_ms": _ms() - started,
        "tokens": tokens,
    })
    return {"evidence": kept, "event_index": event_index, "tokens": tokens}


async def run_hypothesis_agent(
    incident_id: str,
    incident_code: str,
    evidence: list[dict[str, Any]],
    seed_techniques: list[str],
) -> dict[str, Any]:
    started = _ms()
    terms = _uniq(seed_techniques + _keywords(" ".join(e["fact"] for e in evidence)))
    kb = await search_attack_kb(terms)
    data = "\n".join([
        "EVIDENCE:",
        *[f"  {e['evidence_id']} ({e['kind']}, conf {e['confidence']}): {e['fact']}" for e in evidence],
        "",
        "ATT&CK KB:",
        *[f"  {k['technique_id']} {k['name']} [{k.get('tactic')}]: {k.get('description')}" for k in kb],
    ])
    parsed, tokens = await reason(schema=HypothesisOut, system=HYPOTHESIS_SYSTEM, data=data, name="form_hypotheses")
    hypotheses = [
        {
            "id": f"H-{incident_code}-{i + 1}",
            "statement": h.statement,
            "technique": h.technique,
            "citations": list(h.citations),
            "confidence": h.confidence,
            "recommended_actions": list(h.recommended_actions),
        }
        for i, h in enumerate(parsed.hypotheses)
    ]
    await record_agent_run({
        "incident_id": incident_id,
        "agent": "hypothesis-attack",
        "tools_used": ["searchAttackKb"],
        "citations": [c for h in hypotheses for c in h["citations"]],
        "output": {"hypotheses": hypotheses, "kb_techniques": [k["technique_id"] for k in kb]},
        "status": "ok",
        "unsupported_claims": [],
        "latency_ms": _ms() - started,
        "tokens": tokens,
    })
    return {"hypotheses": hypotheses, "tokens": tokens}


async def run_verifier(
    incident_id: str,
    hypotheses: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    started = _ms()
    ev_by_id = {e["evidence_id"]: e for e in evidence}
    deterministic: dict[str, str | None] = {}

    for h in hypotheses:
        citations = h.get("citations") or []
        if not citations:
            deterministic[h["id"]] = "[deterministic] no citations — claim is ungrounded"
        elif not all(c in ev_by_id for c in citations):
            bad = [c for c in citations if c not in ev_by_id]
            deterministic[h["id"]] = "[deterministic] citations do not resolve to evidence: " + ", ".join(bad)
        else:
            deterministic[h["id"]] = None

    gate_one = [h for h in hypotheses if deterministic[h["id"]] is None]
    sigs_by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cited_event_ids = _uniq([
        event_id
        for h in gate_one
        for citation in h["citations"]
        for event_id in ev_by_id[citation].get("source_event_ids", [])
    ])
    if cited_event_ids:
        for signal in await get_signals_for_events(cited_event_ids):
            sigs_by_event[signal["event_id"]].append(signal)

    for h in gate_one:
        refs = _uniq([
            s.get("detector_ref")
            for citation in h["citations"]
            for event_id in ev_by_id[citation].get("source_event_ids", [])
            for s in sigs_by_event.get(event_id, [])
            if s.get("detector") != "label" and s.get("detector_ref")
        ])
        conflict = technique_conflict(h["technique"], refs)
        if conflict:
            deterministic[h["id"]] = f"[consistency] {conflict}"

    gate_passed = [h for h in hypotheses if deterministic[h["id"]] is None]
    llm_verdicts: list[dict[str, Any]] = []
    tokens = 0
    if gate_passed:
        data = "\n\n".join(
            f"HYPOTHESIS {h['id']} (technique {h['technique']}):\n"
            f"  statement: {h['statement']}\n"
            "  cited evidence:\n"
            + "\n".join(f"      {c}: {ev_by_id[c]['fact']}" for c in h["citations"])
            for h in gate_passed
        )
        parsed, tokens = await reason(schema=VerifierOut, system=VERIFIER_SYSTEM, data=data, name="verify_hypotheses")
        llm_verdicts = [v.model_dump() for v in parsed.verdicts]

    llm_by_id = {v["hypothesis_id"]: v for v in llm_verdicts}
    verdicts, supported, rejected = [], [], []

    for h in hypotheses:
        det_reason = deterministic[h["id"]]
        if det_reason:
            verdicts.append({"hypothesis_id": h["id"], "supported": False, "reason": det_reason})
            rejected.append({"hypothesis": h, "reason": det_reason})
            continue
        verdict = llm_by_id.get(h["id"])
        if not verdict or not verdict.get("supported"):
            why = (verdict or {}).get("reason") or "no verifier verdict returned"
            verdicts.append({"hypothesis_id": h["id"], "supported": False, "reason": f"[entailment] {why}"})
            rejected.append({"hypothesis": h, "reason": why})
        else:
            verdicts.append({"hypothesis_id": h["id"], "supported": True, "reason": verdict["reason"]})
            supported.append(h)

    assessment = []
    for h in supported:
        event_ids = _uniq([
            event_id
            for citation in h["citations"]
            for event_id in ev_by_id[citation].get("source_event_ids", [])
        ])
        mine = [s for event_id in event_ids for s in sigs_by_event.get(event_id, [])]
        behavioural = [s for s in mine if s.get("detector") != "label"]
        has_annotation = any(s.get("detector") == "label" for s in mine)

        detector_component = 0.0
        top_detector = None
        for s in behavioural:
            score = float(s.get("score") or 0)
            if score > detector_component:
                detector_component = score
                top_detector = s.get("detector_ref")

        corroborated = detector_component > 0
        basis = "behavioural+annotation" if corroborated and has_annotation else "behavioural" if corroborated else "annotation-only"
        if not corroborated:
            detector_component = ANNOTATION_SCORE if has_annotation else 0.0
            label_signal = next((s for s in mine if s.get("detector") == "label"), None)
            top_detector = label_signal.get("detector_ref") if label_signal else None

        raw = (llm_by_id.get(h["id"]) or {}).get("evidence_strength")
        entailment = min(1.0, max(0.0, float(raw))) if isinstance(raw, (int, float)) and math.isfinite(float(raw)) else 0.5

        assessment.append({
            "hypothesis_id": h["id"],
            "statement": h["statement"],
            "technique": h["technique"],
            "confidence_pct": round(detector_component * entailment * 100, 1),
            "detector_component": round(detector_component, 3),
            "entailment_component": round(entailment, 3),
            "basis": basis,
            "corroborated_by_detector": corroborated,
            "top_detector": top_detector,
            "cited_evidence": h["citations"],
        })
    assessment.sort(key=lambda x: x["confidence_pct"], reverse=True)

    await record_agent_run({
        "incident_id": incident_id,
        "agent": "verifier",
        "tools_used": ["getSignalsForEvents"] if cited_event_ids else [],
        "citations": [c for h in supported for c in h["citations"]],
        "output": {"verdicts": verdicts, "supported": [h["id"] for h in supported], "attack_assessment": assessment},
        "status": "partial" if rejected else "ok",
        "unsupported_claims": [
            {"hypothesis_id": r["hypothesis"]["id"], "statement": r["hypothesis"]["statement"], "reason": r["reason"]}
            for r in rejected
        ],
        "latency_ms": _ms() - started,
        "tokens": tokens,
    })
    return {"verdicts": verdicts, "supported": supported, "rejected": rejected, "assessment": assessment, "tokens": tokens}


async def run_report_writer(
    incident_id: str,
    supported: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    event_index: dict[str, dict[str, Any]],
    assessment: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    started = _ms()
    assessment = assessment or []
    if not supported:
        raise RuntimeError("report requires at least one verified finding")

    cited_ids = {c for h in supported for c in h["citations"]}
    used_evidence = [e for e in evidence if e["evidence_id"] in cited_ids]
    score_by_id = {a["hypothesis_id"]: a for a in assessment}
    lines = []
    for h in supported:
        a = score_by_id.get(h["id"])
        score_text = ""
        if a:
            corroboration = f", corroborated by detector {a.get('top_detector')}" if a.get("corroborated_by_detector") else ", NOT corroborated by any independent detector"
            score_text = f"\n      confidence: {a['confidence_pct']}% (basis: {a['basis']}{corroboration})"
        lines.append(
            f"  {h['id']} [{h['technique']}] (conf {h['confidence']}): {h['statement']}\n"
            f"      cites: {', '.join(h['citations'])}{score_text}"
        )

    data = "\n".join([
        "VERIFIED HYPOTHESES:", *lines, "", "EVIDENCE:",
        *[f"  {e['evidence_id']}: {e['fact']}" for e in used_evidence],
    ])
    parsed, tokens = await reason(schema=ReportOut, system=REPORT_SYSTEM, data=data, name="write_report")

    techniques = _uniq([h["technique"] for h in supported if h.get("technique")])
    await write_report(incident_id, parsed.summary, techniques)

    timeline = []
    for e in used_evidence:
        timestamps = sorted([
            str(event_index[event_id]["ts"])
            for event_id in e.get("source_event_ids", [])
            if event_id in event_index and event_index[event_id].get("ts")
        ])
        timeline.append({
            "ts": timestamps[0] if timestamps else datetime.now(timezone.utc).isoformat(),
            "label": e["fact"],
            "evidence_id": e["evidence_id"],
        })
    timeline.sort(key=lambda x: x["ts"])
    await insert_timeline(incident_id, timeline)

    await record_agent_run({
        "incident_id": incident_id,
        "agent": "report-writer",
        "tools_used": ["writeReport", "insertTimeline"],
        "citations": [c for h in supported for c in h["citations"]],
        "output": {**parsed.model_dump(), "attack_assessment": assessment},
        "status": "ok",
        "unsupported_claims": [],
        "latency_ms": _ms() - started,
        "tokens": tokens,
    })
    return {**parsed.model_dump(), "tokens": tokens}
