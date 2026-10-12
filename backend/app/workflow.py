from __future__ import annotations

from typing import Any

from .config import AGENT_MAX_TOKENS
from .db import clean, collection

AGENTS = ['evidence-collector', 'hypothesis-attack', 'verifier', 'report-writer']


async def load_workflow(incident_id: str) -> dict[str, Any] | None:
    incident = clean(await collection('incidents').find_one(
        {'incident_id': incident_id},
        {'_id': 0, 'incident_id': 1, 'code': 1, 'title': 1, 'risk_score': 1, 'batch_id': 1},
    ))
    if not incident:
        return None

    history = await collection('agent_runs').find(
        {'incident_id': incident_id}, {'_id': 0}
    ).sort([('created_at', 1), ('run_id', 1)]).to_list(length=None)

    start = -1
    for i in range(len(history) - 1, -1, -1):
        if history[i].get('agent') == AGENTS[0]:
            start = i
            break
    runs = history[start:] if start >= 0 else []
    latest = [next((r for r in reversed(runs) if r.get('agent') == agent), None) for agent in AGENTS]
    collector, hypothesis, verifier, writer = latest

    evidence = ((collector.get('output') or {}).get('evidence', []) if collector and collector.get('status') in {'ok', 'partial'} else [])
    hypotheses = ((hypothesis.get('output') or {}).get('hypotheses', []) if hypothesis and hypothesis.get('status') == 'ok' else [])
    verified = bool(verifier and verifier.get('status') in {'ok', 'partial'})
    verifier_output = (verifier or {}).get('output') or {}
    supported_ids = set(verifier_output.get('supported') or [])
    verdicts = verifier_output.get('verdicts') or []
    supported = [
        h for h in hypotheses
        if h.get('id') in supported_ids
        and any(v.get('hypothesis_id') == h.get('id') and v.get('supported') for v in verdicts)
    ] if verified else []

    evidence_by_id = {e.get('evidence_id'): e for e in evidence}
    valid_citations = all(
        h.get('citations') and all(c in evidence_by_id and evidence_by_id[c].get('source_event_ids') for c in h['citations'])
        for h in supported
    )
    budget_exceeded = sum(int(r.get('tokens') or 0) for r in runs) >= AGENT_MAX_TOKENS
    writer_output = (writer or {}).get('output') or {}
    report = writer_output if writer and writer.get('status') == 'ok' and writer_output.get('summary') else None
    can_report = bool(supported and valid_citations and not budget_exceeded and not report)

    if report:
        reason = 'Report generated from verified findings.'
    elif budget_exceeded:
        reason = 'Investigation token budget exhausted.'
    elif not verified:
        reason = 'Complete verification to unlock the report writer.'
    elif not supported:
        reason = 'No findings passed verification. Review the rejected claims.'
    elif not valid_citations:
        reason = 'Verified findings are missing grounded citations.'
    else:
        reason = 'Verified findings are ready. Generate your report.'

    return {
        'incident': incident,
        'runs': runs,
        'latest': latest,
        'evidence': evidence,
        'supported': supported,
        'assessment': verifier_output.get('attack_assessment') or [],
        'can_report': can_report,
        'reason': reason,
        'report': report,
    }


async def report_context(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not workflow['can_report']:
        raise RuntimeError(workflow['reason'])
    ids = list(dict.fromkeys(
        event_id for e in workflow['evidence'] for event_id in e.get('source_event_ids', [])
    ))
    if not ids:
        raise RuntimeError('Source events are missing; investigate again before generating a report.')
    events = await collection('events').find(
        {'event_id': {'$in': ids}},
        {'_id': 0, 'event_id': 1, 'ts': 1, 'src_ip': 1, 'dst_ip': 1, 'severity': 1, 'template_text': 1, 'raw': 1, 'mitre_tags': 1},
    ).to_list(length=None)
    index = {e['event_id']: e for e in events}
    if any(event_id not in index for event_id in ids):
        raise RuntimeError('Source events are missing; investigate again before generating a report.')
    return index
