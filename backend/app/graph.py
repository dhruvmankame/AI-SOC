from __future__ import annotations

import operator
from typing import Annotated, Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from .agents import run_evidence_collector, run_hypothesis_agent, run_report_writer, run_verifier
from .config import AGENT_MAX_TOKENS
from .tools import get_incident, record_agent_run


class SocState(TypedDict, total=False):
    incident_id: str
    incident_code: str
    auto_report: bool
    report_pending: bool
    seed_techniques: list[str]
    evidence: list[dict[str, Any]]
    event_index: dict[str, dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    verdicts: list[dict[str, Any]]
    supported: list[dict[str, Any]]
    rejected: list[dict[str, Any]]
    assessment: list[dict[str, Any]]
    report: dict[str, Any] | None
    tokens_used: Annotated[int, operator.add]


async def record_skip(incident_id: str, agent: str, reason: str) -> None:
    await record_agent_run({
        "incident_id": incident_id,
        "agent": agent,
        "tools_used": [],
        "citations": [],
        "output": {"skipped": True, "reason": reason},
        "status": "skipped",
        "unsupported_claims": [],
        "latency_ms": 0,
        "tokens": 0,
    })


def over_budget(state: SocState) -> bool:
    return int(state.get("tokens_used", 0)) >= AGENT_MAX_TOKENS


async def collect_node(state: SocState) -> dict[str, Any]:
    r = await run_evidence_collector(state["incident_id"])
    return {"evidence": r["evidence"], "event_index": r["event_index"], "tokens_used": r["tokens"]}


async def hypothesize_node(state: SocState) -> dict[str, Any]:
    if over_budget(state) or not state.get("evidence"):
        why = "token budget exhausted" if over_budget(state) else "no grounded evidence"
        await record_skip(state["incident_id"], "hypothesis-attack", why)
        return {"hypotheses": []}
    r = await run_hypothesis_agent(
        state["incident_id"],
        state["incident_code"],
        state["evidence"],
        state.get("seed_techniques", []),
    )
    return {"hypotheses": r["hypotheses"], "tokens_used": r["tokens"]}


async def verify_node(state: SocState) -> dict[str, Any]:
    if not state.get("hypotheses"):
        await record_skip(state["incident_id"], "verifier", "no hypotheses")
        return {"supported": [], "rejected": [], "verdicts": [], "assessment": []}
    r = await run_verifier(state["incident_id"], state["hypotheses"], state.get("evidence", []))
    return {
        "verdicts": r["verdicts"],
        "supported": r["supported"],
        "rejected": r["rejected"],
        "assessment": r["assessment"],
        "tokens_used": r["tokens"],
    }


async def report_node(state: SocState) -> dict[str, Any]:
    if not state.get("supported") or over_budget(state):
        why = "no verified findings" if not state.get("supported") else "token budget exhausted"
        await record_skip(state["incident_id"], "report-writer", why)
        return {}
    if not state.get("auto_report", True):
        return {"report_pending": True}
    r = await run_report_writer(
        state["incident_id"],
        state["supported"],
        state.get("evidence", []),
        state.get("event_index", {}),
        state.get("assessment", []),
    )
    return {
        "report": {
            "summary": r["summary"],
            "narrative": r["narrative"],
            "recommended_actions": r["recommended_actions"],
        },
        "tokens_used": r["tokens"],
    }


builder = StateGraph(SocState)
builder.add_node("collect", collect_node)
builder.add_node("hypothesize", hypothesize_node)
builder.add_node("verify", verify_node)
builder.add_node("write_report", report_node)
builder.add_edge(START, "collect")
builder.add_edge("collect", "hypothesize")
builder.add_edge("hypothesize", "verify")
builder.add_edge("verify", "write_report")
builder.add_edge("write_report", END)
soc_graph = builder.compile()


async def investigate_streaming(
    incident_id: str,
    on_phase: Callable[[dict[str, Any]], None],
    auto_report: bool = True,
) -> SocState:
    incident = await get_incident(incident_id)
    if not incident:
        raise RuntimeError(f"incident not found: {incident_id}")

    on_phase({"phase": "collecting"})
    initial: SocState = {
        "incident_id": incident_id,
        "incident_code": incident["code"],
        "seed_techniques": incident.get("mitre_techniques") or [],
        "auto_report": auto_report,
        "tokens_used": 0,
    }
    next_phase = {"collect": "hypothesizing", "hypothesize": "verifying", "verify": "reporting"}
    accumulated: SocState = dict(initial)

    async for chunk in soc_graph.astream(initial, stream_mode="updates"):
        for node, update in chunk.items():
            previous_tokens = int(accumulated.get("tokens_used", 0))
            delta = int(update.get("tokens_used", 0))
            accumulated.update(update)
            accumulated["tokens_used"] = previous_tokens + delta
            if node in next_phase and (node != "verify" or auto_report):
                on_phase({"phase": next_phase[node]})

    has_report = bool(accumulated.get("report"))
    phase = (
        "done_with_report"
        if has_report
        else "ready_for_report"
        if accumulated.get("report_pending")
        else "done_no_report"
    )
    on_phase({
        "phase": phase,
        "supported": len(accumulated.get("supported", [])),
        "rejected": len(accumulated.get("rejected", [])),
        "hasReport": has_report,
    })
    return accumulated
