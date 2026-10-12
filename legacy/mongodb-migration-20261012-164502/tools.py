from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from .db import execute, fetch_all, fetch_one, pool


async def get_incident(incident_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        """
        select incident_id::text, code, title, risk_score, mitre_techniques, batch_id::text
        from incidents where incident_id = %s::uuid
        """,
        (incident_id,),
    )


async def get_incident_entities(incident_id: str) -> list[dict[str, Any]]:
    return await fetch_all(
        """
        select entity_type, entity_value, role
        from incident_entities where incident_id = %s::uuid
        """,
        (incident_id,),
    )


async def query_events_for_entity(entity_value: str, limit: int = 40) -> list[dict[str, Any]]:
    return await fetch_all(
        """
        select event_id::text, ts::text, host(src_ip) as src_ip, host(dst_ip) as dst_ip,
               severity::text, template_text, raw, mitre_tags
        from events
        where src_ip = %s::inet or dst_ip = %s::inet
        order by ts desc
        limit %s
        """,
        (entity_value, entity_value, limit),
    )


async def get_incident_events(incident_id: str, limit: int = 60) -> list[dict[str, Any]]:
    return await fetch_all(
        """
        select event_id::text, ts::text, host(src_ip) as src_ip, host(dst_ip) as dst_ip,
               severity::text, template_text, raw, mitre_tags
        from events
        where event_id in (
          select unnest(event_ids) from alerts where incident_id = %s::uuid
        )
        order by ts desc
        limit %s
        """,
        (incident_id, limit),
    )


async def get_signals_for_events(event_ids: list[str]) -> list[dict[str, Any]]:
    if not event_ids:
        return []
    return await fetch_all(
        """
        select event_id::text, detector, detector_ref, score, reason
        from signals where event_id = any(%s::uuid[])
        """,
        (event_ids,),
    )


async def search_attack_kb(terms: list[str]) -> list[dict[str, Any]]:
    if not terms:
        return []
    like = [f"%{t.replace('%', '').replace('_', '')}%" for t in terms]
    return await fetch_all(
        """
        select technique_id, name, tactic, description
        from attack_kb
        where technique_id = any(%s::text[])
           or name ilike any(%s::text[])
           or description ilike any(%s::text[])
        limit 8
        """,
        (terms, like, like),
    )


async def insert_evidence(items: list[dict[str, Any]]) -> None:
    if not items:
        return
    sql = """
        insert into evidence
          (evidence_id, incident_id, kind, source_event_ids, fact, provenance, confidence)
        values (%s, %s::uuid, %s, %s::uuid[], %s, %s, %s)
        on conflict (evidence_id) do update set
          fact = excluded.fact,
          kind = excluded.kind,
          source_event_ids = excluded.source_event_ids,
          provenance = excluded.provenance,
          confidence = excluded.confidence
    """
    rows = [
        (
            e["evidence_id"],
            e["incident_id"],
            e["kind"],
            e["source_event_ids"],
            e["fact"],
            "agent:evidence-collector",
            e["confidence"],
        )
        for e in items
    ]
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.executemany(sql, rows)
        await conn.commit()


async def insert_timeline(incident_id: str, items: list[dict[str, Any]]) -> None:
    if not items:
        return
    sql = """
        insert into incident_timeline (incident_id, ts, label, evidence_id)
        values (%s::uuid, %s::timestamptz, %s, %s)
    """
    rows = [
        (incident_id, x["ts"], x["label"], x.get("evidence_id"))
        for x in items
    ]
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.executemany(sql, rows)
        await conn.commit()


async def write_report(incident_id: str, summary: str, mitre_techniques: list[str]) -> None:
    await execute(
        """
        update incidents
        set summary = %s,
            mitre_techniques = %s::text[],
            status = 'investigating',
            updated_at = now()
        where incident_id = %s::uuid
        """,
        (summary, mitre_techniques, incident_id),
    )


async def record_agent_run(row: dict[str, Any]) -> None:
    await execute(
        """
        insert into agent_runs
          (incident_id, agent, tools_used, citations, output, status,
           unsupported_claims, latency_ms, tokens)
        values (%s::uuid, %s, %s::jsonb, %s::text[], %s::jsonb, %s,
                %s::jsonb, %s, %s)
        """,
        (
            row["incident_id"],
            row["agent"],
            Jsonb(row.get("tools_used", [])),
            row.get("citations", []),
            Jsonb(row.get("output", {})),
            row.get("status", "ok"),
            Jsonb(row.get("unsupported_claims", [])),
            int(row.get("latency_ms", 0)),
            int(row.get("tokens", 0)),
        ),
    )
