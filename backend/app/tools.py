from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .db import clean, collection


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


async def get_incident(incident_id: str) -> dict[str, Any] | None:
    return clean(await collection('incidents').find_one(
        {'incident_id': incident_id},
        {'_id': 0, 'incident_id': 1, 'code': 1, 'title': 1, 'risk_score': 1, 'mitre_techniques': 1, 'batch_id': 1},
    ))


async def get_incident_entities(incident_id: str) -> list[dict[str, Any]]:
    cur = collection('incident_entities').find(
        {'incident_id': incident_id},
        {'_id': 0, 'entity_type': 1, 'entity_value': 1, 'role': 1},
    )
    return await cur.to_list(length=None)


async def query_events_for_entity(entity_value: str, limit: int = 40) -> list[dict[str, Any]]:
    cur = collection('events').find(
        {'$or': [{'src_ip': entity_value}, {'dst_ip': entity_value}]},
        {'_id': 0, 'event_id': 1, 'ts': 1, 'src_ip': 1, 'dst_ip': 1, 'severity': 1, 'template_text': 1, 'raw': 1, 'mitre_tags': 1},
    ).sort('ts', -1).limit(limit)
    return await cur.to_list(length=limit)


async def get_incident_events(incident_id: str, limit: int = 60) -> list[dict[str, Any]]:
    alerts = await collection('alerts').find(
        {'incident_id': incident_id}, {'_id': 0, 'event_ids': 1}
    ).to_list(length=None)
    event_ids = list(dict.fromkeys(e for a in alerts for e in (a.get('event_ids') or [])))
    if not event_ids:
        return []
    cur = collection('events').find(
        {'event_id': {'$in': event_ids}},
        {'_id': 0, 'event_id': 1, 'ts': 1, 'src_ip': 1, 'dst_ip': 1, 'severity': 1, 'template_text': 1, 'raw': 1, 'mitre_tags': 1},
    ).sort('ts', -1).limit(limit)
    return await cur.to_list(length=limit)


async def get_signals_for_events(event_ids: list[str]) -> list[dict[str, Any]]:
    if not event_ids:
        return []
    cur = collection('signals').find(
        {'event_id': {'$in': event_ids}},
        {'_id': 0, 'event_id': 1, 'detector': 1, 'detector_ref': 1, 'score': 1, 'reason': 1},
    )
    return await cur.to_list(length=None)


async def search_attack_kb(terms: list[str]) -> list[dict[str, Any]]:
    if not terms:
        return []
    ors: list[dict[str, Any]] = []
    for term in terms[:12]:
        if not term:
            continue
        rx = re.escape(term)
        ors.extend([
            {'technique_id': {'$regex': rx, '$options': 'i'}},
            {'name': {'$regex': rx, '$options': 'i'}},
            {'description': {'$regex': rx, '$options': 'i'}},
        ])
    if not ors:
        return []
    cur = collection('attack_kb').find({'$or': ors}, {'_id': 0}).limit(8)
    return await cur.to_list(length=8)


async def insert_evidence(items: list[dict[str, Any]]) -> None:
    for e in items:
        doc = {
            'evidence_id': e['evidence_id'],
            'incident_id': e['incident_id'],
            'kind': e['kind'],
            'source_event_ids': e.get('source_event_ids') or [],
            'fact': e['fact'],
            'provenance': 'agent:evidence-collector',
            'confidence': e.get('confidence', 1.0),
            'created_at': iso_now(),
        }
        await collection('evidence').update_one(
            {'evidence_id': e['evidence_id']},
            {'$set': doc, '$setOnInsert': {'created_at': doc['created_at']}},
            upsert=True,
        )


async def insert_timeline(incident_id: str, items: list[dict[str, Any]]) -> None:
    if not items:
        return
    base = int(time.time() * 1000)
    docs = [{
        'id': base + i,
        'incident_id': incident_id,
        'ts': x['ts'],
        'label': x['label'],
        'event_id': x.get('event_id'),
        'evidence_id': x.get('evidence_id'),
    } for i, x in enumerate(items)]
    await collection('incident_timeline').insert_many(docs, ordered=True)


async def write_report(incident_id: str, summary: str, mitre_techniques: list[str]) -> None:
    await collection('incidents').update_one(
        {'incident_id': incident_id},
        {'$set': {
            'summary': summary,
            'mitre_techniques': mitre_techniques,
            'status': 'investigating',
            'updated_at': iso_now(),
        }},
    )


async def record_agent_run(row: dict[str, Any]) -> None:
    doc = {
        'run_id': str(uuid4()),
        'incident_id': row['incident_id'],
        'agent': row['agent'],
        'tools_used': row.get('tools_used', []),
        'citations': row.get('citations', []),
        'output': row.get('output', {}),
        'status': row.get('status', 'ok'),
        'unsupported_claims': row.get('unsupported_claims', []),
        'latency_ms': int(row.get('latency_ms', 0)),
        'tokens': int(row.get('tokens', 0)),
        'created_at': iso_now(),
    }
    await collection('agent_runs').insert_one(doc)
