from __future__ import annotations

from typing import Any

from pymongo import ASCENDING, DESCENDING, AsyncMongoClient, IndexModel
from pymongo.server_api import ServerApi

from .config import MONGODB_DB, MONGODB_URI

client: AsyncMongoClient[dict[str, Any]] | None = None
db = None


def collection(name: str):
    if db is None:
        raise RuntimeError('MongoDB is not initialized')
    return db[name]


async def open_db() -> None:
    global client, db
    client = AsyncMongoClient(MONGODB_URI, server_api=ServerApi('1'))
    await client.admin.command('ping')
    db = client[MONGODB_DB]

    indexes = {
        'ingest_batches': [IndexModel([('batch_id', ASCENDING)], unique=True), IndexModel([('created_at', DESCENDING)])],
        'events': [IndexModel([('event_id', ASCENDING)], unique=True), IndexModel([('batch_id', ASCENDING)]), IndexModel([('src_ip', ASCENDING)]), IndexModel([('dst_ip', ASCENDING)]), IndexModel([('ts', DESCENDING)])],
        'signals': [IndexModel([('event_id', ASCENDING)]), IndexModel([('batch_id', ASCENDING)])],
        'alerts': [IndexModel([('alert_id', ASCENDING)], unique=True), IndexModel([('incident_id', ASCENDING)]), IndexModel([('batch_id', ASCENDING)]), IndexModel([('created_at', DESCENDING)])],
        'incidents': [IndexModel([('incident_id', ASCENDING)], unique=True), IndexModel([('code', ASCENDING)], unique=True), IndexModel([('batch_id', ASCENDING)]), IndexModel([('created_at', DESCENDING)])],
        'incident_entities': [IndexModel([('incident_id', ASCENDING), ('entity_type', ASCENDING), ('entity_value', ASCENDING)], unique=True)],
        'evidence': [IndexModel([('evidence_id', ASCENDING)], unique=True), IndexModel([('incident_id', ASCENDING)])],
        'agent_runs': [IndexModel([('run_id', ASCENDING)], unique=True), IndexModel([('incident_id', ASCENDING), ('created_at', ASCENDING)])],
        'incident_timeline': [IndexModel([('incident_id', ASCENDING), ('ts', ASCENDING)])],
        'detection_rules': [IndexModel([('rule_id', ASCENDING)], unique=True)],
        'attack_kb': [IndexModel([('technique_id', ASCENDING)], unique=True)],
    }
    for name, models in indexes.items():
        await collection(name).create_indexes(models)


async def close_db() -> None:
    global client, db
    if client is not None:
        await client.close()
    client = None
    db = None


def clean(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if doc is None:
        return None
    doc = dict(doc)
    doc.pop('_id', None)
    return doc
