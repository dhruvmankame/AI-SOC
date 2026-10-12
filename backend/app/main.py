"""AI-SOC FastAPI runtime entrypoint.

CRITICAL RUNTIME FILE: HTTP API, dataset upload lifecycle, job state, MongoDB
persistence handoff, and investigation orchestration live here.

Upload pipeline:
CSV -> deterministic detection -> persistence -> evidence -> hypothesis ->
fail-closed verification -> report.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo import ReplaceOne

from .agents import run_report_writer
from .config import AGENT_CONCURRENCY, ANALYZE_PY, CORS_ORIGINS, LLM_PROVIDER, MAX_UPLOAD_MB, ML_DIR, MONGODB_DB
from .db import clean, close_db, collection, open_db
from .graph import investigate_streaming
from .llm import classify_llm_error
from .tools import record_agent_run
from .workflow import AGENTS, load_workflow, report_context

jobs: dict[str, dict[str, Any]] = {}
active_job_id: str | None = None
state_lock = asyncio.Lock()
background_tasks: set[asyncio.Task] = set()

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
PHASE_AGENT = {'collecting': AGENTS[0], 'hypothesizing': AGENTS[1], 'verifying': AGENTS[2], 'reporting': AGENTS[3]}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def now_ms() -> int:
    return int(time.time() * 1000)


def llm_error_message(err: Exception | object) -> str:
    kind = classify_llm_error(err)
    if kind == 'overload':
        return f'{LLM_PROVIDER.capitalize()} model overloaded (503 / high demand) — retry later'
    if kind == 'quota':
        return f'{LLM_PROVIDER.capitalize()} quota / rate limit reached'
    return str(err)[:200]


def spawn_background(coro: Any) -> None:
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)


async def claim_slot(job_id: str) -> tuple[bool, str | None]:
    global active_job_id
    async with state_lock:
        if active_job_id:
            current = jobs.get(active_job_id)
            if not current or current.get('status') != 'complete':
                return False, active_job_id
        active_job_id = job_id
        return True, None


async def release_slot(job_id: str) -> None:
    global active_job_id
    async with state_lock:
        if active_job_id == job_id:
            active_job_id = None


async def run_analyze(csv_path: Path, batch_id: str, label: str) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(ANALYZE_PY), str(csv_path), '--batch', batch_id, '--label', label,
        cwd=str(ML_DIR), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        for line in stderr.decode('utf-8', errors='replace').splitlines():
            if line.strip():
                print(f'[detector] {line}', flush=True)
    if proc.returncode != 0:
        raise RuntimeError(f'analyze.py exited {proc.returncode}: ' + stderr.decode('utf-8', errors='replace')[:500])
    try:
        return json.loads(stdout.decode('utf-8'))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'unparseable analyze.py output: {exc}; stderr: ' + stderr.decode('utf-8', errors='replace')[:300]) from exc


def stamp(doc: dict[str, Any], *, created: bool = True) -> dict[str, Any]:
    out = dict(doc)
    if created:
        out.setdefault('created_at', iso_now())
    return out


async def insert_batch(batch_id: str, data: dict[str, Any]) -> None:
    batch = data['batch']
    await collection('ingest_batches').insert_one(stamp({
        'batch_id': batch_id,
        'label': batch.get('label'),
        'source_filename': batch.get('source_filename'),
        'event_count': batch.get('event_count'),
        'incident_count': batch.get('incident_count'),
        'status': batch.get('status') or 'detected',
    }))

    incidents = []
    for i in data.get('incidents', []):
        incidents.append(stamp({
            'incident_id': i['incident_id'], 'code': i.get('code'), 'title': i.get('title'),
            'risk_score': i.get('risk_score', 0), 'risk_factors': i.get('risk_factors') or {},
            'status': i.get('status') or 'open', 'approval_state': i.get('approval_state') or 'none',
            'mitre_techniques': i.get('mitre_techniques') or [], 'summary': i.get('summary'),
            'batch_id': batch_id, 'updated_at': iso_now(),
        }))
    if incidents:
        await collection('incidents').insert_many(incidents, ordered=True)

    events = [stamp({**e, 'batch_id': batch_id}) for e in data.get('events', [])]
    if events:
        await collection('events').insert_many(events, ordered=False)

    signals = [stamp({**s, 'batch_id': batch_id}) for s in data.get('signals', [])]
    if signals:
        await collection('signals').insert_many(signals, ordered=False)

    entities = [{**e, 'batch_id': batch_id} for e in data.get('incident_entities', [])]
    for e in entities:
        await collection('incident_entities').update_one(
            {'incident_id': e.get('incident_id'), 'entity_type': e.get('entity_type'), 'entity_value': e.get('entity_value')},
            {'$setOnInsert': e}, upsert=True,
        )

    alerts = [stamp({**a, 'batch_id': batch_id}) for a in data.get('alerts', [])]
    if alerts:
        await collection('alerts').insert_many(alerts, ordered=False)

    rules = [
        ReplaceOne({'rule_id': r.get('rule_id')}, {
            'rule_id': r.get('rule_id'), 'title': r.get('title'), 'detector': r.get('detector'),
            'logic': {'ref': r.get('rule_id')}, 'mitre_tags': r.get('mitre_tags') or [],
            'severity': r.get('severity') or 'medium', 'enabled': True, 'version': 1,
        }, upsert=True)
        for r in data.get('rules', []) if r.get('rule_id')
    ]
    if rules:
        await collection('detection_rules').bulk_write(rules, ordered=False)

    kb = [
        ReplaceOne({'technique_id': k.get('technique_id')}, {
            'technique_id': k.get('technique_id'), 'name': k.get('name'), 'tactic': k.get('tactic'), 'description': k.get('description')
        }, upsert=True)
        for k in data.get('attack_kb', []) if k.get('technique_id')
    ]
    if kb:
        await collection('attack_kb').bulk_write(kb, ordered=False)


async def record_failure(incident_id: str, phase: str, err: Exception | object) -> None:
    agent = PHASE_AGENT.get(phase)
    if not agent:
        return
    try:
        await record_agent_run({
            'incident_id': incident_id, 'agent': agent, 'tools_used': [], 'citations': [],
            'output': {'error': llm_error_message(err)}, 'status': 'error', 'unsupported_claims': [],
            'latency_ms': 0, 'tokens': 0,
        })
    except Exception as persist_error:
        print(f'[agent-error] could not persist agent failure: {persist_error}', flush=True)


async def run_investigations(job: dict[str, Any]) -> None:
    job['status'] = 'investigating'
    if job.get('batchId'):
        await collection('ingest_batches').update_one({'batch_id': job['batchId']}, {'$set': {'status': 'investigating'}})

    for incident_job in job['incidents']:
        incident_id = incident_job['incidentId']
        existing = await collection('incidents').find_one({'incident_id': incident_id}, {'_id': 0, 'summary': 1})
        if existing and existing.get('summary'):
            incident_job['phase'] = 'done_with_report'
            incident_job['finishedAt'] = now_ms()
            continue

        incident_job['phase'] = 'collecting'
        incident_job['startedAt'] = now_ms()

        def on_phase(progress: dict[str, Any]) -> None:
            incident_job['phase'] = progress['phase']
            if progress['phase'] in {'ready_for_report', 'done_with_report', 'done_no_report'}:
                incident_job['finishedAt'] = now_ms()

        try:
            # Uploaded datasets use one continuous demo pipeline. The report writer is
            # still gated by the fail-closed verifier inside the investigation graph.
            await investigate_streaming(incident_id, on_phase, auto_report=True)
        except Exception as exc:
            await record_failure(incident_id, incident_job['phase'], exc)
            incident_job['phase'] = 'error'
            incident_job['error'] = llm_error_message(exc)
            incident_job['finishedAt'] = now_ms()

    job['status'] = 'complete'
    if job.get('batchId'):
        await collection('ingest_batches').update_one({'batch_id': job['batchId']}, {'$set': {'status': 'complete'}})


async def persist_and_investigate(job_id: str, batch_id: str, data: dict[str, Any]) -> None:
    try:
        print(f"[persist/mongodb] batch {batch_id[:8]}: {len(data.get('events', []))} events, {len(data.get('signals', []))} signals", flush=True)
        await insert_batch(batch_id, data)
        job = jobs[job_id]
        if not job['incidents']:
            job['status'] = 'complete'
            await collection('ingest_batches').update_one({'batch_id': batch_id}, {'$set': {'status': 'complete'}})
        else:
            await run_investigations(job)
    except Exception as exc:
        job = jobs.get(job_id)
        if job:
            job['error'] = str(exc)[:200]
            job['status'] = 'complete'
            for incident in job['incidents']:
                if incident['phase'] == 'queued':
                    incident['phase'] = 'error'
                    incident['error'] = str(exc)[:200]
                    incident['finishedAt'] = now_ms()
        print(f'[background-analysis] {exc}', flush=True)
    finally:
        await release_slot(job_id)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await open_db()
    print(f'[ai-soc] connected to MongoDB database: {MONGODB_DB}', flush=True)
    try:
        yield
    finally:
        for task in list(background_tasks):
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        await close_db()


app = FastAPI(title='AI-SOC Python + MongoDB Backend', version='2.0.0', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False, allow_methods=['GET', 'POST'], allow_headers=['*'])


@app.get('/api/health')
async def health() -> dict[str, Any]:
    await collection('ingest_batches').database.command('ping')
    return {'ok': True, 'database': 'mongodb'}


@app.post('/api/analyze')
async def analyze(file: UploadFile = File(...)):
    label = file.filename or 'upload.csv'
    if Path(label).suffix.lower() != '.csv':
        return JSONResponse(status_code=400, content={'error': 'only .csv flow files are accepted'})

    batch_id, job_id = str(uuid4()), str(uuid4())
    claimed, running = await claim_slot(job_id)
    if not claimed:
        return JSONResponse(status_code=409, content={'error': 'An analysis is already running. Wait for it to finish before uploading another dataset.', 'activeJobId': running})

    handed_off = False
    temp_path: Path | None = None
    request_started = now_ms()
    try:
        fd, raw_path = tempfile.mkstemp(prefix='ai-soc-', suffix='.csv')
        os.close(fd)
        temp_path = Path(raw_path)
        size, max_bytes = 0, MAX_UPLOAD_MB * 1024 * 1024
        with temp_path.open('wb') as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    return JSONResponse(status_code=400, content={'error': f'file too large; max upload is {MAX_UPLOAD_MB} MB'})
                handle.write(chunk)

        data = await run_analyze(temp_path, batch_id, label)
        if data.get('error'):
            return JSONResponse(status_code=400, content={'error': data['error']})
        data['batch']['source_filename'] = label
        kb_name = {item['technique_id']: item['name'] for item in data.get('attack_kb', [])}
        incidents = []
        for item in data.get('incidents', []):
            techniques = item.get('mitre_techniques') or []
            incidents.append({
                'incidentId': item['incident_id'], 'code': item['code'], 'title': item['title'],
                'attackType': item.get('title') or (kb_name.get(techniques[0]) if techniques else None) or 'Unknown',
                'risk': item.get('risk_score', 0), 'phase': 'queued',
            })
        job = {'jobId': job_id, 'batchId': batch_id, 'createdAt': now_ms(), 'status': 'inserting', 'incidents': incidents}
        jobs[job_id] = job
        response = {
            'batchId': batch_id, 'jobId': job_id,
            'stats': {'storedEvents': data['batch'].get('event_count', 0), 'signals': len(data.get('signals', [])), 'alerts': len(data.get('alerts', [])), 'incidents': len(data.get('incidents', [])), 'processingMs': now_ms() - request_started, 'sourceFilename': data['batch'].get('source_filename')},
            'standardization': data.get('standardization'),
            'incidents': [{k: i[k] for k in ('incidentId', 'code', 'title', 'attackType', 'risk')} for i in incidents],
            'alerts': [{'title': a.get('title'), 'severity': a.get('severity'), 'confidence': a.get('confidence'), 'detector': a.get('detector'), 'entity': a.get('entity'), 'correlationCount': a.get('correlation_count'), 'contributions': a.get('contributions') or {}} for a in data.get('alerts', [])],
            'eval': data.get('eval'),
        }
        handed_off = True
        spawn_background(persist_and_investigate(job_id, batch_id, data))
        return response
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': str(exc)[:500]})
    finally:
        await file.close()
        if temp_path:
            temp_path.unlink(missing_ok=True)
        if not handed_off:
            await release_slot(job_id)


@app.get('/api/jobs/{job_id}')
async def get_job(job_id: str):
    job = jobs.get(job_id)
    return job if job else JSONResponse(status_code=404, content={'error': 'job not found'})


@app.get('/api/incidents/{incident_id}/workflow')
async def get_workflow(incident_id: str):
    if not UUID_RE.match(incident_id):
        return JSONResponse(status_code=400, content={'error': 'Invalid incident ID'})
    try:
        workflow = await load_workflow(incident_id)
        if not workflow:
            return JSONResponse(status_code=404, content={'error': 'Incident not found'})
        current_job = jobs.get(active_job_id) if active_job_id else None
        live = None
        if current_job and current_job.get('status') != 'complete':
            live = next((x for x in current_job['incidents'] if x['incidentId'] == incident_id and not x.get('finishedAt')), None)
        active_agent = PHASE_AGENT.get(live.get('phase')) if live else None
        blocked, stages = False, []
        for index, agent in enumerate(AGENTS):
            run = workflow['latest'][index]
            if live and live.get('startedAt') and live.get('phase') != 'reporting' and run:
                created = run.get('created_at')
                try:
                    created_ms = int(datetime.fromisoformat(str(created).replace('Z', '+00:00')).timestamp() * 1000)
                except Exception:
                    created_ms = 0
                if created_ms < int(live['startedAt']):
                    run = None
            if agent == active_agent: status = 'running'
            elif run and run.get('status') == 'error': status = 'error'
            elif run and run.get('status') == 'skipped': status = 'skipped'
            elif run: status = 'complete'
            elif index == 3 and workflow['can_report'] and not live: status = 'ready'
            elif blocked: status = 'blocked'
            else: status = 'waiting'
            if status in {'error', 'skipped'}: blocked = True
            stages.append({'agent': agent, 'status': status, 'runId': run.get('run_id') if run else None, 'tokens': int(run.get('tokens') or 0) if run else 0, 'durationMs': int(run.get('latency_ms') or 0) if run else 0, 'output': (run.get('output') or {}) if run else {}})
        busy = bool(active_job_id)
        return {'stages': stages, 'active': bool(live), 'busy': busy, 'canReport': bool(workflow['can_report'] and not busy), 'canInvestigate': bool(not busy and not workflow['report']), 'reason': workflow['reason'], 'report': workflow['report'], 'startedAt': live.get('startedAt') if live else None}
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': llm_error_message(exc)})


async def run_manual_action(job_id: str, incident_job: dict[str, Any], action: str, workflow: dict[str, Any], event_index: dict[str, dict[str, Any]] | None) -> None:
    job = jobs[job_id]
    try:
        if action == 'investigate':
            await run_investigations(job)
        else:
            await run_report_writer(incident_job['incidentId'], workflow['supported'], workflow['evidence'], event_index or {}, workflow['assessment'])
            incident_job['phase'] = 'done_with_report'
            job['status'] = 'complete'
    except Exception as exc:
        await record_failure(incident_job['incidentId'], incident_job['phase'], exc)
        incident_job['phase'] = 'error'
        incident_job['error'] = llm_error_message(exc)
        job['status'] = 'complete'
    finally:
        incident_job['finishedAt'] = now_ms()
        await release_slot(job_id)


@app.post('/api/incidents/{incident_id}/{action}')
async def start_action(incident_id: str, action: str):
    if action not in {'investigate', 'report'}:
        return JSONResponse(status_code=404, content={'error': 'action not found'})
    if not UUID_RE.match(incident_id):
        return JSONResponse(status_code=400, content={'error': 'Invalid incident ID'})
    job_id = str(uuid4())
    claimed, _ = await claim_slot(job_id)
    if not claimed:
        return JSONResponse(status_code=409, content={'error': 'Another investigation is running. Wait for it to finish.'})
    handed_off = False
    try:
        workflow = await load_workflow(incident_id)
        if not workflow:
            return JSONResponse(status_code=404, content={'error': 'Incident not found'})
        if workflow['report']:
            return {'complete': True}
        if action == 'report' and not workflow['can_report']:
            return JSONResponse(status_code=409, content={'error': workflow['reason']})
        event_index = await report_context(workflow) if action == 'report' else None
        incident = workflow['incident']
        incident_job = {'incidentId': incident_id, 'code': incident['code'], 'title': incident['title'], 'attackType': incident['title'], 'risk': incident['risk_score'], 'phase': 'reporting' if action == 'report' else 'queued', 'startedAt': now_ms()}
        job = {'jobId': job_id, 'batchId': incident.get('batch_id') or '', 'createdAt': now_ms(), 'status': 'investigating', 'incidents': [incident_job]}
        jobs[job_id] = job
        handed_off = True
        spawn_background(run_manual_action(job_id, incident_job, action, workflow, event_index))
        return JSONResponse(status_code=202, content={'jobId': job_id})
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': llm_error_message(exc)})
    finally:
        if not handed_off:
            await release_slot(job_id)


# ---------- React read API (replaces Supabase/PostgREST) ----------------------
def batch_filter(batch_id: str | None) -> dict[str, Any]:
    if not batch_id:
        return {}
    return {'batch_id': None} if batch_id == 'seed' else {'batch_id': batch_id}


@app.get('/api/data/batches')
async def data_batches():
    return await collection('ingest_batches').find({}, {'_id': 0}).sort('created_at', -1).to_list(length=None)


@app.get('/api/data/alerts')
async def data_alerts(batchId: str | None = None, incidentId: str | None = None):
    q: dict[str, Any] = batch_filter(batchId)
    if incidentId: q['incident_id'] = incidentId
    return await collection('alerts').find(q, {'_id': 0}).sort('created_at', -1).to_list(length=None)


@app.get('/api/data/incidents')
async def data_incidents(batchId: str | None = None):
    return await collection('incidents').find(batch_filter(batchId), {'_id': 0}).sort('created_at', -1).to_list(length=None)


@app.get('/api/data/incidents/{incident_id}')
async def data_incident(incident_id: str):
    doc = clean(await collection('incidents').find_one({'incident_id': incident_id}, {'_id': 0}))
    return doc if doc else JSONResponse(status_code=404, content={'error': 'Incident not found'})


@app.get('/api/data/incidents/{incident_id}/entities')
async def data_entities(incident_id: str):
    return await collection('incident_entities').find({'incident_id': incident_id}, {'_id': 0, 'batch_id': 0}).to_list(length=None)


@app.get('/api/data/incidents/{incident_id}/evidence')
async def data_evidence(incident_id: str):
    return await collection('evidence').find({'incident_id': incident_id}, {'_id': 0}).sort('created_at', 1).to_list(length=None)


@app.get('/api/data/incidents/{incident_id}/timeline')
async def data_timeline(incident_id: str):
    return await collection('incident_timeline').find({'incident_id': incident_id}, {'_id': 0}).sort('ts', 1).to_list(length=None)


@app.get('/api/data/incidents/{incident_id}/agent-runs')
async def data_agent_runs(incident_id: str):
    return await collection('agent_runs').find({'incident_id': incident_id}, {'_id': 0}).sort('created_at', 1).to_list(length=None)


@app.get('/api/data/attack-kb')
async def data_attack_kb():
    return await collection('attack_kb').find({}, {'_id': 0}).to_list(length=None)


@app.get('/api/data/verifier-counts')
async def data_verifier_counts(incidentIds: str = Query(default='')):
    ids = [x for x in incidentIds.split(',') if x]
    if not ids:
        return {}
    runs = await collection('agent_runs').find({'incident_id': {'$in': ids}, 'agent': 'verifier'}, {'_id': 0}).sort('created_at', -1).to_list(length=None)
    out: dict[str, Any] = {}
    for run in runs:
        iid = run.get('incident_id')
        if iid in out: continue
        output = run.get('output') or {}
        verdicts = output.get('verdicts') if isinstance(output.get('verdicts'), list) else []
        rejected = run.get('unsupported_claims') if isinstance(run.get('unsupported_claims'), list) else []
        out[iid] = {'supported': sum(1 for v in verdicts if v.get('supported')), 'rejected': len(rejected), 'assessment': output.get('attack_assessment') if isinstance(output.get('attack_assessment'), list) else []}
    return out


@app.get('/api/data/overview')
async def data_overview(batchId: str | None = None):
    q = batch_filter(batchId)
    events_c, signals_c, alerts_c, incidents_c, rules_c = await asyncio.gather(
        collection('events').count_documents(q), collection('signals').count_documents(q),
        collection('alerts').count_documents(q), collection('incidents').count_documents(q),
        collection('detection_rules').count_documents({}),
    )
    event_rows = await collection('events').find(q, {'_id': 0, 'ts': 1, 'source_type': 1, 'severity': 1}).to_list(length=50001)
    incident_rows = await collection('incidents').find(q, {'_id': 0}).to_list(length=None)
    sev: dict[str, int] = {}; src: dict[str, int] = {}; hour: dict[str, int] = {}
    for event in event_rows:
        s = str(event.get('severity') or 'info'); sev[s] = sev.get(s, 0) + 1
        source = str(event.get('source_type') or 'unknown'); src[source] = src.get(source, 0) + 1
        key = str(event.get('ts') or '').replace('T', ' ')[:13] + ':00'; hour[key] = hour.get(key, 0) + 1
    volume = [{'hour': h, 'count': c} for h, c in sorted(hour.items())[-24:]]
    priority = sorted(incident_rows, key=lambda x: float(x.get('risk_score') or 0), reverse=True)[:6]
    return {'events': events_c, 'signals': signals_c, 'alerts': alerts_c, 'incidents': incidents_c, 'rules': rules_c,
            'severity': [{'name': n, 'count': c} for n, c in sev.items()],
            'sources': sorted([{'name': n, 'count': c} for n, c in src.items()], key=lambda x: x['count'], reverse=True),
            'volume': volume, 'priority': priority}
