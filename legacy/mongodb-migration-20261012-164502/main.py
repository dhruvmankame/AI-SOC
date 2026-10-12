from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg.types.json import Jsonb

from .agents import run_report_writer
from .config import ANALYZE_PY, CORS_ORIGINS, MAX_UPLOAD_MB, ML_DIR
from .db import close_db, execute, fetch_one, open_db, pool
from .graph import investigate_streaming
from .llm import classify_llm_error
from .tools import record_agent_run
from .workflow import AGENTS, load_workflow, report_context

jobs: dict[str, dict[str, Any]] = {}
active_job_id: str | None = None
state_lock = asyncio.Lock()
background_tasks: set[asyncio.Task] = set()

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)

PHASE_AGENT = {
    "collecting": AGENTS[0],
    "hypothesizing": AGENTS[1],
    "verifying": AGENTS[2],
    "reporting": AGENTS[3],
}


def now_ms() -> int:
    return int(time.time() * 1000)


def llm_error_message(err: Exception | object) -> str:
    kind = classify_llm_error(err)
    if kind == "overload":
        return "Gemini model overloaded (503 / high demand) — retry later"
    if kind == "quota":
        return "Gemini quota / rate limit reached"
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
            if not current or current.get("status") != "complete":
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
        sys.executable,
        str(ANALYZE_PY),
        str(csv_path),
        "--batch",
        batch_id,
        "--label",
        label,
        cwd=str(ML_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        for line in stderr.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                print(f"[detector] {line}", flush=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"analyze.py exited {proc.returncode}: "
            + stderr.decode("utf-8", errors="replace")[:500]
        )
    try:
        return json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"unparseable analyze.py output: {exc}; stderr: "
            + stderr.decode("utf-8", errors="replace")[:300]
        ) from exc


async def _many(cur: Any, sql: str, rows: list[tuple[Any, ...]]) -> None:
    if rows:
        await cur.executemany(sql, rows)


async def insert_batch(batch_id: str, data: dict[str, Any]) -> None:
    async with pool.connection() as conn:
        async with conn.transaction():
            async with conn.cursor() as cur:
                batch = data["batch"]
                await cur.execute(
                    """
                    insert into ingest_batches
                      (batch_id, label, source_filename, event_count, incident_count, status)
                    values (%s::uuid, %s, %s, %s, %s, %s)
                    """,
                    (
                        batch_id,
                        batch.get("label"),
                        batch.get("source_filename"),
                        batch.get("event_count"),
                        batch.get("incident_count"),
                        batch.get("status") or "detected",
                    ),
                )

                await _many(
                    cur,
                    """
                    insert into incidents
                      (incident_id, code, title, risk_score, risk_factors,
                       mitre_techniques, summary, batch_id)
                    values (%s::uuid, %s, %s, %s, %s::jsonb, %s::text[], %s, %s::uuid)
                    """,
                    [
                        (
                            i["incident_id"], i.get("code"), i.get("title"),
                            i.get("risk_score", 0), Jsonb(i.get("risk_factors") or {}),
                            i.get("mitre_techniques") or [], i.get("summary"), batch_id,
                        )
                        for i in data.get("incidents", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into events
                      (event_id, ts, source_type, vendor, product, class_uid, category,
                       activity, severity, outcome, src_ip, dst_ip, template_id,
                       template_text, parser_confidence, mitre_tags, raw, raw_hash,
                       gt_label, gt_scenario, batch_id)
                    values (
                       %s::uuid, %s::timestamptz, %s, %s, %s, %s, %s, %s,
                       %s::severity_t, %s, %s::inet, %s::inet, %s, %s, %s,
                       %s::text[], %s, %s, %s, %s, %s::uuid
                    )
                    """,
                    [
                        (
                            e.get("event_id"), e.get("ts"), e.get("source_type"),
                            e.get("vendor"), e.get("product"), e.get("class_uid"),
                            e.get("category"), e.get("activity"), e.get("severity") or "info",
                            e.get("outcome"), e.get("src_ip"), e.get("dst_ip"),
                            e.get("template_id"), e.get("template_text"),
                            e.get("parser_confidence"), e.get("mitre_tags") or [],
                            e.get("raw"), e.get("raw_hash"), e.get("gt_label"),
                            e.get("gt_scenario"), batch_id,
                        )
                        for e in data.get("events", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into signals
                      (event_id, detector, detector_ref, score, reason, batch_id)
                    values (%s::uuid, %s, %s, %s, %s, %s::uuid)
                    """,
                    [
                        (
                            s.get("event_id"), s.get("detector"), s.get("detector_ref"),
                            s.get("score"), s.get("reason"), batch_id,
                        )
                        for s in data.get("signals", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into incident_entities
                      (incident_id, entity_type, entity_value, role, batch_id)
                    values (%s::uuid, %s, %s, %s, %s::uuid)
                    on conflict (incident_id, entity_type, entity_value) do nothing
                    """,
                    [
                        (
                            e.get("incident_id"), e.get("entity_type"),
                            e.get("entity_value"), e.get("role"), batch_id,
                        )
                        for e in data.get("incident_entities", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into alerts
                      (alert_id, title, severity, confidence, detector, contributions,
                       entity, event_ids, correlation_count, status, incident_id, batch_id)
                    values (
                      %s::uuid, %s, %s::severity_t, %s, %s, %s::jsonb, %s,
                      %s::uuid[], %s, %s, %s::uuid, %s::uuid
                    )
                    """,
                    [
                        (
                            a.get("alert_id"), a.get("title"), a.get("severity") or "low",
                            a.get("confidence", 0), a.get("detector"),
                            Jsonb(a.get("contributions") or {}), a.get("entity"),
                            a.get("event_ids") or [], a.get("correlation_count", 1),
                            a.get("status") or "new", a.get("incident_id"), batch_id,
                        )
                        for a in data.get("alerts", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into detection_rules
                      (rule_id, title, detector, logic, mitre_tags, severity)
                    values (%s, %s, %s, %s::jsonb, %s::text[], %s::severity_t)
                    on conflict (rule_id) do nothing
                    """,
                    [
                        (
                            r.get("rule_id"), r.get("title"), r.get("detector"),
                            Jsonb({"ref": r.get("rule_id")}), r.get("mitre_tags") or [],
                            r.get("severity") or "medium",
                        )
                        for r in data.get("rules", [])
                    ],
                )

                await _many(
                    cur,
                    """
                    insert into attack_kb (technique_id, name, tactic, description)
                    values (%s, %s, %s, %s)
                    on conflict (technique_id) do nothing
                    """,
                    [
                        (k.get("technique_id"), k.get("name"), k.get("tactic"), k.get("description"))
                        for k in data.get("attack_kb", [])
                    ],
                )


async def record_failure(incident_id: str, phase: str, err: Exception | object) -> None:
    agent = PHASE_AGENT.get(phase)
    if not agent:
        return
    try:
        await record_agent_run({
            "incident_id": incident_id,
            "agent": agent,
            "tools_used": [],
            "citations": [],
            "output": {"error": llm_error_message(err)},
            "status": "error",
            "unsupported_claims": [],
            "latency_ms": 0,
            "tokens": 0,
        })
    except Exception as persist_error:
        print(f"[agent-error] could not persist agent failure: {persist_error}", flush=True)


async def run_investigations(job: dict[str, Any]) -> None:
    job["status"] = "investigating"
    if job.get("batchId"):
        try:
            await execute(
                "update ingest_batches set status=%s where batch_id=%s::uuid",
                ("investigating", job["batchId"]),
            )
        except Exception:
            pass

    for incident_job in job["incidents"]:
        incident_id = incident_job["incidentId"]
        existing = await fetch_one(
            "select summary from incidents where incident_id=%s::uuid",
            (incident_id,),
        )
        if existing and existing.get("summary"):
            incident_job["phase"] = "done_with_report"
            incident_job["finishedAt"] = now_ms()
            continue

        incident_job["phase"] = "collecting"
        incident_job["startedAt"] = now_ms()

        def on_phase(progress: dict[str, Any]) -> None:
            incident_job["phase"] = progress["phase"]
            if progress["phase"] in {"ready_for_report", "done_with_report", "done_no_report"}:
                incident_job["finishedAt"] = now_ms()

        try:
            await investigate_streaming(incident_id, on_phase, auto_report=False)
        except Exception as exc:
            await record_failure(incident_id, incident_job["phase"], exc)
            incident_job["phase"] = "error"
            incident_job["error"] = llm_error_message(exc)
            incident_job["finishedAt"] = now_ms()

    job["status"] = "complete"
    if job.get("batchId"):
        try:
            await execute(
                "update ingest_batches set status=%s where batch_id=%s::uuid",
                ("complete", job["batchId"]),
            )
        except Exception:
            pass


async def persist_and_investigate(job_id: str, batch_id: str, data: dict[str, Any]) -> None:
    try:
        print(
            f"[persist] batch {batch_id[:8]}: {len(data.get('events', []))} events, "
            f"{len(data.get('signals', []))} signals",
            flush=True,
        )
        await insert_batch(batch_id, data)
        job = jobs[job_id]
        if not job["incidents"]:
            job["status"] = "complete"
            await execute(
                "update ingest_batches set status=%s where batch_id=%s::uuid",
                ("complete", batch_id),
            )
        else:
            await run_investigations(job)
    except Exception as exc:
        job = jobs.get(job_id)
        if job:
            job["error"] = str(exc)[:200]
            job["status"] = "complete"
            for incident in job["incidents"]:
                if incident["phase"] == "queued":
                    incident["phase"] = "error"
                    incident["error"] = str(exc)[:200]
                    incident["finishedAt"] = now_ms()
        print(f"[background-analysis] {exc}", flush=True)
    finally:
        await release_slot(job_id)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await open_db()
    try:
        yield
    finally:
        for task in list(background_tasks):
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        await close_db()


app = FastAPI(title="AI-SOC Python Backend", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    label = file.filename or "upload.csv"
    if Path(label).suffix.lower() != ".csv":
        return JSONResponse(status_code=400, content={"error": "only .csv flow files are accepted"})

    batch_id = str(uuid4())
    job_id = str(uuid4())
    claimed, running = await claim_slot(job_id)
    if not claimed:
        return JSONResponse(
            status_code=409,
            content={
                "error": "An analysis is already running. Wait for it to finish before uploading another dataset.",
                "activeJobId": running,
            },
        )

    handed_off = False
    temp_path: Path | None = None
    request_started = now_ms()

    try:
        fd, raw_path = tempfile.mkstemp(prefix="ai-soc-", suffix=".csv")
        os.close(fd)
        temp_path = Path(raw_path)

        size = 0
        max_bytes = MAX_UPLOAD_MB * 1024 * 1024
        with temp_path.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"file too large; max upload is {MAX_UPLOAD_MB} MB"},
                    )
                handle.write(chunk)

        data = await run_analyze(temp_path, batch_id, label)
        if data.get("error"):
            return JSONResponse(status_code=400, content={"error": data["error"]})

        data["batch"]["source_filename"] = label
        kb_name = {item["technique_id"]: item["name"] for item in data.get("attack_kb", [])}
        incidents = []
        for item in data.get("incidents", []):
            techniques = item.get("mitre_techniques") or []
            incidents.append({
                "incidentId": item["incident_id"],
                "code": item["code"],
                "title": item["title"],
                "attackType": item.get("title") or (kb_name.get(techniques[0]) if techniques else None) or "Unknown",
                "risk": item.get("risk_score", 0),
                "phase": "queued",
            })

        job = {
            "jobId": job_id,
            "batchId": batch_id,
            "createdAt": now_ms(),
            "status": "inserting",
            "incidents": incidents,
        }
        jobs[job_id] = job

        response = {
            "batchId": batch_id,
            "jobId": job_id,
            "stats": {
                "storedEvents": data["batch"].get("event_count", 0),
                "signals": len(data.get("signals", [])),
                "alerts": len(data.get("alerts", [])),
                "incidents": len(data.get("incidents", [])),
                "processingMs": now_ms() - request_started,
                "sourceFilename": data["batch"].get("source_filename"),
            },
            "standardization": data.get("standardization"),
            "incidents": [
                {
                    "incidentId": i["incidentId"],
                    "code": i["code"],
                    "title": i["title"],
                    "attackType": i["attackType"],
                    "risk": i["risk"],
                }
                for i in incidents
            ],
            "alerts": [
                {
                    "title": a.get("title"),
                    "severity": a.get("severity"),
                    "confidence": a.get("confidence"),
                    "detector": a.get("detector"),
                    "entity": a.get("entity"),
                    "correlationCount": a.get("correlation_count"),
                    "contributions": a.get("contributions") or {},
                }
                for a in data.get("alerts", [])
            ],
            "eval": data.get("eval"),
        }

        handed_off = True
        spawn_background(persist_and_investigate(job_id, batch_id, data))
        return response

    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)[:500]})
    finally:
        await file.close()
        if temp_path:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
        if not handed_off:
            await release_slot(job_id)


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "job not found"})
    return job


@app.get("/api/incidents/{incident_id}/workflow")
async def get_workflow(incident_id: str):
    if not UUID_RE.match(incident_id):
        return JSONResponse(status_code=400, content={"error": "Invalid incident ID"})
    try:
        workflow = await load_workflow(incident_id)
        if not workflow:
            return JSONResponse(status_code=404, content={"error": "Incident not found"})

        current_job = jobs.get(active_job_id) if active_job_id else None
        live = None
        if current_job and current_job.get("status") != "complete":
            live = next(
                (
                    item for item in current_job["incidents"]
                    if item["incidentId"] == incident_id and not item.get("finishedAt")
                ),
                None,
            )

        active_agent = PHASE_AGENT.get(live.get("phase")) if live else None
        blocked = False
        stages = []

        for index, agent in enumerate(AGENTS):
            run = workflow["latest"][index]
            if live and live.get("startedAt") and live.get("phase") != "reporting" and run:
                created = run.get("created_at")
                if created and int(created.timestamp() * 1000) < int(live["startedAt"]):
                    run = None

            if agent == active_agent:
                status = "running"
            elif run and run.get("status") == "error":
                status = "error"
            elif run and run.get("status") == "skipped":
                status = "skipped"
            elif run:
                status = "complete"
            elif index == 3 and workflow["can_report"] and not live:
                status = "ready"
            elif blocked:
                status = "blocked"
            else:
                status = "waiting"

            if status in {"error", "skipped"}:
                blocked = True

            stages.append({
                "agent": agent,
                "status": status,
                "runId": run.get("run_id") if run else None,
                "tokens": int(run.get("tokens") or 0) if run else 0,
                "durationMs": int(run.get("latency_ms") or 0) if run else 0,
                "output": (run.get("output") or {}) if run else {},
            })

        busy = bool(active_job_id)
        return {
            "stages": stages,
            "active": bool(live),
            "busy": busy,
            "canReport": bool(workflow["can_report"] and not busy),
            "canInvestigate": bool(not busy and not workflow["report"]),
            "reason": workflow["reason"],
            "report": workflow["report"],
            "startedAt": live.get("startedAt") if live else None,
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": llm_error_message(exc)})


async def run_manual_action(
    job_id: str,
    incident_job: dict[str, Any],
    action: str,
    workflow: dict[str, Any],
    event_index: dict[str, dict[str, Any]] | None,
) -> None:
    job = jobs[job_id]
    try:
        if action == "investigate":
            await run_investigations(job)
        else:
            await run_report_writer(
                incident_job["incidentId"],
                workflow["supported"],
                workflow["evidence"],
                event_index or {},
                workflow["assessment"],
            )
            incident_job["phase"] = "done_with_report"
            job["status"] = "complete"
    except Exception as exc:
        await record_failure(incident_job["incidentId"], incident_job["phase"], exc)
        incident_job["phase"] = "error"
        incident_job["error"] = llm_error_message(exc)
        job["status"] = "complete"
    finally:
        incident_job["finishedAt"] = now_ms()
        await release_slot(job_id)


@app.post("/api/incidents/{incident_id}/{action}")
async def start_action(incident_id: str, action: str):
    if action not in {"investigate", "report"}:
        return JSONResponse(status_code=404, content={"error": "action not found"})
    if not UUID_RE.match(incident_id):
        return JSONResponse(status_code=400, content={"error": "Invalid incident ID"})

    job_id = str(uuid4())
    claimed, _ = await claim_slot(job_id)
    if not claimed:
        return JSONResponse(status_code=409, content={"error": "Another investigation is running. Wait for it to finish."})

    handed_off = False
    try:
        workflow = await load_workflow(incident_id)
        if not workflow:
            return JSONResponse(status_code=404, content={"error": "Incident not found"})
        if workflow["report"]:
            return {"complete": True}
        if action == "report" and not workflow["can_report"]:
            return JSONResponse(status_code=409, content={"error": workflow["reason"]})

        event_index = await report_context(workflow) if action == "report" else None
        incident = workflow["incident"]
        incident_job = {
            "incidentId": incident_id,
            "code": incident["code"],
            "title": incident["title"],
            "attackType": incident["title"],
            "risk": incident["risk_score"],
            "phase": "reporting" if action == "report" else "queued",
            "startedAt": now_ms(),
        }
        job = {
            "jobId": job_id,
            "batchId": incident.get("batch_id") or "",
            "createdAt": now_ms(),
            "status": "investigating",
            "incidents": [incident_job],
        }
        jobs[job_id] = job
        handed_off = True
        spawn_background(run_manual_action(job_id, incident_job, action, workflow, event_index))
        return JSONResponse(status_code=202, content={"jobId": job_id})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": llm_error_message(exc)})
    finally:
        if not handed_off:
            await release_slot(job_id)
