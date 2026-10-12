# AI-SOC

Evidence-grounded Security Operations Center prototype for network-flow telemetry.

**Active stack:** React/TanStack frontend + FastAPI/Python backend + deterministic Python detection + MongoDB + Gemini investigation agents.

## Start here

```bash
bash scripts/setup.sh
# edit .env: set MONGODB_URI and GEMINI_API_KEY
bash scripts/dev_python.sh
```

Frontend: `http://localhost:5173`  
Backend: `http://127.0.0.1:8787`

## Repository map

```text
frontend/   React analyst UI and presentation flow
backend/    FastAPI API, MongoDB persistence and investigation agents
ml/         deterministic CSV standardization/detection (no LLM decisions)
data/       CICIDS demo datasets and evaluation artifacts
docs/       architecture, research, handoff and presentation material
scripts/    setup, run and verification commands
archive/    old Node/Supabase/migration code; not active runtime
```

## Runtime pipeline

```text
CSV upload
 -> standardize
 -> deterministic detect
 -> signals / alerts / incidents
 -> MongoDB persistence
 -> evidence collector
 -> hypothesis + ATT&CK mapping
 -> fail-closed verifier
 -> report writer
 -> incident record
```

## Best teacher demo

Upload `data/cicids/demo/demo_ddos_T1498.csv` from the **Analyze** page.

The upload bar may reach 100% quickly; that only means the browser finished sending bytes. The end-to-end progress remains below 100% while detection, persistence, investigation, verification and report generation continue. Stay on the Analyze page: deterministic findings appear first and the live agent workflow updates underneath them.

## Critical files

| File | Responsibility |
|---|---|
| `backend/app/main.py` | HTTP API, upload lifecycle, job state and orchestration |
| `backend/app/config.py` | environment validation and detector paths |
| `backend/app/db.py` | MongoDB connection and indexes |
| `backend/app/graph.py` | investigation graph |
| `backend/app/agents.py` | evidence/hypothesis/verifier/report agents |
| `backend/app/workflow.py` | persisted workflow reconstruction |
| `ml/analyze.py` | uploaded CSV -> deterministic findings |
| `ml/soccore.py` | canonicalization, detectors, ATT&CK bridge |
| `frontend/src/components/soc/analyze.tsx` | one-page demo workflow |
| `frontend/src/lib/analyze-client.ts` | frontend API + phase contract |
| `scripts/run_python_backend.sh` | backend startup |
| `scripts/dev_python.sh` | backend + frontend startup |

## Presentation / research

Read `docs/DEMO_PRESENTATION.md`, `docs/CYBER_ATTACK_REPORT.md`, and `docs/PROJECT_STRUCTURE.md`.

Before presenting:

```bash
bash scripts/check.sh
curl http://127.0.0.1:8787/api/health
```
