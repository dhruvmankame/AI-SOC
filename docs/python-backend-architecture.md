# AI-SOC Python backend architecture

The runtime backend is Python. The React/TanStack frontend keeps the same REST contract and
continues to use `VITE_ANALYZE_API=http://127.0.0.1:8787`.

```text
React/TanStack UI
       |
       | HTTP /api/*
       v
FastAPI (Python, local-only :8787)
       |
       +--> ml/analyze.py
       |      normalize -> deterministic detectors -> correlate incidents
       |
       +--> Supabase PostgreSQL
       |      events / signals / alerts / incidents / evidence / agent_runs
       |
       +--> Python LangGraph multi-agent investigation
              Agent 1 Evidence Collector
                  |
              Agent 2 Hypothesis + MITRE
                  |
              Agent 3 Fail-closed Verifier
                  |
              human-controlled report gate
                  |
              Agent 4 Report Writer
```

The migration preserves these frontend-facing routes:

- `GET /api/health`
- `POST /api/analyze`
- `GET /api/jobs/{job_id}`
- `GET /api/incidents/{incident_id}/workflow`
- `POST /api/incidents/{incident_id}/investigate`
- `POST /api/incidents/{incident_id}/report`

The backend remains bound to `127.0.0.1`. Do not expose it publicly without authentication,
authorization, durable job state, and production upload isolation.

Run:

```bash
bash scripts/run_python_backend.sh
# frontend in another terminal
npm --prefix frontend run dev
```

Or:

```bash
bash scripts/dev_python.sh
```
