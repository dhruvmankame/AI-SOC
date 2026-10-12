# AI-SOC Python Backend Architecture

The active backend is **FastAPI + MongoDB + Python LangGraph**.

```text
React / TanStack Start
        |
        | HTTP /api/*
        v
FastAPI (127.0.0.1:8787)
        |
        +--> ml/analyze.py
        |      normalize -> detect -> signals -> alerts -> incidents
        |
        +--> MongoDB
        |      all deterministic incidents are persisted
        |
        +--> highest-risk MAX_AI_INCIDENTS
               |
               +--> Evidence Collector
               +--> Hypothesis + ATT&CK
               +--> Fail-closed Verifier
               +--> Report Writer
```

The LLM provider is selectable with `LLM_PROVIDER=gemini|groq`.

`AGENT_CONCURRENCY` controls concurrent incident workflows. Gemini defaults to one
incident at a time; Groq can use a larger value.

Main routes:

- `GET /api/health`
- `POST /api/analyze`
- `GET /api/jobs/{job_id}`
- `GET /api/incidents/{incident_id}/workflow`
- `POST /api/incidents/{incident_id}/investigate`
- `POST /api/incidents/{incident_id}/report`
- `GET /api/data/*`

Run backend:

```bash
bash scripts/run_python_backend.sh
```

Run frontend separately:

```bash
cd frontend
npm run dev
```

Do not expose this unauthenticated local backend directly to the public internet.
