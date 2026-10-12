# Project Structure

Follow this runtime dependency path:

`frontend/src/components/soc/analyze.tsx`
→ `frontend/src/lib/analyze-client.ts`
→ `backend/app/main.py`
→ `ml/analyze.py`
→ `ml/soccore.py`
→ `backend/app/db.py`
→ `backend/app/graph.py`
→ `backend/app/agents.py`
→ `backend/app/tools.py`

Folder ownership:

- `frontend/` — analyst UI
- `backend/` — FastAPI, MongoDB, workflow orchestration and agents
- `ml/` — deterministic detection plus offline MLP evaluation
- `data/` — CICIDS demo/evaluation artifacts
- `docs/` — architecture, demo and report material
- `scripts/` — setup, run and validation commands

The active runtime does **not** depend on the old Node/Supabase architecture.
