# Project Structure

A new developer should follow this dependency path:

`frontend/src/components/soc/analyze.tsx` -> `frontend/src/lib/analyze-client.ts` -> `backend/app/main.py` -> `ml/analyze.py` -> `ml/soccore.py` -> `backend/app/db.py` -> `backend/app/graph.py` -> `backend/app/agents.py`.

Folder ownership is intentionally simple: browser code in `frontend`, APIs/persistence/agents in `backend`, deterministic detection in `ml`, datasets in `data`, documentation in `docs`, commands in `scripts`, and all obsolete architectures in `archive`.
