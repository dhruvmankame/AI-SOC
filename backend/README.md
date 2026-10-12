# Backend
`app/main.py` is the runtime entry point. `config.py` validates environment settings, `db.py` owns MongoDB, `graph.py` orchestrates investigation, `agents.py` implements agents, and `workflow.py` rebuilds stored workflow state. The service is local-only and unauthenticated; keep it on 127.0.0.1 unless authentication is added.
