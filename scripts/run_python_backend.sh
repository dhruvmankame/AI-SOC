#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -x backend/.venv/bin/python ]]; then
  echo "backend/.venv is missing. Create it with: python3 -m venv backend/.venv && backend/.venv/bin/pip install -r backend/requirements.txt"
  exit 1
fi
if [[ ! -f .env ]]; then
  echo ".env is missing. Create it and set MONGODB_URI, MONGODB_DB, GEMINI_API_KEY."
  exit 1
fi
if ! grep -q '^MONGODB_URI=' .env; then
  echo "MONGODB_URI is missing from .env"
  exit 1
fi

exec backend/.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port "${PORT:-8787}" --workers 1
