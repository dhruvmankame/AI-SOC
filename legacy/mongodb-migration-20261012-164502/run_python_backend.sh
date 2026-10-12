#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -x backend/.venv/bin/python ]]; then
  echo "backend/.venv is missing. Run the conversion/setup script first."
  exit 1
fi

if [[ ! -f .env ]]; then
  echo ".env is missing. Copy .env.example to .env and set DATABASE_URL + GEMINI_API_KEY."
  exit 1
fi

exec backend/.venv/bin/python -m uvicorn app.main:app \
  --app-dir backend \
  --host 127.0.0.1 \
  --port "${PORT:-8787}" \
  --workers 1
