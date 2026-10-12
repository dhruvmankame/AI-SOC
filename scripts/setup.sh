#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v npm >/dev/null || { echo "npm required"; exit 1; }
[[ -d backend/.venv ]] || python3 -m venv backend/.venv
backend/.venv/bin/pip install -U pip
backend/.venv/bin/pip install -r backend/requirements.txt
if [[ -f frontend/package-lock.json ]]; then npm --prefix frontend ci; else npm --prefix frontend install; fi
[[ -f .env ]] || cp .env.example .env
[[ -f frontend/.env.local ]] || cp frontend/.env.example frontend/.env.local
echo "Setup complete. Fill MONGODB_URI and your selected LLM key in .env, then run bash scripts/dev_python.sh"
