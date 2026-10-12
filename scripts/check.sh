#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m unittest discover -s testing -v
bash -n scripts/load_db.sh
backend/.venv/bin/python -m compileall -q backend/app
PYTHONPATH=backend backend/.venv/bin/python -m pytest -q backend/tests

if command -v npm >/dev/null 2>&1; then
  npm --prefix web run typecheck
  npm --prefix web run build
else
  echo "WARNING: npm not found; skipping React typecheck/build."
fi
