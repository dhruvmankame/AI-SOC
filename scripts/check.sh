#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
backend/.venv/bin/python -m compileall -q backend/app ml
PYTHONPATH=backend backend/.venv/bin/python -m pytest -q backend/tests
npm --prefix frontend run typecheck
npm --prefix frontend run build
