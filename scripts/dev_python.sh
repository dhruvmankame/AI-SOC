#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cleanup() {
  [[ -n "${BACK_PID:-}" ]] && kill "$BACK_PID" 2>/dev/null || true
  [[ -n "${FRONT_PID:-}" ]] && kill "$FRONT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

bash scripts/run_python_backend.sh &
BACK_PID=$!

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required for the React frontend."
  exit 1
fi

npm --prefix frontend run dev &
FRONT_PID=$!

wait -n "$BACK_PID" "$FRONT_PID"
