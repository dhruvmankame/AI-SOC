#!/usr/bin/env bash
# Offline completion checks. Requires npm ci in agents/ and web/ first.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s testing -v
bash -n scripts/load_db.sh
npm --prefix agents run typecheck
npm --prefix agents test
npm --prefix web run typecheck
npm --prefix web run build
