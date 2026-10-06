#!/usr/bin/env bash
# Apply every migration; replacing seed data requires an explicit flag.
# Usage: bash scripts/load_db.sh [--seed cicids|synthetic --replace-data]
set -euo pipefail
cd "$(dirname "$0")/.."

seed=""
replace_data=false
while (($#)); do
  case "$1" in
    --seed) seed="${2:?--seed requires cicids or synthetic}"; shift 2 ;;
    --replace-data) replace_data=true; shift ;;
    *) echo "Usage: $0 [--seed cicids|synthetic --replace-data]" >&2; exit 2 ;;
  esac
done
if [[ -n "$seed" && "$seed" != cicids && "$seed" != synthetic ]]; then
  echo "ERROR: seed must be cicids or synthetic" >&2; exit 2
fi
if [[ -n "$seed" && "$replace_data" != true ]]; then
  echo "ERROR: seed SQL replaces telemetry and investigations; add --replace-data intentionally." >&2; exit 2
fi
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi
: "${DATABASE_URL:?Set DATABASE_URL in the environment or repo-root .env}"
command -v psql >/dev/null || { echo "ERROR: install the PostgreSQL psql client" >&2; exit 1; }
for migration in supabase/migrations/*.sql; do
  echo ">> applying $migration"
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -1 -f "$migration"
done
if [[ "$seed" == cicids ]]; then
  [[ -f data/cicids_seed.sql ]] || python3 ml/ingest_cicids.py
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f data/cicids_seed.sql
elif [[ "$seed" == synthetic ]]; then
  if [[ ! -f data/seed.sql ]]; then
    python3 ml/generate_synthetic_logs.py
    python3 ml/pipeline.py
  fi
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f data/seed.sql
  psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -c 'select build_alerts();'
fi
echo ">> database setup complete"
