#!/usr/bin/env bash
# Load the AI-SOC schema + seed into your Supabase Postgres.
# Usage: create `.env` from `.env.example` (with your DATABASE_URL), then:  bash scripts/load_db.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then echo "ERROR: no .env file. Copy .env.example to .env and fill DATABASE_URL."; exit 1; fi
# shellcheck disable=SC1091
set -a; source .env; set +a
: "${DATABASE_URL:?DATABASE_URL not set in .env}"

if [ ! -f data/seed.sql ]; then
  echo ">> seed.sql missing, generating..."
  python3 ml/generate_synthetic_logs.py && python3 ml/pipeline.py
fi

echo ">> applying schema (supabase/migrations/0001_init.sql)"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/migrations/0001_init.sql
echo ">> loading seed (data/seed.sql)"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f data/seed.sql
echo ">> row counts:"
psql "$DATABASE_URL" -c "select 'events' t, count(*) from events union all select 'signals', count(*) from signals union all select 'detection_rules', count(*) from detection_rules;"
echo ">> done."
