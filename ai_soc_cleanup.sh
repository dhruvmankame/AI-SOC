#!/usr/bin/env bash
set -Eeuo pipefail

# AI-SOC panel/team cleanup
# Usage:
#   bash ai_soc_cleanup.sh              # recommended cleanup
#   bash ai_soc_cleanup.sh --dry-run    # show what would be removed
#   bash ai_soc_cleanup.sh --prune-docs # also remove old planning/reference docs
#
# Run from the AI-SOC repository root (the directory containing backend/, frontend/, ml/).

DRY_RUN=0
PRUNE_DOCS=0
ROOT="$(pwd)"

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --prune-docs) PRUNE_DOCS=1 ;;
    --root=*) ROOT="${arg#--root=}" ;;
    -h|--help)
      sed -n '1,14p' "$0"
      exit 0
      ;;
    *)
      echo "[cleanup] Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

need=(
  "backend/app/main.py"
  "backend/app/agents.py"
  "backend/app/graph.py"
  "frontend/package.json"
  "frontend/src"
  "ml/analyze.py"
  "ml/soccore.py"
  "scripts/run_python_backend.sh"
  "README.md"
)
for path in "${need[@]}"; do
  [[ -e "$path" ]] || {
    echo "[cleanup] ERROR: '$path' not found."
    echo "[cleanup] Run this from the current AI-SOC repository root."
    exit 1
  }
done

# Never remove the small reproducible demo files used for the presentation.
demo_need=(
  "data/cicids/demo/demo_bruteforce_T1110.csv"
  "data/cicids/demo/demo_ddos_T1498.csv"
  "data/cicids/demo/demo_botnet_T1071.csv"
)
for path in "${demo_need[@]}"; do
  [[ -f "$path" ]] || {
    echo "[cleanup] ERROR: required demo file is missing: $path"
    exit 1
  }
done

say() { printf '\n[cleanup] %s\n' "$*"; }

rm_path() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || return 0
  if (( DRY_RUN )); then
    printf '[dry-run] remove %s\n' "$path"
  else
    rm -rf -- "$path"
    printf '[removed] %s\n' "$path"
  fi
}

rm_file() {
  local path="$1"
  [[ -f "$path" || -L "$path" ]] || return 0
  if (( DRY_RUN )); then
    printf '[dry-run] remove %s\n' "$path"
  else
    rm -f -- "$path"
    printf '[removed] %s\n' "$path"
  fi
}

say "Removing legacy/history folders and temporary tree dumps"
rm_path "archive"
rm_file "detail.txt"

# Backups created by the earlier refactor/hotfix scripts are useful only while
# recovering from the patch. Once the project is stable they are pure clutter.
for d in .ai-soc-hotfix-backup-* .ai-soc-refactor-backup-* ai-soc-backup-*; do
  [[ -e "$d" ]] && rm_path "$d"
done

say "Removing generated caches/build output"
for d in \
  "frontend/node_modules" \
  "frontend/dist" \
  "frontend/.vite" \
  "frontend/.output" \
  "frontend/.nitro" \
  ".pytest_cache" \
  "backend/.pytest_cache" \
  ".mypy_cache" \
  ".ruff_cache"; do
  rm_path "$d"
done

# Python bytecode is reproducible and should never be handed off.
while IFS= read -r -d '' d; do
  rm_path "$d"
done < <(find backend ml -type d -name '__pycache__' -print0 2>/dev/null || true)

while IFS= read -r -d '' f; do
  rm_file "$f"
done < <(find backend ml -type f \( -name '*.pyc' -o -name '*.pyo' \) -print0 2>/dev/null || true)

say "Removing raw/rebuildable data while PRESERVING data/cicids/demo/"
# These top-level CICIDS captures are large public source files and are already
# ignored by .gitignore. The demo slices remain in data/cicids/demo/.
if [[ -d data/cicids ]]; then
  while IFS= read -r -d '' f; do
    rm_file "$f"
  done < <(
    find data/cicids -maxdepth 1 -type f \
      \( -name '*.csv' -o -name '*.zip' \) -print0 2>/dev/null || true
  )
fi

# Reproducible/generated seed outputs; current FastAPI+MongoDB runtime does not
# need these files for uploaded-dataset analysis.
for f in data/raw_events.jsonl data/seed.json data/seed.sql; do
  rm_file "$f"
done

say "Removing unused frontend scaffolding"
# npm/package-lock.json is the package-manager path used by the current project.
# Remove the duplicate Bun metadata only when npm lock data exists.
if [[ -f frontend/package-lock.json ]]; then
  rm_file "frontend/bun.lock"
  rm_file "frontend/bunfig.toml"
fi

# Confirmed static fallback snapshot with no importers in the live FastAPI build.
rm_file "frontend/src/lib/soc-snapshot.ts"

# Agent-generation notes are not application code and confuse panel handoff.
rm_file "frontend/AGENTS.md"

# Editor / OS debris anywhere in the repo.
while IFS= read -r -d '' f; do
  rm_file "$f"
done < <(find . -type f \( -name '.DS_Store' -o -name 'Thumbs.db' -o -name 'npm-debug.log*' \) -print0 2>/dev/null || true)

if (( PRUNE_DOCS )); then
  say "Pruning historical planning/reference documents (--prune-docs)"
  # Keep architecture, final report, demo material, cyber report, figures,
  # execution phases, backend architecture and the new walkthrough.
  for f in \
    docs/completion.md \
    docs/implementation-plan.md \
    docs/project-plan.md \
    docs/project-plan-updated.md; do
    rm_file "$f"
  done
  rm_path "docs/reference"
fi

say "Keeping the panel-facing structure"
printf '%s\n' \
  "  backend/   FastAPI API + MongoDB + LangGraph agent code" \
  "  frontend/  TanStack/React SOC dashboard source" \
  "  ml/        CSV normalization, deterministic detectors, offline ML" \
  "  data/      Small demo slices + evaluation artifacts" \
  "  docs/      Architecture, reports, demo/presentation material" \
  "  scripts/   Setup, run, dev and validation commands"

# Keep future checkouts clean. Do not disturb existing ignore rules.
IGNORE_BLOCK='
# ---- panel/team cleanup
archive/
detail.txt
.ai-soc-hotfix-backup-*/
.ai-soc-refactor-backup-*/
ai-soc-backup-*/
'
if [[ -f .gitignore ]] && ! grep -q '^# ---- panel/team cleanup$' .gitignore; then
  if (( DRY_RUN )); then
    echo "[dry-run] append cleanup rules to .gitignore"
  else
    printf '%s' "$IGNORE_BLOCK" >> .gitignore
    echo "[updated] .gitignore"
  fi
fi

if (( DRY_RUN )); then
  say "Dry run complete. Re-run without --dry-run to apply."
  exit 0
fi

# Final safety checks: runtime/source files and demo datasets must still exist.
for path in "${need[@]}" "${demo_need[@]}"; do
  [[ -e "$path" ]] || {
    echo "[cleanup] ERROR: cleanup removed a required path: $path" >&2
    exit 1
  }
done

say "Clean project layout"
find . -maxdepth 2 \
  -not -path './.git*' \
  -not -path './frontend/node_modules*' \
  -print | sort

cat <<'TXT'

[cleanup] DONE

The source tree is now panel/team friendly.

Important:
  • frontend/node_modules was intentionally removed because it is reproducible.
    Reinstall with:  npm --prefix frontend ci
  • backend/.venv was intentionally PRESERVED so your backend can still run.
  • .env was intentionally PRESERVED and was never printed or copied.
  • data/cicids/demo/ was PRESERVED for your presentation.
  • MongoDB data was NOT touched. Previous analyzed batches remain in MongoDB.

Run after cleanup:
  bash scripts/run_python_backend.sh

Frontend, after installing dependencies:
  npm --prefix frontend ci
  npm --prefix frontend run dev

Validation:
  bash scripts/check.sh
TXT
