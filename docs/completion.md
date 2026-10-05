# Completion and handoff — 2026-10-05

The handbook's prototype architecture is retained. Remaining implementation,
documentation, and offline verification work is complete. A fresh live test still
requires external credentials and services.

## Delivered

- All-migration setup with an explicit flag for replacing seed data.
- Strict source-event grounding and preservation of invalid hypothesis citations
  for deterministic rejection; unrelated legacy fallback events are refused.
- Explicit structured-output validation, skipped-stage auditing, and a guard
  against writing reports with no verified findings.
- Evidence upserts update source IDs and metadata along with fact text.
- Evaluation checks citation resolution and distinguishes skipped agents.
- Original upload filenames are retained; persistence failures surface in the UI.
- Frontend environment template and type-check command; generated build artifacts ignored.
- [Architecture diagram](architecture.md), [final report](final-report.md), updated
  README, handbook, phase tracker, and demo instructions.
- `scripts/check.sh`, Python CSV/setup regressions, and TypeScript safety regressions.

## Verification

The Python suite passes eight tests, including all three committed CSV slices,
annotation-only evaluation, bad timestamps/schemas, and setup migration ordering
using a fake psql. The TypeScript suite checks grounding, detector conflicts,
omitted verdicts, annotation confidence, skipped audit traversal, mixed hypothesis
citations, empty-report refusal, and evaluation accounting. Both type checks and
the production frontend build pass. Model and database calls are mocked in tests.

Detection, MLP, and investigation result JSONs retain their historical provenance.
The MLP has not been retrained, and stored investigation metrics have not been
regenerated without access to the original database. Dependencies were installed
from the existing lockfiles.

## Live validation steps

1. Fill repo-root `.env` from `.env.example` and `web/.env.local` from
   `web/.env.example`. The backend needs `DATABASE_URL` and `GEMINI_API_KEY`;
   the browser needs the Supabase URL and publishable key.
2. Run `bash scripts/load_db.sh` to apply migrations. For an intentionally fresh
   demo database, load telemetry with `--seed cicids --replace-data`; this deletes
   existing events and investigation outputs.
3. Start `npm run server` in `agents/` and `npm run dev` in `web/`.
4. Upload `data/cicids/demo/demo_ddos_T1498.csv`. Confirm one incident, original
   filename, a committed batch, terminal job phase, and four ordered audit stages.
5. Inspect the incident record's evidence, verifier verdicts, confidence basis,
   and report. A fully rejected investigation should have no report and a skipped
   report-writer audit record. A provider failure should show an incident error.
6. Run `npm run eval` in `agents/` to regenerate metrics from the new stored runs.
7. Capture the demo recording. Rotate account secrets before any public release.

The local backend remains unauthenticated and bound to `127.0.0.1`. No external
database was seeded, no LLM quota was consumed, and no deployment was performed.
