# AI-SOC — Phase-Wise Execution Plan (grounded)

> Execution tracker for `docs/project-plan-updated.md` (the 5–6 day completion
> plan). It maps that plan's Days 1–6 to concrete tasks grounded against the
> **actual** repo state, records the sequencing decisions, and tracks status.
>
> **Legend:** `[x]` done · `[~]` in progress · `[ ]` not started.
> _Started 2026-09-28._

---

## Reality check (verified against the repo, not assumed)

**Already built — preserve, do not redesign:**
- Detection core (`ml/soccore.py`, `ingest_cicids.py`, `analyze.py`); rule +
  statistical detectors; CICIDS seed + detector eval JSON (`data/cicids_eval.json`).
- LangGraph 4-agent investigation `collect → hypothesize → verify → write_report`
  with the fail-closed verifier, evidence-ID grounding, full `agent_runs` audit.
- Upload backend (`agents/src/server.ts`, 127.0.0.1); incident-scoped retrieval.
- Frontend: Overview, Alert Queue, Analyze, Incidents, Incident Record + batch filter.
- 3 CICIDS CSVs on disk (~601 MB) available as demo uploads.

**Missing — must build:**
- Trained deep-learning model + metrics (the "Deep Learning" title requirement).
- Investigation-eval harness (evidence coverage %, unsupported-claim rate,
  rejected-claim count, tokens/latency) + verifier on/off comparison.
- Architecture diagram asset.

**Stale — must fix:**
- `docs/demo-scenarios.md` describes the OLD synthetic scenarios, not the live
  CICIDS `INC-2017-0001/2/3` (T1110 / T1498 / T1071).
- `README.md` quick-start loads the synthetic seed and omits the two-process run
  and the CICIDS ingest path.

---

## Execution decisions (my calls — tell me to change any)

1. **Batch the Gemini quota.** Every new piece that needs no LLM (the model, the
   eval *code*, demo slicing, docs) is done offline first; live investigations run
   **once**, deliberately, on the seed incidents, and that captured run feeds the
   evaluation. No repeated smoke-test quota burns.
2. **Verifier comparison from existing runs — no 2nd LLM pass.** "Without verifier"
   = the raw hypotheses (including the ones later rejected); "with verifier" =
   supported only. Both arms come from **one** stored investigation → quota-free and
   rigorous, matching the plan's "demonstrate the effect, not benchmark." A live
   no-verifier graph is optional only if quota is plentiful.
3. **MLP = numpy, offline eval artifact.** scikit-learn/pandas aren't installed
   (Python 3.14) and the architecture is frozen — a hand-rolled numpy MLP satisfies
   the DL requirement without adding deps or touching the live pipeline.
<!-- PHASES -->

---

## Phase 1 — Freeze & smoke-test the pipeline  (their Day 1)  `[~]`

No new features, frameworks, agents, or infra. Prove the existing flow runs.
- `[x]` Verify offline detection: `python3 ml/analyze.py <cicids.csv>` → clean
  incidents JSON. **Verified** on the DDoS file → 9 incidents (top: T1498 flood,
  risk 96), detector eval F1 = 0.9975, exit 0, no stderr.
- `[x]` Toolchain probe: Python 3.14 + numpy + matplotlib; Node 24; both
  `node_modules` present; all four backend secrets present in `.env`.
- `[ ]` Check current DB seed state (INC-2017-0001/2/3 present; any stale `agent_runs`).
- `[ ]` One deliberate live run of the graph on the 3 seed incidents (the single
  planned quota spend) → proves end-to-end **and** captures data for Phase 3.
- `[ ]` Graded correctness re-check: DDoS incident → T1498 report; verifier still
  rejects a genuinely over-claimed hypothesis.

**Gate:** one known CSV completes upload→detect→incident→investigate→record.

## Phase 2 — Deep-learning evidence  (their Day 2)  `[x]` core done

- `[x]` `ml/train_mlp.py` — numpy MLP `69 → Dense64 ReLU → Dense32 ReLU → sigmoid`,
  Adam + BCE, on balanced CICIDS flow sample (stdlib CSV parse; no pandas).
- `[x]` Test metrics on held-out 22.7k flows: **P 0.977 · R 0.9975 · F1 0.9871 ·
  ROC-AUC 0.9996 · Acc 0.9894**; confusion matrix tp 9218 / fp 217 / fn 23 / tn 13284.
- `[x]` Artifacts: `data/ml_eval.json`, `docs/figures/mlp_confusion_matrix.png`,
  `docs/figures/mlp_training_loss.png`.
- `[ ]` Write the report paragraph (architecture, features, split, CM, P/R/F1) — Phase 5.

**Gate:** one defensible ML result ready. **Met** (write-up folds into Phase 5).

## Phase 3 — Investigation evaluation  (their Day 3)  `[ ]`

- `[ ]` `agents/src/eval.ts` (reuse `db.ts`): from `agent_runs`/`evidence` compute
  evidence-coverage %, unsupported-claim rate, verifier rejected-claim count,
  tokens + latency per incident → `data/investigation_eval.json`.
- `[ ]` Verifier on/off comparison table derived from the same runs (decision #2).
- `[ ]` `npm run eval` script in `agents/package.json`.

**Gate:** one table/chart shows why the verifier is useful.

## Phase 4 — Demo hardening  (their Day 4)  `[ ]`

- `[ ]` Create small trimmed demo CSVs (one clean attack each) from the 3 CICIDS
  files — full files yield 9 incidents (≈40 LLM calls if auto-investigated); slices
  keep the demo fast, cheap, and reliable.
- `[ ]` Rewrite stale `docs/demo-scenarios.md` to the live CICIDS reality + ground truth.
- `[ ]` Confirm graceful Gemini-quota/429 handling (already coded) on a real failure.

**Gate:** demo repeats without manual DB repair.

## Phase 5 — Documentation & presentation  (their Day 5)  `[ ]`

- `[ ]` Architecture diagram (inline SVG / mermaid, legible in both themes).
- `[ ]` Update `README.md`: prerequisites, two-process run, CICIDS path, demo steps.
- `[ ]` Assemble eval tables/charts (detection + ML + investigation), limitations,
  future work, and a demo script.

**Gate:** another person can run the demo from the docs.

## Phase 6 — Buffer  (their Day 6)  `[ ]`

- `[ ]` Fix presentation-blocking bugs; final smoke test; repo cleanup.
- `[ ]` Rotate `DATABASE_URL` + `GEMINI_API_KEY` before any public push; capture a
  backup demo recording/screenshots. No new subsystems.

---

## Open flags
- `git rev-parse` reports **not a git repository** from `/home/kali/dsl` even though
  the session says it is one — resolve before any commit is requested.
- Live investigation + demo uploads spend real Gemini free-tier quota; batched per
  decision #1. Full-file uploads trigger many incidents — use trimmed slices.


