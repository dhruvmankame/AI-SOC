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
- `[x]` Check current DB seed state: INC-2017-0001/2/3 present (T1110/T1498/T1071,
  risk 96), 15 stored `agent_runs` (4 agents each; 0002 has 2 investigations), evidence
  present, **0 upload batches** (clean baseline).
- `[x]` Upload path proven via the real backend: `demo_ddos_T1498.csv` → batch
  `c5571c72…` + 1 T1498 incident `INC-20260928-c5571c-001` (attack type "Network Denial
  of Service", risk 96), rows inserted, job returned fast.
- `[~]` Fresh live investigation is **blocked externally**: `gemini-flash-lite-latest`
  is returning **503 "This model is currently experiencing high demand"** (two attempts,
  ~6-min `maxRetries` backoff each). Not quota, not our code. The 3 seed incidents already
  have STORED complete graph runs (used by Phase 3), so end-to-end is demonstrated; re-run
  the fresh one when Gemini recovers: `npm run investigate -- INC-20260928-c5571c-001`.
- `[x]` Graded correctness re-check (from stored data + Phase 3 eval): verifier REJECTED
  the over-claimed DDoS hypothesis (INC-2017-0002 attempt-1); incident-scoped retrieval
  produced the correct T1498 report on attempt-2. Safety property intact.
- `[x]` Demo slices built (Phase 4 pulled forward): `ml/make_demo_slices.py` →
  `data/cicids/demo/demo_{bruteforce_T1110,ddos_T1498,botnet_T1071}.csv`, each one clean
  incident (offline eval F1 0.9999 / 1.0 / 0.78).

**Gate:** upload→detect→incident proven end-to-end today; the investigate→record leg is
proven from stored runs and pending a fresh pass once Gemini's 503 clears.

## Phase 2 — Deep-learning evidence  (their Day 2)  `[x]` core done

- `[x]` `ml/train_mlp.py` — numpy MLP `69 → Dense64 ReLU → Dense32 ReLU → sigmoid`,
  Adam + BCE, on balanced CICIDS flow sample (stdlib CSV parse; no pandas).
- `[x]` Test metrics on held-out 22.7k flows: **P 0.977 · R 0.9975 · F1 0.9871 ·
  ROC-AUC 0.9996 · Acc 0.9894**; confusion matrix tp 9218 / fp 217 / fn 23 / tn 13284.
- `[x]` Artifacts: `data/ml_eval.json`, `docs/figures/mlp_confusion_matrix.png`,
  `docs/figures/mlp_training_loss.png`.
- `[ ]` Write the report paragraph (architecture, features, split, CM, P/R/F1) — Phase 5.

**Gate:** one defensible ML result ready. **Met** (write-up folds into Phase 5).

## Phase 3 — Investigation evaluation  (their Day 3)  `[x]` DONE

- `[x]` `agents/src/eval.ts` (reuses `db.ts`, quota-free — reads STORED `agent_runs`,
  no new LLM calls): segments runs into investigations (evidence→hypothesis→verify→report),
  computes evidence-grounding coverage, unsupported-claim rate, verifier rejected count,
  tokens + latency per investigation → `data/investigation_eval.json` + stdout table.
- `[x]` Verifier on/off comparison derived from the same runs (decision #2): OFF ships
  every hypothesis incl. rejected; ON ships supported only.
- `[x]` `npm run eval` script added to `agents/package.json`; `tsc --noEmit` clean.

**Result (4 investigations / 3 seed incidents):** grounding coverage **100%**,
unsupported-claim rate **25%**, verifier rejected **1**. Verifier OFF = 4 claims / 1
unsupported (25%); ON = 3 claims / 0 unsupported (0%) → verifier blocked 1. The blocked
claim is INC-2017-0002's over-generalized SSH hypothesis ("multiple hosts made repeated
attempts" when cited evidence showed single attempts) — captured verbatim in the JSON. The
data also shows the retrieval fix: INC-2017-0002 attempt-1 (entity-fallback) → rejected;
attempt-2 (incident-scoped) → correct T1498 report.

**Gate:** MET — the table + the verifier-blocked example show why the verifier is useful.

## Phase 4 — Demo hardening  (their Day 4)  `[~]`

- `[x]` Trimmed demo CSVs built (`ml/make_demo_slices.py` → `data/cicids/demo/*.csv`),
  one clean attack each, verified offline. Done early because Day-1's upload gate needed
  a small file anyway.
- `[x]` Rewrote stale `docs/demo-scenarios.md` to the live CICIDS reality: the 3 seed
  incidents (INC-2017-0001/2/3, T1110/T1498/T1071) with their real entities + ground truth,
  which demo slice maps to each, honest detector eval (overall F1 0.979; botnet weak point
  0.534), the MLP artifact, the investigation safety result (verifier blocked 1 over-claim,
  25%→0% unsupported), the incident-scoped-retrieval leakage explanation, and a demo script.
- `[x]` **503 / overload fast-fail hardening (DONE 2026-09-29).** `agents/src/llm.ts` now
  owns the retry policy: `makeLLM` sets `maxRetries: 0` (was 5 — that turned a 503 into a
  ~6-min stall) and `reason()` classifies errors via new `classifyLLMError()` →
  **overload (503/UNAVAILABLE/"high demand") and quota (429/resource_exhausted) FAIL FAST**
  (no retry), only `other` errors get 2 quick backoff retries. `agents/src/server.ts` imports
  `classifyLLMError` and `llmErrorMessage()` gives the UI a plain per-incident message
  ("Gemini model overloaded (503) — retry later" / "quota reached"). A 503 now fails one
  incident in seconds and the batch continues. `tsc --noEmit` clean; classification unit-checked.
- `[x]` Graceful quota/429 handling confirmed: same fast-fail path (quota classified, fails the
  incident cleanly, batch continues); the async loop already `.catch`-wraps per incident.

**Gate:** demo repeats without manual DB repair. **Met** for docs + fast-fail; the only
remaining live-only confirmation is a fresh investigate pass once Gemini's 503 clears.

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
- **Gemini `gemini-flash-lite-latest` 503 "high demand"** (2026-09-28/29) — a Google-side
  outage, not quota, not our code. Blocks a *fresh* live investigation; the fresh
  upload-incident run is pending until it clears. Phase 3 eval used the STORED runs, so it was
  unaffected. **Hardening now DONE (Phase 4):** a 503/overload/quota fails the affected
  incident in seconds (fast-fail in `llm.ts`), so the demo no longer stalls ~6 min per incident.
- Git: session start shows a valid repo (branch HEAD, last commit `24b1cd9 "phase 1
  implemented"`), so the earlier "not a git repository" anomaly appears resolved — still
  confirm `git status` is clean before any commit. Repo is Lovable-connected: never rewrite
  pushed history.
- Live investigation + demo uploads spend real Gemini free-tier quota; batched per
  decision #1. Full-file uploads trigger many incidents — use trimmed slices.


