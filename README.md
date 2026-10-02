# AI-SOC

An evidence-grounded multi-agent Security Operations Center for network-flow telemetry.

Detection is deterministic Python. Investigation is a LangGraph.js agent graph whose
verifier is **fail-closed**: a hypothesis is only asserted if it cites evidence IDs that
actually exist, if that evidence entails the claim, and if the attack family it names is
not contradicted by the detectors behind its own citations. Every refused hypothesis is
recorded as a rejected claim with a reason, and an incident whose claims are all refused
gets no report at all.

## The problem it answers

An LLM handed a set of flow events will produce a fluent attack narrative whether or not
the events support it. The interesting engineering question is not how to make that
narrative longer — it is how to make the system refuse to assert one it cannot ground.

AI-SOC's answer has three parts:

1. **A fixed evidence set.** The collector distils events into facts `EV-<incident>-<n>`,
   and *drops any fact that cites an event ID which was not in the set it was given*. From
   there on, every later agent can only cite those IDs.
2. **A deterministic gate the model cannot argue past.** No citations, or citations that
   don't resolve → rejected in code. A claimed technique whose attack family is absent from
   the detectors behind its own cited evidence → rejected in code.
3. **Confidence computed in code, never emitted by the model.** It is
   `detector_strength × entailment_strength`, where the detector term is read from the
   `signals` table. A claim resting only on a dataset annotation is capped at the
   annotation score and labelled `annotation-only`, so it can never be presented as though
   an independent detector had confirmed it.

## Architecture — two planes

The system is deliberately split. Everything that can be decided by an explicit rule is
decided by Python, off the LLM path; the LLM is used only for the part that genuinely
needs judgement, and its output is then checked.

```
                    ┌─────────────────── DETECTION PLANE (Python, stdlib only) ───┐
  CICIDS2017 CSVs   │                                                             │
  or an uploaded ──►│  Stage 1  STANDARDIZE   map arbitrary columns to canonical  │
  flow CSV          │           (no LLM)      fields; parse ts; drop unparseable  │
                    │                                                             │
                    │  Stage 2  DETECT        rule + statistical detectors ->     │
                    │                         signals; cluster -> incidents;     │
                    │                         single-owner event assignment      │
                    └────────────────────────────────┬────────────────────────────┘
                                                     │ events / signals / alerts / incidents
                    ┌────────────────────────────────▼────────────────────────────┐
                    │            INVESTIGATION PLANE (LangGraph.js + Gemini)      │
                    │                                                             │
                    │  AGENT 1/4  collect     incident-scoped events -> grounded  │
                    │                         facts EV-…-n (bad citations dropped)│
                    │  AGENT 2/4  hypothesize attack hypotheses, each citing      │
                    │                         evidence IDs + an ATT&CK technique  │
                    │  AGENT 3/4  verify      FAIL-CLOSED. A1 citation gate,      │
                    │                         A2 consistency gate, B LLM         │
                    │                         entailment; then score survivors    │
                    │  AGENT 4/4  report      written ONLY if >=1 hypothesis      │
                    │                         survived — otherwise returns {}     │
                    └─────────────────────────────────────────────────────────────┘
```

The graph is linear — `START → collect → hypothesize → verify → write_report → END`, with
no conditional edges. Branching is done by early-return guards inside the node bodies,
which keeps the traversal order fixed and auditable: every incident produces the same four
`agent_runs` rows in the same order.

See [`AI_SOC_Team_Handbook.html`](AI_SOC_Team_Handbook.html) for a walkthrough written for
teammates, and [`docs/`](docs/) for the plan and execution tracker.

## Repository map

```
ml/                 detection plane (Python, standard library only)
  soccore.py          shared: parsing, detectors, ATT&CK KB, label bridge
  ingest_cicids.py    the fixed 3-scenario CICIDS seed
  analyze.py          one uploaded CSV -> dynamically discovered incidents (JSON)
  train_mlp.py        offline deep-learning artifact (numpy MLP)
  pipeline.py         synthetic-log path (alternative seed)
agents/             investigation plane (Node + LangGraph.js)
  src/graph.ts        the 4-node graph, plus streaming for the UI
  src/agents/         evidence.ts · hypothesis.ts · verifier.ts · report.ts
  src/tools.ts        the ENTIRE tool surface the agents may use
  src/mitre.ts        detector <-> attack-family <-> technique bridge
  src/server.ts       local-only upload backend (POST /api/analyze)
  src/eval.ts         investigation-quality metrics from stored runs
supabase/migrations 0001_init · 0002_alerts_rls · 0003_batches
web/                analyst UI (TanStack Start + React 19 + Tailwind v4)
scripts/load_db.sh  schema + seed loader
data/               seed SQL, eval JSON, CICIDS CSVs
```

## Requirements

- **Node.js** 20+ (developed on 24) — for `agents/` and `web/`
- **Python 3** — the detection plane and `analyze.py` use the **standard library only**
- **PostgreSQL** — a Supabase project (the UI reads through PostgREST; the backend writes
  through `DATABASE_URL`)
- **A Gemini API key** — free tier is enough; the client serialises calls ~13s apart
- Only for the offline ML artifact: `numpy` and `matplotlib`
  (`ml/requirements.txt` is aspirational and lists packages the shipped code does not use)

## Setup

**1. Environment.** Copy the template and fill in real values. `.env` is gitignored.

```sh
cp .env.example .env
```

| Variable | Used by | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `scripts/load_db.sh`, `agents/` | Postgres connection string. Contains the DB password. |
| `GEMINI_API_KEY` | `agents/` | Agent graph only. |
| `GEMINI_MODEL` | `agents/` | Optional; defaults to `gemini-3.8-flash`. |
| `SUPABASE_SECRET_KEY` | reserved | Not read by the current code path. Never expose it to the browser. |
| `PORT` / `MAX_UPLOAD_MB` / `CORS_ORIGIN` | `agents/src/server.ts` | Optional; defaults suit local dev. |

For the UI, create `web/.env.local`:

| Variable | Notes |
| --- | --- |
| `VITE_SUPABASE_URL` | Project URL. |
| `VITE_SUPABASE_ANON_KEY` | Publishable/anon key. RLS restricts it to reads. |
| `VITE_ANALYZE_API` | Optional; defaults to `http://127.0.0.1:8787`. |

**2. Load the schema and seed.**

```sh
bash scripts/load_db.sh
```

> [!WARNING]
> `load_db.sh` applies **only `0001_init.sql`** and the seed. The RLS policies
> (`0002_alerts_rls.sql`) and the batch tables (`0003_batches.sql`) are **not** applied by
> it, and without `0002` the browser has no read access. Apply them yourself:
>
> ```sh
> psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/migrations/0002_alerts_rls.sql
> psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/migrations/0003_batches.sql
> ```

## Running

Two processes in development: the local backend and the UI.

```sh
# Terminal 1 — agents backend (upload + auto-investigate)
cd agents && npm install && npm run server        # 127.0.0.1:8787

# Terminal 2 — analyst UI
cd web && npm install && npm run dev              # http://localhost:5173
```

Other entry points:

```sh
cd agents
npm run investigate              # investigate every incident
npm run investigate -- INC-2017-0002
npm run eval                     # investigation metrics (no new LLM calls)
npm run typecheck

python3 ml/analyze.py data/cicids/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | head
python3 ml/train_mlp.py          # retrain the offline MLP -> data/ml_eval.json
```

If `data/seed.sql` is absent, `load_db.sh` regenerates it via
`ml/generate_synthetic_logs.py` and `ml/pipeline.py`.

## HTTP API

`agents/src/server.ts` binds **127.0.0.1 only** and is **unauthenticated by design** — it
writes with the secret `DATABASE_URL` and runs uploaded CSVs through the Python detector.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness. |
| `POST /api/analyze` | Multipart `file` (`.csv`, size-capped). Runs detection, bulk-inserts one batch in a transaction, responds immediately with the detected incidents, then investigates them asynchronously. |
| `GET /api/jobs/:jobId` | Poll per-incident phase: `collecting` → `hypothesizing` → `verifying` → `reporting` → `done_with_report` \| `done_no_report` \| `error`. |

Uploads are single-flight: a second upload while one is investigating is rejected with
`409`, because the LLM throttle is process-global and the calls would interleave anyway.

## What it detects

Three tiers, and the distinction between them is the honest part of the design.

| Tier | Coverage | Basis |
| --- | --- | --- |
| **1 — behavioural** | brute force, DDoS flood, botnet beaconing | Independent detectors: rules over flow shape plus a flow-rate z-score. These have measured precision and recall (below). |
| **2 — annotated** | 18 further ATT&CK classes (port scan, SQLi, XSS, …) | Carried from the dataset's `Label` column and mapped to a technique. Written as a signal with `detector = 'label'` and labelled `annotation-only` downstream. This is **not** independent detection and is never scored as such. |
| **3 — not covered** | unlabelled non-flow attacks | Produce nothing. Not claimed. |

Two integrity guards back this up:

- **The confusion matrix counts behavioural detections only.** `pred` is captured *before*
  the label-derived signal is appended, so the reported scores never measure the label
  against itself.
- **Corroboration is reported per class** — of the flows the dataset annotated as class X,
  what share an independent detector also flagged. The UI shows this, so Tier 2 is visible
  as annotation rather than passing for detection.

### Detected measurement (CICIDS2017, all flows)

| Class | Precision | Recall | F1 |
| --- | --- | --- | --- |
| DDoS flood | 0.9950 | 1.0000 | 0.9975 |
| Brute force | 0.8026 | 0.9999 | 0.8904 |
| Botnet beaconing | 0.4588 | 0.6394 | 0.5342 |
| **Overall** | **0.9628** | **0.9950** | **0.9787** |

Overall: 143,115 TP · 5,531 FP · 713 FN · 713,328 TN. Beaconing is the weak detector and is
reported as such — its precision is the reason the confidence figure never rests on the
detector score alone.

## The deep-learning artifact

`ml/train_mlp.py` trains a hand-implemented numpy MLP (69 features → Dense64+ReLU →
Dense32+ReLU → Dense1+Sigmoid, Adam, 20 epochs) on the CICIDS flow features:

| Metric | Value |
| --- | --- |
| Precision / Recall / F1 | 0.9770 / 0.9975 / 0.9871 |
| Accuracy / ROC-AUC | 0.9894 / 0.9996 |
| Confusion matrix | TN 13,284 · FP 217 · FN 23 · TP 9,218 |
| Final training loss | 0.0249 |

> [!IMPORTANT]
> This is an **offline evaluation artifact**, kept for the Deep Learning requirement. It is
> **not wired into the live detection pipeline** — the architecture is frozen around the
> interpretable detectors in `soccore.py`, because every confidence figure has to trace
> back to a detector a human can read.

## Measured investigation quality

`npm run eval` recomputes these from stored `agent_runs` with no new LLM calls
(4 investigations over 3 incidents):

| Metric | Value |
| --- | --- |
| Evidence facts collected | 16 |
| Dropped by the grounding gate | 0 |
| Claim-grounding coverage | 100% |
| Verifier supported / rejected | 3 / 1 |
| Unsupported-claim rate | 25% |
| Avg tokens / latency per investigation | 20,469 / 42.7s |

Verifier on vs off, from the same runs:

| | Claims asserted | Unsupported | Rate |
| --- | --- | --- | --- |
| Without verifier | 4 | 1 | 25% |
| **With verifier** | **3** | **0** | **0%** |

## Security posture

Read this before exposing anything.

- **The browser has no write access.** RLS grants `select` only, to `anon` and
  `authenticated`, on all 12 tables; there is no insert/update/delete policy anywhere.
  Every write goes through the local backend.
- **The backend is local-only and unauthenticated.** It is bound to `127.0.0.1` with CORS
  restricted to the Vite origin, and it holds the secret `DATABASE_URL`. Do not put it on a
  public interface or behind a tunnel.
- **Uploaded flow text is untrusted.** It is wrapped by an injection guard before reaching
  a model, and parsed with the standard-library `csv` module — never `eval`.
- **Uploads are `.csv`-only, size-capped, and spawned with an argument array** — never a
  shell string — and the temp file is deleted after parsing.
- **Secrets stay in `.env` / `web/.env.local`,** both gitignored. `.env.example` holds
  placeholders only. Rotate the database and Gemini keys before any public push.

## Limitations

- Beaconing detection is weak (F1 0.53). It is reported, not hidden.
- Tier 2 coverage is the dataset's annotation, not a detector. 18 classes are carried and
  investigated; they are not independently detected.
- The pipeline reads network flows. Host logs, endpoint telemetry, and unlabelled
  non-flow attacks fall outside it and produce nothing.
- One upload is investigated at a time, and a large file can exhaust the Gemini free-tier
  daily quota — the run marks that incident `error` and continues rather than stalling.
- The MLP is not in the live path (see above).

## Development notes

- **This repository is connected to Lovable.** Do not rewrite published history — no force
  pushes, and no rebasing, amending, or squashing commits that are already pushed. Keep the
  connected branch in a working state.
- Keep AI-SOC routes in TanStack Start (`web/src/routes/`) and the shared analyst shell in
  `web/src/components/soc/`. The UI never performs privileged writes.
- Without `VITE_SUPABASE_URL`, the UI falls back to a static snapshot of the CICIDS seed.
  It is labelled as a snapshot in the interface and must never be presented as live
  telemetry.
