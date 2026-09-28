# AI-SOC — Full Project Plan (Zero → Hundred)

> **Purpose of this document.** A single reviewable plan for the whole project,
> so you can confirm it matches your required plan before more work is done.
> This is the master plan; `docs/implementation-plan.md` holds the detailed
> day-by-day engineering notes and is kept in sync with it.
>
> **Status legend:** ✅ done & verified · 🔶 partial · ⬜ not started.
>
> _Last reviewed: 2026-09-28._

---

## 1. The thesis being proved

**"Selective intelligence beats universal intelligence."**

A deterministic **detection plane** does the cheap, high-volume work (parsing,
normalizing, rule/statistical detection, correlation). Expensive **multi-agent
LLM investigation** is spent *only* on the handful of correlated incidents that
matter — and every factual claim an agent makes is grounded in an evidence ID,
with a **verifier that rejects uncited claims**.

The multi-agent investigation loop is the **graded star** of the project.
Everything else exists to hand it a realistic incident to reason about.

---

## 2. Scope philosophy — a coherent vertical slice

The full 12-week research blueprint (`AI_SOC_Project_Research_Architecture.html`)
is not buildable in one week. This plan ships a **coherent vertical slice**: the
investigation loop is *fully real*; detection and correlation are *real but thin*;
ingestion and deep learning are *staged offline* (seeded / precomputed) so they
look real without a live collector. **Nothing in the graded path is faked.**

| Layer | Approach | Real vs staged |
|-------|----------|----------------|
| Ingestion / parsing | parse a CICIDS subset offline, load into Supabase | staged (seeded) |
| Deep learning | train small model offline, load precomputed scores | staged (offline) |
| Detection | Sigma-style SQL rules + IOC + 1 statistical detector | real (thin) |
| Correlation → incidents | entity/time-window correlation + risk fusion | real (thin) |
| **Multi-agent investigation** | LangGraph.js, evidence-ID grounding, verifier | **fully real — the star** |
| UI | Overview · Alert Queue · Incidents · Incident Record · Analyze | real |
| Response | simulation-only proposal + Approve/Reject | real (thin) |
| Evaluation | evidence coverage %, unsupported-claim rate, 1 detection number | real (thin) |

---

## 3. Architecture — two planes

**Detection plane (Python, stdlib-only, offline):**
CICIDS2017 flow CSVs → normalize to an OCSF-subset `events` table → feature-based
detectors → `signals` → dedup into `alerts` → correlate into `incidents`.
Detectors (none of which read the ground-truth `Label`):
- **R-NET-BRUTEFORCE** — SSH/FTP credential attacks (ATT&CK **T1110**)
- **R-NET-FLOOD** + `flow_rate_zscore` statistical detector — DDoS (**T1498**)
- **R-NET-BEACON** — botnet / C2 beaconing (**T1071**)

**Investigation plane (LangGraph.js + Gemini free tier):**
`START → collect → hypothesize → verify → write_report → END`.
- Orchestrator → Evidence Collector → Timeline + ATT&CK Mapper → Hypothesis →
  **Verifier → Report**.
- Every factual claim carries an `evidence_id`; the **verifier rejects uncited
  claims** (fail-closed). Read-only query tools only; log text treated as
  untrusted (prompt-injection guarded); light pgvector RAG over `attack_kb`;
  token/step budgets; full audit trail → `agent_runs`.

**Trust boundary:** the browser uses the anon/publishable key and is **read-only**
via RLS (`for select using(true)`, no write policy). **All writes are server-side**
through a local Node backend using the secret `DATABASE_URL`.

### Stack mapping (blueprint → this build)

| Blueprint | This build | Trade-off |
|-----------|-----------|-----------|
| Next.js | React + Vite + TS (+ plain-CSS design tokens) | equivalent |
| FastAPI | local Node/Express backend + Supabase PostgREST | fine at student scale |
| ClickHouse | Supabase Postgres (indexed/partitioned) | loses petabyte throughput — irrelevant here |
| Postgres + pgvector | Supabase Postgres + pgvector | perfect fit |
| Kafka/Redpanda | replay script + upload endpoint | simulated stream |
| LangGraph (py) | LangGraph.js (TS) | same model, human-in-the-loop preserved |
| PyTorch + MLflow | offline notebooks; export scores | training offline (normal) |
| Redis / Docker / Prometheus | jobs table / in-app metrics | dropped for the week; future work |

---

## 4. The build roadmap (7 days)

### Day 1 — Foundation & data ✅
Repo structure; `0001_init.sql` (OCSF-subset events + signals, alerts, incidents,
incident_entities, evidence, agent_runs, detection_rules, attack_kb, feedback);
synthetic + CICIDS ingestion; `docs/demo-scenarios.md` with ground truth.
**Gate:** normalized events searchable, ingest metrics visible.

### Day 2 — Detection API & dashboard ✅
`build_alerts()` dedups `signals → alerts` grouped by (entity, source_type) with
per-detector contributions + noisy-OR confidence; RLS enabled everywhere
(anon read-only). Frontend **Overview** (KPI tiles + charts) + **Alert Queue**
(expandable per-detector "why" + source events).
**Gate:** rules + statistical detector produce explainable alerts.

### Day 3 — Correlation → incidents ✅
Sliding-window entity correlation; transparent risk fusion with component
breakdown; incident builder + timeline; Incidents list.
**Gate:** related alerts merge into one incident with entities, timeline, risk
factors, ATT&CK tags.

### Days 4–5 — Multi-agent investigation (PRIORITY) ✅
LangGraph.js graph over the shared incident-state contract; every claim carries
an `evidence_id`; the **verifier rejects uncited claims**; read-only tools;
untrusted log text; pgvector RAG over `attack_kb`; budgets; full audit.
**Gate:** an incident triggers agents that emit a cited evidence packet,
hypotheses, verifier result and final report; every tool call audited.

### Day 6 — Incident Workbench & Agent Audit UI ✅
Incident Record: timeline · entities · evidence panel · verified-findings-only
AI panel · verifier verdicts **including rejections** · response proposal
(Approve/Reject, simulation). Agent Audit: which agent ran, tools, citations,
tokens, rejected claims.

### Day 7 — Evaluation & demo ⬜ (remaining)
Metrics: evidence-coverage %, unsupported-claim rate, single-agent vs
multi-agent+verifier comparison, one detection F1/PR-AUC number; charts/tables.
Record the 3 demo scenarios; write limitations & future work.
**Gate:** system runs reproducibly end-to-end.

---

## 5. The product loop (UI-driven, approved & built) ✅

On top of the roadmap, the end-to-end loop driven from the UI:
**upload a log file → detect the attacks in it → name the attack type →
auto-investigate → show the incident record.**

1. User opens **Analyze**, picks a CICIDS/CICFlowMeter `.csv`, uploads.
2. Backend runs detection on that one file, creates a **batch** +
   dynamically-discovered incidents (not hardcoded scenarios), returns the
   incident list immediately.
3. Backend auto-runs the agent graph on **every** incident (async); the UI polls
   and shows live per-incident progress (collecting → hypothesizing → verifying
   → verdict), degrading gracefully on a Gemini quota error.
4. **Incidents** list shows each detected attack with attack type (from the
   ATT&CK KB), MITRE technique, risk, and verified/rejected status.
5. Clicking one opens the **Incident Record**: entities, cited evidence, the
   agent report (summary/narrative/actions), verifier verdicts **including
   rejections**, timeline, and the agent-run audit.

**Two product decisions baked in:**
- **Keep + append uploads** — each upload is a new *batch*; the seeded CICIDS
  demo is preserved; a topbar filter switches Seed / each upload / All.
- **Auto-investigate all** detected incidents on upload (accepting Gemini
  free-tier quota risk; the loop fails one incident fast rather than stalling).

**Key correctness fix (independent of upload):** incident-scoped retrieval
(`getIncidentEvents`) so an incident's investigation pulls only its own events —
this stopped the DDoS incident from leaking port-22 brute-force flows and
mis-hypothesizing. The verifier still rejects genuinely over-claimed hypotheses.

---

## 6. Current status snapshot

Everything through **Day 6 plus the full product loop is implemented and
verified**: both builds green (`tsc -b && vite build` for web; `tsc --noEmit`
for agents), all PostgREST read queries return 200, and the upload backend was
tested end-to-end (valid upload, `.csv`-only rejection, single-flight guard, job
polling, batch stamping, seed data untouched).

**Not yet done:**
- **Nothing is committed yet** (Lovable-connected branch — no history rewrite).
- **Day 7 evaluation** is the main unbuilt piece.
- A **live two-process browser smoke test** (needs you at the browser; burns a
  little Gemini quota).

---

## 7. What's left to hit 100

1. **Day 7 evaluation** — evidence-coverage %, unsupported-claim rate,
   single-agent vs multi-agent+verifier comparison, one detection F1/PR-AUC
   number; the tables/charts that quantitatively back the thesis. **(main gap)**
2. **Demo** — record the 3 CICIDS scenarios end-to-end; write limitations &
   future work.
3. **Live two-process smoke test** — `cd agents && npm run server` +
   `cd web && npm run dev`, then upload a CSV in the browser and watch the loop.
4. **Pre-public-push housekeeping** — resolve/accept the pre-existing
   high-severity `langsmith` npm advisory (a langchain transitive dep, not from
   express/multer/cors; the backend is local-only); **rotate `DATABASE_URL` and
   `GEMINI_API_KEY`**; decide on committing.

---

## 8. Priorities & cut order (if time runs short)

**Protect the verifier + evidence-grounding loop and the Incident Record — that
loop is the project.** Cut in this order only if forced:
1. a demo scenario → 2. the statistical detector → 3. the entity graph →
4. eval-on-upload → 5. live per-incident progress degrades to one spinner.

**Never cut:** the verifier, evidence-grounding, or the Incident Record.

---

## 9. Security posture (standing constraints)

- Backend is **local-only (127.0.0.1), unauthenticated by design** — never
  expose it; it writes with the secret `DATABASE_URL` and runs uploaded CSVs.
  CORS restricted to the Vite origin, `.csv` only, upload size capped, Python
  spawned with an args array (never a shell string), temp files deleted.
- Browser is **RLS read-only**; all writes are server-side.
- Uploaded flow text is **untrusted** — injection-guarded; parser is stdlib
  `csv`, no `eval`.
- **Secrets** live only in gitignored `.env` / `web/.env.local`; the
  `*.example` files stay placeholders. Rotate DB/Gemini keys before any public
  push. Never echo secret values.
- Lovable-connected repo — **do not rewrite published git history**; keep the
  connected branch in a working state; commit/push only when explicitly asked.

---

## 10. Where to look

| Concern | File(s) |
|---------|---------|
| Detailed engineering notes | `docs/implementation-plan.md` |
| Demo scenarios + ground truth | `docs/demo-scenarios.md` |
| Detection core | `ml/soccore.py`, `ml/ingest_cicids.py`, `ml/analyze.py` |
| DB schema / migrations | `supabase/migrations/000{1,2,3}_*.sql` |
| Agent graph | `agents/src/graph.ts`, `agents/src/agents/*`, `agents/src/tools.ts` |
| Upload backend | `agents/src/server.ts` |
| Frontend | `web/src/pages/*`, `web/src/lib/*`, `web/src/App.tsx` |

> **Review request:** if the weighting here is off — e.g. you want the response/
> simulation layer, deeper pgvector RAG, or the entity graph treated as
> must-have rather than nice-to-have, or Day 7 evaluation scoped differently —
> mark it up and I'll realign before building further.
