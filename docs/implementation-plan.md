# AI-SOC — One-Week Implementation Plan

Derived from `AI_SOC_Project_Research_Architecture.html` (the research blueprint),
compressed from its 12-week roadmap to **7 days**, built on a **React/Vite + Supabase**
stack (Lovable subscription ended — standard local tooling only), with
**multi-agent investigation** as the graded priority.

## 1. Honest scope

The full blueprint is not buildable in 7 days. This plan ships a **coherent vertical
slice** that proves the core thesis — *"selective intelligence beats universal
intelligence"* — and fully delivers the multi-agent, evidence-grounded investigation.
Parts that are not the star are made to *look* real by pre-loading them.

| Layer | Approach | Real vs staged |
|-------|----------|----------------|
| Ingestion / parsing | parse a dataset subset **offline**, load into Supabase | staged (seeded, not a live collector) |
| Deep learning | train small model **offline**, load precomputed scores | staged (offline, not live-served) |
| Detection | real Sigma-style SQL rules + IOC + 1 statistical detector | real (thin) |
| Correlation → incidents | real entity/time-window correlation + risk fusion | real (thin) |
| **Multi-agent investigation** | LangGraph.js, evidence-ID grounding, working verifier | **fully real — the star** |
| UI | 3 pages: Overview, Alert Queue, Incident Workbench | real |
| Response | simulation-only proposal + Approve/Reject | real (thin) |
| Evaluation | evidence coverage %, unsupported-claim rate, 1 detection number | real (thin) |

## 2. Blueprint stack → this build

| Blueprint | This build | Trade-off to state in the report |
|-----------|-----------|----------------------------------|
| Next.js | React + Vite + TS + Tailwind + shadcn | equivalent |
| FastAPI | Supabase Edge Functions (Deno/TS) | fine at student scale |
| ClickHouse | Supabase Postgres (indexed/partitioned) | loses petabyte throughput — irrelevant here |
| Postgres + pgvector | Supabase Postgres + pgvector | perfect fit |
| Kafka/Redpanda | replay script + Supabase Realtime | simulated stream |
| LangGraph (py) | LangGraph.js (TS) in Edge Function | same model, human-in-the-loop preserved |
| PyTorch + MLflow | offline notebooks; export scores + tiny inference endpoint | training offline (normal) |
| Redis / Vector / Docker / Prometheus | jobs table / replay / in-app metrics | dropped for the week; future work |

## 3. The 7-day plan

### Day 1 — Foundation & data  ✅ (done)
- Repo structure, `supabase/migrations/0001_init.sql` (OCSF-subset events + signals, alerts,
  incidents, incident_entities, evidence, agent_runs, detection_rules, attack_kb, feedback).
- `ml/generate_synthetic_logs.py` — labelled logs with 3 planted attacks.
- `ml/pipeline.py` — Drain-lite templates → OCSF normalize → rule/IOC/statistical detectors → `data/seed.sql`.
- `docs/demo-scenarios.md` — scenarios + ground truth.
- **M1 gate:** normalized events searchable, ingest metrics visible.

### Day 2 — Detection API & dashboard  ✅ (done)
- Read "API" = **PostgREST auto-generated over RLS'd tables** (browser uses the publishable
  key; RLS makes it read-only). Edge Functions are reserved for Day 4 agent writes (secret key).
- `0002_alerts_rls.sql`: `build_alerts()` dedups `signals` → `alerts` grouped by (entity,
  source_type) with per-detector `contributions` + noisy-OR confidence (54 signals → 6 alerts);
  RLS enabled on all tables (anon read-only — verified REST read 200 / write 401).
- Frontend (`web/`): **Overview** (KPI tiles + ingest / severity / source charts) + **Alert Queue**
  (expandable per-detector "why" + source events). Dark-first, dataviz-validated palette.
- **M2 gate:** ✅ rules + statistical detector produce explainable alerts (reason, score, source events).

### Day 3 — Correlation → incidents
- Sliding-window entity correlation (§9.4); transparent risk fusion (§9.3) with component
  breakdown; incident builder + timeline; `incidents` list page.
- **M4 gate:** related alerts merge into one incident with entities, timeline, risk factors, ATT&CK tags.

### Days 4–5 — Multi-agent investigation (PRIORITY)
- LangGraph.js graph over the shared incident-state contract (§8):
  **Orchestrator → Evidence Collector → Timeline + ATT&CK Mapper → Hypothesis → Verifier → Report.**
- Every factual claim carries an `evidence_id`; the **Verifier rejects uncited claims**.
- Read-only query tools only; log text treated as untrusted (prompt-injection safe).
- Light pgvector RAG over `attack_kb`; token/step budgets; full audit → `agent_runs`.
- **M5 gate:** an incident triggers agents that emit a cited evidence packet, hypotheses,
  verifier result and final report; every tool call audited.

### Day 6 — Incident Workbench & Agent Audit UI
- §12 workbench: timeline · entity graph (React Flow) · evidence panel · verified-findings-only
  AI panel · response proposal (Approve/Reject, simulation).
- Agent Audit view: which agent ran, tools, citations, tokens, rejected claims.

### Product loop — upload → detect → identify → incident record  ✅ (done)
- UI-driven end-to-end loop: **Analyze** page uploads a `.csv` flow log → local Node backend
  (`agents/src/server.ts`, 127.0.0.1, unauthenticated) runs `ml/analyze.py` → creates an
  **ingest batch** + dynamically-discovered incidents → auto-investigates every incident
  (`socGraph.stream`) with live per-incident phase polling (`GET /api/jobs/:id`).
- **Batch namespacing** (`0003_batches.sql`): each upload is a batch; seeded CICIDS rows keep
  `batch_id = NULL` ("CICIDS Seed"). Topbar batch selector filters Overview/Alerts/Incidents.
- New read pages: **Incidents** (attack type via ATT&CK KB, MITRE, risk, verifier status) and
  **Incident Record** (summary · agent report · verifier verdicts incl. **rejections** ·
  cited evidence · entities · timeline · agent-run audit). Reads stay on PostgREST; writes
  are server-side only (RLS keeps the browser read-only).
- **Two-process dev:** `npm run dev` (web/) **and** `npm run server` (agents/) run together;
  frontend uses the backend only for `POST /api/analyze` + `GET /api/jobs/:id`.

### Day 7 — Evaluation & demo
- Metrics: evidence-coverage %, unsupported-claim rate, single-agent vs multi-agent+verifier,
  one detection F1/PR-AUC number; charts/tables.
- Record the 3 demo scenarios; limitations & future work.
- **M6 gate:** system runs reproducibly end-to-end.

## 4. Cut order if behind
Protect Days 4–6. Cut in this order: a demo scenario → the statistical detector → the entity
graph. **Never cut the Verifier or evidence-grounding — that loop is the project.**

## 5. Open decisions
- **LLM provider** (needed Day 4): free options — Google **Gemini** free tier (best hosted),
  **Groq** (fast, free), or **Ollama** local on this Kali box (fully free/offline, aligns with the
  "local model" guardrail and reproducible demos). All work with LangGraph.js.
- Optional: a free **Telegram bot** as an incident-alert notification channel (Telegram Bot API
  is free) — nice-to-have, not on the critical path.

