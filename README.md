# AI-SOC — Evidence-Grounded Multi-Agent SOC (1-week build)

A buildable slice of the *AI-SOC* blueprint: a two-plane security-operations system
where a cheap **detection plane** compresses raw logs into a few correlated incidents,
and an **agentic investigation plane** produces **evidence-cited** incident narratives
with a verifier that rejects any unsupported claim.

Priority for this build: **multi-agent investigation** (the graded contribution).

## Stack (built without Lovable)

- **Frontend:** React + Vite + TypeScript + Tailwind + shadcn/ui (`web/`)
- **Backend / data:** Supabase — Postgres + pgvector + Edge Functions + Realtime + Auth
- **Agents:** LangGraph.js (TypeScript) in a Supabase Edge Function, LLM via a free provider
- **Offline ML:** Python notebooks/scripts (`ml/`) — parsing, detection, sequence model — results loaded into Supabase

> The heavy blueprint components (ClickHouse, Kafka, FastAPI microservices, MLflow infra)
> are intentionally replaced by Postgres + a replay script + offline training to fit one week.
> See `docs/implementation-plan.md` for the mapping and honest trade-offs.

## Repo layout

```
dsl/
├── web/                     # React/Vite frontend (Day 2+)
├── supabase/migrations/     # 0001_init.sql — OCSF-subset schema + agent tables
├── ml/                      # offline data + detection pipeline (Day 1, stdlib-only)
│   ├── generate_synthetic_logs.py
│   ├── pipeline.py          # parse -> normalize -> detect -> seed export
│   └── requirements.txt     # real model deps (Day 4-5)
├── data/                    # generated seed (gitignored)
└── docs/
    ├── implementation-plan.md
    └── demo-scenarios.md
```

## Quick start (Day 1 — data foundation)

```bash
# 1. generate labelled logs + run the detection pipeline (no deps needed)
python3 ml/generate_synthetic_logs.py
python3 ml/pipeline.py           # -> data/seed.sql, data/seed.json

# 2. create the schema + load seed (once you have a Supabase project or `supabase start`)
psql "$SUPABASE_DB_URL" -f supabase/migrations/0001_init.sql
psql "$SUPABASE_DB_URL" -f data/seed.sql
```

## Status

- [x] **Day 1** — schema, labelled data generator, detection pipeline, 3 demo scenarios, seed export
- [ ] Day 2 — detection API + Overview dashboard + Alert Queue
- [ ] Day 3 — correlation → incidents + risk fusion
- [ ] Days 4–5 — **multi-agent investigation (LangGraph.js) + verifier**
- [ ] Day 6 — Incident Workbench + Agent Audit UI
- [ ] Day 7 — evaluation (evidence coverage, unsupported-claim rate) + demo
