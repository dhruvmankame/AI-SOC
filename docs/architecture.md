# AI-SOC architecture

The controller has fixed traversal. Python creates incidents before any LLM call;
LangGraph investigates only the evidence retrieved for a particular incident.

```mermaid
flowchart TD
  CSV[Uploaded flow CSV] --> API[Local Express API: 127.0.0.1:8787]
  API --> PY[Python: normalize, detect, correlate]
  PY --> JSON[Events, signals, alerts, incidents, evaluation]
  JSON --> TX[Transactional batch insert]
  TX --> DB[(Supabase PostgreSQL)]
  TX --> C[1. Collect incident-scoped evidence]
  C --> CG{Every source event ID exists?}
  CG -->|invalid fact dropped| H[2. Propose cited hypotheses]
  CG -->|grounded facts| H
  H --> V[3. Verify citations, detector consistency, entailment]
  V --> S[Compute confidence in code]
  S --> R[4. Write report from supported findings]
  R -->|supported findings| DB
  R -->|none supported or budget exhausted| NO[No report; audit skipped stage]
  C --> AUD[Agent audit: tools, citations, tokens, latency]
  H --> AUD
  V --> AUD
  R --> AUD
  NO --> AUD
  AUD --> DB
  API --> JOB[In-memory job phases]
  DB --> REST[Read-only PostgREST under RLS]
  REST --> UI[React analyst interface]
  JOB --> UI
  UI -->|CSV upload| API
```

The browser holds only publishable credentials. Writes go through the local
backend's PostgreSQL connection. Uploads are serialized; each incident makes at
most four reasoning calls before retries, with process-wide spacing of 13 seconds.
Skipped nodes still produce audit records and consume no model tokens. The token
budget is checked between calls; an individual call may overshoot it, and verification
is retained for already proposed claims even when the budget has been reached.

Evidence retrieval follows `alerts.event_ids`. Legacy entity fallback is narrowed
by the incident's detector family; it refuses events when no matching family exists.
The collector rejects a whole fact if any source ID is absent. The verifier rejects
missing citations, absent evidence IDs, contradictory techniques, and absent or
negative entailment verdicts. Confidence is detector strength multiplied by
entailment strength; dataset-only annotation is capped at 50 percent.

The MLP is an offline evaluation artifact. It has no connection to the runtime graph.
Job phases are process-local and lost when the backend restarts; stored incident
records and agent audits survive in PostgreSQL.
