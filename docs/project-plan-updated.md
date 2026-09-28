# AI-SOC — Simplified 5–6 Day Completion Plan

> **Goal of this document.** Finish a complete, stable, demonstrable AI-SOC project
> within the next **5–6 days** without increasing architectural complexity.
>
> This plan intentionally protects only the features required to prove the project:
> **log upload → detection → correlation → AI investigation → evidence verification → incident record → evaluation**.
>
> **Status legend:** ✅ done & verified · 🔶 keep but simplify · ⬜ remaining.
>
> _Revised for fast completion: 2026-09-28._

---

## 1. Project goal

Build a small but complete **AI Security Operations Center** that can:

1. Accept CICIDS/CICFlowMeter CSV logs.
2. Detect a small number of important attack types.
3. Group related alerts into incidents.
4. Investigate important incidents with a multi-agent LLM workflow.
5. Ground every important AI claim in evidence.
6. Reject unsupported claims using a verifier.
7. Show the incident clearly in the frontend.
8. Measure whether the verifier improves reliability.

The goal is **not** to reproduce Splunk, Microsoft Sentinel, CrowdStrike, Kafka,
SOAR, or a production SOC. The goal is to demonstrate one coherent end-to-end
research prototype that works reliably.

---

## 2. Main thesis

**"Selective intelligence beats universal intelligence."**

The normal detection pipeline should handle most work using deterministic code.
LLM reasoning should be used only after an incident has already been detected and
correlated.

The most important part of the project is:

**Incident → evidence collection → hypothesis → verifier → final report**

Every factual AI claim should reference an `evidence_id`. The verifier should
reject claims that do not have sufficient evidence.

This evidence-grounded investigation loop is the **main contribution of the project**.

---

## 3. Scope — keep it small

Only build the following vertical slice.

| Layer | Simplified implementation | Priority |
|---|---|---|
| Log input | Upload CICIDS/CICFlowMeter `.csv` | MUST |
| Parsing | Normalize only the fields required by detectors | MUST |
| Detection | 2–3 rule detectors + 1 statistical detector | MUST |
| Deep learning | One very small offline model or precomputed ML score | KEEP SIMPLE |
| Alert building | Deduplicate detector signals into alerts | MUST |
| Correlation | Time/entity-based grouping into incidents | MUST |
| Risk score | Simple weighted/noisy-OR score already used by the project | MUST |
| AI investigation | Evidence → hypothesis → verifier → report | MUST |
| ATT&CK mapping | Small local knowledge base | MUST |
| Frontend | Analyze, Incidents, Incident Record, basic Overview | MUST |
| Response | Recommendation only; simulation if already built | OPTIONAL |
| Evaluation | Detection metric + evidence/unsupported-claim metrics | MUST |

### Explicitly out of scope for this deadline

Do **not** add these unless everything else is already completely finished:

- Kafka / Redpanda
- ClickHouse
- Redis
- Docker orchestration
- Prometheus / Grafana
- production authentication
- live endpoint agents
- SIEM-scale streaming
- complex entity graph visualization
- complex SOAR automation
- many attack types
- many LLM agents
- large transformer or LSTM models
- framework migrations
- cloud deployment

These can be mentioned as **future work**.

---

## 4. Final architecture

Keep the current stack. Do **not** migrate technologies now.

### Detection side

```text
CSV Upload
   ↓
Parser / Normalizer
   ↓
Rule Detector + Statistical Detector + optional small ML score
   ↓
Signals
   ↓
Alerts
   ↓
Simple correlation
   ↓
Incidents + risk score
```

### Investigation side

```text
Incident
   ↓
Evidence Collector
   ↓
Timeline / ATT&CK lookup
   ↓
Hypothesis Agent
   ↓
Verifier Agent
   ↓
Report Agent
   ↓
Incident Record
```

### Technology stack — freeze it

| Area | Keep |
|---|---|
| Frontend | React + Vite + TypeScript |
| Database | Supabase Postgres |
| Backend | Existing local Node/Express service |
| Detection | Existing Python scripts |
| Agents | LangGraph.js |
| LLM | Gemini free tier |
| Knowledge base | Existing `attack_kb`; pgvector only if already working |

**Do not move Node to FastAPI. Do not replace Supabase. Do not rewrite the agent
workflow in Python.** At this point stability is more valuable than architectural
purity.

---

## 5. Detection scope

Keep only a few attacks that are easy to demonstrate and explain.

Recommended set:

- **Brute force / credential attack** — ATT&CK T1110
- **DDoS / network flood** — ATT&CK T1498
- **Botnet / beaconing** — ATT&CK T1071, only if already stable

The detector must not use the dataset `Label` field during detection.

### Minimum detection flow

```text
features
   ↓
rule/statistical detector
   ↓
signal
   ↓
alert
   ↓
incident
```

Do not add more attack classes just to make the system look larger.
Two attacks that work correctly are better than ten unreliable ones.

---

## 6. Deep-learning requirement — keep it minimal

Because the project title contains **Deep Learning**, the final report should show
one clear ML component. It does not need to be complex.

### Preferred minimal option

Train one small MLP offline on selected CICIDS features:

```text
Input features
   ↓
Dense 64 + ReLU
   ↓
Dense 32 + ReLU
   ↓
Attack probability
```

Use its output only as one additional signal or as an evaluation component.

### If time becomes tight

Do not spend multiple days tuning the neural network. Use the already prepared
or precomputed score and document clearly that training is offline.

Required evidence for the report:

- model architecture
- features used
- train/test split
- one confusion matrix
- Precision / Recall / F1

That is enough to justify the deep-learning component for this project scope.

---

## 7. Multi-agent investigation — protect this feature

Keep the number of intelligent agents small.

### Required workflow

`START → collect → hypothesize → verify → write_report → END`

### Responsibilities

**Evidence Collector**
- reads only incident-scoped events
- collects relevant alerts/events
- assigns/returns evidence IDs

**Hypothesis Agent**
- explains the likely attack
- must cite evidence IDs

**Verifier Agent**
- checks every important claim
- rejects unsupported/uncited claims
- should fail closed

**Report Agent**
- produces the final short incident summary
- includes only verified findings as confirmed findings
- rejected claims remain visible separately for auditability

Timeline construction, sorting, database lookup, token budgeting, and simple
filtering should remain deterministic code instead of becoming extra LLM agents.

---

## 8. Simple investigation selection

Do not build a complicated routing engine.

Use one simple rule:

```text
High-risk incident → auto-investigate
Other incident     → Investigate button / optional
```

If the current implementation already investigates all incidents and changing it
would create risk, **leave it as-is for the demo** and describe risk-based routing
as the intended optimization/future improvement.

The deadline is more important than implementing a new router.

---

## 9. Product loop — final demo path

The final demo should follow one clear story:

1. User opens **Analyze**.
2. User uploads a CICIDS/CICFlowMeter CSV.
3. Backend parses the file.
4. Detection creates signals and alerts.
5. Related alerts become incidents.
6. The UI names the detected attack and shows the risk score.
7. AI investigation starts for the selected/high-risk incident.
8. Evidence is collected.
9. The hypothesis agent explains what happened.
10. The verifier accepts supported claims and rejects unsupported claims.
11. The Incident Record displays:
    - attack type
    - MITRE technique
    - risk score
    - entities
    - timeline
    - evidence
    - verified findings
    - rejected claims
    - short recommended actions

If this path works reliably, the project is demo-ready.

---

## 10. Current implementation status

According to the current project state, the following are already implemented and
should be **preserved rather than redesigned**:

- normalized event storage
- signals → alerts
- correlation → incidents
- risk scoring
- React frontend pages
- LangGraph investigation
- evidence IDs
- verifier
- incident-scoped event retrieval
- upload backend
- incident record
- agent audit data

The remaining work should focus on **testing, evaluation, documentation, and demo
stability**, not architectural expansion.

---

## 11. Revised 5–6 day completion roadmap

### Day 1 — Freeze features and smoke-test the full pipeline ⬜

Run the complete flow several times:

`upload → detect → alerts → incidents → investigate → verify → report`

Fix only bugs that block this flow.

**Do not add new pages, frameworks, agents, or infrastructure.**

**Gate:** one known CSV completes end-to-end from upload to Incident Record.

---

### Day 2 — Finish the minimum deep-learning evidence ⬜

Use the smallest possible MLP/offline model.

Produce:

- model architecture
- training result
- Precision
- Recall
- F1
- confusion matrix

If the model is already trained, do not retrain repeatedly unless necessary.

**Gate:** one defensible ML result is ready for the report and presentation.

---

### Day 3 — Evaluation of the AI investigation ⬜

Run a small comparison on the prepared demo incidents.

Measure:

- **evidence coverage %**
- **unsupported-claim rate**
- verifier rejected-claim count
- optionally investigation latency/token usage

If feasible, compare:

```text
LLM without verifier
vs
LLM + verifier
```

Keep the sample small. The goal is to demonstrate the effect, not publish a large
benchmark.

**Gate:** one table/chart shows why the verifier is useful.

---

### Day 4 — Demo hardening ⬜

Prepare only **2–3 reliable demo scenarios**.

Recommended:

1. Brute force
2. DDoS
3. Botnet/beaconing only if stable

Test the exact files you will use in the presentation.

Also test graceful behaviour when Gemini quota/API calls fail.

**Gate:** demo can be repeated without manual database repair.

---

### Day 5 — Documentation and presentation ⬜

Complete:

- architecture diagram
- problem statement
- existing-system comparison
- implementation explanation
- screenshots
- evaluation table/charts
- limitations
- future work
- README / run instructions
- final presentation/demo script

**Gate:** another person can understand the project and run the demo from the docs.

---

### Day 6 — Buffer only ⬜

Use this day only for:

- fixing presentation-blocking bugs
- final smoke test
- cleaning the repository
- rotating exposed/test secrets before public push
- recording a backup demo video or screenshots
- final report/presentation polish

Do not start a new subsystem on Day 6.

---

## 12. Evaluation — minimum required

Do not build a large evaluation framework.

A small table is enough:

| Area | Metric |
|---|---|
| Detection / ML | Precision, Recall, F1 |
| Evidence grounding | Evidence coverage % |
| Verifier | Unsupported-claim rate |
| Verifier | Number of rejected claims |
| Optional | Investigation latency |
| Optional | Token usage |

The most useful research comparison is:

```text
Single investigation without verification
              vs
Evidence-grounded investigation + verifier
```

The result should support the project thesis without requiring a large dataset of
LLM experiments.

---

## 13. UI — minimum pages to protect

### Must keep

- **Analyze** — upload CSV
- **Incidents** — detected incidents and attack type
- **Incident Record** — the main demo page

### Keep only if already working

- Overview dashboard
- Alert Queue
- Agent Audit details

### Do not spend time on

- cosmetic redesigns
- advanced graph visualizations
- animation-heavy dashboards
- mobile optimization
- complex filtering

Functional clarity is more important than visual complexity.

---

## 14. Cut order if time becomes short

Protect the following at all costs:

1. CSV upload
2. detection
3. incident creation
4. evidence collection
5. hypothesis agent
6. verifier
7. final incident report
8. Incident Record UI
9. basic evaluation

Cut or simplify in this order:

1. extra demo scenario
2. botnet/beacon detector if unstable
3. statistical detector if it causes problems
4. entity graph
5. detailed agent-audit UI
6. response simulation
7. live progress animations/polling polish
8. pgvector depth
9. extra charts/dashboard polish

**Never cut the verifier, evidence grounding, or Incident Record.**

---

## 15. Security — keep only practical protections

For the student/local demo:

- backend stays on `127.0.0.1`
- do not publicly expose the unauthenticated backend
- accept `.csv` only
- cap upload size
- use subprocess argument arrays, not shell command strings
- delete temp files
- browser stays read-only through RLS
- keep secrets in gitignored environment files
- rotate `DATABASE_URL` and `GEMINI_API_KEY` before any public repository push
- treat uploaded/log text as untrusted input

Do not add a full authentication/authorization system now.

---

## 16. Definition of DONE

The project is complete when the following works reliably:

```text
Upload CICIDS CSV
      ↓
Detect attack
      ↓
Create alert
      ↓
Create correlated incident
      ↓
Show attack type + MITRE technique + risk
      ↓
Collect incident evidence
      ↓
Generate hypothesis
      ↓
Verifier checks the claims
      ↓
Show verified report + rejected claims
      ↓
Display final Incident Record
```

And you have:

- one ML result
- one detection result
- one verifier/evidence evaluation
- 2–3 reliable demo files
- architecture diagram
- limitations and future work
- reproducible run instructions

Anything beyond this is optional.

---

## 17. Final rule for the next 5–6 days

**Do not make the project larger. Make the existing flow reliable, measurable,
and easy to explain.**

For this deadline, a smaller system that works end-to-end is stronger than a
larger architecture with unfinished modules.

---

## 18. Main project files

| Concern | File(s) |
|---|---|
| Detailed engineering notes | `docs/implementation-plan.md` |
| Demo scenarios + ground truth | `docs/demo-scenarios.md` |
| Detection core | `ml/soccore.py`, `ml/ingest_cicids.py`, `ml/analyze.py` |
| DB schema / migrations | `supabase/migrations/000{1,2,3}_*.sql` |
| Agent graph | `agents/src/graph.ts`, `agents/src/agents/*`, `agents/src/tools.ts` |
| Upload backend | `agents/src/server.ts` |
| Frontend | `web/src/pages/*`, `web/src/lib/*`, `web/src/App.tsx` |

