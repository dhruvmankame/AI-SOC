# AI-SOC

Evidence-grounded Security Operations Center prototype for CICIDS/CICFlowMeter
network-flow telemetry.

## Current stack

- **Frontend:** React + TanStack Start + TypeScript
- **Backend:** FastAPI + Python
- **Detection:** deterministic Python rules + statistical anomaly detection
- **Persistence:** MongoDB
- **Investigation:** Python LangGraph
- **LLM:** Gemini by default, optional Groq
- **Deep learning:** offline CICIDS MLP evaluation artifact

## Runtime architecture

```text
CICIDS/CICFlowMeter CSV
        |
        v
FastAPI /api/analyze
        |
        v
Standardize network flows
        |
        v
Rules + statistical detection
        |
        v
Signals -> Alerts -> Correlated Incidents
        |
        +---------------------> MongoDB (all incidents)
                                  |
                                  | highest-risk MAX_AI_INCIDENTS
                                  v
                          Evidence Collector
                                  |
                          Hypothesis + ATT&CK
                                  |
                          Fail-closed Verifier
                                  |
                          Verified Report Writer
                                  |
                                  v
                          Incident Record / Audit
```

**Important:** the AI quota does not truncate deterministic detection. Every incident
is persisted; only the highest-risk incidents are auto-investigated. Other incidents
can be investigated manually from their Incident Record.

## Setup

```bash
bash scripts/setup.sh
# edit .env and set MONGODB_URI + the key for your selected LLM provider
```

Start both services:

```bash
bash scripts/dev_python.sh
```

Or separately:

```bash
# terminal 1
bash scripts/run_python_backend.sh

# terminal 2
cd frontend
npm run dev
```

Backend: `http://127.0.0.1:8787`

Frontend: normally `http://localhost:8080` with the current Vite configuration.
Use the exact URL printed by Vite if the port changes.

## Demo datasets

- `data/cicids/demo/demo_bruteforce_T1110.csv`
- `data/cicids/demo/demo_ddos_T1498.csv`
- `data/cicids/demo/demo_botnet_T1071.csv`

## Repository map

```text
frontend/   analyst UI
backend/    FastAPI, MongoDB persistence, LangGraph agents
ml/         CSV normalization, detectors, offline MLP training/evaluation
data/       demo datasets and evaluation artifacts
docs/       current architecture, demo and report material
scripts/    setup, run and validation commands
```

## Deep-learning scope

`ml/train_mlp.py` implements the project MLP and produces evaluation metrics and
figures. It is intentionally an **offline evaluation component**, not part of the
live detector. The live path uses deterministic and statistical detection before
LLM investigation.

## Final verification

```bash
bash scripts/check.sh
curl http://127.0.0.1:8787/api/health
```

See `docs/architecture.md` for the active architecture.
