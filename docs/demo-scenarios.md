# Demo scenarios & ground truth (CICIDS2017)

The demo runs on **CICIDS2017** flow records — a real, widely-cited intrusion dataset
(Canadian Institute for Cybersecurity / UNB) — not synthetic logs. Each flow carries a
`Label` column (`BENIGN` or the attack name). Ground truth is used **only for evaluation**;
the behavioural detectors never read the `Label` (they fire on flow features: failed-login
bursts, flow-rate z-scores, and low-variance beacon fan-in). We target **three** attack
families that map cleanly to MITRE ATT&CK.

> **Which CSVs to upload:** use the trimmed slices in `data/cicids/demo/` — each yields
> exactly **one** clean incident and stays inside the Gemini free-tier quota. The raw
> CICIDS day-files (70–170 MB) discover ~9 incidents each and will exhaust the quota if
> auto-investigated. Do **not** demo on the raw files.

## The three live scenarios

| # | Family | ATT&CK | Detectors that fire | Demo upload | Seed incident |
|---|--------|--------|---------------------|-------------|---------------|
| 1 | SSH/FTP brute-force credential attack | **T1110** | `R-NET-BRUTEFORCE` + `failed_login`-style burst | `demo_bruteforce_T1110.csv` | `INC-2017-0001` |
| 2 | Volumetric HTTP DDoS flood | **T1498** | `R-NET-FLOOD` + `flow_rate_zscore` (statistical) | `demo_ddos_T1498.csv` | `INC-2017-0002` |
| 3 | Ares botnet C2 beaconing | **T1071** | `R-NET-BEACON` (external C2, internal fan-in ≥ 3) | `demo_botnet_T1071.csv` | `INC-2017-0003` |

Source day-files behind the slices: Tuesday (SSH/FTP-Patator), Friday-Afternoon (DDoS),
Friday-Morning (Ares botnet).

## Expected incident outcome (live seed — `batch_id NULL`)

- **INC-2017-0001** — *SSH/FTP brute-force credential attack*, T1110, risk 96.
  Entities: actor `172.16.0.1` → target `192.168.10.50`.
- **INC-2017-0002** — *Volumetric HTTP DDoS flood*, T1498, risk 96.
  Entities: actor `172.16.0.1` → target `192.168.10.50`.
- **INC-2017-0003** — *Ares botnet C2 beaconing*, T1071, risk 96.
  Entities: C2 actor `205.174.165.73` → infected victims `192.168.10.5/8/9/14/15`.

> **Why incident-scoped retrieval matters (the leakage trap):** INC-0001 and INC-0002 share
> the *same* actor (`172.16.0.1`) and target (`192.168.10.50`) IPs. The old entity-IP match
> (`src_ip=$1 or dst_ip=$1`) therefore pulled port-22 **and** port-80 flows into the DDoS
> investigation, letting it mis-form an SSH hypothesis. The fix (`getIncidentEvents` in
> `agents/src/tools.ts`, wired in `agents/src/agents/evidence.ts`) retrieves each incident's
> events via `alerts.event_ids where incident_id=$1`, so evidence is per-incident. The
> entity-IP path remains only as a fallback for rows without a scoped alert.

## Detector evaluation (honest, vs. `Label` ground truth — `data/cicids_eval.json`)

Evaluated over **all** CICIDS2017 flows for the three families (predicted-attack = ≥1
behavioural signal fired):

| Family | Precision | Recall | F1 |
|--------|-----------|--------|-----|
| Brute force | 0.803 | 0.9999 | 0.890 |
| DDoS | 0.995 | 1.000 | 0.9975 |
| Botnet (beacon) | 0.459 | 0.639 | 0.534 |
| **Overall** | **0.963** | **0.995** | **0.979** |

**Botnet is the honest weak point** (F1 0.534) — low-and-slow beaconing is genuinely the
hardest of the three to catch on flow features alone. This is stated openly and is exactly
what motivates the agent layer: the investigation reasons over the weak signal rather than
relying on the detector's confidence.

Trimmed demo slices re-scored offline: brute-force F1 ≈ **0.9999**, DDoS F1 ≈ **1.0**,
botnet F1 ≈ **0.78** (recall 0.64 — the same beaconing gap, on cleaner data).

## Deep-learning artifact (offline, `data/ml_eval.json`)

A hand-rolled numpy MLP (`ml/train_mlp.py`, `69 → 64 → 32 → sigmoid`) classifies CICIDS
flows BENIGN vs ATTACK on a held-out split: **P 0.977 · R 0.9975 · F1 0.9871 · ROC-AUC
0.9996**. It is a report/eval artifact only — deliberately **not** wired into the live
detection pipeline (architecture frozen).

## Investigation outcome — the graded safety property (`data/investigation_eval.json`)

Auto-investigation runs the LangGraph pipeline `collect → hypothesize → verify →
write_report` on each incident, grounding every claim to real `event_id`s and passing it
through the **fail-closed verifier**. Over the 3 seed incidents (4 stored investigations):

- **Evidence-grounding coverage: 100%** — every asserted claim cites real evidence.
- **Verifier ON → 0% unsupported claims; OFF → 25%** — the verifier **blocked 1**
  over-claimed hypothesis: INC-2017-0002's over-generalized SSH hypothesis ("multiple hosts
  made repeated attempts" when the cited evidence showed single attempts). That rejection —
  no report written, reason logged to `agent_runs.unsupported_claims` — **is** the graded
  safety property working.
- The same stored runs also show the retrieval fix end-to-end: INC-2017-0002 attempt-1
  (entity-fallback) → rejected; attempt-2 (incident-scoped) → correct **T1498** report.

## Demo script (order)

1. **Overview / Alert Queue** — show the seeded CICIDS baseline (3 incidents, per-detector
   "why", source events).
2. **Analyze** — upload `data/cicids/demo/demo_ddos_T1498.csv`; watch detection create a new
   batch + one T1498 incident, then live per-incident agent progress
   (collecting → hypothesizing → verifying → verdict).
3. **Incidents / Incident Record** — open the record: entities, cited evidence, agent report,
   verifier verdicts (including any rejection), timeline, agent-run audit.
4. **The headline** — point to the verifier-blocked DDoS over-claim (from
   `npm run eval` / `data/investigation_eval.json`) as the evidence-grounding guarantee.

> **If Gemini is overloaded (503) or over quota:** auto-investigation now **fails the
> affected incident in seconds** with a clear "model overloaded / quota reached" message
> (fast-fail in `agents/src/llm.ts`), instead of stalling ~6 min per incident. Detection and
> the batch still complete; fall back to the **stored** seed investigations for the
> agent-layer walkthrough (they are pre-populated and quota-free).
