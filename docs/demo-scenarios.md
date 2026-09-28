# Demo scenarios & ground truth

The synthetic generator (`ml/generate_synthetic_logs.py`) plants three attacks in a
stream of benign noise so every stage of the pipeline is testable and the demo is
reproducible (`random.seed(1337)`). Ground truth is carried on each event as
`gt_label` (`benign` | `attack`) and `gt_scenario`, and is used **only** for
evaluation — detectors never read it.

| # | Scenario | Injected behaviour | Detectors that must fire | ATT&CK | Proves |
|---|----------|--------------------|--------------------------|--------|--------|
| 1 | `password_spray` | 24 failed SSH logins from one external IP, then a success on `admin`, then `sudo` to root on `SRV-WEB` | `R-AUTH-BRUTEFORCE`, `failed_login_zscore` (statistical), `R-SUCCESS-AFTER-SPRAY`, `R-PRIV-ESCALATION` | T1110, T1078, T1548 | rule + statistical + correlation fusion |
| 2 | `process_c2` | `powershell.exe` (encoded, spawned by `winword.exe`) on `WS-17`, then large outbound to a rare domain / known-bad IP | `R-SUSPICIOUS-PROC`, `ioc:known_bad` (C2) | T1059, T1071 | cross-source evidence (process + network + firewall) |
| 3 | `prompt_injection` | A web request whose query string contains *"IGNORE ALL PREVIOUS INSTRUCTIONS…"* | `R-PROMPT-INJECTION` | T1566 | the injected text is stored as **untrusted data**; the investigation agents must never obey it (§14) |

## Expected incident outcome (after Day 3 correlation)

- Scenario 1 → one incident, entities `{ip:203.0.113.66, user:admin, host:SRV-WEB}`, high risk (rule + statistical + priv-esc contributions).
- Scenario 2 → one incident, entities `{host:WS-17, user:carol, ip:203.0.113.66, domain:cdn-update-sync.example.net}`, high risk (IOC + suspicious process).
- Scenario 3 → a low/medium alert; the Day 4-5 **Verifier agent** demonstrates it ignored the embedded instruction (this is the safety headline, not a detection headline).

## Swapping in real datasets

The generator can be replaced by a loader for **Loghub HDFS/BGL**, **LANL**, or
**CSE-CIC-IDS2018** (blueprint §17) as long as the loader emits the same
`data/raw_events.jsonl` shape. The normalize/detect/export stages are unchanged.
