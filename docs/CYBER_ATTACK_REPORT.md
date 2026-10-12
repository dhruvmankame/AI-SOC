# Cyber Attack Research / Report Guide

## Research basis
CICIDS2017 (Canadian Institute for Cybersecurity, University of New Brunswick) contains labelled benign traffic and attacks including brute force, DoS/DDoS, web attacks, infiltration and botnet activity, with CICFlowMeter flow features.

Official dataset: https://www.unb.ca/cic/datasets/ids-2017.html

MITRE ATT&CK references:
- T1498 Network Denial of Service: https://attack.mitre.org/techniques/T1498/
- T1110 Brute Force: https://attack.mitre.org/techniques/T1110/
- T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/

## DDoS demo
Dataset: `data/cicids/demo/demo_ddos_T1498.csv`.
Explain high-volume traffic directed at a service, availability impact, detector evidence, target entity and confidence. Map to T1498 only when supported; T1498.001 is appropriate only when direct flooding evidence supports the sub-technique. Recommended response: validate affected service, rate-limit/filter, engage upstream/CDN/DDoS scrubbing when necessary, preserve flow telemetry, and avoid unrelated compromise claims.

## Brute-force demo
Dataset: `data/cicids/demo/demo_bruteforce_T1110.csv`.
Repeated connection/authentication-oriented behavior can support T1110, but flow data alone does not prove a successful login. Correlate with authentication logs before claiming credential compromise. Recommended response: MFA, lockout/rate controls, source blocking/throttling and credential reset only when success is independently confirmed.

## Botnet/C2-like demo
Dataset: `data/cicids/demo/demo_botnet_T1071.csv`.
Periodic application traffic may support a C2 hypothesis, but benign software can also beacon. Map to T1071 only when protocol and evidence support it. Correlate with DNS, proxy, EDR and process telemetry.

## Final incident report must contain
Dataset/batch ID; standardization quality; independent alerts/confidence; incident risk/entities; cited evidence IDs; hypotheses and ATT&CK mapping; verifier accepted/rejected claims; supported narrative; defensive actions; and explicit limitations. The generated incident record is authoritative for a specific run—never replace run-specific evidence with a generic narrative.
