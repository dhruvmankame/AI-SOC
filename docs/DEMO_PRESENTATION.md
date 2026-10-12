# Teacher Presentation (5–7 minutes)

1. **Problem:** LLMs can create fluent but unsupported attack narratives. AI-SOC makes deterministic detection first and verifies model claims against evidence.
2. **Architecture:** show `frontend/`, `backend/`, `ml/`, `data/`, then the pipeline in the root README.
3. **Live run:** upload `data/cicids/demo/demo_ddos_T1498.csv`, click **Run analysis**, and stay on that page. Explain that upload 100% is transfer completion, not analysis completion.
4. **Findings:** show event/signal/alert/incident counts, standardization, detector alerts and risk.
5. **Agents:** Evidence -> Hypothesis/ATT&CK -> Fail-closed Verifier -> Report. The report stage runs automatically only after supported findings survive verification.
6. **Limitations:** CICIDS2017 is research data; annotation-only classes are not independent detections; flow data alone cannot prove host compromise or successful login.
7. **Closing:** the contribution is the evidence gate, not just report generation.
