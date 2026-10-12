from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_four_stage_graph_contract():
    text = source("backend/app/graph.py")
    for edge in (
        'builder.add_edge(START, "collect")',
        'builder.add_edge("collect", "hypothesize")',
        'builder.add_edge("hypothesize", "verify")',
        'builder.add_edge("verify", "write_report")',
        'builder.add_edge("write_report", END)',
    ):
        assert edge in text


def test_detection_is_not_capped_by_ai_quota():
    analyze = source("ml/analyze.py")
    main = source("backend/app/main.py")
    assert "os.getenv('MAX_AI_INCIDENTS'" not in analyze
    assert "MAX_INCIDENTS =" not in analyze
    assert "MAX_AI_INCIDENTS" in main
    assert "not_selected" in main


def test_concurrency_setting_is_used():
    main = source("backend/app/main.py")
    assert "asyncio.Semaphore(AGENT_CONCURRENCY)" in main
    assert "asyncio.gather(" in main


def test_successful_report_marks_incident_investigated():
    tools = source("backend/app/tools.py")
    assert "'status': 'investigated'" in tools
