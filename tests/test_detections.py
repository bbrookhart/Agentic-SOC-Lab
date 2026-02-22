import json
from pathlib import Path
from agentic_soc_lab.detect import detect, load_rules
from agentic_soc_lab.simulate import emit_session
from agentic_soc_lab.events import JsonlWriter

NORMAL = Path("data/sample_logs/session_normal.jsonl")
MAL = Path("data/sample_logs/session_malicious.jsonl")

def read_jsonl(path: Path):
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def ensure_fixtures():
    NORMAL.parent.mkdir(parents=True, exist_ok=True)

    if not NORMAL.exists():
        with open("data/scenarios/normal_session.json", "r", encoding="utf-8") as f:
            scenario = json.load(f)
        NORMAL.write_text("", encoding="utf-8")
        writer = JsonlWriter(str(NORMAL))
        emit_session(writer, scenario)

    if not MAL.exists():
        with open("data/scenarios/malicious_session.json", "r", encoding="utf-8") as f:
            scenario = json.load(f)
        MAL.write_text("", encoding="utf-8")
        writer = JsonlWriter(str(MAL))
        emit_session(writer, scenario)

def test_malicious_triggers_expected_alerts():
    ensure_fixtures()
    rules = load_rules([
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
    ])
    events = read_jsonl(MAL)
    alerts = detect(events, rules)
    fired = {a["rule_id"] for a in alerts}
    assert "D002" in fired
    assert "D003" in fired
    assert "D001" in fired

def test_normal_does_not_trigger_high_or_critical():
    ensure_fixtures()
    rules = load_rules([
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
    ])
    events = read_jsonl(NORMAL)
    alerts = detect(events, rules)
    severities = {a["severity"] for a in alerts}
    assert "high" not in severities
    assert "critical" not in severities
