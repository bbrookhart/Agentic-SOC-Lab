import json
from agentic_soc_lab.detect import detect, load_rules

def read_jsonl(path: str):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def test_malicious_triggers_expected_alerts():
    rules = load_rules([
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
    ])
    events = read_jsonl("data/sample_logs/session_malicious.jsonl")
    alerts = detect(events, rules)
    fired = {a["rule_id"] for a in alerts}
    assert "D002" in fired
    assert "D003" in fired
    assert "D001" in fired  # tool loop should fire in malicious scenario

def test_normal_does_not_trigger_high_or_critical():
    rules = load_rules([
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
    ])
    events = read_jsonl("data/sample_logs/session_normal.jsonl")
    alerts = detect(events, rules)
    # Allow zero alerts or only low/medium if you later add benign heuristics
    severities = {a["severity"] for a in alerts}
    assert "high" not in severities
    assert "critical" not in severities
