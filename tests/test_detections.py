import json
from pathlib import Path

from agentic_soc_lab.detect import detect, load_rules
from conftest import ensure_fixtures  # <-- this works in pytest collection

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


def test_malicious_triggers_expected_alerts():
    ensure_fixtures()
    rules = load_rules([
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
        "detections/D004_deny_then_exfil.yml",
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
        "detections/D004_deny_then_exfil.yml",
    ])
    events = read_jsonl(NORMAL)
    alerts = detect(events, rules)
    severities = {a["severity"] for a in alerts}
    assert "high" not in severities
    assert "critical" not in severities
