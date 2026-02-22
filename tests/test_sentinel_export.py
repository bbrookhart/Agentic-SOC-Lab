from agentic_soc_lab.sentinel_export import normalize_for_log_analytics

def test_normalize_for_log_analytics_shape():
    evt = {
        "ts": "2026-01-01T00:00:00Z",
        "event_type": "ALERT",
        "rule_id": "D003",
        "severity": "critical",
        "trace_id": "t",
        "session_id": "s",
        "tenant": "tenant_a",
        "env": "lab",
        "actor": {"id": "user:demo", "kind": "user"},
        "integrity": {"hash": "h", "prev": "p"},
    }
    rec = normalize_for_log_analytics(evt)
    assert rec["EventType"] == "ALERT"
    assert rec["RuleId"] == "D003"
    assert rec["RawEvent"]["event_type"] == "ALERT"
