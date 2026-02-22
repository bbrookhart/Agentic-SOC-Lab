import json
from pathlib import Path
from agentic_soc_lab.export import to_splunk_hec_event

def test_splunk_hec_shape():
    evt = {"ts":"2026-01-01T00:00:00Z","event_type":"ALERT"}
    hec = to_splunk_hec_event(evt, "agentic_soc", "agentic:soc:json", "host")
    assert "event" in hec and hec["event"]["event_type"] == "ALERT"
    assert hec["index"] == "agentic_soc"
