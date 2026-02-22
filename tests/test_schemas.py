import json
from agentic_soc_lab.schemas import validate_base

def test_sample_logs_have_valid_base_schema():
    for p in [
        "data/sample_logs/session_normal.jsonl",
        "data/sample_logs/session_malicious.jsonl",
    ]:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                evt = json.loads(line)
                # validate_base expects base keys at top-level; sample logs include integrity too (ok)
                validate_base(evt)
