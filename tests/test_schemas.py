import json
from pathlib import Path

from agentic_soc_lab.schemas import validate_base
from conftest import ensure_fixtures  # <-- same approach

NORMAL = Path("data/sample_logs/session_normal.jsonl")
MAL = Path("data/sample_logs/session_malicious.jsonl")


def test_sample_logs_have_valid_base_schema():
    ensure_fixtures()
    for p in [NORMAL, MAL]:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                evt = json.loads(line)
                validate_base(evt)
