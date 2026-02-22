import json
from pathlib import Path
from agentic_soc_lab.schemas import validate_base
from tests.test_detections import ensure_fixtures, NORMAL, MAL  # reuse fixture builder

def test_sample_logs_have_valid_base_schema():
    ensure_fixtures()
    for p in [NORMAL, MAL]:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                evt = json.loads(line)
                validate_base(evt)
