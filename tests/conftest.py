import json
from pathlib import Path

from agentic_soc_lab.events import JsonlWriter
from agentic_soc_lab.simulate import emit_session

NORMAL = Path("data/sample_logs/session_normal.jsonl")
MAL = Path("data/sample_logs/session_malicious.jsonl")


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
