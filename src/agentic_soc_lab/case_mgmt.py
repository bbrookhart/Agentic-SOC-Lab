from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import json

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def ensure_case_file(case_path: str, title: str, severity: str, session_id: str, trace_id: str) -> None:
    p = Path(case_path)
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"# Case: {title}\n"
        f"**Date opened:** {utc_now()}\n"
        f"**Severity:** {severity}\n"
        f"**Trace/Session:** {trace_id} / {session_id}\n"
        f"**Status:** Open\n\n"
        "## Summary\n"
        "- \n\n"
        "## Timeline (UTC)\n"
        "- \n\n"
        "## Findings\n"
        "- Root cause:\n- Impact:\n- Indicators:\n\n"
        "## Actions taken\n"
        "- Containment:\n- Remediation:\n- Evidence preserved:\n\n"
        "## Lessons learned / control changes\n"
        "- Detection updates:\n- Policy/control updates:\n- Tests added:\n",
        encoding="utf-8",
    )

def append_case_update(case_path: str, alerts: List[Dict[str, Any]], notes: List[str] | None = None) -> None:
    p = Path(case_path)
    if not p.exists():
        raise FileNotFoundError(case_path)
    notes = notes or []
    ts = utc_now()
    block = "\n\n---\n" + f"## Triage Update ({ts})\n"
    block += f"Observed **{len(alerts)}** alert(s):\n"
    for a in alerts:
        ctx = json.dumps(a.get("context", {}), sort_keys=True)
        block += f"- **{a['rule_id']}** ({a['severity']}): {a['msg']} — `{ctx}`\n"
    if notes:
        block += "\nNotes:\n"
        for n in notes:
            block += f"- {n}\n"
    p.write_text(p.read_text(encoding="utf-8") + block, encoding="utf-8")
