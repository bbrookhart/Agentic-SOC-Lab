from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional
import re
from datetime import datetime, timezone

EventType = Literal["AUTHN","TOOL_CALL","RETRIEVAL","POLICY_DECISION","ALERT","CASE_NOTE"]

ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValueError(msg)

def validate_base(evt: Dict[str, Any]) -> None:
    require("ts" in evt and isinstance(evt["ts"], str), "missing ts")
    require(ISO8601_RE.match(evt["ts"]) is not None, "ts must be ISO8601 Z")
    for k in ("event_type","trace_id","session_id","tenant","env","actor"):
        require(k in evt, f"missing {k}")
    require(evt["event_type"] in ("AUTHN","TOOL_CALL","RETRIEVAL","POLICY_DECISION","ALERT","CASE_NOTE"), "bad event_type")
    require(isinstance(evt["actor"], dict), "actor must be object")
    require("id" in evt["actor"] and "kind" in evt["actor"], "actor missing id/kind")
