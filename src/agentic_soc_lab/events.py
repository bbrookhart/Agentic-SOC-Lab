from __future__ import annotations
from typing import Any, Dict, Optional
import json
import hashlib
from .schemas import now_utc_iso, validate_base

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class JsonlWriter:
    """
    Writes events as JSONL with a simple hash chain to demonstrate evidence thinking.
    Not a full tamper-proof ledger—v1 only.
    """
    def __init__(self, path: str):
        self.path = path
        self.prev_hash = "0"*64

    def write(self, evt: Dict[str, Any]) -> None:
        validate_base(evt)
        payload = json.dumps(evt, sort_keys=True, separators=(",",":")).encode("utf-8")
        h = sha256_hex((self.prev_hash + sha256_hex(payload)).encode("utf-8"))
        evt_out = dict(evt)
        evt_out["integrity"] = {"prev": self.prev_hash, "hash": h}
        line = json.dumps(evt_out, separators=(",",":"))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        self.prev_hash = h

def base_event(event_type: str, trace_id: str, session_id: str, tenant: str, env: str, actor_id: str, actor_kind: str) -> Dict[str, Any]:
    return {
        "ts": now_utc_iso(),
        "event_type": event_type,
        "trace_id": trace_id,
        "session_id": session_id,
        "tenant": tenant,
        "env": env,
        "actor": {"id": actor_id, "kind": actor_kind},
    }
