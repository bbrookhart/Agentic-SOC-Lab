from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def normalize_for_log_analytics(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log Analytics likes a flat-ish shape. We'll keep the original object in RawEvent
    and promote the fields you query constantly into top-level columns.
    """
    actor = evt.get("actor") or {}
    integrity = evt.get("integrity") or {}

    return {
        # Recommended time field (Sentinel typically uses TimeGenerated automatically)
        "EventTime": evt.get("ts"),
        "EventType": evt.get("event_type"),
        "RuleId": evt.get("rule_id"),
        "Severity": evt.get("severity"),
        "TraceId": evt.get("trace_id"),
        "SessionId": evt.get("session_id"),
        "Tenant": evt.get("tenant"),
        "Environment": evt.get("env"),
        "ActorId": actor.get("id"),
        "ActorKind": actor.get("kind"),
        "IntegrityHash": integrity.get("hash"),
        "IntegrityPrev": integrity.get("prev"),
        # Keep full fidelity
        "RawEvent": evt,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input JSONL (events or alerts)")
    ap.add_argument("--out", required=True, help="Output NDJSON (one normalized record per line)")
    ap.add_argument("--table", default="AgenticSocLab_CL", help="Target custom table name convention (for docs/README)")
    args = ap.parse_args()

    items = read_jsonl(args.inp)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for evt in items:
            rec = normalize_for_log_analytics(evt)
            rec["TargetTable"] = args.table  # metadata for humans; not required by ingestion
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    print(f"Wrote {len(items)} records to {out_path} (table hint: {args.table})")


if __name__ == "__main__":
    main()
