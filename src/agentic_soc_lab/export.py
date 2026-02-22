from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def to_splunk_hec_event(evt: Dict[str, Any], index: str, sourcetype: str, host: str) -> Dict[str, Any]:
    # Splunk HEC expects fields: time, host, source/sourcetype, index, event
    # We keep "event" as the full object so it remains searchable
    ts = evt.get("ts")
    # Splunk "time" is typically epoch; keep string timestamp inside event for simplicity
    return {
        "time": None,
        "host": host,
        "index": index,
        "sourcetype": sourcetype,
        "event": evt,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input JSONL (events or alerts)")
    ap.add_argument("--out", required=True, help="Output file (Splunk HEC JSON lines)")
    ap.add_argument("--index", default="agentic_soc")
    ap.add_argument("--sourcetype", default="agentic:soc:json")
    ap.add_argument("--host", default="agentic-soc-lab")
    args = ap.parse_args()

    items = read_jsonl(args.inp)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for evt in items:
            f.write(json.dumps(to_splunk_hec_event(evt, args.index, args.sourcetype, args.host)) + "\n")

    print(f"Wrote {len(items)} HEC events to {out_path}")


if __name__ == "__main__":
    main()
