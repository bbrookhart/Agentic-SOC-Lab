from __future__ import annotations
import argparse, json
from datetime import datetime

def read_jsonl(path: str):
    out=[]
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if line:
                out.append(json.loads(line))
    return out

def append_case(case_path: str, alerts):
    ts = datetime.utcnow().isoformat() + "Z"
    with open(case_path, "a", encoding="utf-8") as f:
        f.write("\n\n---\n")
        f.write(f"## Triage Update ({ts})\n")
        f.write(f"Observed {len(alerts)} alert(s):\n")
        for a in alerts:
            f.write(f"- **{a['rule_id']}** ({a['severity']}): {a['msg']} — `{json.dumps(a['context'])}`\n")
        f.write("\nInitial actions:\n")
        f.write("- Validate tenant/scope boundaries\n- Review tool call history\n- Contain: disable external tool connectors if needed\n- Preserve evidence: retain JSONL logs + hashes\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--case", required=True)
    args = ap.parse_args()

    alerts = read_jsonl(args.alerts)
    append_case(args.case, alerts)
    print(f"Appended triage notes to {args.case}")

if __name__ == "__main__":
    main()
