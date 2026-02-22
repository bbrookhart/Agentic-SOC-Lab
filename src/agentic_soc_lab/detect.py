from __future__ import annotations
import argparse, json, re
from typing import Any, Dict, List
import yaml

def load_rules(paths: List[str]) -> List[Dict[str, Any]]:
    rules = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            rules.append(yaml.safe_load(f))
    return rules

def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def regex_any(patterns: List[str], text: str) -> bool:
    for pat in patterns:
        if re.search(pat, text, flags=re.IGNORECASE):
            return True
    return False

def detect(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    # simple rolling window per session
    by_session: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        by_session.setdefault(e["session_id"], []).append(e)

    for session_id, evs in by_session.items():
        for r in rules:
            rid = r["id"]
            if rid == "D001":
                # tool loop: same tool >= threshold in last N tool_calls
                tool = r["match"]["tool"]
                threshold = r["match"]["threshold"]
                window = r["match"]["window"]
                tool_calls = [x for x in evs if x["event_type"] == "TOOL_CALL" and x.get("tool_call",{}).get("tool")==tool]
                if len(tool_calls) >= threshold:
                    # approximate window check by last N occurrences
                    if len(tool_calls[-window:]) >= threshold:
                        alerts.append({
                            "event_type":"ALERT",
                            "rule_id":rid,
                            "severity":r["severity"],
                            "session_id":session_id,
                            "trace_id": evs[-1]["trace_id"],
                            "msg": r["title"],
                            "context":{"tool":tool, "count":len(tool_calls[-window:])}
                        })
            elif rid == "D002":
                # retrieval scope mismatch
                for x in evs:
                    if x["event_type"] == "RETRIEVAL":
                        tenant = x["tenant"]
                        req_tenant = x["retrieval"].get("requested_tenant", tenant)
                        if req_tenant != tenant:
                            alerts.append({
                                "event_type":"ALERT",
                                "rule_id":rid,
                                "severity":r["severity"],
                                "session_id":session_id,
                                "trace_id": x["trace_id"],
                                "msg": r["title"],
                                "context":{"tenant":tenant,"requested_tenant":req_tenant,"resource":x["retrieval"].get("resource")}
                            })
                            break
            elif rid == "D003":
                # sensitive egress: secrets in TOOL_CALL args/results to external tool
                external_tools = r["match"]["external_tools"]
                patterns = r["match"]["patterns"]
                for x in evs:
                    if x["event_type"] == "TOOL_CALL":
                        tc = x.get("tool_call",{})
                        if tc.get("tool") in external_tools:
                            blob = json.dumps(tc, sort_keys=True)
                            if regex_any(patterns, blob):
                                alerts.append({
                                    "event_type":"ALERT",
                                    "rule_id":rid,
                                    "severity":r["severity"],
                                    "session_id":session_id,
                                    "trace_id": x["trace_id"],
                                    "msg": r["title"],
                                    "context":{"tool":tc.get("tool"),"target":tc.get("target")}
                                })
                                break
            else:
                continue
    return alerts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input JSONL")
    ap.add_argument("--out", required=True, help="Output alerts JSONL")
    ap.add_argument("--rules", nargs="*", default=[
        "detections/D001_tool_loop.yml",
        "detections/D002_retrieval_scope_violation.yml",
        "detections/D003_sensitive_egress.yml",
    ])
    args = ap.parse_args()

    events = read_jsonl(args.inp)
    rules = load_rules(args.rules)
    alerts = detect(events, rules)

    open(args.out, "w", encoding="utf-8").close()
    with open(args.out, "a", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a, separators=(",",":")) + "\n")

    print(f"Alerts: {len(alerts)} written to {args.out}")
    for a in alerts:
        print(f"[{a['severity']}] {a['rule_id']} {a['msg']} ctx={a['context']}")

if __name__ == "__main__":
    main()
