from __future__ import annotations
import argparse, json, uuid
from typing import Any, Dict, List
from .events import JsonlWriter, base_event

def emit_session(writer: JsonlWriter, scenario: Dict[str, Any]) -> None:
    trace_id = scenario.get("trace_id") or str(uuid.uuid4())
    session_id = scenario.get("session_id") or str(uuid.uuid4())
    tenant = scenario["tenant"]
    env = scenario.get("env","lab")
    actor = scenario.get("actor", {"id":"user:demo","kind":"user"})

    # AUTHN
    evt = base_event("AUTHN", trace_id, session_id, tenant, env, actor["id"], actor["kind"])
    evt["authn"] = {"method": scenario.get("authn_method","password"), "mfa": scenario.get("mfa", False)}
    writer.write(evt)

    for step in scenario["steps"]:
        et = step["event_type"]
        evt = base_event(et, trace_id, session_id, tenant, env, actor["id"], actor["kind"])

        if et == "TOOL_CALL":
            evt["tool_call"] = {
                "tool": step["tool"],
                "args": step.get("args", {}),
                "target": step.get("target"),
                "result": step.get("result", {"status":"ok"}),
            }
        elif et == "RETRIEVAL":
            evt["retrieval"] = {
                "resource": step["resource"],
                "requested_tenant": step.get("requested_tenant", tenant),
                "scope": step.get("scope","default"),
                "query": step.get("query",""),
                "records": step.get("records", 0),
            }
        elif et == "POLICY_DECISION":
            evt["policy"] = {
                "decision": step["decision"],
                "policy_id": step.get("policy_id","policy:default"),
                "rule_id": step.get("rule_id","rule:unknown"),
                "reason": step.get("reason",""),
            }
        else:
            raise ValueError(f"unsupported event_type in scenario steps: {et}")

        writer.write(evt)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, help="Path to scenario JSON")
    ap.add_argument("--out", required=True, help="Output JSONL path")
    args = ap.parse_args()

    with open(args.scenario, "r", encoding="utf-8") as f:
        scenario = json.load(f)

    # truncate output
    open(args.out, "w", encoding="utf-8").close()
    writer = JsonlWriter(args.out)
    emit_session(writer, scenario)
    print(f"Wrote events to {args.out}")

if __name__ == "__main__":
    main()
