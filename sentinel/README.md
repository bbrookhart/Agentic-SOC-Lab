# Microsoft Sentinel Package (Agentic SOC Lab)

This folder contains Microsoft Sentinel artifacts aligned to the **Agentic SOC Lab** telemetry model and detections (**D001–D004**). The goal is to demonstrate how agentic AI security detections can be **operationalized** in Sentinel—without requiring a live Azure workspace.

## What’s included
- `sentinel/analytics-rules/`  
  One Analytics Rule YAML per lab detection:
  - **D001** Tool loop / repeated tool calls
  - **D002** Cross-tenant retrieval attempt
  - **D003** Sensitive data egress via external tool
  - **D004** Deny-then-exfil escalation chain

- `dashboards/sentinel_kql.md`  
  A KQL triage pack: alert queue, pivots, timelines, and escalation correlation.

## Assumptions (data model)
The lab exporter `agentic_soc_lab.sentinel_export` normalizes JSONL into a Log Analytics–friendly shape intended for a custom table:

- **Table name (default):** `AgenticSocLab_CL`
- **Timestamp field inside record:** `EventTime` (ISO8601 string)
- **Core columns (top-level):**
  - `EventTime`, `EventType`
  - `RuleId`, `Severity` (primarily populated for ALERT events)
  - `TraceId`, `SessionId`
  - `Tenant`, `Environment`
  - `ActorId`, `ActorKind`
  - `RawEvent` (dynamic JSON with full original fidelity)
  - optional integrity columns: `IntegrityHash`, `IntegrityPrev`

> Why `RawEvent` matters: it preserves the full nested structure (`tool_call`, `retrieval`, `policy`) while keeping common pivots as first-class columns.

### EventType values
The lab emits (and exporters preserve) these event types:
- `AUTHN`
- `TOOL_CALL`
- `RETRIEVAL`
- `POLICY_DECISION`
- `ALERT`
- `CASE_NOTE`

The Sentinel rules in `sentinel/analytics-rules/` primarily operate on:
- `TOOL_CALL` for outbound/exfil and tool loops
- `RETRIEVAL` for boundary violations
- `POLICY_DECISION` + `TOOL_CALL` correlation for escalation chains

## Exporting data (no Azure required)
Even without a workspace, you can generate ingestion-ready NDJSON and show the rule + query logic.

### Generate sessions and alerts
```bash
python -m agentic_soc_lab.simulate --scenario data/scenarios/malicious_session.json --out data/sample_logs/session_malicious.jsonl
python -m agentic_soc_lab.detect --in data/sample_logs/session_malicious.jsonl --out data/sample_logs/alerts.jsonl

## Export into Sentinel custom-table shape

python -m agentic_soc_lab.sentinel_export --in data/sample_logs/session_malicious.jsonl --out exports/sentinel/events.ndjson --table AgenticSocLab_CL
python -m agentic_soc_lab.sentinel_export --in data/sample_logs/alerts.jsonl --out exports/sentinel/alerts.ndjson --table AgenticSocLab_CL

Artifacts:

- exports/sentinel/events.ndjson

- exports/sentinel/alerts.ndjson

## How to tune the analytics rules (SOC realism)

These rules are intentionally conservative and parameterized in KQL. In a real environment, you should tune:

# D001 (Tool loop)

- Threshold: ToolLoopThreshold (default: 5 calls)

- Lookback: ToolLoopLookback (default: 1 hour)

- Consider excluding known “chatty” tools or adding allowlisted targets/domains.

# D002 (Cross-tenant retrieval)

- Treat as high severity by default.

- Consider adding suppression if you expect legitimate cross-tenant service accounts (rare; heavily controlled).

# D003 (Sensitive egress)

- Update SensitivePatterns with your environment’s indicators:

 - cloud access keys (AWS/Azure/GCP)

 - internal token prefixes

 - known secret formats (e.g., ghp_ for GitHub PATs)

- Expand ExternalTools if you add more connectors.

- Consider scoping to Target domains that are not on an allowlist.

# D004 (Deny → exfil)

- Adjust the join window (OutTime <= DenyTime + 30m) based on your expected agent workflows.

- Tighten DenyRulePrefixes to the exact boundary rules used in your policy engine.

- Add additional correlation steps (e.g., multiple denies before exfil) to raise confidence.

## Entity mapping guidance (to generate incidents with useful context)

The rules map ActorId to the Account entity:

- entityType: Account

- identifier: Name

- columnName: ActorId

If you later represent the actor as a UPN/email, update to map:

AccountUPN or Name accordingly

optionally map a Host entity if you add workstation or container IDs

## Incident grouping strategy (why it’s configured this way)

Rules group incidents by:

- SessionId

- TraceId

Agentic workflows often involve many events per session. Grouping keeps the SOC queue manageable while still preserving investigative fidelity.

## Operational workflow (what a SOC analyst would do)

1. Start with alerts (High/Critical queue)

2. Pivot to the session timeline (by SessionId / TraceId)

3. Validate boundary failure (requested tenant vs session tenant)

4. Review outbound tools used (web/email/webhook targets and args)

5. Contain: disable external connectors, tighten allowlists, rotate secrets

6. Preserve evidence: logs, alerts, hashes + manifest (evidence_pack)

7. Improve controls: add policy rules + detection regression tests

## Importing into Sentinel (optional / future)

If you choose to operationalize in a real workspace:

- Create a custom table (or DCR mapping) for AgenticSocLab_CL

- Use Logs Ingestion API / DCR to ingest NDJSON records

- Import analytics rules from sentinel/analytics-rules/ (format may require minor adjustments depending on Sentinel tooling)

This repo is designed so that even without Azure access, your portfolio still proves: data model + detection logic + KQL + incident workflow.

File index

- sentinel/analytics-rules/D001_tool_loop.yaml

- sentinel/analytics-rules/D002_cross_tenant_retrieval.yaml

- sentinel/analytics-rules/D003_sensitive_egress.yaml

- sentinel/analytics-rules/D004_deny_then_exfil.yaml

- dashboards/sentinel_kql.md

