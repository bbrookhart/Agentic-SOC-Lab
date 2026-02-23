# Microsoft Sentinel Package (Agentic SOC Lab)

This folder contains Microsoft Sentinel artifacts aligned to the **Agentic SOC Lab** telemetry model and detections (**D001–D004**). The goal is to demonstrate how agentic AI security detections can be **operationalized** in Sentinel—without requiring a live Azure workspace.

## Contents
- **Analytics rules (YAML):** `sentinel/analytics-rules/`  
  Sentinel Analytics Rule YAMLs aligned to lab detections:
  - `D001_tool_loop.yaml`
  - `D002_cross_tenant_retrieval.yaml`
  - `D003_sensitive_egress.yaml`
  - `D004_deny_then_exfil.yaml`

- **Analytics KQL (rule queries):** `sentinel/kql/analytics/`  
  KQL used by the Analytics Rules (one file per detection):
  - `D001_tool_loop.kql`
  - `D002_cross_tenant_retrieval.kql`
  - `D003_sensitive_egress.kql`
  - `D004_deny_then_exfil.kql`

- **Hunting KQL (investigation pivots):** `sentinel/kql/hunting/`  
  SOC pivot queries and timelines:
  - `H001_alert_queue.kql`
  - `H002_session_timeline.kql`
  - `H003_outbound_connectors.kql`
  - `H004_boundary_violation_pivot.kql`

- **DCR mapping notes:** `sentinel/dcr/README.md`  
  Guidance on mapping exported NDJSON into a Log Analytics custom table (schema + timestamp + types).

- **Additional triage pack:** `dashboards/sentinel_kql.md`  
  A consolidated KQL pack used for demos and quick reference (kept for convenience).

---

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

---

## Exporting data (no Azure required)
Even without a workspace, you can generate ingestion-ready NDJSON and show the rule + query logic.

### Generate sessions and alerts
```bash
python -m agentic_soc_lab.simulate --scenario data/scenarios/malicious_session.json --out data/sample_logs/session_malicious.jsonl
python -m agentic_soc_lab.detect --in data/sample_logs/session_malicious.jsonl --out data/sample_logs/alerts.jsonl

Artifacts:

- exports/sentinel/events.ndjson

- exports/sentinel/alerts.ndjson

## How to use the Sentinel content (operational workflow)
# 1) Deploy/Import (conceptual)

- In a real workspace, you would:

 - create a custom table (or DCR mapping) for AgenticSocLab_CL

 - ingest events.ndjson and alerts.ndjson via Logs Ingestion API / DCR

 - import analytics rules from sentinel/analytics-rules/ (tooling may require minor normalization)

# 2) SOC triage (KQL-driven)

Use sentinel/kql/hunting/ as the SOC pivot set:

1. Alert queue: H001_alert_queue.kql

2. Session timeline pivot: H002_session_timeline.kql (paste SessionId)

3. Outbound connectors: H003_outbound_connectors.kql

4. Boundary pivot: H004_boundary_violation_pivot.kql

# 3) Analytics rules (detections)

The sentinel/kql/analytics/ queries correspond 1:1 to the YAML rules in sentinel/analytics-rules/.
Treat these as your detection “source of truth” for:

- thresholds (D001)

- boundary checks (D002)

- sensitive pattern matching (D003)

- deny→exfil correlation window (D004)

## Tuning guidance (SOC realism)
# D001 (Tool loop)

- Adjust threshold and lookback to reduce false positives.

- Consider excluding known “chatty” tools or allowlisting safe targets.

# D002 (Cross-tenant retrieval)

- Usually high severity. Suppression should be rare and heavily justified.

# D003 (Sensitive egress)

- Expand indicator patterns based on your environment (cloud keys, token formats, internal secret prefixes).

- Restrict outbound tools and/or enforce allowlists on targets/domains.

# D004 (Deny → exfil)

- Tighten boundary rule prefixes to your policy engine’s real identifiers.

- Adjust correlation time window based on normal agent behavior.

# Entity mapping guidance

Rules map ActorId to the Account entity:

- entityType: Account

- identifier: Name

- columnName: ActorId

If ActorId becomes a UPN/email later, update entity mappings accordingly.

# DCR mapping notes

See sentinel/dcr/README.md for:

 - recommended schema types

 - timestamp handling (EventTime)

 - why RawEvent is retained

 - operational considerations (redaction/access/retention)

# File index

- sentinel/analytics-rules/D001_tool_loop.yaml

- sentinel/analytics-rules/D002_cross_tenant_retrieval.yaml

- sentinel/analytics-rules/D003_sensitive_egress.yaml

- sentinel/analytics-rules/D004_deny_then_exfil.yaml

- sentinel/kql/analytics/D001_tool_loop.kql

- sentinel/kql/analytics/D002_cross_tenant_retrieval.kql

- sentinel/kql/analytics/D003_sensitive_egress.kql

- sentinel/kql/analytics/D004_deny_then_exfil.kql

- sentinel/kql/hunting/H001_alert_queue.kql

- sentinel/kql/hunting/H002_session_timeline.kql

- sentinel/kql/hunting/H003_outbound_connectors.kql

- sentinel/kql/hunting/H004_boundary_violation_pivot.kql

- sentinel/dcr/README.md

- dashboards/sentinel_kql.md
