# DCR Mapping Notes (Agentic SOC Lab)

This repo exports agent telemetry into an ingestion-friendly NDJSON format intended for a Log Analytics custom table.

- Analytics rules: sentinel/analytics-rules/

- Analytics KQL: sentinel/kql/analytics/

- Hunting KQL: sentinel/kql/hunting/

- DCR mapping notes: sentinel/dcr/README.md

## Target table
- Suggested custom table name: `AgenticSocLab_CL`

## Timestamp
- Record timestamp field: `EventTime` (ISO8601)
- In a DCR mapping, map `EventTime` to the table’s time column (or configure time generated accordingly).

## Core columns and types (recommended)
- `EventTime` (datetime/string → datetime)
- `EventType` (string)
- `RuleId` (string, nullable)
- `Severity` (string, nullable)
- `TraceId` (string)
- `SessionId` (string)
- `Tenant` (string)
- `Environment` (string)
- `ActorId` (string)
- `ActorKind` (string)
- `RawEvent` (dynamic)

## Why this shape
- Top-level columns make KQL fast and readable for SOC triage.
- `RawEvent` preserves full fidelity for forensics (tool args, retrieval query, policy reason).

## Source of truth
- Exporter: `src/agentic_soc_lab/sentinel_export.py`
- Output artifacts: `exports/sentinel/events.ndjson` and `exports/sentinel/alerts.ndjson`

## Operational tuning
- Consider redaction of sensitive fields before ingesting into production environments.
- Restrict retention and access controls for `RawEvent` if it may contain secrets/PII.
