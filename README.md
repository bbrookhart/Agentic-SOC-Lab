# Agentic SOC Lab (In Progress)
**Detection + triage for LLM/agent tool abuse with audit-ready telemetry — including a Microsoft Sentinel (Log Analytics) workflow.**

This repository is a **hands-on SOC lab** focused on **agentic AI security**. It simulates an “agent” that can **retrieve data** and **call tools**, emits **structured security telemetry (JSONL)**, runs **detections** to produce alerts, and supports **SOC-style triage artifacts** (case notes, playbooks) plus an **evidence pack**.

This is intentionally built to be **recruiter-readable** and **interview-demoable**:
- SOC fundamentals: logging, detections, triage, escalation chains
- Agentic AI threats: prompt injection, tool abuse, retrieval boundary failures, exfil
- Ethical GRC signal: evidence lifecycle, integrity thinking, repeatable artifacts
- Microsoft Sentinel: **custom table shape + KQL pack**, even without a live workspace

---

## What this repo demonstrates

### Technical (SOC + engineering)
- **Detection-ready telemetry design** (consistent schema + correlation keys)
- **Detection engineering** (rule-driven detections + regression tests)
- **Incident workflow** (alerts → case notes → containment guidance)
- **Evidence mindset** (hashes + manifest for defensible artifacts)

### Security domain (agentic AI)
- **Tool abuse** (probing/loops, connector misuse)
- **RAG / retrieval boundary violations** (tenant/scope mismatch attempts)
- **Sensitive data egress** (secrets/PII leaving via outbound tools)
- **Escalation chains** (policy denied → outbound exfil attempt)

### SIEM workflow (Microsoft Sentinel)
- Export telemetry into a **Log Analytics custom table**-friendly record shape
- Provide a **KQL triage pack** to drive SOC investigation and timelines

---


---

## Threat model

### System model
A user interacts with an **agent** that can:
- call tools (e.g., `web_request`, `email_send`, `webhook_post`)
- retrieve information (RAG/KB/database connectors)
- receive policy decisions (allow/deny)

### Adversary goals
1. **Data exfiltration** via outbound tools  
2. **Boundary violations** (cross-tenant / cross-scope access)  
3. **Policy probing** (tool loops, retries to discover allowed behavior)  
4. **Escalation chains** (deny → attempt exfil)

### Security outcomes this lab targets
- detect abuse via telemetry correlation
- contain/limit blast radius using policy + connector controls
- preserve evidence for investigation and audit review

---

## Telemetry model (JSONL)

Each line is a single event with shared base fields:
- `ts` (UTC ISO8601)
- `event_type` ∈ `AUTHN | TOOL_CALL | RETRIEVAL | POLICY_DECISION | ALERT | CASE_NOTE`
- `trace_id`, `session_id`
- `tenant`, `env`
- `actor` (id + kind)
- `integrity` (v1 hash chain)

Event-specific payloads:
- `tool_call`: tool name, args, target, result metadata
- `retrieval`: resource, requested tenant, scope, query, records
- `policy`: decision, policy_id, rule_id, reason

This mirrors how SOC teams structure logs for correlation in a SIEM.

---

## Detections (v1)

### D001 — Tool loop / repeated tool calls (**medium**)
**Catches:** rapid repeated calls to the same tool  
**Why:** probing, stuck agent behavior, or automation abuse  
**Signal:** N calls to same tool within a rolling window

### D002 — Retrieval tenant/scope mismatch attempt (**high**)
**Catches:** retrieval requests where requested tenant differs from session tenant  
**Why:** cross-tenant access is a top-tier confidentiality failure  
**Signal:** `retrieval.requested_tenant != event.tenant`

### D003 — Sensitive data egress via external tool (**critical**)
**Catches:** secrets/PII patterns sent to outbound connectors  
**Why:** common exfil pattern when agents have external tools  
**Signal:** regex matches (AWS keys, private key blocks, SSNs, token prefixes) in tool call args/results

### D004 — Deny-then-exfil escalation chain (**critical**)
**Catches:** boundary-related policy denial followed by outbound tool activity with sensitive indicators  
**Why:** indicates escalation after controls blocked the initial attempt  
**Signal:** `POLICY_DECISION deny` (boundary rule prefix) → outbound tool call matching sensitive patterns

---

## Quickstart

### 1) Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .

## 2) Generate normal + malicious sessions

python -m agentic_soc_lab.simulate \
  --scenario data/scenarios/normal_session.json \
  --out data/sample_logs/session_normal.jsonl

python -m agentic_soc_lab.simulate \
  --scenario data/scenarios/malicious_session.json \
  --out data/sample_logs/session_malicious.jsonl

## 3) Run detections
python -m agentic_soc_lab.detect \
  --in data/sample_logs/session_malicious.jsonl \
  --out data/sample_logs/alerts.jsonl

Expected console output examples:

- [high] D002 Retrieval tenant/scope mismatch attempt …

- [critical] D003 Sensitive data egress via external tool …

- [critical] D004 Deny-then-exfil escalation chain …

- [medium] D001 Tool loop / repeated tool calls …

## 4) SOC triage: append alerts to a case file

python -m agentic_soc_lab.triage \
  --alerts data/sample_logs/alerts.jsonl \
  --case cases/CASE_AUTO.md

## Quality gates (CI)

This repo runs pytest on every push/PR. Tests cover:

- base event schema validation

- detections firing for malicious fixtures

- normal scenario not producing high/critical alerts

- Sentinel export record shape validation

Run locally:
pytest -q

## Evidence pack (audit-ready artifacts)

- Generate a deterministic evidence bundle containing:

- session logs (JSONL)

- alerts (JSONL)

- hashes.txt (SHA256)

- manifest.json

python -m agentic_soc_lab.evidence_pack \
  --logs data/sample_logs/session_malicious.jsonl \
  --alerts data/sample_logs/alerts.jsonl \
  --outdir evidence/sample_evidence_pack

## Microsoft Sentinel walkthrough (works even without a live workspace)

Sentinel queries data in Log Analytics. Typical onboarding uses a custom table (often with an _CL suffix). This repo supports a Sentinel-style workflow without requiring Azure access by providing:

1. an exporter that normalizes telemetry into a Log Analytics–friendly record shape

2. a KQL triage pack assuming your custom table is named AgenticSocLab_CL

## A) Export logs/alerts into Sentinel (Log Analytics) custom table shape

python -m agentic_soc_lab.sentinel_export \
  --in data/sample_logs/session_malicious.jsonl \
  --out exports/sentinel/events.ndjson \
  --table AgenticSocLab_CL

python -m agentic_soc_lab.sentinel_export \
  --in data/sample_logs/alerts.jsonl \
  --out exports/sentinel/alerts.ndjson \
  --table AgenticSocLab_CL

## What you get

- exports/sentinel/events.ndjson — normalized records (one per line)

- exports/sentinel/alerts.ndjson — alerts in the same record shape

##Normalized columns (examples)

- EventTime, EventType, RuleId, Severity

- TraceId, SessionId, Tenant, ActorId

- RawEvent (dynamic) retains full fidelity (tool args, retrieval details, policy reason)

In a real Sentinel deployment, you’d configure a Data Collection Rule (DCR) + Logs Ingestion API to map these fields into a custom table. This repo focuses on the parts that prove SOC readiness: the data model and the KQL.

## B) KQL triage pack (SOC view)

Open:

- dashboards/sentinel_kql.md

It includes:

- alert queue (high/critical)

- cross-tenant retrieval attempts

- outbound tools (exfil paths)

- tool-loop/probing behavior

- deny→external activity correlation

- per-session timeline reconstruction

## C) Example SOC investigation flow (KQL-driven)

1. Start with high/critical alerts

2. Pivot to the session timeline for the flagged session

3. Confirm boundary violation (requested tenant vs session tenant)

4. Review outbound tools used (web/email/webhook)

5. Document actions and preserve an evidence pack

## SOC artifacts: playbooks and case files

- playbooks/ contains IR runbooks for key agentic AI threats:

 - prompt injection

 - tool abuse

 - data exfiltration

 - retrieval boundary violations

- cases/ contains narrative case files showing incident documentation:

 - detection → triage → containment → remediation

These are designed to be interview-ready artifacts, not just “extra docs.”

## Evidence & integrity (v1)

Events include a basic hash chain (integrity.prev, integrity.hash) to demonstrate:

- evidence lifecycle thinking

- tamper-detection concepts

- audit-minded design

Note: This is not a full WORM ledger in v1. Future milestones can add signing, immutable storage targets, and manifest verification.

## Roadmap (next upgrades)

- Sentinel packaging: DCR schema + mapping templates (optional)

- KQL-based analytics rules aligned to detections

- Baselining + anomaly scoring vs normal sessions

- Expanded attack battery: indirect prompt injection via RAG + tool hijacking

- Hardening controls: tool schemas, strict allowlists, retrieval proofs, connector segmentation
