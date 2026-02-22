# Agentic SOC Lab
**Detection + triage for LLM/agent tool abuse with audit-ready telemetry.**

This repository is a **hands-on SOC lab** for modern **agentic AI security**. It simulates an “agent” that uses tools (web requests, retrieval, etc.), emits **structured security telemetry (JSONL)**, and runs a **detection pipeline** that produces actionable alerts and case notes.

If you’re hiring for **SOC / Security Analyst** roles (with a pivot to **ethical GRC**), this repo demonstrates that I can:
- design **detection-ready logging** for agent/tool systems
- write **detections** for real AI abuse patterns (exfil, boundary violations, tool abuse)
- perform **SOC-style triage** and preserve **evidence** for audit/forensics

---

## What you’ll see in this repo

### Core capabilities
- **Telemetry-first security design**  
  Every session produces JSONL events with consistent fields (trace/session IDs, tenant, actor, environment), enabling correlation like a real SOC pipeline.

- **Agentic AI threat scenarios**
  - Cross-tenant / cross-scope retrieval attempts (RAG boundary failure)
  - Tool loops / rapid retries (probing, stuck agent, abuse)
  - Sensitive data egress to external tools (exfiltration)

- **Detections + severity**
  Rules are stored as YAML and executed by a lightweight detection engine.

- **SOC triage artifacts**
  Alerts can be appended into a markdown case file so the repo contains “how I work an incident,” not just code.

- **Evidence mindset**
  JSONL events include a simple **hash chain** (v1) to show integrity thinking and evidence lifecycle patterns.

---


---

## Threat model (what this lab is defending against)

### System model
A user interacts with an **agent** that can:
- call tools (e.g., `web_request`, `email_send`, `webhook_post`)
- retrieve information (RAG or database connectors)
- receive policy decisions (allow/deny)

### Adversary goals
1. **Data exfiltration** via external tools  
2. **Boundary violations** (cross-tenant / cross-scope access)  
3. **Policy probing** (retries/loops to discover what’s allowed)  

### Security outcomes this lab targets
- Detect abuse via telemetry correlation
- Contain/limit blast radius using policy + connector controls
- Preserve evidence for investigation and audit review

---

## Event telemetry model (JSONL)

Each line is an event with shared base fields:
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
**What it catches:** rapid repeated calls to the same tool (e.g., `web_request`)  
**Why it matters:** indicates probing, stuck agent behavior, or automation abuse  
**Signal:** N calls to same tool within a rolling window

### D002 — Retrieval tenant/scope mismatch attempt (**high**)
**What it catches:** retrieval requests where the requested tenant differs from the session tenant  
**Why it matters:** cross-tenant access is a top-tier confidentiality failure  
**Signal:** `retrieval.requested_tenant != event.tenant`

### D003 — Sensitive data egress via external tool (**critical**)
**What it catches:** secrets/PII patterns being sent to external connectors  
**Why it matters:** common real-world exfil pattern for agents with tools  
**Signal:** regex matches (AWS keys, private key blocks, SSNs, token prefixes) in tool call args/results

---

## Quickstart (run the lab)

### 1) Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .

### 2) Generate normal + malicious sessions
python -m agentic_soc_lab.simulate \
  --scenario data/scenarios/normal_session.json \
  --out data/sample_logs/session_normal.jsonl

python -m agentic_soc_lab.simulate \
  --scenario data/scenarios/malicious_session.json \
  --out data/sample_logs/session_malicious.jsonl

### 3) Run detections against the malicious session

###You should see console output like:
[medium] D001 Tool loop / repeated tool calls …

[high] D002 Retrieval tenant/scope mismatch attempt …

[critical] D003 Sensitive data egress via external tool …


###4) Append alerts into a case file (SOC workflow)
python -m agentic_soc_lab.triage \
  --alerts data/sample_logs/alerts.jsonl \
  --case cases/CASE004_secret_egress.md

###How to interpret results (SOC lens)

When an alert fires, the next steps are:
- Confirm scope/tenant and verify the boundary violation intent

- Review tool call history (sequence, args, targets, external domains)

- Contain by disabling external connectors or tightening allowlists

- Preserve evidence (retain JSONL logs, hashes, relevant configs)

- Root cause and control improvements (policy + schemas + guardrails)

- This repo intentionally keeps outputs readable and case-oriented.

###Playbooks and cases
- playbooks/ contains incident response runbooks for key agentic AI threats:

- prompt injection

- tool abuse

- data exfiltration

- retrieval boundary violations

- cases/ contains narrative case files showing how incidents are documented:

- detection → triage → containment → remediation

- These are designed to be interview-ready artifacts.

###Evidence & integrity (v1)
- Events include a basic hash chain (integrity.prev, integrity.hash) to demonstrate:
- evidence lifecycle thinking
- tamper-detection concepts
- audit-minded design

Note: This is not a full WORM ledger in v1. Future milestones can add signing (KMS), immutable storage targets, and manifest verification.

###Roadmap (what I’m building next)

- Policy correlation: alerts reference related POLICY_DECISION denies and rule IDs

- Baselining: anomaly scoring against normal session behavior

- SIEM export: outputs in Splunk HEC / Elastic bulk formats

- Expanded attack battery: indirect prompt injection via RAG + tool hijacking

- Hardening controls: tool schemas, strict allowlists, retrieval proofs, connector segmentation

###Why this matters

Agentic systems introduce a new SOC problem: the “endpoint” is a tool-using workflow, not just a laptop.
Security teams need:

- consistent telemetry

- detections that understand tool context

- containment playbooks

- evidence that stands up to review

- This lab is a practical, end-to-end demonstration of those skills.

License: MIT
