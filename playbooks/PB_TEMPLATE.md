# Playbook: <TITLE>
**Threat:** <what is happening>  
**Severity guidance:** <low/med/high/critical>  
**Primary signals:** <what detections/logs show>  

## Objective
Contain and investigate with minimal business disruption.

## Triage
- Validate tenant/session context (trace_id, session_id, actor)
- Identify tool(s) involved and targets/domains
- Check policy decisions around the time of the event

## Containment
- Disable or restrict external connectors (web/email/webhook)
- Tighten allowlist / schema constraints
- Apply retrieval boundary enforcement (tenant/scope)

## Eradication & Recovery
- Remove compromised credentials/secrets
- Rotate keys/tokens
- Restore safe connector configuration

## Evidence to preserve
- JSONL logs + alerts + hashes/manifest
- Policy bundle/rules version (if applicable)
- Tool configuration (allowlists, schemas)

## Post-incident improvements
- Add/adjust detections (reduce false positives)
- Add controls (policy rules, schema validation)
- Add regression test for this scenario
