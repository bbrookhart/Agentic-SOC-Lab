# Splunk Searches (Agentic SOC Lab)

## 1) High/Critical alerts over time
index=agentic_soc sourcetype=agentic:soc:json event.event_type=ALERT
| stats count by event.rule_id event.severity

## 2) Cross-tenant retrieval attempts
index=agentic_soc sourcetype=agentic:soc:json event.event_type=RETRIEVAL
| where event.retrieval.requested_tenant != event.tenant
| table event.ts event.session_id event.trace_id event.tenant event.retrieval.requested_tenant event.retrieval.resource event.retrieval.scope

## 3) External tool calls (potential exfil path)
index=agentic_soc sourcetype=agentic:soc:json event.event_type=TOOL_CALL
| where like(event.tool_call.tool, "web_%") OR event.tool_call.tool="email_send" OR event.tool_call.tool="webhook_post"
| table event.ts event.session_id event.tool_call.tool event.tool_call.target event.tool_call.args
