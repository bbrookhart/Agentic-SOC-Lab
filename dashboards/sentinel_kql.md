# Microsoft Sentinel KQL Pack (Agentic SOC Lab)

> Assumes custom table name: `AgenticSocLab_CL`
> Columns: EventTime, EventType, RuleId, Severity, TraceId, SessionId, Tenant, ActorId, RawEvent (dynamic)

---

## 1) Alert summary by rule + severity
AgenticSocLab_CL
| where EventType == "ALERT"
| summarize Alerts=count() by RuleId, Severity
| order by Severity desc, Alerts desc

## 2) High/Critical alerts in last 24h (SOC queue)
AgenticSocLab_CL
| where EventType == "ALERT"
| where Severity in ("high","critical")
| project EventTime, Severity, RuleId, TraceId, SessionId, Tenant, ActorId, RawEvent
| order by EventTime desc

## 3) Cross-tenant retrieval attempts (boundary violation)
AgenticSocLab_CL
| where EventType == "RETRIEVAL"
| extend reqTenant=tostring(RawEvent.retrieval.requested_tenant), sessTenant=tostring(Tenant)
| where reqTenant != sessTenant
| project EventTime, TraceId, SessionId, Tenant=sessTenant, RequestedTenant=reqTenant,
          Resource=tostring(RawEvent.retrieval.resource), Scope=tostring(RawEvent.retrieval.scope),
          Query=tostring(RawEvent.retrieval.query), Records=tolong(RawEvent.retrieval.records)
| order by EventTime desc

## 4) Tool loop / probing behavior (same tool repeated)
AgenticSocLab_CL
| where EventType == "TOOL_CALL"
| extend tool=tostring(RawEvent.tool_call.tool), target=tostring(RawEvent.tool_call.target)
| summarize Calls=count() by SessionId, TraceId, Tenant, tool, target
| where Calls >= 5
| order by Calls desc

## 5) External connectors used (exfil paths)
AgenticSocLab_CL
| where EventType == "TOOL_CALL"
| extend tool=tostring(RawEvent.tool_call.tool), target=tostring(RawEvent.tool_call.target)
| where tool in ("web_request","email_send","webhook_post")
| project EventTime, SessionId, TraceId, Tenant, tool, target, Args=RawEvent.tool_call.args
| order by EventTime desc

## 6) Policy denies correlated with later tool calls (escalation chain)
AgenticSocLab_CL
| where EventType in ("POLICY_DECISION","TOOL_CALL")
| project EventTime, EventType, TraceId, SessionId, Tenant, RawEvent
| order by SessionId asc, EventTime asc
| extend decision=tostring(RawEvent.policy.decision), rule=tostring(RawEvent.policy.rule_id),
         tool=tostring(RawEvent.tool_call.tool)
| summarize
    Denies=countif(EventType=="POLICY_DECISION" and decision=="deny"),
    ExternalCalls=countif(EventType=="TOOL_CALL" and tool in ("web_request","email_send","webhook_post"))
  by SessionId, TraceId, Tenant
| where Denies > 0 and ExternalCalls > 0
| order by Denies desc

## 7) Find sessions with critical exfil alert (D003/D004)
AgenticSocLab_CL
| where EventType == "ALERT"
| where RuleId in ("D003","D004") or Severity == "critical"
| project EventTime, RuleId, Severity, TraceId, SessionId, Tenant, RawEvent
| order by EventTime desc

## 8) Build a timeline for a specific session (paste SessionId)
let sid = "<PASTE_SESSION_ID>";
AgenticSocLab_CL
| where SessionId == sid
| project EventTime, EventType, RuleId, Severity, TraceId, Tenant, RawEvent
| order by EventTime asc
