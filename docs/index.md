# Agent Guard — authorization, human approval, audit trail and budgets for Spring AI agents and MCP servers

Your MCP server has authentication. It has no authorization, no "ask a human before this runs", no audit trail an
auditor can read, and no budget that stops an agent at 3 a.m. Agent Guard adds the four, as one Spring Boot starter,
with the same policy engine for Spring AI tool calling (`@Tool` / `ToolCallback`) and MCP servers (`@McpTool`).

Spring Boot 4.0.x, Spring Framework 7, Spring AI 2.0.x, Java 21. Core is Apache-2.0.

## Quickstart (about 60 lines)

```xml
<dependency>
  <groupId>com.housedevinci</groupId>
  <artifactId>agent-guard-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
@Component
public class OrderTools {

  @McpTool(name = "get_order", description = "Status of an order")
  @ToolPolicy(roles = "AGENT")                                  // READ: allowed, audited
  public String getOrder(@McpToolParam(description = "order id") String orderId) { ... }

  @McpTool(name = "refund_order", description = "Refund an order")
  @ToolPolicy(roles = "AGENT", sideEffect = SideEffect.WRITE)   // WRITE: parked until a human approves
  public String refundOrder(@McpToolParam(description = "order id") String orderId) { ... }
}
```

```yaml
agentguard:
  enabled: true
  store: JDBC                 # PostgreSQL via your DataSource; MEMORY for a quick try
  endpoints:
    enabled: true             # /agentguard/decisions, /agentguard/audit — protect them with Spring Security
  budgets:
    limits:
      - { scope: PRINCIPAL, kind: TOOL_CALLS, window: 1m, limit: 3 }
```

What the model sees:

| Situation | Tool result |
|---|---|
| allowed | the tool's own result |
| role / scope / tenant miss | `{"status":"DENIED","error":"TOOL_DENIED","code":"AG-POLICY-001","tool":"...","message":"requires one of roles [ADMIN]"}` |
| write tool | `{"status":"AWAITING_APPROVAL","code":"AG-APPROVAL-001","decisionId":"...","expiresAt":"..."}` |
| budget exhausted | `{"status":"DENIED","error":"BUDGET_EXCEEDED","code":"AG-BUDGET-001",...}` |
| tool threw | `{"status":"ERROR","error":"TOOL_FAILED","code":"AG-TOOL-001","message":"IllegalStateException: db down"}` |

Never a stack trace. On MCP the same JSON comes back as `CallToolResult(isError=true)`.

A human approves with `POST /agentguard/decisions/{id}/approve`: the call runs **once**, the result is stored, a second
approval returns the same result and runs nothing. When the agent re-asks with the same arguments it gets the stored
result. See `agent-guard-sample/` for the runnable version (`docker compose up -d && ../mvnw spring-boot:run`).

## How a call flows

```
tool call ──▶ principal (Spring Security) ──▶ policy rule (@ToolPolicy | registry | MCP readOnlyHint | default)
   ──▶ DENY ─────────────────────────────▶ audit DENIED, structured error
   ──▶ REQUIRE_APPROVAL ──▶ park PendingDecision (args hash + redacted preview), notify, audit PENDING
   ──▶ ALLOW ──▶ budget reserve (before dispatch) ──▶ execute ──▶ audit ALLOWED (latency, result hash)
```

## Configuration

| Property | Default | Meaning |
|---|---|---|
| `agentguard.enabled` | `false` | Master switch. |
| `agentguard.store` | `JDBC` | `JDBC` (PostgreSQL, needs a `DataSource`) or `MEMORY` (dev only). |
| `agentguard.jdbc.initialize-schema` | `true` | Run the bundled idempotent schema (`agentguard_decision`, `agentguard_audit`, `agentguard_budget`). |
| `agentguard.policy.unregistered-tools` | `DENY` | `DENY`, `ALLOW` (treat as READ) or `REQUIRE_APPROVAL` for tools without a policy. |
| `agentguard.policy.approval-required-for` | `WRITE, DESTRUCTIVE` | Side effects that park the call. |
| `agentguard.approval.ttl` | `1h` | Parked calls expire after this. |
| `agentguard.approval.notifier.log-enabled` | `true` | WARN log per parked call (logger `agentguard.approval`). |
| `agentguard.approval.notifier.webhook-url` | – | POST a JSON payload per parked call; `webhook-secret` goes in `X-AgentGuard-Token`. |
| `agentguard.budgets.store` | `DEFAULT` | `DEFAULT` (follows `store`), `JDBC`, `REDIS` (`agentguard.redis.uri`), `MEMORY`. |
| `agentguard.budgets.limits[]` | – | `scope` (PRINCIPAL, TENANT, CONVERSATION), `kind` (TOOL_CALLS, STEPS, TOKENS), `window`, `limit`. |
| `agentguard.redaction.sensitive-keys` | password, token, api_key, … | Masked in previews, logs, webhooks. |
| `agentguard.redaction.max-preview-length` | `512` | |
| `agentguard.endpoints.enabled` | `false` | Approval + audit endpoints under `agentguard.endpoints.base-path` (`/agentguard`). |

Misconfiguration fails at startup with a message naming the property (for example
`agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true`).

### Principal and tenant
Roles come from `ROLE_*` authorities, scopes from `SCOPE_*`. Provide a `TenantResolver` bean to map a JWT claim or a
Tenantify context to the tenant, or a `PrincipalResolver` bean to replace the whole mapping (API keys, MCP sessions).
Without Spring Security every caller is `anonymous`.

### Conversation id (for `STEPS` budgets)
Spring AI: `ToolContext` key `agentguard.conversationId` (or Spring AI's `chat_memory_conversation_id`).
MCP: `_meta.agentguard.conversationId` on the call.

## Error codes

| Code | Meaning |
|---|---|
| `AG-POLICY-001/002/003` | role / scope / tenant not satisfied |
| `AG-POLICY-004` | tool has no policy and unregistered tools are denied |
| `AG-APPROVAL-001` | awaiting approval |
| `AG-APPROVAL-002` | decision not found |
| `AG-APPROVAL-003` | illegal state transition (e.g. reject after approve) |
| `AG-APPROVAL-004` | arguments changed between approval and execution |
| `AG-APPROVAL-005/006` | rejected / expired |
| `AG-APPROVAL-007` | no executor registered for the tool at resume time |
| `AG-BUDGET-001` | budget exceeded |
| `AG-TOOL-001` | the tool itself failed |

## Free vs Pro

| | Core (Apache-2.0) | Pro |
|---|---|---|
| `@ToolPolicy`, registry, Spring Security integration | yes | yes |
| Approval gate, log + webhook notifier, JSON endpoints | yes | + inbox UI, Slack/Teams/email with action links, SLA timers |
| Hash-chained audit in PostgreSQL, chain verifier | yes | + console, search, CSV/JSON export, retention, verification endpoint, per-tenant views |
| Budgets per principal / tenant / conversation, JDBC + Redis | yes | + cost-based, monthly caps with alerts, per-API-key, admin overrides |
| Policy as YAML with hot reload and dry-run | – | yes |
| Multi-tenant isolation (Tenantify), SSO | – | yes |
| Conformance suite (replay recorded tool calls) | – | yes |

## Threat notes
See `SECURITY-NOTES.md`: policy on the actual call, args hash bound to the decision, single-use decisions, redacted
previews, per-call evaluation plus per-conversation budgets, append-only chained audit.

## FAQ
**Does it work without Spring AI?** The core has no Spring dependency; the starter activates the Spring AI and MCP
pieces only when their classes are present. You can call `ToolGuard.execute(...)` from any code.

**Async / WebFlux MCP servers?** Not yet (see QUESTIONS.md).

**Where are the raw arguments?** In `agentguard_decision.arguments_json`, needed to run the call after approval.
Everything humans see is the redacted preview.
