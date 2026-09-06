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
| the guard itself failed (store, audit, ...) | `{"status":"ERROR","error":"GUARD_UNAVAILABLE","code":"AG-GUARD-001","correlationId":"..."}` — details only in the server log |

Never a stack trace. On MCP the same JSON comes back as `CallToolResult(isError=true)`.

A human reads the complete redacted arguments (`GET /agentguard/decisions/{id}/arguments`) and approves with
`POST /agentguard/decisions/{id}/approve?argsHash=<the hash they reviewed>`: the call runs **once**, inside the
identity of the principal that asked (never the approver's), the result is stored, a second approval returns the same
result and runs nothing. When the agent re-asks with the same arguments it gets the stored result. See
`agent-guard-sample/` for the runnable version (`docker compose up -d && ../mvnw spring-boot:run`).

Every Spring AI tool is guarded at the `ToolCallingManager` chokepoint (Spring AI's own manager bean is wrapped, so
`spring.ai.tools.limits.*` still apply), so `ChatClient.prompt().tools(obj)` and callbacks built inline are covered
too — a manager you build by hand and pass to a `ChatModel` builder is not: use the bean or `AgentGuard.guard(manager)`; every `@McpTool` specification bean (single or list) is wrapped. With
`agentguard.strict=true` (default) the application refuses to start if a tool that carries `@ToolPolicy` is not
reachable through a guarded path, and the startup log lists the guarded tools.

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
| `agentguard.strict` | `true` | Fail startup on unguarded `@ToolPolicy` tools; deny calls whose budget scope has no subject. |
| `agentguard.jdbc.initialize-schema` | `true` | Run the bundled idempotent schema (`agentguard_decision`, `agentguard_audit`, `agentguard_budget`). |
| `agentguard.policy.unregistered-tools` | `DENY` | `DENY`, `ALLOW` (treat as READ) or `REQUIRE_APPROVAL` for tools without a policy. |
| `agentguard.policy.approval-required-for` | `WRITE, DESTRUCTIVE` | Side effects that park the call. |
| `agentguard.approval.ttl` | `1h` | Parked calls expire after this. |
| `agentguard.approval.max-pending-per-principal` | `20` | Further WRITE calls are refused (`AG-APPROVAL-008`). |
| `agentguard.approval.max-argument-bytes` | `65536` | Larger arguments are not parked (`AG-APPROVAL-009`). |
| `agentguard.approval.replay-window` | `= ttl` | How far back an identical call is matched to an existing decision. |
| `agentguard.approval.allow-self-approval` | `false` | Four-eyes: the parking principal may not decide its own call (`AG-APPROVAL-011`). |
| `agentguard.approval.notifier.webhook-allow-insecure` | `false` | Trial only; otherwise https or a loopback host. |
| `agentguard.audit.hmac-secret` | – | Keyed chain (`ag2h`): rewrites by anyone without the key become detectable. |
| `agentguard.errors.include-tool-message` | `false` | Forward the tool's exception message to the model (default: class + correlation id). |
| `agentguard.endpoints.tenant-scoped` | `true` | Approvers only see and decide their own tenant's decisions. |
| `agentguard.redis.pool.platform-threads` | `true` | JDK 21-23: Redis calls on a bounded platform-thread pool. |
| `agentguard.approval.notifier.log-enabled` | `true` | WARN log per parked call (logger `agentguard.approval`). |
| `agentguard.approval.notifier.webhook-url` | – | POST a JSON payload per parked call; `webhook-secret` goes in `X-AgentGuard-Token`. |
| `agentguard.budgets.store` | `DEFAULT` | `DEFAULT` (follows `store`), `JDBC`, `REDIS` (`agentguard.redis.uri`), `MEMORY`. |
| `agentguard.budgets.limits[]` | – | `scope` (PRINCIPAL, TENANT, CONVERSATION), `kind` (TOOL_CALLS, STEPS, TOKENS), `window`, `limit`. A parked call counts as a call. |
| `agentguard.budgets.missing-subject` | `DEFAULT` | What a TENANT / CONVERSATION limit does without an id: `DEFAULT` (= `DENY` under strict, else `SKIP`), `DENY` (`AG-BUDGET-002`), `FALLBACK_TO_PRINCIPAL`, `SKIP`. |
| `agentguard.redis.pool.max-total` | `8` | Size at or above peak concurrent tool calls (see "Redis and virtual threads"). |
| `agentguard.redis.pool.min-idle` / `max-wait` / `prepare-pool` | `= max-total` / `2s` / `true` | Pre-filled pool; never grows under load. |
| `agentguard.redaction.sensitive-keys` | password, token, api_key, … | Masked in previews, logs, webhooks. |
| `agentguard.redaction.max-preview-length` | `512` | |
| `agentguard.endpoints.enabled` | `false` | Approval + audit endpoints under `agentguard.endpoints.base-path` (`/agentguard`). |
| `agentguard.endpoints.allow-anonymous` | `false` | Trial only: accept an unauthenticated approver. Otherwise 401. |

Misconfiguration fails at startup with a message naming the property (for example
`agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true`).

### Principal and tenant
Roles come from `ROLE_*` authorities, scopes from `SCOPE_*`. Provide a `TenantResolver` bean to map a JWT claim or a
Tenantify context to the tenant, or a `PrincipalResolver` bean to replace the whole mapping (API keys, MCP sessions).
Without Spring Security every caller is `anonymous`.

### Conversation id (for `STEPS` budgets)
Spring AI: `ToolContext` key `agentguard.conversationId` (or Spring AI's `chat_memory_conversation_id`), set by
your server code. MCP: the server-side session id; nothing the client sends is trusted for budgets. When a
configured scope has no id the call is denied under strict (`AG-BUDGET-002`).

### Endpoints
`GET /decisions` (pending), `GET /decisions/{id}`, `GET /decisions/{id}/arguments` (complete, redacted),
`POST /decisions/{id}/approve?argsHash=…` (required; 409 on mismatch), `POST /decisions/{id}/reject`,
`GET /audit`. Put Spring Security in front of them, e.g. `.requestMatchers("/agentguard/**").hasRole("APPROVER")`;
anonymous approvers get 401, the principal that parked the call gets 403, another tenant's decision is a 404.
Before running, the approved call is re-checked against the current policy and a refreshed principal
(`PrincipalRefresher` bean): a role revoked between park and approve denies.

### Webhook verification
With `agentguard.approval.notifier.webhook-secret` set, each POST carries `X-AgentGuard-Timestamp` (epoch seconds)
and `X-AgentGuard-Signature: v1=<hex>`. Verify with `hex(HMAC-SHA256(secret, timestamp + "." + body)) == <hex>` and
reject timestamps older than a few minutes. The URL must be https unless the host is loopback.

### Database roles
`agentguard.jdbc.initialize-schema=true` runs DDL with the application's credentials. For production use two roles:
an owner/migration role that runs the schema once, and a runtime role with `SELECT, INSERT` on `agentguard_audit`,
`SELECT, INSERT, UPDATE` on `agentguard_decision`, `agentguard_budget` and `agentguard_audit_anchor`, and no DDL
(so it cannot disable the append-only triggers); then set `initialize-schema=false`. The chain verifier reports
`ANCHOR_MISMATCH` if the tail is trimmed or the table truncated by a role that could.

### Redis and virtual threads
On JDK 21–23 a virtual thread blocked on the connection pool's growth lock pins its carrier; with more concurrent
tool calls than carriers the JVM hangs (reproduced: 64 virtual threads on a cold pool of 4, zero completions).
The starter pre-fills the pool at startup (`min-idle = max-total`, `prepare-pool=true`) so it never grows under
load: set `agentguard.redis.pool.max-total` at or above your peak concurrent tool calls. JDK 24+ removes the pin.

### Arguments and hashes
The hash bound to a decision is over the canonical arguments (sorted keys, no whitespace), so
`{"a":1,"b":2}` and `{ "b":2, "a":1 }` are one call. Identical calls within `replay-window` reuse the decision.

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
| `AG-APPROVAL-007` | no executor captured for the decision (parked before a restart) |
| `AG-APPROVAL-008` | too many decisions already pending for this principal |
| `AG-APPROVAL-009` | arguments too large to park |
| `AG-APPROVAL-010` | the attested arguments hash does not match the decision |
| `AG-APPROVAL-011` | the parking principal tried to decide its own call |
| `AG-BUDGET-001` | budget exceeded |
| `AG-BUDGET-002` | a configured budget scope has no subject (no conversation / tenant id) |
| `AG-TOOL-001` | the tool itself failed |
| `AG-GUARD-001` | the guard's own infrastructure failed; the call was not run |

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

**Async / WebFlux MCP servers?** Not yet: async tool specification beans make startup fail rather than run
unguarded (see QUESTIONS.md).

**A tool failed after approval — can the agent retry?** No: the single execution is spent (`"retryable":false`).
The agent must ask again and a human must approve again.

**Where are the raw arguments?** In `agentguard_decision.arguments_json`, needed to run the call after approval.
Everything humans see is the redacted preview.
