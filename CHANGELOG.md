# Changelog

All notable changes to Agent Guard. Format: Keep a Changelog; versions: SemVer. `-SNAPSHOT` is never published.

## [Unreleased]

### Added
- `agent-guard-core` (Apache-2.0, no framework dependencies):
  - `@ToolPolicy(roles, scopes, tenants, sideEffect)` and `ToolPolicyRegistry`; `ToolPolicyEvaluator` with a stable
    decision (`ALLOW` / `DENY(code)` / `REQUIRE_APPROVAL`).
  - Approval gate: `PendingDecision`, `DecisionState` enum state machine (`PENDING -> APPROVED | REJECTED | EXPIRED`,
    everything else throws), `ApprovalService`, `DecisionResumer` (executes once, args hash verified), `Notifier` SPI
    with logging, webhook and composite implementations.
  - Audit: `AuditEvent` hash chain, `AuditSink` / `AuditReader` ports, `AuditChainVerifier`.
  - Budgets: `BudgetLimit` (PRINCIPAL / TENANT / CONVERSATION x TOOL_CALLS / STEPS / TOKENS), `BudgetEnforcer`
    enforced before dispatch, `BudgetStore` port.
  - Adapters: PostgreSQL (JDBC, append-only trigger, advisory-lock chain), Redis (Jedis, atomic Lua counter),
    in-memory.
  - Error codes `AG-POLICY-00x`, `AG-APPROVAL-00x`, `AG-BUDGET-001`, `AG-TOOL-001`.
- `agent-guard-spring-boot-starter`:
  - `agentguard.*` properties (validated, documented metadata, fail-fast messages naming the property).
  - Spring AI 2.0.x: every `ToolCallback` / `ToolCallbackProvider` bean is decorated; `AgentGuard.guard(...)` for
    programmatic use.
  - MCP: every `@McpTool` (sync and stateless sync servers) is decorated; refusals return
    `CallToolResult(isError=true)` with structured JSON.
  - Spring Security: principal from the security context, `TenantResolver` SPI,
    `ToolPolicyAuthorizationManager` (`AuthorizationManager<ToolInvocation>`).
  - Opt-in endpoints: list / approve / reject decisions, audit query.
- `agent-guard-sample`: 60-line MCP server (one read tool, one write tool parked for approval, budget of 3) with an
  end-to-end test through a real MCP streamable-HTTP client and Testcontainers PostgreSQL.
