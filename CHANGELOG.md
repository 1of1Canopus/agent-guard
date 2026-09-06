# Changelog

All notable changes to Agent Guard. Format: Keep a Changelog; versions: SemVer. `-SNAPSHOT` is never published.

## [Unreleased]

### Security (Cipher review of `feat/agent-guard-core`, all HIGH and MEDIUM fixed)
- H1: executors are registered per decision id and released after the run; approved calls execute inside a
  security context rebuilt from the stored principal (`ResumeContextProvider` SPI, `RunAsAuthentication`), with the
  parking caller's `ToolContext` / MCP exchange, never as the approver.
- H2: Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline `.tools(obj)`,
  `ToolCallbacks.from`, resolver-by-name included); single MCP specification beans are wrapped; async (WebFlux)
  specifications fail startup; `agentguard.strict=true` (default) fails startup when a scanned `@ToolPolicy` is not
  reachable through a guarded path; the startup log lists the guarded tools.
- H3: `agentguard.redis.pool.{max-total,min-idle,max-wait,prepare-pool}`; the Jedis pool is pre-filled at startup
  so it never grows under virtual threads (commons-pool2 growth lock pins JDK 21–23 carriers).
- M1: the approver (`actor_id`) is part of every APPROVED / REJECTED audit row and of the hash chain.
- M2: length-prefixed canonical form (`ag1`), millisecond timestamps everywhere, `BEFORE TRUNCATE` trigger, anchor
  row (`agentguard_audit_anchor`), verifier statuses `EMPTY` / `INTACT` / `BROKEN` / `ANCHOR_MISMATCH`.
- M3: MCP conversation id is the server-side session id (client `_meta` ignored); missing budget subjects are
  denied under strict (`agentguard.budgets.missing-subject`, `AG-BUDGET-002`); TENANT limits without a
  `TenantResolver` warn at startup.
- M4: parking consumes the call budget (execution is not charged again); pending decisions capped per principal
  (`AG-APPROVAL-008`); arguments capped (`AG-APPROVAL-009`); dedup key includes the tenant.
- M5: `GET /decisions/{id}/arguments` returns the complete redacted arguments; `POST …/approve` requires the
  attested `argsHash` (409 `AG-APPROVAL-010` on mismatch).
- M6: every guard-infrastructure failure becomes a structured `AG-GUARD-001` error with a correlation id.
- M7: endpoints refuse anonymous approvers (401) unless `agentguard.endpoints.allow-anonymous=true`.

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
  - Error codes `AG-POLICY-00x`, `AG-APPROVAL-001..010`, `AG-BUDGET-001/002`, `AG-TOOL-001`, `AG-GUARD-001`.
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
