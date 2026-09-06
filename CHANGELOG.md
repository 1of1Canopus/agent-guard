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
- R1 (re-verification): the guarded default `ToolCallingManager` no longer competes with Spring AI's
  `ToolCallingAutoConfiguration` (`@ConditionalOnMissingClass`); Spring AI's manager, with
  `spring.ai.tools.limits.*` and `resolution.fallback`, is wrapped by the bean post-processor instead.
- R2 (re-verification): the schema seeds `agentguard_audit_anchor` from an existing trail, and `JdbcAuditSink`
  re-anchors from the table head (WARN once) when the anchor row is missing, so upgraded installations stay INTACT.
- R5 (re-verification): `RunAsAuthentication` keeps the tenant during a resumed call (`SecurityContextPrincipalResolver`
  short-circuits on it, `NoTenantResolver` understands it).

### Security (no-allowance round: every LOW / INFO of the review closed)
- L1 four-eyes: the parking principal cannot approve/reject its own call (`AG-APPROVAL-011`, 403;
  `agentguard.approval.allow-self-approval=false`).
- L2 tamper detection is audited (`AuditDecision.TAMPERED`, with actor) and closes the decision.
- L3 policy re-evaluated at resume with a refreshed principal (`PrincipalRefresher` SPI); a revoked role or a
  tightened rule denies, audited with the approver as actor.
- L4 dedup bounded by `agentguard.approval.replay-window` (default = ttl).
- L5 JSON-aware redactor: dependency-free parser in the domain, sensitive keys mask their whole value whatever its
  shape, keys compared after unescaping, `\p{Cc}\p{Cf}` + U+0085/2028/2029 stripped, unparseable input fully masked.
- L6 webhook: https required (loopback or `webhook-allow-insecure` excepted), `X-AgentGuard-Timestamp` +
  `X-AgentGuard-Signature: v1=HMAC-SHA256(secret, ts.body)`; static token only with `webhook-legacy-token`.
- L7 duration properties fail naming the property; empty `approval-required-for` / `sensitive-keys` warn.
- L8 expired budget rows purged every 1000 increments, `key` column `text`, long subjects hashed.
- L9 sample keeps CSRF on for the approval endpoints; README says the demo credentials are demo-only.
- L10/R11 schema step runs once per DataSource, under the sink's advisory lock, creating triggers only when absent
  (no deadlock with appends, eight concurrent first starts succeed); WARN when the runtime role owns the audit table.
- I1 arguments hashed in canonical form (sorted keys, no whitespace): key order and spacing share one decision.
- I2 `Failed.retryable=false` after an approval; documented.
- I3 anonymous tokens map to the anonymous principal in the `AuthorizationManager` too.
- I4 endpoints are tenant-scoped (`agentguard.endpoints.tenant-scoped=true`): other tenants' decisions are 404.
- I5 tool exception messages stay server-side (`agentguard.errors.include-tool-message=false`); the model gets the
  class name and the correlation id.
- I6 two different policies for one tool name fail at startup.
- I7 optional keyed chain (`agentguard.audit.hmac-secret`, >= 32 bytes, version `ag2h`).
- I8 `STEPS` only with `CONVERSATION`, `TOOL_CALLS` only with `PRINCIPAL`/`TENANT` (fail fast);
  `AgentGuardUsageAdvisor` records model tokens for `TOKENS` budgets (closes QUESTIONS #8).
- I9 workflows: `permissions: contents: read`, actions pinned by SHA, wrapper `distributionSha256Sum`, container
  images pinned by digest.
- R3 startup log names the wrapped manager and the hand-built-manager caveat.
- R4 `agentguard_audit_anchor` only advances by one row (trigger).
- R6 Redis calls run on a bounded platform-thread pool on JDK 21-23 (`agentguard.redis.pool.platform-threads`).
- R7 WARN when a CONVERSATION limit has no PRINCIPAL limit.
- R8 pending cap counted per principal and tenant.
- R9 an `AgentGuardException` from the tool path leaves a FAILED row before failing closed.
- R10 `RunAsAuthentication`: package-private constructor, never serializable, cannot be re-authenticated.

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
  - Error codes `AG-POLICY-00x`, `AG-APPROVAL-001..011`, `AG-BUDGET-001/002`, `AG-TOOL-001`, `AG-GUARD-001`.
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
