# Changelog

All notable changes to Agent Guard. Format: Keep a Changelog; versions: SemVer. `-SNAPSHOT` is never published.

## [Unreleased]

### Security (the security review review of `feat/agent-guard-core`, all HIGH and MEDIUM fixed)
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

### Security (clean-verdict round: C1-C12, all closed)
- C4 (MEDIUM) `ToolGuard.gate` and `.dispatch` refuse arguments over `agentguard.guard.max-argument-bytes` as their
  first step, before anything parses them; the audit row for that refusal hashes the raw text directly instead of
  through the canonical parser, so a rejected call never triggers the amplification it was rejected for.
- C1 unpaired UTF-16 surrogates are `\u`-escaped in `JsonText.escape` instead of silently colliding with a literal
  `?` under UTF-8 encoding, so they no longer dedup two different calls onto one decision.
- C2 sensitive-key matching also splits on `_ - .` and camel-case boundaries (`userPassword`, `myApiKey`,
  `password_confirmation` now mask); the existing whole-word-suffix rule is unchanged.
- C5 four-eyes (`ApprovalService.fourEyes`) compares approver and requester trimmed, case-folded and NFKC-normalised.
- C7 a Redis call that misses `maxWait` is cancelled and removed from the queue; the platform-thread pool is a
  bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to the pool, `AbortPolicy`) instead of an unbounded
  `newFixedThreadPool`, so a saturated pool refuses immediately (`AG-GUARD-001`) instead of queueing forever.
- C9 `agentguard.endpoints.require-tenant` (default `true` when `tenant-scoped`): an approver whose resolver yields
  no tenant gets 403 instead of every tenant's decisions and audit rows; set `false` only for a deliberate
  cross-tenant approver role.
- C11 the domain ArchUnit rule bans `javax..` again, with an explicit carve-out for `javax.crypto..` (the keyed
  chain's only use) instead of the three named packages that also re-permitted `javax.naming` / `javax.management` /
  `javax.net` / `javax.xml`.
- C3 the hand-written JSON parser accepts only ASCII `0`-`9` as digits and only `[0-9a-fA-F]` in a `\u` escape, so it
  never treats text Jackson would refuse as structured.
- C6 the audit chain records the version (`ag1` / `ag2h`) each row was actually written with (`agentguard_audit.
  chain_version`, backfilled `ag1`) and the verifier applies that row's version instead of whatever chain it is
  configured with today, so enabling `agentguard.audit.hmac-secret` no longer reports the pre-key trail BROKEN.
- C8 `JedisBudgetStore implements AutoCloseable`; the platform-thread pool is shut down on close (Spring's default
  inferred destroy method picks it up).
- C10 `DecisionStore.findByState(state, tenantId, limit)` and `AuditReader.latest(tenantId, limit)` push the tenant
  filter into the store query instead of filtering the page after `limit`, so a busy neighbour tenant can no longer
  hide a tenant's own pending work.
- C12 `AuditRecorder.record` hashes `ArgumentCanonicalizer.canonical(argumentsJson)`, the same form the decision
  store hashes, so `agentguard_audit.args_hash` and `agentguard_decision.args_hash` join for the same call again.

### Security (re-verification round: V1-V5, all closed or scoped)
- V1 (MEDIUM) `ToolGuard.guarded` now applies the raw byte cap (`rejectIfTooLarge`) as the first statement on
  every path into the guard, including the unregistered-tool and policy-denial paths — both reachable with no
  role and no policy at all. Those two denials previously canonicalised (parsed) the arguments before the cap
  ran; `gate`/`dispatch` keep their now-redundant checks.
- V2 (MEDIUM) `AuditChainVerifier.verify` tracks whether a `KEYED_VERSION` row has verified while walking the
  trail; once it has, a later row claiming `CANONICAL_VERSION` is `BROKEN` at its own sequence instead of being
  silently re-verified with plain SHA-256. C6's migration case (an unkeyed prefix, then keyed rows) is unaffected.
  **Scope:** this closes a *partial* downgrade — a genuinely keyed prefix followed by a downgraded tail. It cannot
  close a downgrade of the *entire* trail back to GENESIS: that row shape is identical to a deployment that has
  never used HMAC, which `AuditChainVerifier` must (and does) still report `INTACT` — see QUESTIONS.md #20.
- V3 (LOW) the two `args_hash` domains are separated with a fixed prefix hashed into the material:
  `AuditRecorder.recordOversized` hashes `"agraw1:" + argumentsJson`, `ArgumentCanonicalizer.hash` hashes
  `"agcanon1:" + canonical(argumentsJson)` — an oversized denial can no longer share `args_hash` with an allowed
  call. `ToolGuard.rejectIfTooLarge` additionally checks the canonical form's byte length (once the raw check has
  already bounded the cost of computing it), so a sub-cap raw payload whose canonical form exceeds the cap is also
  refused as oversized. **Hash-format change:** existing `args_hash` values are unaffected (the chain hashes the
  row, not the arguments), but a stored `args_hash` can no longer be recomputed from raw arguments text without
  the domain prefix.
- V4 (LOW) `AgentGuardStartupCheck` now warns when `agentguard.endpoints.enabled` and either
  `agentguard.endpoints.tenant-scoped=false` or `agentguard.endpoints.require-tenant=false`, naming the property
  and the consequence ("approvers see and decide every tenant's decisions and audit rows").
- V5 (LOW) `AgentGuardProperties.Pool` gets `platform-thread-count` and `platform-thread-queue-size`, decoupled
  from `max-total` (the Jedis connection pool size); both default to `max-total` when unset, preserving prior
  behaviour. `JedisBudgetStore.onPlatformThreads` takes the queue bound as its own parameter.
  `CipherProbeJedisFactoryTest.burst` is restored to `max-total=4` (the real H3/R6 connection-pool contention
  scenario) with `platform-thread-count`/`platform-thread-queue-size=200`, so the burst still passes without
  inflating the connection pool.

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
