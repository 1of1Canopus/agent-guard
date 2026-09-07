# SECURITY-NOTES.md — Agent Guard (module B), free core

Skeleton for the adversarial pass required by `specs/RELEASE-PROCESS.md`. Each threat from the SPEC, what the code
does about it, and what still needs a reviewer's eye.

## Threat 1 — Prompt-injected tool calls
- **Mitigation:** policy is evaluated on the *actual* call (`ToolGuard.execute` receives the tool name and the exact
  arguments the framework is about to execute), never on model intent. Nothing in the pipeline reads the prompt.
- **Test:** `ToolGuardTest`, `GuardedToolCallbackTest`, `McpToolGuardTest`.
- **Open:** the tool *name* is taken from the framework's `ToolDefinition` / `McpSchema.Tool`, not from the model
  message, so a model cannot rename a tool. Reviewer: confirm the `DefaultToolCallingManager` resolves callbacks by
  name from the configured set only (it does in 2.0.1).

## Threat 2 — Argument tampering between approval and execution
- **Mitigation:** `PendingDecision.argsHash = SHA-256(argumentsJson)`; `DecisionResumer` recomputes the hash of the
  stored arguments before running (`ArgumentsTamperedException`, `AG-APPROVAL-004`); a re-call by the agent only
  resumes when the new arguments hash to the approved hash, otherwise a new decision is parked. The approver
  attests the hash they reviewed: `POST /decisions/{id}/approve?argsHash=` is required, a mismatch is a 409
  (`AG-APPROVAL-010`) and nothing runs; `GET /decisions/{id}/arguments` returns the **complete** redacted
  arguments (never truncated) so no key is hidden from the reviewer (Cipher M5).
- **Residual:** the raw arguments are stored in `agentguard_decision.arguments_json` (needed to execute later). Protect
  the table like any other sensitive table; there is no encryption at rest in core (pro candidate).
- **Test:** `ToolGuardTest.tampered_arguments_between_approval_and_execution_are_refused`.

## Threat 3 — Replay of approvals, wrong identity at resume
- **Mitigation:** `DecisionStore.markExecutedOnce` is a single conditional `UPDATE ... WHERE executed = false`
  (processed-event-ledger pattern); the state machine forbids leaving a terminal state; a second approve returns the
  stored result and runs nothing.
- **Identity and context at resume (Cipher H1):** the executor closure (the parking caller's `ToolContext` / MCP
  exchange) is registered **per decision id** and released after the run; the call executes inside a security
  context rebuilt from the stored principal (`RunAsAuthentication`, via the `ResumeContextProvider` SPI), never as
  the approver, and the approver's context is restored afterwards. Closures live in memory: a decision parked
  before a restart cannot be resumed (`AG-APPROVAL-007`). The approved call runs on the approver's request thread.
- **Test:** `JdbcAdaptersIntegrationTest.mark_executed_once_wins_exactly_once_under_concurrency` (50 threads),
  `GuardedToolCallbackTest`, `SampleEndToEndTest`.

## Threat 4 — Log injection
- **Mitigation:** `ArgumentRedactor` parses the JSON (dependency-free parser in the domain) and masks the whole
  value of a sensitive key whatever its shape; keys are compared after unescaping; bearer-like tokens are masked in
  any string; `\p{Cc}\p{Cf}` and U+0085/2028/2029 are stripped; unparseable input is masked whole; the preview is
  capped at 512 chars, the approver's view is not. Only the preview reaches logs, webhooks and the endpoints; the raw
  arguments never do. Exceptions reach the model as `class: message` (300 chars), never a stack trace.
- **Test:** `ArgumentRedactorTest`, `NotifiersTest`.
- Tool exception messages stay server-side by default (`agentguard.errors.include-tool-message=false`).

## Threat 5 — Privilege escalation via tool chaining, budget evasion
- **Mitigation:** every call is evaluated on its own with the caller's principal; budgets have a `CONVERSATION`
  scope (`kind: STEPS`) so a chain cannot loop forever inside one conversation.
- **Subject is server-side (Cipher M3):** on MCP the conversation is the server's session id
  (`McpSyncServerExchange.sessionId()`); client `_meta` is ignored. On Spring AI it is the `ToolContext` key set by
  server code. When a configured scope has no subject the call is **denied** (`AG-BUDGET-002`) under
  `agentguard.strict=true` (`agentguard.budgets.missing-subject` = `DENY` | `FALLBACK_TO_PRINCIPAL` | `SKIP`); a
  TENANT limit without a `TenantResolver` bean warns at startup.
- **Parking is bounded (Cipher M4):** a parked call consumes the call budget (its later execution is not charged
  again), pending decisions are capped per principal (`agentguard.approval.max-pending-per-principal`, default 20,
  `AG-APPROVAL-008`), arguments are capped (`max-argument-bytes`, default 64 KiB, `AG-APPROVAL-009`), and the
  dedup key includes the tenant so `admin@tenant-2` never receives `admin@tenant-1`'s stored result.
- **Coverage is checked (Cipher H2):** Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline
  `.tools(obj)` / `ToolCallbacks.from` / resolver-by-name included); MCP single and list specification beans are
  wrapped; async (WebFlux) specifications fail startup; `agentguard.strict=true` fails startup when a scanned
  `@ToolPolicy` is not reachable through a guarded path, and the startup log lists the guarded tools.
- **Tenant scoping fails closed (Cipher C9):** `agentguard.endpoints.require-tenant` defaults `true` whenever
  `tenant-scoped` is on: an approver whose `TenantResolver` yields no tenant (missing claim, service account,
  misconfigured resolver) is refused (403, `AG-HTTP-403`) instead of silently seeing and deciding every tenant's
  decisions and audit rows. A genuinely single-tenant deployment (no `TenantResolver`, as in the sample) should set
  `agentguard.endpoints.tenant-scoped=false` explicitly; set `require-tenant=false` only for a deliberate
  cross-tenant approver role. The tenant filter is also pushed into the store query
  (`DecisionStore.findByState(state, tenantId, limit)`, `AuditReader.latest(tenantId, limit)`, Cipher C10) instead of
  applied after the page's `limit`, so a busy neighbour tenant cannot hide a tenant's own pending work.

## Threat 6 — Audit tampering
- **Mitigation:** hash chain (`hash = SHA-256(canonical(row) || prevHash)`) with a **length-prefixed** canonical form
  (`ag1|<len>:<value>|…`, nulls as `-`), so no rewrite can move a boundary between fields (Cipher M2); the approver
  is part of the material (`actor_id`, Cipher M1); timestamps are truncated to milliseconds in `AuditEvent` so every
  store round-trips them; appends are serialised by a PostgreSQL transaction-scoped advisory lock; triggers refuse
  UPDATE, DELETE **and TRUNCATE**; a separate **anchor row** (`agentguard_audit_anchor`: head hash + row count) is
  written in the same transaction, and `AuditChainVerifier` reports `EMPTY` / `INTACT` / `BROKEN` /
  `ANCHOR_MISMATCH` — tail deletion or truncation by a role that can disable triggers is detected.
- **Residual (Cipher R4):** the runtime role needs UPDATE on the anchor row, so anyone with that grant (or the
  owner) can reset the anchor after trimming the tail; the anchor raises the bar only when roles are split as
  described below. A role that owns the tables can rewrite chain **and** anchor consistently. Run the application with a
  least-privilege role (INSERT + SELECT on `agentguard_audit`, UPDATE on the anchor row only, no DDL, not the table
  owner) and keep `agentguard.jdbc.initialize-schema` for a migration step run by the owner role; log or export the
  head hash periodically. An HMAC-keyed chain and external anchoring stay pro items.
- **Enabling the HMAC key is a one-way step, safely (Cipher C6):** each row records the chain version it was written
  with (`agentguard_audit.chain_version`, `ag1` unkeyed / `ag2h` keyed; backfilled `ag1` for rows written before this
  column existed). `AuditChainVerifier` recomputes every row with the version *it* carries, not with whichever chain
  the verifier happens to be constructed with today — so turning on `agentguard.audit.hmac-secret` on a running
  installation does not make the pre-key trail report `BROKEN`. A row that claims `ag2h` but the verifier was not
  given the matching secret still fails to recompute: that is a real break, not a version mismatch, and is reported
  as one.
- **Test:** `JdbcAdaptersIntegrationTest.audit_*`, `AuditChainVerifierTest`, `CipherProbeJdbcTest`,
  `CipherProbeAuditChainTest`, `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail`.

## Operational hazards
- **Redis + virtual threads on JDK 21–23 (Cipher H3).** The pin is not in Jedis itself but in commons-pool2's growth
  path: `GenericObjectPool.create()` holds a monitor (`makeObjectCountLock`) around the Jedis handshake I/O. A virtual
  thread blocked on that `monitorenter` pins its carrier; once every carrier is pinned the threads doing the handshake
  never get scheduled again and the JVM hangs. Reproduced with 64 virtual threads on a cold pool of 4: zero
  completions after 10 s; the same on platform threads completes in 62 ms (`CipherProbeJedisPinningTest`, profile
  `pinning-probe`). It recurs every time the pool has to grow (idle eviction after 60 s, Redis restarts). **Fix
  shipped:** the pool is pre-filled at startup from the platform startup thread (`min-idle = max-total`,
  `prepare-pool=true`, `agentguard.redis.pool.*`) so it never grows under load; size `max-total` at or above peak
  concurrent tool calls. Proven: 200 virtual threads on 8 pre-filled connections finish in 76 ms. JDK 24 (JEP 491)
  removes the pinning. Residual (Cipher R6): after a Redis restart or failover the destroyed connections are
  re-created on the next borrow, so the growth path (and the pin) is possible for that window; running
  `JedisBudgetStore` calls on a small platform-thread executor is the belt-and-braces option.
- **The platform-thread pool fails closed, on purpose (Cipher C7/C8):** the pool backing `JedisBudgetStore` is a
  bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to `agentguard.redis.pool.max-total`, `AbortPolicy`), not
  an unbounded queue: a call that misses `maxWait` is cancelled and removed from the queue instead of being
  abandoned there, and a saturated pool refuses new calls immediately with `AG-GUARD-001` rather than queueing
  behind a growing backlog. This means a burst well past `max-total` concurrent callers gets guard-unavailable
  errors (the guard fails closed, denying the tool call) instead of eventually succeeding once Redis catches up —
  size `max-total` at or above the real peak concurrency, the same sizing guidance as above. `JedisBudgetStore`
  implements `AutoCloseable` and its `close()` shuts the pool down; the auto-configured bean is picked up by
  Spring's default inferred destroy method, so a context that rebuilds it (devtools restart, `@DirtiesContext`) does
  not leak `agentguard-redis` threads.
- **Hand-built managers (Cipher R3):** a `DefaultToolCallingManager` built in code and handed to a `ChatModel`
  builder never passes through the context, so it is not guarded and strict mode cannot see it. Use the
  `ToolCallingManager` bean or wrap yours with `AgentGuard.guard(manager)`.
- **Guard failures are structured (Cipher M6):** any failure of the guard's own infrastructure (store, audit sink,
  notifier, JSON, security context) becomes `{"error":"GUARD_UNAVAILABLE","code":"AG-GUARD-001","correlationId":…}`
  on both paths; the cause is logged server-side at ERROR with that correlation id, and the tool is not run. Tool
  authors' own exception messages still reach the model (300 chars): do not put secrets in exception messages.
- **Endpoints refuse anonymous approvers (Cipher M7):** 401 unless `agentguard.endpoints.allow-anonymous=true`
  (trial only). Still put Spring Security in front of `/agentguard/**` (the sample: `hasRole("APPROVER")`).

## Review status
Cipher's adversarial pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, five passes): H1–H3, M1–M7, R1, R2, R5
fixed and re-verified; under the no-allowance rule every LOW and INFO of the first four passes (L1–L10, I1–I9, R3,
R4, R6–R11) and every finding of the clean-verdict pass (C4 MEDIUM; C1, C2, C5, C7, C9, C11 LOW; C3, C6, C8, C10,
C12 INFO) is fixed on the branch with its probe flipped. Documented residuals that remain by design: a role that
*owns* the tables can drop the append-only and anchor triggers (split roles, see docs "Database roles"; external
anchoring and the keyed chain reduce what such a role can do silently); a `ToolCallingManager` built by hand and
handed to a `ChatModel` builder is outside the guard (use the bean or `AgentGuard.guard(manager)`); on JDK 21–23
Redis calls run on platform threads so the pool's growth lock is never touched by a virtual thread; a burst past
`agentguard.redis.pool.max-total` concurrent callers now fails closed (`AG-GUARD-001`) instead of queueing
unboundedly, by design (Cipher C7) — size the pool at or above real peak concurrency.

## Reviewer checklist (before the first public release)
- [ ] Dependency scan (`./mvnw -Psecurity-scan verify`) clean or triaged.
- [x] Fuzz `ArgumentRedactor` with adversarial JSON (done by Cipher; L5 closed with the JSON-aware redactor).
- [ ] Confirm no secret / PII reaches logs in the sample run (grep the log for `hunter2`, `Bearer `, IBAN-like patterns).
- [ ] Two-role database setup documented and used by the sample compose file.
- [x] Threat model the webhook (done by Cipher; L6 closed: https, HMAC signature, timestamp).
