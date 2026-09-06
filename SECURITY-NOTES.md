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
  arguments (never truncated) so no key is hidden from the reviewer (the security review M5).
- **Residual:** the raw arguments are stored in `agentguard_decision.arguments_json` (needed to execute later). Protect
  the table like any other sensitive table; there is no encryption at rest in core (pro candidate).
- **Test:** `ToolGuardTest.tampered_arguments_between_approval_and_execution_are_refused`.

## Threat 3 — Replay of approvals, wrong identity at resume
- **Mitigation:** `DecisionStore.markExecutedOnce` is a single conditional `UPDATE ... WHERE executed = false`
  (processed-event-ledger pattern); the state machine forbids leaving a terminal state; a second approve returns the
  stored result and runs nothing.
- **Identity and context at resume (the security review H1):** the executor closure (the parking caller's `ToolContext` / MCP
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
- **Subject is server-side (the security review M3):** on MCP the conversation is the server's session id
  (`McpSyncServerExchange.sessionId()`); client `_meta` is ignored. On Spring AI it is the `ToolContext` key set by
  server code. When a configured scope has no subject the call is **denied** (`AG-BUDGET-002`) under
  `agentguard.strict=true` (`agentguard.budgets.missing-subject` = `DENY` | `FALLBACK_TO_PRINCIPAL` | `SKIP`); a
  TENANT limit without a `TenantResolver` bean warns at startup.
- **Parking is bounded (the security review M4):** a parked call consumes the call budget (its later execution is not charged
  again), pending decisions are capped per principal (`agentguard.approval.max-pending-per-principal`, default 20,
  `AG-APPROVAL-008`), arguments are capped (`max-argument-bytes`, default 64 KiB, `AG-APPROVAL-009`), and the
  dedup key includes the tenant so `admin@tenant-2` never receives `admin@tenant-1`'s stored result.
- **Coverage is checked (the security review H2):** Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline
  `.tools(obj)` / `ToolCallbacks.from` / resolver-by-name included); MCP single and list specification beans are
  wrapped; async (WebFlux) specifications fail startup; `agentguard.strict=true` fails startup when a scanned
  `@ToolPolicy` is not reachable through a guarded path, and the startup log lists the guarded tools.

## Threat 6 — Audit tampering
- **Mitigation:** hash chain (`hash = SHA-256(canonical(row) || prevHash)`) with a **length-prefixed** canonical form
  (`ag1|<len>:<value>|…`, nulls as `-`), so no rewrite can move a boundary between fields (the security review M2); the approver
  is part of the material (`actor_id`, the security review M1); timestamps are truncated to milliseconds in `AuditEvent` so every
  store round-trips them; appends are serialised by a PostgreSQL transaction-scoped advisory lock; triggers refuse
  UPDATE, DELETE **and TRUNCATE**; a separate **anchor row** (`agentguard_audit_anchor`: head hash + row count) is
  written in the same transaction, and `AuditChainVerifier` reports `EMPTY` / `INTACT` / `BROKEN` /
  `ANCHOR_MISMATCH` — tail deletion or truncation by a role that can disable triggers is detected.
- **Residual (the security review R4):** the runtime role needs UPDATE on the anchor row, so anyone with that grant (or the
  owner) can reset the anchor after trimming the tail; the anchor raises the bar only when roles are split as
  described below. A role that owns the tables can rewrite chain **and** anchor consistently. Run the application with a
  least-privilege role (INSERT + SELECT on `agentguard_audit`, UPDATE on the anchor row only, no DDL, not the table
  owner) and keep `agentguard.jdbc.initialize-schema` for a migration step run by the owner role; log or export the
  head hash periodically. An HMAC-keyed chain and external anchoring stay pro items.
- **Test:** `JdbcAdaptersIntegrationTest.audit_*`, `AuditChainVerifierTest`, `CipherProbeJdbcTest`,
  `CipherProbeAuditChainTest`.

## Operational hazards
- **Redis + virtual threads on JDK 21–23 (the security review H3).** The pin is not in Jedis itself but in commons-pool2's growth
  path: `GenericObjectPool.create()` holds a monitor (`makeObjectCountLock`) around the Jedis handshake I/O. A virtual
  thread blocked on that `monitorenter` pins its carrier; once every carrier is pinned the threads doing the handshake
  never get scheduled again and the JVM hangs. Reproduced with 64 virtual threads on a cold pool of 4: zero
  completions after 10 s; the same on platform threads completes in 62 ms (`CipherProbeJedisPinningTest`, profile
  `pinning-probe`). It recurs every time the pool has to grow (idle eviction after 60 s, Redis restarts). **Fix
  shipped:** the pool is pre-filled at startup from the platform startup thread (`min-idle = max-total`,
  `prepare-pool=true`, `agentguard.redis.pool.*`) so it never grows under load; size `max-total` at or above peak
  concurrent tool calls. Proven: 200 virtual threads on 8 pre-filled connections finish in 76 ms. JDK 24 (JEP 491)
  removes the pinning. Residual (the security review R6): after a Redis restart or failover the destroyed connections are
  re-created on the next borrow, so the growth path (and the pin) is possible for that window; running
  `JedisBudgetStore` calls on a small platform-thread executor is the belt-and-braces option.
- **Hand-built managers (the security review R3):** a `DefaultToolCallingManager` built in code and handed to a `ChatModel`
  builder never passes through the context, so it is not guarded and strict mode cannot see it. Use the
  `ToolCallingManager` bean or wrap yours with `AgentGuard.guard(manager)`.
- **Guard failures are structured (the security review M6):** any failure of the guard's own infrastructure (store, audit sink,
  notifier, JSON, security context) becomes `{"error":"GUARD_UNAVAILABLE","code":"AG-GUARD-001","correlationId":…}`
  on both paths; the cause is logged server-side at ERROR with that correlation id, and the tool is not run. Tool
  authors' own exception messages still reach the model (300 chars): do not put secrets in exception messages.
- **Endpoints refuse anonymous approvers (the security review M7):** 401 unless `agentguard.endpoints.allow-anonymous=true`
  (trial only). Still put Spring Security in front of `/agentguard/**` (the sample: `hasRole("APPROVER")`).

## Review status
the security review's adversarial pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, four passes): H1–H3, M1–M7, R1, R2, R5
fixed and re-verified; under the no-allowance rule every LOW and INFO (L1–L10, I1–I9, R3, R4, R6–R11) is fixed on
the branch with its probe flipped. Documented residuals that remain by design: a role that *owns* the tables can
drop the append-only and anchor triggers (split roles, see docs "Database roles"; external anchoring and the
keyed chain reduce what such a role can do silently); a `ToolCallingManager` built by hand and handed to a
`ChatModel` builder is outside the guard (use the bean or `AgentGuard.guard(manager)`); on JDK 21–23 Redis calls run
on platform threads so the pool's growth lock is never touched by a virtual thread.

## Reviewer checklist (before the first public release)
- [ ] Dependency scan (`./mvnw -Psecurity-scan verify`) clean or triaged.
- [x] Fuzz `ArgumentRedactor` with adversarial JSON (done by the security review; L5 closed with the JSON-aware redactor).
- [ ] Confirm no secret / PII reaches logs in the sample run (grep the log for `hunter2`, `Bearer `, IBAN-like patterns).
- [ ] Two-role database setup documented and used by the sample compose file.
- [x] Threat model the webhook (done by the security review; L6 closed: https, HMAC signature, timestamp).
