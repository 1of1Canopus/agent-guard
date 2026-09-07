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
- **The size cap is first on every path, including the two that need no policy at all (the security review V1):**
  `ToolGuard.guarded` applies `rejectIfTooLarge` before `policies.resolve`, so an unregistered tool or a rule with
  no matching role — both reachable by any caller — are refused as oversized before anything canonicalises
  (parses) the arguments. Previously only `gate`/`dispatch` (the policy-matched paths) capped first; the two
  denial paths above them canonicalised the full payload for their audit row regardless of size.
- **Coverage is checked (the security review H2):** Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline
  `.tools(obj)` / `ToolCallbacks.from` / resolver-by-name included); MCP single and list specification beans are
  wrapped; async (WebFlux) specifications fail startup; `agentguard.strict=true` fails startup when a scanned
  `@ToolPolicy` is not reachable through a guarded path, and the startup log lists the guarded tools.
- **Tenant scoping fails closed (the security review C9):** `agentguard.endpoints.require-tenant` defaults `true` whenever
  `tenant-scoped` is on: an approver whose `TenantResolver` yields no tenant (missing claim, service account,
  misconfigured resolver) is refused (403, `AG-HTTP-403`) instead of silently seeing and deciding every tenant's
  decisions and audit rows. A genuinely single-tenant deployment (no `TenantResolver`, as in the sample) should set
  `agentguard.endpoints.tenant-scoped=false` explicitly; set `require-tenant=false` only for a deliberate
  cross-tenant approver role. **The opt-out is no longer silent (the security review V4):** `AgentGuardStartupCheck` warns at
  startup when `endpoints.enabled` and either `tenant-scoped=false` or `require-tenant=false`, naming the property
  and the consequence, alongside its existing warnings for an empty `approval-required-for`, an empty
  `sensitive-keys`, `store=MEMORY`, a missing notifier, a missing `TenantResolver` and a runtime role that owns the
  audit table. The tenant filter is also pushed into the store query
  (`DecisionStore.findByState(state, tenantId, limit)`, `AuditReader.latest(tenantId, limit)`, the security review C10) instead of
  applied after the page's `limit`, so a busy neighbour tenant cannot hide a tenant's own pending work.

## Threat 6 — Audit tampering
- **Mitigation:** hash chain (`hash = SHA-256(canonical(row) || prevHash)`) with a **length-prefixed** canonical form
  (`ag1|<len>:<value>|…`, nulls as `-`), so no rewrite can move a boundary between fields (the security review M2); the approver
  is part of the material (`actor_id`, the security review M1); timestamps are truncated to milliseconds in `AuditEvent` so every
  store round-trips them; appends are serialised by a PostgreSQL transaction-scoped advisory lock; triggers refuse
  UPDATE, DELETE **and TRUNCATE**; a separate **anchor row** (`agentguard_audit_anchor`: head hash, row count and
  `keyed`) is written in the same transaction, and `AuditChainVerifier` reports `EMPTY` / `INTACT` / `INTACT_UNKEYED`
  / `BROKEN` / `ANCHOR_MISMATCH` / `NO_ANCHOR` — tail deletion, truncation, or a downgraded keyed chain, by a role that can
  disable triggers, is detected; a missing anchor is reported, not silently guessed past.
- **Residual (the security review R4):** a role that owns the tables can disable the append-only and anchor triggers and rewrite
  chain, anchor **and** `keyed` consistently — run the application with a least-privilege role (INSERT + SELECT on
  `agentguard_audit`, INSERT/SELECT/UPDATE on the anchor, no DDL, not the table owner) and keep
  `agentguard.jdbc.initialize-schema` for a migration step run by the owner role; log or export the head hash
  periodically. The anchor's `agentguard_audit_anchor_no_delete`/`_no_truncate` triggers (the security review F3(a)) mean that
  role cannot lose the anchor row even by accident.
- **Keyed-from-birth (design change, QUESTIONS.md #20, superseding the earlier per-row-version design and the security review
  C6/V2/F1–F4):** a trail is keyed from row 1 or unkeyed forever — no mixing, no later switch.
  `agentguard.audit.hmac-secret` is **required by default**; missing, startup fails naming the property and the
  remedy (`openssl rand -base64 32`). The explicit local-dev opt-out, `agentguard.audit.unkeyed=true`, starts
  unkeyed but warns at every startup, not only the first. Which mode a trail is in is recorded once, at the first
  append, on `agentguard_audit_anchor.keyed` (a plain boolean, immutable afterwards via the anchor's existing
  monotonic trigger — the same protection `head_hash`/`row_count` already had). Every later append, from this
  instance or any other, must agree with it or is refused with `AG-AUDIT-001`, naming the property and the remedy
  (start a new trail — see below). This is what makes a **rolling restart that changes
  `agentguard.audit.hmac-secret` unsafe by itself**: stop every instance before starting the first one with the
  new setting, or the mismatched instance is refused rather than silently corrupting the trail (the earlier
  per-row-version design could not detect this at all).
- **Key rotation, from row 1 (amendment, the maintainers, after the security review's design review):** the key id
  (`agentguard.audit.hmac-key-id`, default `k1`) is baked into every row's hashed material — the canonical form is
  `version|key_id|timestamp|…`, so relabelling a row's `key_id` without the matching secret still fails to
  recompute the hash. This makes rotation data, not a chain-format break: `agentguard_audit.key_id` records which
  key signed each row (`'none'`/`AuditChain.UNKEYED_KEY_ID` for unkeyed rows); `AuditChainVerifier` holds a
  keyring (the current key plus every id in `agentguard.audit.hmac-keys.<id>`) and picks the right secret per row
  by its `key_id`. A row claiming an id the keyring does not hold is `BROKEN`, not skipped or treated as unkeyed.
  This is not a second mode switch on top of keyed-from-birth: `keyed` still only says whether the trail is keyed
  at all (immutable); `key_id` says which already-trusted key signed a given row within that mode, and a
  table-owning attacker can only relabel to an id whose secret they also hold.
- **Anchor-missing refused, never guessed (amendment, superseding the F1/F2 sequence-position mechanism and the
  prior schema-seed-from-an-existing-trail behaviour):** `JdbcAuditSink` no longer re-derives a lost anchor's
  state from the trail head — that was exactly the kind of guess the anchor exists to make unnecessary, the same
  class of gap the retired `keyed_from_seq` findings were about. A trail with rows but no anchor row is refused
  with `AG-AUDIT-002`, on both the next append and at the next startup; the schema step's seed only ever creates
  the anchor row for a genuinely empty trail (`INSERT … WHERE NOT EXISTS (SELECT 1 FROM agentguard_audit)`), never
  by deriving `keyed`/`head_hash`/`row_count` from existing rows. Recovery is an owner-run procedure — see
  "Starting a new trail" in docs/index.md — not something an application instance does for itself.
- **`NO_ANCHOR` unconditionally, keyed or unkeyed (amendment, widening the security review F3(a)):** the first version of this
  fix only refused to render `INTACT` when a key was *given* to the verifier; an unkeyed verification against an
  unanchored reader still silently fell back to the old in-trail rule. `AuditChainVerifier.verify` now reports the
  distinct `Status.NO_ANCHOR` whenever the reader is not an `AuditAnchor`, or has no anchor row, and the trail is
  not empty — regardless of whether a key was configured. The `Report` also now carries the trail's mode
  (`anchored`, `keyed`, `keyIds`), and an unkeyed trail's clean result renders as the distinct `Status.INTACT_UNKEYED`,
  never plain `INTACT` — an operator glancing at a status word can no longer mistake "nothing is signing this
  trail" for "the signature checked out". A table-owning attacker's row-level rewrite (even a whole-trail
  downgrade to `ag1`/GENESIS from a genuinely keyed trail — the security review's original V2 repro) cannot also flip `keyed`,
  which lives outside the rows they rewrite.
  **Residual, unchanged from R4:** the table owner can disable the anchor's trigger and rewrite `keyed` along with
  everything else; run the application with a role that does not own the tables (see "Database roles" below).
- **`InMemoryAuditSink` has no external anchor (the security review H3, doc-only):** its `anchor()` is derived from the very
  events list it anchors (`headHash`/`rowCount` from the last event, `keyed` from the instance's own `AuditChain`),
  not a separate record like `JdbcAuditSink`'s anchor row. It therefore cannot detect its own tail being trimmed —
  a trimmed in-memory trail still verifies `INTACT`/`INTACT_UNKEYED` with `anchored() == true`. Tests and
  development only; not a substitute for the JDBC store in any deployment where the audit trail matters.
- **Test:** `AuditChainVerifierTest.a_key_given_with_no_anchor_reports_no_anchor_never_intact`,
  `AuditChainVerifierTest.an_unkeyed_trail_never_renders_plain_intact`,
  `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` (partial downgrade),
  `CipherProbeReverifyTest.probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` (the security review's original
  whole-trail repro), `CipherProbeAnchorKeyingJdbcTest` (F1–F4 replacements: mismatched instances refused at
  startup and on append, anchor DELETE/TRUNCATE refused, `NO_ANCHOR`, an orphaned keyed trail refusing to append,
  mixed-key rows verifying `INTACT` with both keys in the keyring, an unknown key id reporting `BROKEN`, a
  stale-key second instance during a rotation), `CipherProbeReverifyJdbcTest
  .a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor`,
  `AgentGuardAutoConfigurationTest.missing_hmac_secret_fails_startup_naming_the_property_and_the_remedy`,
  `AgentGuardAutoConfigurationTest.unkeyed_opt_out_starts_but_warns_every_time`.
- **Two `args_hash` domains (the security review V3):** `ArgumentCanonicalizer.hash` (used for every decision and normal audit
  row) hashes `"agcanon1:" + canonical(argumentsJson)`; `AuditRecorder.recordOversized` (the size-cap denial)
  hashes `"agraw1:" + argumentsJson`. Before this, both landed in the same SHA-256 space with no domain separation,
  and canonicalisation is not size-preserving (an unpaired surrogate is 1 raw UTF-8 byte, 6 after the `\u` escape),
  so a payload under the cap could have a canonical form over it — replayed raw, it hashed identically to its own
  denial. `ToolGuard.rejectIfTooLarge` also checks the canonicalised length once the raw check has already bounded
  the parse cost, so that payload is refused as oversized on the canonical check too, not silently allowed through.

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
- **The platform-thread pool fails closed, on purpose (the security review C7/C8):** the pool backing `JedisBudgetStore` is a
  bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to `agentguard.redis.pool.max-total`, `AbortPolicy`), not
  an unbounded queue: a call that misses `maxWait` is cancelled and removed from the queue instead of being
  abandoned there, and a saturated pool refuses new calls immediately with `AG-GUARD-001` rather than queueing
  behind a growing backlog. This means a burst well past `max-total` concurrent callers gets guard-unavailable
  errors (the guard fails closed, denying the tool call) instead of eventually succeeding once Redis catches up —
  size `max-total` at or above the real peak concurrency, the same sizing guidance as above. `JedisBudgetStore`
  implements `AutoCloseable` and its `close()` shuts the pool down; the auto-configured bean is picked up by
  Spring's default inferred destroy method, so a context that rebuilds it (devtools restart, `@DirtiesContext`) does
  not leak `agentguard-redis` threads.
- **Platform-thread pool sizing is decoupled from the Redis connection pool (the security review V5):**
  `agentguard.redis.pool.platform-thread-count` and `.platform-thread-queue-size` (both default `max-total` when
  unset) size the worker pool and its bounded queue independently of `max-total` (the Jedis connection pool). A
  small, deliberately contended connection pool (to exercise H3/R6-style contention) and a large burst of
  concurrent virtual-thread callers are two different numbers: workers just block on the connection pool, the way
  a virtual thread must never be allowed to.
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
the security review's adversarial pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, seven passes): H1–H3, M1–M7, R1, R2, R5
fixed and re-verified; under the no-allowance rule every LOW and INFO of the first four passes (L1–L10, I1–I9, R3,
R4, R6–R11) and every finding of the clean-verdict pass (C4 MEDIUM; C1, C2, C5, C7, C9, C11 LOW; C3, C6, C8, C10,
C12 INFO) is fixed on the branch with its probe flipped. The re-verification round (V1 MEDIUM, V2 MEDIUM, V3 LOW,
V4 LOW, V5 LOW) is fixed on the branch, with its probes flipped. V2's first fix (the `keyed_from_seq` anchor field,
QUESTIONS.md #20) was itself re-verified and found to have its own plumbing wrong (F1/F2 MEDIUM: written from the
wrong sequence, forgotten by the schema seed) and its silent-fallback gap unclosed (F3 MEDIUM: no DELETE/TRUNCATE
guard on the anchor, no distinct status for an unanchored verification) and a rolling-restart hole (F4 LOW). Rather
than patch the sequence-position mechanism further, the design changed: **keyed-from-birth** (QUESTIONS.md #20,
same question, later ruling) — a trail is keyed from row 1 or unkeyed forever, recorded once as a plain
`agentguard_audit_anchor.keyed` boolean, `agentguard.audit.hmac-secret` required by default. This closes V2 in
full (including the security review's original whole-trail repro) more simply than the sequence-position design did, and closes
F3(a) (the anchor DELETE/TRUNCATE guard, independent of the migration) directly; F1/F2/F4 against the old mechanism
no longer apply (there is no sequence arithmetic and no accommodating-a-later-key-enable left to get wrong) — see
QUESTIONS.md #20, the audit-tampering section above, and `docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Design
change: keyed-from-birth". Documented residuals that remain by design: a role that *owns* the tables can drop the
append-only and anchor triggers, rewriting the trail, the anchor's head/count *and* `keyed` consistently (split
roles, see docs "Database roles"); a `ToolCallingManager` built by hand and handed to a `ChatModel` builder is
outside the guard (use the bean or `AgentGuard.guard(manager)`); on JDK 21–23 Redis calls run on platform threads so
the pool's growth lock is never touched by a virtual thread; a burst past `agentguard.redis.pool.max-total`
concurrent callers now fails closed (`AG-GUARD-001`) instead of queueing unboundedly, by design (the security review C7) — size
the pool at or above real peak concurrency, and size `platform-thread-count`/`platform-thread-queue-size` (the security review
V5) at or above real peak concurrent tool calls independently of `max-total` if the connection pool itself is
deliberately smaller.

## Reviewer checklist (before the first public release)
- [ ] Dependency scan (`./mvnw -Psecurity-scan verify`) clean or triaged.
- [x] Fuzz `ArgumentRedactor` with adversarial JSON (done by the security review; L5 closed with the JSON-aware redactor).
- [ ] Confirm no secret / PII reaches logs in the sample run (grep the log for `hunter2`, `Bearer `, IBAN-like patterns).
- [ ] Two-role database setup documented and used by the sample compose file.
- [x] Threat model the webhook (done by the security review; L6 closed: https, HMAC signature, timestamp).
