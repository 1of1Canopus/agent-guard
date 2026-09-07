# SECURITY-REVIEW — branch `feat/agent-guard-core` (Agent Guard free core)

Reviewer: `cipher` (adversarial pass, per `AGENTS.md` "Cipher — security review on EVERY PR").
Date: 2026-09-06. Scope: `agent-guard-core`, `agent-guard-spring-boot-starter`, `agent-guard-sample`, build and
workflows, at commit `0d5e840`. Read first: `SPEC.md` (Threats), `SECURITY-NOTES.md`, `QUESTIONS.md`, `STATUS.md`.

Method: every claim below is backed by a probe test named `CipherProbe*` that **passes against the current code**
(it asserts the weakness). When the engineering agent fixes an item, the matching probe must be flipped or deleted
in the same PR; a probe that starts failing is the signal that the item is closed. Production code was not touched.

Probes (32, all green with `./mvnw -B clean verify`, which stays green):

| Module | Class | Probes |
|---|---|---|
| core | `application/CipherProbeApprovalGateTest` | 10 |
| core | `domain/CipherProbeAuditChainTest`, `domain/CipherProbeRedactorTest` | 1 + 4 |
| core | `adapter/jdbc/CipherProbeJdbcTest` (Testcontainers PostgreSQL) | 5 |
| core | `adapter/redis/CipherProbeJedisPinningTest` + `CipherProbeJedisPinningMain` (child JVM, Testcontainers Redis) | 2 |
| starter | `ai/CipherProbeSpringAiTest`, `mcp/CipherProbeMcpTest`, `web/CipherProbeEndpointsTest`, `autoconfigure/CipherProbePropertiesTest` | 3 + 3 + 1 + 3 |

---

## Verdict

**Not mergeable as is.** The core design is sound (enum state machine, execute-once ledger, args-hash binding,
fail-closed defaults, parameterised SQL, structured errors). The problems sit at the integration seams and in the
guarantees the audit trail claims to give. Three HIGH findings must be fixed before merge; the seven MEDIUM findings
must be fixed or explicitly accepted by Souhaile. LOW/INFO can ride along or go to the backlog.

| Severity | Count | Ids |
|---|---|---|
| HIGH | 3 | H1 resume runs in the wrong identity/context · H2 silent coverage gaps (Spring AI inline tools, MCP single/async specs) · H3 Redis store + virtual threads deadlocks the JVM at default settings |
| MEDIUM | 7 | M1 approver not in the hash chain · M2 audit chain: ambiguous canonical form, TRUNCATE, tail deletion, timestamp precision · M3 conversation/tenant budgets skipped or client-controlled · M4 parking unbounded + cross-tenant principal collision · M5 approver decides on a truncated preview and attests only an id · M6 guard failures leak internal messages to the model/MCP client · M7 anonymous approver accepted by the endpoints |
| LOW | 10 | L1–L10 |
| INFO | 9 | I1–I9 |

---

## HIGH

### H1 — Resumed execution runs with the last caller's closure and the approver's security context
**Where:** `application/ToolGuard.gate` (`executors.register(tool.name(), executor)`), `application/ToolExecutorRegistry`,
`application/DecisionResumer.executeOnce`, `ai/GuardedToolCallback` (closure captures `toolContext`),
`mcp/McpToolGuard` (closure captures `exchange`/`ctx`).

**Repro:** `CipherProbeApprovalGateTest.probe_executor_registry_is_keyed_by_tool_name_so_resume_runs_the_last_callers_closure`
and `CipherProbeSpringAiTest.probe_resume_runs_with_the_last_callers_tool_context_and_the_approvers_security_context`.
Bob (tenant `acme`) parks `refundOrder(1)`; Carol (tenant `globex`) parks `refundOrder(2)`; Alice approves Bob's
decision. The tool executes with `ToolContext{tenantId=globex}` and `SecurityContextHolder` = `alice`
(result: `refunded 1 tenant=globex runAs=alice`).

**Impact:** The executor registry is a global map keyed by tool name, overwritten on every park. On resume the
approved call of user A runs inside the `ToolContext` (Spring AI's documented way to pass user/tenant data to tools)
or the `McpSyncServerExchange` (logging/sampling go to the other client's session) of whichever caller parked that
tool last, and on the approver's thread, so tools that read the security context (`@PreAuthorize`, tenant filters,
Tenantify) run **as the approver**, who normally has more rights than the agent. This is tenant confusion and
privilege confusion at the same time, and it is routine in any multi-user deployment, not an edge case. After a
restart the registry is empty and the approval fails with `AG-APPROVAL-007` (fine), but before a restart it silently
uses the wrong context.

**Fix:** (1) Register the executor **per decision id**, not per tool name; on resume use the closure captured for
that decision or fail with `AG-APPROVAL-007`. (2) Run the resumed call inside a security context rebuilt from the
stored `PendingDecision.principal()` (a `RunAs` authentication carrying the stored roles/scopes/tenant), restore the
previous context afterwards; make this an SPI (`ResumeContextProvider`) so hosts can rehydrate their own context.
(3) Persist a serialisable snapshot of the tool context with the decision (or refuse to park tools whose method
takes `ToolContext`/`McpSyncServerExchange` unless the SPI is provided). (4) Document that the approved call runs on
the approver's request thread.

### H2 — Enabling the guard does not guard everything: silent coverage gaps on both integrations
**Where:** `ai/ToolCallbackGuardBeanPostProcessor` (wraps `ToolCallback`/`ToolCallbackProvider` **beans** only),
`autoconfigure/ToolPolicyAnnotationScanner` (registers `@ToolPolicy` of any bean, whether or not its callbacks are
guarded), `mcp/McpToolSpecificationGuardBeanPostProcessor` (wraps `List<SyncToolSpecification>` beans only).

**Repro:** `CipherProbeSpringAiTest.probe_inline_tool_objects_bypass_the_guard_although_their_policy_was_scanned`:
`ToolCallbacks.from(new OrderTools())` (what `ChatClient.prompt().tools(obj)` does) executes a `DESTRUCTIVE`
`@ToolPolicy(roles="SUPPORT")` tool for a `VIEWER` with no approval, no budget and no audit row, while
`ToolPolicyRegistry.find("refundOrder")` is present. `CipherProbeMcpTest.probe_single_spec_beans_and_async_spec_lists_are_silently_unguarded`:
a `SyncToolSpecification` bean (not in a `List`) and a `List<AsyncToolSpecification>` (WebFlux server) execute for an
anonymous caller, nothing audited. No warning at startup in either case.

**Impact:** The most common Spring AI usage (`.tools(obj)`, `.toolCallbacks(...)` built inline, `FunctionToolCallback`
built in code) bypasses the guard entirely, while the scanned policy gives the developer a false sense of
enforcement. Spring AI's function-bean resolution by name (`SpringBeanToolCallbackResolver`, not on this classpath,
unverified) follows the same pattern. On MCP, hand-written spec beans and every async server are unguarded with
`agentguard.enabled=true`. For a product whose one promise is "policy holds", silent non-enforcement is a HIGH.

**Fix:** Decorate at the framework chokepoint instead of at bean creation: provide a `ToolCallingManager` bean (or
a `BeanPostProcessor` wrapping `DefaultToolCallingManager`) whose `executeToolCalls` guards every callback it
resolves, so inline tools are covered. For MCP: wrap single `SyncToolSpecification` beans, implement the
`AsyncToolSpecification` wrapper (blocking stores on `Schedulers.boundedElastic()`) or **fail startup** when async
specs exist. Log a startup summary ("guarded tools: …") and add `agentguard.strict=true` (default) that fails
startup when a tool with a scanned `@ToolPolicy` is not reachable through a guarded path.

### H3 — `agentguard.budgets.store=REDIS` + virtual threads: the whole JVM deadlocks on a burst at default settings
**Where:** `adapter/redis/JedisBudgetStore` (any call), `autoconfigure/JedisBudgetStoreFactory` (`new JedisPooled(uri)`,
default `maxTotal=8`, no pool properties exposed). Root cause is in `commons-pool2 2.12.1`
`GenericObjectPool.create()`: `synchronized (makeObjectCountLock)` around pool growth while `makeObject()` performs the
Jedis handshake I/O (`Connection.initializeFromClientConfig` → `CLIENT SETINFO` reads). On JDK 21 a virtual thread
blocked on `monitorenter` pins its carrier with no compensation; `Object.wait` inside the same block is compensated
(`Blocker`) but the `monitorenter` contention is not.

**Repro:** `CipherProbeJedisPinningTest.probe_cold_pool_growth_under_virtual_threads_deadlocks_the_jvm_at_default_settings`:
child JVM, default scheduler (10 carriers on this machine, `maxPoolSize=256`), 64 virtual threads × 5
`incrementAndGet` against a cold pool of 4: **zero completions after 10 s** (`HUNG … remaining=64`); the same with
platform threads completes in 62 ms. Thread dump of the hung child: 9 virtual threads at
`GenericObjectPool.create(GenericObjectPool.java:520)` (monitorenter), 1 in `Object.wait` (line 536), 4 unmounted
on the handshake socket read inside `makeObject`, all 10 carriers busy; the 4 connecting threads never get a carrier
to finish, so `makeObjectCount` never drops, so the waiters never wake.

**Assessment of the existing note:** the effect described in `SECURITY-NOTES.md` ("more concurrent tool calls than
carrier threads → deadlock") is real and worse than stated: it happens at **default** settings on the first burst
and reappears every time the pool has to grow again (Jedis evicts idle connections after 60 s, every 30 s; Redis
restarts/failovers destroy connections). The site is wrong: Jedis `Connection` has no monitors; the pin is in
commons-pool2's growth path. With Boot's `spring.threads.virtual.enabled=true` (this shop's default) an MCP server
using Redis budgets hangs entirely: an untrusted agent bursting cheap READ calls is enough to take the service down.

**Proven mitigations** (`probe_mitigations_pool_at_least_concurrency_or_prefilled_pool_complete`): `maxTotal >=`
concurrency (64/64: done in 64 ms), or a **pre-filled pool** (`minIdle = maxTotal`, `pool.preparePool()` from a
platform thread at startup): 200 virtual threads on 8 connections complete in 76 ms.

**Fix:** In `JedisBudgetStoreFactory` set `minIdle = maxTotal`, disable eviction below `minIdle` (default already), call
`preparePool()` at startup, and expose `agentguard.redis.pool.max-total` (+ `max-wait`); document that on JDK 21–23
Redis calls should not run on virtual threads under growth (or run `JedisBudgetStore` calls on a small
platform-thread executor), and that JDK 24 (JEP 491) removes the hazard. Rewrite the SECURITY-NOTES paragraph with
the correct site and the reproduction numbers.

---

## MEDIUM

### M1 — Who approved is not in the tamper-evident trail
**Repro:** `CipherProbeApprovalGateTest.probe_approver_identity_and_time_are_absent_from_the_hash_chained_audit`:
after Alice approves, every audit row has `principalId = agent-1` and no canonical form contains `alice`.
`decided_by`/`decided_at` live only in `agentguard_decision`, which has no append-only trigger and is updated in
place. **Impact:** an auditor cannot prove from the chain who authorised a DESTRUCTIVE call; a DB writer can change
the approver name without touching the chain. **Fix:** add an `actor` field to `AuditEvent` and the canonical form
(schema column `actor_id`), record `APPROVED`/`REJECTED` events with the approver as actor, and include the
approver in the `AuditDecision.APPROVED` row written by `DecisionResumer`.

### M2 — The hash chain is weaker than SECURITY-NOTES claims
**Repros:** `CipherProbeAuditChainTest.probe_canonical_form_is_ambiguous_across_field_boundaries` — `String.join("|")`
lets a rewrite move the boundary between `principalId|tenantId` or `correlationId|decisionId` **without changing the
hash** (e.g. principal `alice|x` tenant `acme` ≡ principal `alice` tenant `x|acme`); `CipherProbeJdbcTest`:
(1) an event appended with sub-millisecond precision verifies as broken after storage (Postgres keeps micros; only
`AuditRecorder` truncates, not the sink/chain), i.e. false tamper alarms for any other producer; (2) `TRUNCATE
agentguard_audit` is not blocked by the row-level trigger and the verifier reports **intact, 0 rows**; (3) the same
credentials that ran the schema can `ALTER TABLE … DISABLE TRIGGER`, delete the last row, re-enable, and the verifier
reports intact. **Impact:** "detectable, not impossible" holds only for mid-chain edits by a careless attacker; the
app's own DB credentials (any SQL injection or RCE in the host app) can erase or trim the trail undetectably.
**Fix:** length-prefixed (or JSON) canonical form; truncate to millis inside `AuditChain.canonical`/the sink; add a
`BEFORE TRUNCATE` statement trigger; make `Report` distinguish `EMPTY` from `INTACT` and let the verifier accept an
expected head hash (anchor) — the free core can at least log the head hash periodically; document split DB roles
(DDL role for `initialize-schema`, runtime role with INSERT only) and default `initialize-schema=false` outside
`MEMORY`/sample; HMAC-keyed chain stays a pro item.

### M3 — Conversation and tenant budgets are skipped or client-controlled
**Repros:** `CipherProbeMcpTest.probe_client_controlled_meta_conversation_id_defeats_the_steps_budget` — a STEPS
limit of 2 per conversation is bypassed by omitting `_meta.agentguard.conversationId` or sending a fresh one per
call (the MCP client, i.e. the untrusted agent, chooses it); `CipherProbeApprovalGateTest.probe_conversation_budget_is_skipped_without_an_id_and_reset_by_rotating_it`.
`BudgetEnforcer.reserve` silently `continue`s when a scope has no subject, so `TENANT` limits do nothing with the
default `TenantResolver` (returns empty) and no warning is logged. **Impact:** SPEC threat 5 ("privilege escalation
via tool chaining … budgets per conversation") is not mitigated on MCP; operators believe a cap exists. **Fix:**
derive the conversation id server-side (MCP session id from the exchange/transport context; Spring AI chat-memory
id) and treat `_meta` as a hint only; when a configured scope has no subject, fail closed (deny, or fall back to
the PRINCIPAL counter) behind `agentguard.budgets.missing-subject=DENY|FALLBACK|SKIP`; warn at startup when TENANT
limits exist with the default resolver.

### M4 — Parking is unbounded, and decisions are keyed without the tenant
**Repros:** `probe_parking_is_not_budgeted_so_pending_decisions_and_notifications_are_unbounded` — with a TOOL_CALLS
limit of 3, 50 WRITE calls with distinct arguments park 50 decisions and fire 50 notifications (webhook POST + WARN
log each; `arguments_json`/`result_json` are unbounded `text`). `probe_same_principal_id_in_another_tenant_receives_the_other_tenants_stored_result`
— `findLatest(principalId, tool, argsHash)` ignores the tenant: `admin@tenant-2` calling with the same arguments as
`admin@tenant-1` receives tenant-1's stored result and never gets a decision of its own. **Impact:** approver-channel
flooding and DB growth driven by a prompt-injected model; cross-tenant result disclosure whenever principal ids are
per-tenant usernames (common with Basic/LDAP/Tenantify). **Fix:** count a park as a call (reserve budget before
parking), cap pending decisions per principal, cap `argumentsJson` size (reject above N KB), include `tenant_id` in
the dedup lookup and its index.

### M5 — The approver decides on a lossy preview and attests only an id
**Repro:** `probe_preview_truncation_hides_trailing_keys_from_the_approver` — a 600-char `send_email` argument with
`"bcc":"attacker@evil.example"` last: the preview ends in `...[truncated]` and does not contain `bcc`; the raw
arguments do. The model controls key order and value length. `POST /decisions/{id}/approve` takes no hash, so what
the human saw is not bound to what runs; `args_preview` is a separate mutable column. **Fix:** structural preview
(parse JSON, mask by key, elide long values per field, never drop keys), an endpoint returning the full **redacted**
arguments, and an optional `argsHash` parameter on approve (409 on mismatch; make it required in strict mode).

### M6 — Guard infrastructure failures escape unstructured to the model / MCP client
**Repros:** `CipherProbeSpringAiTest.probe_guard_infrastructure_failure_escapes_unstructured_to_the_chat_call` and
`CipherProbeMcpTest.probe_guard_infrastructure_failure_escapes_as_a_raw_exception_to_the_mcp_layer` — an audit sink
that throws `"… Connection to db.internal:5432 refused (user agentguard)"` propagates as a raw `IllegalStateException`
out of `GuardedToolCallback.call` / the MCP `callHandler`. Verified in the jars: MCP SDK 2.0.0
`McpServerSession.handleIncomingRequest` maps it to a JSON-RPC error whose message is `Throwable.getMessage()`
(with causes, `McpError.aggregateExceptionMessages`) → sent to the client; Spring AI 2.0.1 `DefaultToolCallingManager`
only processes `ToolExecutionException`, so the chat call itself aborts with the exception. Same path for
`ArgumentsTamperedException`, `JdbcAccessException` (which embeds the SQL error text), notifier exceptions.
**Impact:** internal hostnames/users/SQL reach the untrusted agent, and on Spring AI the user-facing request fails
instead of the tool. Still fail-closed, so MEDIUM. **Fix:** catch `RuntimeException` around the pipeline in
`ToolGuard.execute` (and in the adapters), return `GuardResult.Failed` with a new code `AG-GUARD-001 "guard
unavailable"` and the correlation id, log the cause server-side at ERROR.

### M7 — Endpoints accept an anonymous approver
**Repro:** `CipherProbeEndpointsTest.probe_anonymous_approver_is_accepted_when_no_filter_chain_protects_the_endpoint`
— with no security filter chain, `POST /agentguard/decisions/{id}/approve` returns 200, `decidedBy = "anonymous"`,
`executed = true` for a DESTRUCTIVE call. `AgentGuardEndpoints.name()` falls back to `anonymous` and
`ApprovalService.approve` accepts it. **Impact:** the starter explicitly supports running without Spring Security
(`anonymousPrincipalResolver`), and a `permitAll()` matcher or an internal-network deployment is a one-line
mistake; the endpoints are off by default and Boot's default chain does return 401, which is why this is MEDIUM
not HIGH. **Fix:** in `AgentGuardEndpoints` (and `ApprovalService`) refuse `Principal.ANONYMOUS_ID` as approver with
401/403 unless `agentguard.endpoints.allow-anonymous-approver=true`; document the required role and add the
sample's `hasRole("APPROVER")` line to the starter docs.

---

## LOW

- **L1 — No four-eyes rule.** `probe_self_approval_is_accepted`: the parking principal can approve its own decision.
  Fix: reject `approver == decision.principal().id()` unless `agentguard.approval.allow-self-approval=true`.
- **L2 — Tamper detection is not audited.** `probe_tamper_detection_leaves_no_audit_row`: `ArgumentsTamperedException`
  writes nothing to the trail and leaves the decision `APPROVED, executed=false`. Fix: record a `FAILED` (or new
  `TAMPERED`) event and move the decision to a terminal error state.
- **L3 — Policy is not re-evaluated at resume.** `probe_policy_tightened_after_parking_is_not_rechecked_at_resume`:
  roles revoked or rules tightened between park and approve do not matter. Fix: re-run `ToolPolicyEvaluator` with
  the stored principal at resume (cheap) and offer a `PrincipalRefresher` SPI for live role lookup.
- **L4 — Dedup has no time bound.** `probe_an_approved_decision_answers_identical_calls_with_the_stale_result_forever`:
  30 days later the same call returns the stored result and never runs; a REJECTED decision is a permanent block.
  Fix: bound `findLatest` to the decision TTL (or a configurable replay window) and document.
- **L5 — Redactor gaps** (`CipherProbeRedactorTest`): array/object values under sensitive keys leak
  (`{"password":["hunter2"]}`, `{"api_key":{"value":…}}`); JSON `\u`-escaped keys (`"password"`) bypass the
  match on the Spring AI path, where the model's JSON text is used verbatim (Jackson would still deliver the
  `password` parameter to the tool); U+0085 (NEL) and U+202E (bidi override) pass the control-character filter.
  Fix: parse the JSON (fall back to full mask when unparseable), mask by key regardless of value shape, strip
  `\p{Cc}\p{Cf}` plus U+0085/U+2028/U+2029.
- **L6 — Webhook secret in the clear / no signature.** `WebhookNotifier` sends a static `X-AgentGuard-Token` over
  whatever scheme is configured (`http://` allowed) and cannot be verified per message. Fix: refuse non-`https`
  unless loopback, add `X-AgentGuard-Signature: sha256=HMAC(secret, timestamp.body)` with a timestamp header.
- **L7 — Property validation misses the convention.** `CipherProbePropertiesTest`: `agentguard.approval.ttl=PT0S`
  fails with "approval ttl must be positive", `budgets.limits[0].window=PT0S` with "window must be positive" —
  neither names the property; empty `policy.approval-required-for` (no approvals at all, DESTRUCTIVE runs directly)
  and empty `redaction.sensitive-keys` (nothing masked) are accepted silently. Fix: `@DurationMin`/custom validator
  with the `<module>.<prop> …` message; WARN at startup for the two empty sets.
- **L8 — Budget table hygiene.** `CipherProbeJdbcTest`: expired `agentguard_budget` rows are never purged (one row
  per subject per window, forever); a subject longer than the `varchar(512)` key fails the call (fail closed, but a
  client-chosen conversation id can trigger it). Fix: purge on increment (`DELETE … WHERE expires_at < now() - 1 day`
  every N calls) or a scheduled purge; hash the subject into the key.
- **L9 — Sample hardening.** `csrf.disable()` with HTTP Basic makes `POST …/approve` CSRF-able from a browser that
  cached the credentials; `{noop}` passwords. Fine for a sample, but say so in the README.
- **L10 — `initialize-schema=true` by default** runs DDL (`CREATE OR REPLACE FUNCTION`, `DROP/CREATE TRIGGER`) with
  the runtime credentials on every start, three times (`jdbc()` is called from three bean methods), and steers users
  towards a schema-owner runtime role that defeats the append-only trigger (see M2). Fix: run once, default to
  `false` outside the sample, document the two-role setup.

## INFO

- **I1** `argsHash` is over the raw JSON text, not a canonical form: whitespace/key-order differences park a second
  decision instead of deduplicating (safe direction; approvers may see duplicates).
- **I2** On MCP, a tool result with `isError=true` after approval is stored as the final result; a transient failure
  needs a new approval. Document.
- **I3** `ToolPolicyAuthorizationManager` builds the principal with `from(auth)` without the anonymous check:
  `AnonymousAuthenticationToken` becomes id `anonymousUser` with role `ANONYMOUS`, while the resolver yields
  `anonymous`. Harmless today, inconsistent ids in audit.
- **I4** Decision and audit endpoints are not tenant-scoped (pro item); any approver sees every tenant's previews and
  raw results (`DecisionResponse.result`).
- **I5** `Errors.describe` forwards the tool's own exception message (300 chars) to the model: tool authors must not
  put secrets in exception messages. Document.
- **I6** `ToolPolicyRegistry.register` is last-wins; two beans declaring the same tool name with different policies
  silently keep one. Fail at startup on conflicting duplicates.
- **I7** The hash chain has no secret: anyone with INSERT can extend it consistently, anyone with rewrite access can
  recompute it (documented residual; HMAC is the pro answer).
- **I8** `STEPS` and `TOOL_CALLS` are the same counter with different names today; `TOKENS` is checked with
  `requestedUnits=1`, so one call can overshoot the token cap by its own size, and nothing calls `recordTokens` yet
  (QUESTIONS #8). Document until the advisor exists.
- **I9** Supply chain (see "what is fine" for what is pinned): workflows have no `permissions:` block (default
  token scope), actions pinned by tag (`@v4`) not SHA, `maven-wrapper.properties` has no `distributionSha256Sum`,
  Testcontainers/compose images by tag (`postgres:16-alpine`, `redis:7-alpine`) not digest, `wiremock-standalone
  3.13.1` declared in the starter but unused (no `wiremock` reference in test sources). Fix before the repo goes
  public: `permissions: contents: read`, SHA-pin actions, add the wrapper checksum, digest-pin images, drop WireMock.

---

## What is fine (verified by reading and by existing tests / probes)

- **Approval state machine and single execution.** `DecisionState` is a 40-line enum SM; every non-PENDING source
  throws; transitions and `markExecutedOnce` are single conditional `UPDATE`s (CAS) — exactly-once under 50
  concurrent approvers is covered by `JdbcAdaptersIntegrationTest`; second approval is a no-op returning the stored
  result; expired decisions cannot be approved; approve-vs-expire races are settled by the CAS on `state`.
- **Args-hash binding.** `PendingDecision.argsHash = SHA-256(argumentsJson)`, recomputed before execution; the agent
  re-calling with different arguments parks a new decision, never resumes the old one.
- **Decision ids** are `UUID.randomUUID()` (122 random bits), validated by `UUID.fromString` at the endpoint (400 on
  garbage), and never accepted from the model for anything but display.
- **Policy is evaluated on the actual call.** Tool name comes from the framework's `ToolDefinition` / `McpSchema.Tool`
  (the model cannot alias it), arguments are the ones about to run; roles/scopes/tenants are exact, case-sensitive
  set membership with no normalisation (so a mismatch fails closed); anonymous is denied on any role/scope/tenant
  restriction; unregistered tools are denied by default; MCP `destructiveHint` is deliberately ignored so an
  unannotated tool cannot become "approved" by a client-supplied hint; the `AuthorizationManager` treats
  `REQUIRE_APPROVAL` as not granted.
- **Structured errors.** Policy, budget and tool failures reach the model as JSON with stable codes, no stack traces,
  messages capped (`Errors.describe`, 300 chars).
- **Budgets.** Increments are atomic in all three stores (Lua `INCRBY`+`PEXPIRE`, Postgres upsert with expiry
  reset, `ConcurrentHashMap.compute`); the window start is part of the key so a lost TTL cannot extend a window;
  a refused attempt still counts (documented); Redis/Postgres overflow raises (fail closed); enforced before
  dispatch and again at resume.
- **Audit fail-closed.** A failing sink blocks the tool call (`AuditRecorder` propagates); rows are appended under a
  transaction-scoped advisory lock, so `seq`/`prevHash` order is linear under 100 concurrent writers (existing test);
  `UPDATE`/`DELETE` are refused by the trigger; only hashes of args/results are stored in the trail.
- **SQL.** Every statement is parameterised; `limit` values are clamped to `1..1000`; enum columns are mapped through
  `valueOf`.
- **Webhook.** URL is operator configuration (no SSRF from the model); `HttpClient` default `Redirect.NEVER` and
  default TLS validation; timeouts applied; only the host is logged; the secret is never logged; payload carries the
  redacted preview, never raw arguments; delivery failures never throw (`CompositeNotifier` isolates notifiers).
- **Secrets/PII in logs.** Raw arguments never reach logs, notifiers or endpoints (`SampleEndToEndTest` and
  `AgentGuardEndpointsTest` assert `argumentsJson` absent); previews are masked, control-stripped and capped; the Redis
  URI is not logged and Boot's sanitiser masks `uri`-typed properties in Actuator.
- **Defaults.** `agentguard.enabled=false`; `store=JDBC` with a startup error naming the property; `MEMORY` warns;
  endpoints off by default; Boot's default security chain returns 401 for them when Spring Security is present.
- **Boundaries.** ArchUnit enforces zero Spring/Jakarta/JDBC/Redis/MCP imports in `domain` and `application`.
- **Build/supply chain.** All dependencies come from the Boot 4.0.8 / Spring AI 2.0.1 BOMs; `maven-enforcer`
  (`dependencyConvergence`, banned duplicates, Java 21); plugin versions pinned; OWASP Dependency-Check profile
  (fail on CVSS ≥ 7) and Dependabot (Maven + Actions) present; GPL/AGPL blacklisted in the third-party notices step.
- **Jedis itself** (`Connection`) has no `synchronized` sections; the virtual-thread hazard is in commons-pool2's
  growth path (H3), which the proposed prefill fix avoids.

---

## Closing notes for the engineering agent

1. Fix H1–H3, then M1–M7 (or get Souhaile's explicit acceptance in `QUESTIONS.md`), flip/delete the matching probes,
   and ping `cipher` for re-verification.
2. Update `SECURITY-NOTES.md`: correct the virtual-thread paragraph (site and numbers), add M2's residuals (TRUNCATE,
   owner role, canonical form) and the approver-in-chain point; the reviewer checklist items "fuzz the redactor" and
   "threat-model the webhook" are done here.
3. The child-JVM pinning probe adds about 25 s to `agent-guard-core` tests (a deliberate 10 s hang, twice); move it
   behind a profile if CI time matters.

---

# Re-verification — commit `e1ca399` (builder's fixes for H1–H3, M1–M7)

Reviewer: `cipher`, 2026-09-06 (second pass). Method: the **original** probes from `259a23b` were re-run unchanged
against `e1ca399` (as throwaway `CipherProbeV1*` copies, not committed) so that a fix shows up as an original probe
failing; the builder's flipped probes were read, not trusted; three new probes were added and committed
(`adapter/jdbc/CipherProbeReverifyJdbcTest`, `ai/CipherProbeReverifySpringAiTest`,
`autoconfigure/CipherProbeJedisFactoryTest`). `./mvnw -B clean verify` is green: core 105, starter 29, sample 1.

## Verdict

**Mergeable after two small follow-ups (R1, R2 below), no design change needed.** All three HIGH and all seven MEDIUM
findings are fixed and confirmed by the original repros. The fixes introduced one behavioural regression (R1: Spring
AI's tool-call limits are dropped when the guarded default manager wins) and one upgrade gap (R2: an existing trail
without an anchor row reads as BROKEN after the first append). Both are a few lines. Everything else found on this
pass is LOW/INFO and can go to the backlog.

## Fix confirmation, item by item

| Id | Original repro against `e1ca399` | Status |
|---|---|---|
| H1 wrong identity/context on resume | `probe_executor_registry_is_keyed_by_tool_name…` **fails** (closure of the parking decision ran: `ToolExecutorRegistry` is keyed by `DecisionId`, released after the run); `probe_resume_runs_with_the_last_callers_tool_context…` **fails** (result `tenant=acme runAs=bob`, approver context restored, verified again in `CipherProbeReverifySpringAiTest`) | fixed |
| H2 silent coverage gaps | inline `ToolCallbacks.from(obj)` is guarded through the `GuardedToolCallingManager` bean (`TOOL_DENIED` for a VIEWER, parked for SUPPORT); single `SyncToolSpecification` beans wrapped (`AG-POLICY-004` for anonymous); a `List<AsyncToolSpecification>` bean **fails startup** (original MCP probe class cannot even build its context); `agentguard.strict=true` refuses to start when an `@ToolPolicy` tool is unreachable | fixed, with residual R3 |
| H3 Redis + virtual threads | `CipherProbeJedisFactoryTest`: the starter's factory with defaults (`max-total=8`, `min-idle=8`, `prepare-pool=true`) completes 200 virtual threads × 5 increments on a cold start in-process with the default scheduler (count 1000, no errors); `preparePool()` runs on the startup platform thread; Redis down at startup fails with a message naming `agentguard.redis.uri`; the child-JVM probe is behind `-Ppinning-probe` | fixed, with residual R6 |
| M1 approver not in the chain | `probe_approver_identity_and_time_are_absent…` **fails**: `actor_id` column, `AuditEvent.actorId` in the canonical form, APPROVED/REJECTED/FAILED-on-resume rows carry the approver; forging the actor breaks the hash | fixed |
| M2 chain weaknesses | canonical form is versioned (`ag1`) and length-prefixed (`<bytes>:<value>`, null as `-`), the original boundary-shift probe **fails**; timestamps truncated to millis in the `AuditEvent` constructor (original sub-millisecond probe **fails**); `BEFORE TRUNCATE` statement trigger (original TRUNCATE probe **errors** with "append-only"); anchor row (`agentguard_audit_anchor`: head hash + row count, written in the same advisory-locked transaction as the append) turns tail deletion and trigger-disabled TRUNCATE into `ANCHOR_MISMATCH`; `Report.status` distinguishes `EMPTY`/`INTACT`/`BROKEN`/`ANCHOR_MISMATCH`; docs describe the two-role setup | fixed, with R2 and residual R4 |
| M3 conversation/tenant budgets | MCP uses the server-side `exchange.sessionId()`; client `_meta` is ignored; missing subject → `AG-BUDGET-002` under strict (`MissingSubjectPolicy` DENY/FALLBACK_TO_PRINCIPAL/SKIP); startup WARN when TENANT limits exist with `NoTenantResolver`; original probes **fail** | fixed, with residual R7 |
| M4 unbounded parking, tenant-less dedup | budget reserved before parking (and not charged again at resume), `max-pending-per-principal=20` (`AG-APPROVAL-008`), `max-argument-bytes=64 KiB` (`AG-APPROVAL-009`), `findLatest` keyed on `(principal, tenant, tool, argsHash)` with `IS NOT DISTINCT FROM` and a new index; original probes **fail** | fixed, with residual R8 |
| M5 lossy preview, id-only attestation | `GET /decisions/{id}/arguments` returns the complete redacted arguments; `POST …/approve?argsHash=` is required, mismatch → 409 `AG-APPROVAL-010` and nothing runs; `ApprovalService.approve(id, approver, hash)`; sample e2e updated | fixed (list preview still capped by design) |
| M6 guard failures leak | `ToolGuard.execute` catches `RuntimeException` → `AG-GUARD-001` with a correlation id, cause logged at ERROR; both adapters catch around principal resolution too; original Spring AI and MCP probes **fail** (`db.internal` never reaches the model) | fixed, with residual R9 |
| M7 anonymous approver | every endpoint calls `approver(caller)`; anonymous → 401 `AG-HTTP-401` unless `agentguard.endpoints.allow-anonymous=true`; original probe **fails** (401, decision still PENDING, not executed) | fixed |

## The two things the builder flagged

**`ToolCallingChatOptions.mutate()` rebuild (GuardedToolCallingManager).** Verified by bytecode on the real provider
artifacts (fetched `spring-ai-openai:2.0.1` and `spring-ai-anthropic:2.0.1`): `OpenAiChatOptions.mutate()` and
`AnthropicChatOptions.mutate()` both carry the `ToolCallingChatOptions$Builder` bridge (their `Builder` extends an
`AbstractBuilder` that implements it), and `DefaultToolCallingChatOptions.mutate()` does too. So the
`options.mutate() instanceof ToolCallingChatOptions.Builder` check holds for the default and for the two providers
checked, provider-specific fields survive the copy, and a provider that does not implement it fails closed with an
`IllegalStateException` (caught by `GuardedToolCallback`/adapters only when it happens inside a callback — here it
happens in the manager before execution, so it surfaces as an exception from `executeToolCalls`; acceptable, but
see R1 for the better shape). The rebuilt `Prompt` keeps instructions and options only, which is all `Prompt` holds.

**Bean ordering vs Spring AI's `ToolCallingAutoConfiguration`.** The class name in `beforeName` is correct
(`org.springframework.ai.model.tool.autoconfigure.ToolCallingAutoConfiguration`, present in
`spring-ai-autoconfigure-model-tool:2.0.1`, its `toolCallingManager` is `@ConditionalOnMissingBean`). Both orders
were exercised: with Agent Guard's config first (the real order) the guarded default is the only manager; with a
Spring-AI-like `@ConditionalOnMissingBean ToolCallingManager` registered first (`CipherProbeReverifySpringAiTest`)
there is still exactly one bean and it is a `GuardedToolCallingManager` wrapping the `DefaultToolCallingManager`,
because the `BeanPostProcessor` wraps whichever instance wins. Ordering is therefore not load-bearing for security.
It **is** load-bearing for behaviour, which is R1.

## New findings from the fixes

### R1 — MEDIUM: the guarded default manager drops Spring AI's tool-call limits and resolution fallback
Spring AI's `ToolCallingAutoConfiguration.toolCallingManager` (bytecode read) builds the manager with
`spring.ai.tools.limits.*` (`maxCallsPerTool`, `maxTotalToolCalls`, `onLimitExceeded`, exclusions),
`spring.ai.tools.resolution.fallback.enabled`, the observation registry and the `ToolCallingObservationConvention`.
`AgentGuardSpringAiAutoConfiguration.agentGuardToolCallingManager` runs **before** it (`beforeName`) and wins the
`@ConditionalOnMissingBean`, passing only registry/resolver/exception-processor. Result: enabling Agent Guard
silently disables the loop limit Spring AI 2.0.1 added (the SPEC's own motivation) and the resolution fallback
setting. **Fix:** do not compete with Spring AI's bean. Remove `beforeName`; let Spring AI create its manager (the
`BeanPostProcessor` wraps it, proven above) and keep the guarded default only as a fallback with
`@ConditionalOnMissingClass("org.springframework.ai.model.tool.autoconfigure.ToolCallingAutoConfiguration")` (or
`afterName` + `@ConditionalOnMissingBean`). Add a probe asserting `maxTotalToolCalls` still applies with the guard on.

### R2 — MEDIUM: trails that predate the anchor row read as BROKEN after the first append
`CipherProbeReverifyJdbcTest.probe_trail_without_anchor_row_breaks_on_the_next_append`: with rows present and no
`agentguard_audit_anchor` row (any database created before `e1ca399`, or the row deleted), `JdbcAuditSink.append`
takes `prev = GENESIS` and `count = 0` from the missing anchor instead of the table's last row, so the new row links
to GENESIS; the verifier then reports `BROKEN` at that row for ever, and the anchor's row count is wrong from then
on. The schema is advertised as idempotent at every startup, so this is an upgrade bug, not a theoretical one.
**Fix:** seed the anchor in the schema
(`INSERT INTO agentguard_audit_anchor SELECT 1, hash, count(*) OVER (), ts FROM agentguard_audit ORDER BY seq DESC
LIMIT 1 ON CONFLICT DO NOTHING`, or equivalent), and in `append` fall back to `SELECT hash, count(*) …` when the
anchor row is absent and the table is not empty (log a WARN once). Add a probe for "rows, no anchor, append, INTACT".

### R3 — LOW: a hand-built `DefaultToolCallingManager` (not a bean) bypasses the chokepoint
`CipherProbeReverifySpringAiTest.probe_hand_built_manager_outside_the_context_bypasses_the_chokepoint`: code that
does `OpenAiChatModel.builder().toolCallingManager(DefaultToolCallingManager.builder().build())` never touches the
bean and runs unguarded tools; `GuardCoverage.springAiChokepointActive()` still reports the chokepoint as active, so
strict mode does not notice. **Fix:** document ("use the `ToolCallingManager` bean or `AgentGuard.guard(manager)`");
optionally wrap `ChatModel` beans too (their `toolCallingManager` field is not accessible without reflection, so
documentation is the honest answer).

### R4 — LOW (documented residual): the anchor row is rewritable by any role with UPDATE on it
`probe_owner_can_rewrite_the_anchor_to_hide_a_tail_deletion`: after trimming the tail with triggers disabled, an
`UPDATE agentguard_audit_anchor` makes the verifier report `INTACT` again. The runtime role needs UPDATE on the
anchor by design, so the anchor raises the bar against the owner role only when roles are split as the docs now
describe; it does not replace external anchoring (pro). Keep, but say so in SECURITY-NOTES.

### R5 — LOW: nested principal during a resumed call keeps roles and scopes but loses the tenant
`probe_nested_principal_during_resume_keeps_roles_but_loses_the_tenant`: `RunAsAuthentication` carries `ROLE_*`
and `SCOPE_*`, and `SecurityContextPrincipalResolver` resolves the tenant through the `TenantResolver`, which does not
know the run-as token; a tenant-restricted nested tool (or a Tenantify filter) runs tenant-less (denied, fail
closed; or unfiltered if the host's filter treats "no tenant" as "all"). **Fix:** make the default
`SecurityContextPrincipalResolver` short-circuit on `RunAsAuthentication` and return `agentGuardPrincipal()`
verbatim; document for custom `TenantResolver`s.

### R6 — LOW (documented): Redis pool can still grow after connection loss
The pre-filled pool never grows under a burst, but a Redis restart/failover destroys connections and the next
borrower triggers `create()` again; the pin is then possible for that window. `max-wait=2s` bounds the wait on the
deque (virtual-thread friendly) but not the pinned monitor. Note it under "Redis and virtual threads" with the
JDK 24 pointer; consider running `JedisBudgetStore` calls on a small platform-thread executor as the belt-and-braces
option.

### R7 — INFO: MCP conversation budget resets per session
The session id is server-issued (a client cannot choose it) but a client may re-initialise at will; a STEPS limit per
conversation is a per-session limit. Pair it with a PRINCIPAL limit (docs).

### R8 — INFO: pending-cap lockout and tenant-less count
A prompt-injected model can fill the 20 pending slots with distinct-argument WRITE calls and lock the principal out of
legitimate WRITEs until approvers act or the TTL expires (1 h); `countPending` is per principal id across tenants.
Acceptable trade-off; document, and let operators lower the TTL.

### R9 — INFO: `AgentGuardException` thrown by the tool itself is reported as guard failure without an audit row
`ToolGuard.dispatch` rethrows `AgentGuardException` from the executor path so real guard failures are not mislabelled
as tool failures, but a tool that (unusually) throws one is then reported `AG-GUARD-001` and no FAILED row is written
while the budget was charged. Record a FAILED row before rethrowing.

## Still open from the first pass (unchanged, LOW/INFO)
L1 self-approval, L2 tamper detection not audited, L3 policy not re-evaluated at resume, L4 permanent dedup,
L5 regex redactor gaps (now also visible in `GET /decisions/{id}/arguments`), L6 webhook secret/HMAC, L7 validation
messages, L8 budget-row purge and key length, L9 sample CSRF, L10 DDL at startup (docs now describe the two-role
setup, default unchanged), I1–I9. The original LOW probes still pass, as the builder noted.

## What the re-verification did not cover
Real OpenAI/Anthropic `ChatModel` end to end (the provider artifacts were inspected by bytecode only; no API key, no
network in tests). The `-Ppinning-probe` child-JVM test was not re-run (the code it exercises, `JedisBudgetStore`
over a raw pool, is unchanged; the fix lives in the factory, which `CipherProbeJedisFactoryTest` covers).

---

# Final verdict — commit `258bdf3` (R1, R2, R5 applied)

Reviewer: `cipher`, 2026-09-06 (third pass). New standing rule from Souhaile: **no allowance — every LOW and INFO
must be fixed before merge.** This section therefore (a) closes the items this pass verified and (b) lists every
remaining open item with its exact fix so the builder can close them in one round. Probes added this pass:
`adapter/jdbc/CipherProbeFinalJdbcTest` (concurrent first starts), `ai/CipherProbeFinalSpringAiTest` (Spring AI's
real `ToolCallingAutoConfiguration`, run-as forgeability). `./mvnw -B clean verify` is green.

## Verdict: MERGE WITH FIXES

Nothing found on this pass is exploitable from outside; the design holds. Under the no-allowance rule the branch is
not mergeable until every row of the "Open items" table is closed. None of them needs a design change; the largest
is L5 (JSON-aware redactor). One new LOW (R11, schema-at-startup races) was found while checking the anchor seeding.

## Verified this pass

- **R1 — fixed.** The guarded default manager is now `@ConditionalOnMissingClass(ToolCallingAutoConfiguration)` and
  `beforeName` is gone. Verified against Spring AI's **real** `ToolCallingAutoConfiguration` (jar
  `spring-ai-autoconfigure-model-tool:2.0.1` put on the test classpath with `-Dmaven.test.additionalClasspath`;
  the probe self-skips without it): with `spring.ai.tools.limits.max-total-tool-calls=1` there is exactly one
  `ToolCallingManager` bean, it is a `GuardedToolCallingManager` whose delegate is Spring AI's `toolCallingManager`
  bean (`agentGuardToolCallingManager` is absent), the first of two calls is parked by the guard and the second gets
  Spring AI's own "Total tool call limit (1) exceeded for this turn". The builder's `LimitedManagerConfig` test mimics
  the same bean and exercises the real `ToolCallLimits` code inside `DefaultToolCallingManager`; it is a fair
  stand-in, and the real-autoconfig probe removes the remaining doubt.
- **R2 — fixed.** My unchanged probe from the second pass now fails (an append after an anchor-less trail links to
  the real head, `INTACT`); the seed `INSERT … SELECT … ON CONFLICT (id) DO NOTHING` was exercised with eight
  concurrent `initializeSchema` calls plus four concurrent appends on a pre-anchor trail: in every run the anchor
  equals the verified head and row count (`INTACT`, `rowCount == verified`). Seeding is correct under concurrency;
  what is **not** is the rest of the startup script (R11 below).
- **R5 — fixed.** `SecurityContextPrincipalResolver.from` and `NoTenantResolver` short-circuit on
  `RunAsAuthentication`; the builder's test with a host `TenantResolver` that only knows its own tokens shows
  `tenant=acme` inside the resumed call and the approver's context restored afterwards.
- **Run-as forgeability.** `RunAsAuthentication` cannot arrive from outside the JVM: no authentication provider
  produces it, and it is **not serializable** (`Principal` is a record without `Serializable`; verified
  `NotSerializableException`), so a session store (Spring Session with JDK serialization) cannot carry a forged one.
  It is publicly constructible by application code and then trusted verbatim (`resolve()` returns roles, scopes and
  tenant as given); application code is trusted, so this is hardening, not a hole: R10 below.

## Open items — exact fixes (all required before merge)

Each row: what to change, where, and which probe flips. "Flip" means rename and invert the named probe so it asserts
the fixed behaviour, as done for the H/M items.

| Id | Sev | Exact fix | Probe to flip |
|---|---|---|---|
| L1 self-approval | LOW | `ApprovalService.approve`/`reject`: if `approver.equals(decision.principal().id())` and `!allowSelfApproval` throw `SelfApprovalException` (`AG-APPROVAL-011`); endpoints map it to 403; property `agentguard.approval.allow-self-approval=false` (metadata + docs). | `probe_self_approval_is_accepted` |
| L2 tamper not audited | LOW | `DecisionResumer.executeOnce`: when `!argumentsIntact()`, first `audit.record(…, AuditDecision.TAMPERED, …, actor)` (new enum value), `store.storeResult(id, Denied(AG-APPROVAL-004).toModelText())`, `markExecutedOnce(id)` so the decision is terminal, then throw. Endpoint still 422. | `probe_tamper_detection_leaves_no_audit_row` |
| L3 policy not re-evaluated at resume | LOW | Inject `PolicyLookup` + `ToolPolicyEvaluator` into `DecisionResumer`; before running: `principal = refresher.refresh(decision.principal()).orElse(stored)` (new SPI `PrincipalRefresher`, default identity), `evaluator.evaluate(rule, principal, tool)`; `Deny` → store `Denied(code)`, audit `DENIED` with actor, return; `Allow`/`RequireApproval` → run; no rule any more → `AG-POLICY-004`. | `probe_policy_tightened_after_parking_is_not_rechecked_at_resume` |
| L4 dedup has no time bound | LOW | `DecisionStore.findLatest(principal, tenant, tool, argsHash, Instant createdAfter)`; `ToolGuard.gate` passes `now - agentguard.approval.replay-window` (new property, default = `approval.ttl`); JDBC adds `AND created_at > ?` (existing index covers it); an executed/rejected decision older than the window parks a new one. | `probe_an_approved_decision_answers_identical_calls_with_the_stale_result_forever` |
| L5 regex redactor | LOW | Replace the regex key match with a JSON walk: a small tolerant JSON parser in `domain` (no Jackson in core; objects, arrays, strings with escapes, numbers, literals) or a `JsonRedaction` port implemented in the starter with `tools.jackson`. Rules: a sensitive key masks its **whole value** whatever its shape; keys are compared after JSON unescaping; unparseable input returns `"***"` (full mask, DEBUG log); the control filter becomes `[\p{Cc}\p{Cf}  ]`; keep the `Bearer` regex on string values; `preview` = `redact` + cap. | `probe_array_and_object_values…`, `probe_unicode_escaped_keys…`, `probe_line_and_direction_control…` in `CipherProbeRedactorTest` (keep `probe_what_is_fine`) |
| L6 webhook secret / no signature | LOW | `WebhookNotifier`: refuse a non-`https` URL unless the host is loopback or `agentguard.approval.notifier.webhook-allow-insecure=true` (fail at startup naming the property); when a secret is set send `X-AgentGuard-Timestamp: <epochSeconds>` and `X-AgentGuard-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>`; keep `X-AgentGuard-Token` only behind `webhook-legacy-token=true` for one release. Test with the already-declared WireMock (`NotifiersTest`), which also settles I9's unused-dependency point. Document the verification snippet. | new test in `NotifiersTest` |
| L7 validation messages / silent empties | LOW | Hibernate Validator `@DurationMin(nanos = 1)` (or a custom `@PositiveDuration`) with `message = "agentguard.approval.ttl must be positive"` on `approval.ttl`, `approval.notifier.webhook-timeout`, `budgets.limits[].window`, `redis.pool.max-wait`. `AgentGuardStartupCheck`: WARN when `policy.approval-required-for` is empty ("no side effect requires approval; DESTRUCTIVE tools run without a human") and when `redaction.sensitive-keys` is empty. | `probe_non_positive_durations_fail_without_naming_the_property` (assert the property name is present); `probe_empty_approval_set_and_empty_sensitive_keys_are_accepted_silently` (assert the WARN with `OutputCaptureExtension`) |
| L8 budget rows never purged; long key fails | LOW | `JdbcBudgetStore.incrementAndGet`: every 1000th call (`AtomicLong`) run `DELETE FROM agentguard_budget WHERE expires_at < ? - interval '1 day'`; column `key` `varchar(512)` → `text`; `BudgetLimit.key` uses `sha256(subject)` hex when `subject.length() > 128`. | `probe_expired_budget_rows_are_never_purged`, `probe_key_longer_than_the_column_fails_the_call_closed` |
| L9 sample CSRF / noop passwords | LOW | `SecurityConfig`: `csrf(c -> c.ignoringRequestMatchers("/mcp/**"))` instead of `disable()` so the approval POSTs need the token; `SampleEndToEndTest` adds `.with(csrf())`; README: one line that `{noop}` users and Basic are for the demo only. | `SampleEndToEndTest` |
| L10 DDL at every start, three times | LOW | `AgentGuardAutoConfiguration`: run `initializeSchema` once per `DataSource` (a marker bean or a set of `System.identityHashCode(ds)`); INFO log "agentguard schema step ran"; WARN when `initialize-schema=true` and `SELECT tableowner FROM pg_tables WHERE tablename = 'agentguard_audit'` equals `current_user` ("the runtime role owns the audit table and can disable its triggers; see Database roles"). Default stays `true`. Combine with R11. | new test in `AgentGuardAutoConfigurationTest` (schema runs once) |
| I1 args hash over raw text | INFO | Hash a canonical form: with the parser from L5, re-serialise with sorted keys and no whitespace before `Hashes.sha256Hex` in `PendingDecision.park`, `ToolGuard.gate` and `argumentsIntact()`; unparseable → raw text as today; document. | `ToolGuardTest`: `{"a":1,"b":2}` and `{ "b":2, "a":1 }` share one decision |
| I2 `isError` after approval is final | INFO | Docs FAQ line: "A tool that returns an error after approval is final (single execution); the agent must ask again and a human must approve again." `GuardResult.Failed` for that case carries `retryable:false`. | docs |
| I3 anonymous token in `AuthorizationManager` | INFO | `SecurityContextPrincipalResolver.of(Authentication)` applies the same anonymous check as `resolve()` (`AnonymousAuthenticationToken`, unauthenticated, `"anonymousUser"` → `Principal.anonymous()`); `ToolPolicyAuthorizationManager` uses it. | new case in the AuthorizationManager test |
| I4 endpoints not tenant-scoped | INFO | `AgentGuardEndpoints`: resolve the approver's tenant via `PrincipalResolver`; when present, `pending`/`audit` filter on it and `get`/`arguments`/`approve`/`reject` return 404 for another tenant's decision; `agentguard.endpoints.tenant-scoped=true` (default). Pro keeps the UI. | new test in `AgentGuardEndpointsTest` |
| I5 tool exception message forwarded | INFO | `Errors.describe`: return `<SimpleClassName> (correlationId=…)`; log the message at WARN server-side; `agentguard.errors.include-tool-message=false` to opt back in. Update `ToolGuardTest.tool_failure_becomes_structured_error…` ("db down" no longer reaches the model by default). | `ToolGuardTest` |
| I6 duplicate tool policy last-wins | INFO | `ToolPolicyRegistry.register`: identical rule → no-op; different rule for an existing name → `IllegalStateException("tool 'x' already has a different @ToolPolicy")` (startup failure). | `ToolPolicyAnnotationScannerTest` |
| I7 chain has no secret | INFO | Optional keyed chain: `agentguard.audit.hmac-secret` (env var; at least 32 bytes, validated); when set `AuditChain` hashes with `HMAC-SHA256(secret, canonical + prev)` and `CANONICAL_VERSION = "ag2h"`; `AuditChainVerifier` takes the same key; documented as "detects rewrites by anyone without the key". | `AuditChainVerifierTest` |
| I8 STEPS same as TOOL_CALLS; TOKENS overshoot; no auto-recording | INFO | (a) startup validation: `kind=STEPS` only with `scope=CONVERSATION`, `kind=TOOL_CALLS` only with `PRINCIPAL`/`TENANT` (fail fast naming `agentguard.budgets.limits[i]`); (b) ship `AgentGuardUsageAdvisor` (`CallAdvisor` + `StreamAdvisor` bean, `@ConditionalOnClass(ChatClient)`) that calls `budgets.recordTokens(principal, conversationId, usage.getTotalTokens())` after each response (closes QUESTIONS #8); (c) docs: a TOKENS check admits one more call, overshoot at most that call's tokens. | new advisor test with the fake `ChatModel` |
| I9 supply chain | INFO | Both workflows: top-level `permissions: { contents: read }`; pin `actions/checkout`, `actions/setup-java`, `actions/upload-artifact` to full commit SHAs (resolve with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, keep the tag in a comment; Dependabot updates SHAs); `.mvn/wrapper/maven-wrapper.properties`: add `distributionSha256Sum` from `https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip.sha256`; pin `postgres:16-alpine` and `redis:7-alpine` by digest in the four test files and the sample compose (`docker inspect --format '{{index .RepoDigests 0}}'`); keep `wiremock-standalone` only if L6 uses it, else remove. | CI config review |
| R3 hand-built manager bypass | LOW | Docs sentence already added in `258bdf3`; remaining: `AgentGuardStartupCheck` logs the delegate class of the guarded manager; SECURITY-NOTES sentence "a manager built by hand and passed to a ChatModel builder is outside the guard; use the bean or `AgentGuard.guard(manager)`". | keep `probe_hand_built_manager_outside_the_context_bypasses_the_chokepoint` as documentation (rename without `probe_`) |
| R4 anchor rewritable by UPDATE holders | LOW | Trigger `agentguard_audit_anchor_monotonic` `BEFORE UPDATE` on `agentguard_audit_anchor`: `RAISE EXCEPTION` unless `NEW.row_count = OLD.row_count + 1 AND NEW.head_hash <> OLD.head_hash`; the runtime role (UPDATE only) can then not reset it; the owner still can (documented residual in SECURITY-NOTES). | `probe_owner_can_rewrite_the_anchor_to_hide_a_tail_deletion` (assert the UPDATE is refused) |
| R6 Redis regrowth after connection loss | LOW | `JedisBudgetStore`: run every Jedis call on a bounded daemon platform-thread executor (`Executors.newFixedThreadPool(maxTotal)`) with `Future.get(maxWait)` when `Runtime.version().feature() < 24` and `agentguard.redis.pool.platform-threads=true` (default); timeout → `AgentGuardException` → `AG-GUARD-001`. Removes the pin regardless of pool growth; keep the pre-fill. | `CipherProbeJedisFactoryTest` (add a `prepare-pool=false` variant, must still complete) |
| R7 MCP conversation budget per session | INFO | Startup WARN when a `CONVERSATION` limit exists without a `PRINCIPAL` limit; docs sentence "a conversation is an MCP session; a client can open a new one; pair with a PRINCIPAL limit". | `AgentGuardAutoConfigurationTest` (log) |
| R8 pending-cap lockout, tenant-less count | INFO | `DecisionStore.countPending(principalId, tenantId)` (`IS NOT DISTINCT FROM`); docs: the cap plus `approval.ttl` bound a prompt-injected model's lockout; approvers `reject` to free slots. | `parking_is_budgeted_and_capped_per_principal` (add the tenant case) |
| R9 `AgentGuardException` from the tool leaves no audit row | INFO | `ToolGuard.dispatch`: in the `catch (AgentGuardException e)` branch record a `FAILED` row (`Errors.describe(e)`) before rethrowing; budget stays charged (document). | `ToolGuardTest` |
| R10 run-as token hardening | LOW | `RunAsAuthentication`: constructor package-private (only `SecurityContextResumeContextProvider` builds it); `writeObject`/`readObject` throw `NotSerializableException` (stays non-serializable even if `Principal` becomes Serializable); override `setAuthenticated(true)` to throw `IllegalArgumentException` for external callers, as Spring's own tokens do. | `run_as_token_is_publicly_constructible_and_fully_trusted_but_not_serializable` (assert the constructor is not public) |
| R11 schema-at-startup races (new) | LOW | Reproduced in `CipherProbeFinalJdbcTest`: a schema run on one instance while another appends → PostgreSQL **deadlock detected** (aborting either the append, i.e. a refused tool call, or the startup); eight instances starting on an **empty** database → `duplicate key value violates unique constraint "pg_type_typname_nsp_index"` (the `CREATE TABLE IF NOT EXISTS` race). Fix: first statement of `schema-postgresql.sql` = `SELECT pg_advisory_xact_lock(0x41474741554449)` (the sink's key, so schema runs serialise against appends; the script runs as one implicit transaction through `Statement.execute`); create triggers only when absent (`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '…') THEN CREATE TRIGGER … END IF; END $$`) instead of `DROP TRIGGER` + `CREATE TRIGGER` on every start; run the script once per `DataSource` (L10). | the two tests in `CipherProbeFinalJdbcTest` (assert every outcome is `ok`) |

## Not covered
Real OpenAI/Anthropic `ChatModel` end to end (provider artifacts inspected by bytecode only). The `-Ppinning-probe`
child-JVM test was not re-run (unchanged code path).

---

## Clean verdict (50ed8d3)

Reviewer: `cipher`, 2026-09-07 (fourth pass, clean-verdict re-verification). Branch `feat/agent-guard-core`,
HEAD `50ed8d3`, Docker up, everything below run on this machine. New probes: `domain/CipherProbeCleanTest`,
`application/CipherProbeCleanGuardTest`, `adapter/redis/CipherProbeCleanRedisTest`,
`web/CipherProbeCleanEndpointsTest` (12 tests). As in every earlier round the probes assert **today's**
behaviour, so the suite stays green; the fix "flips" each one (rename without `probe_`, invert the assertion).

### Verdict: MERGE WITH FIXES

No HIGH. The whole previous fix list (L1–L10, I1–I9, R3, R4, R6–R11) is closed — verified in the code and by a
green test for each. What is new is what the fixes themselves brought in: a hand-written JSON parser and a
canonical hash in the hot path, a bounded Redis executor, and tenant scoping at the endpoints. Twelve findings
come out of attacking those surfaces: one MEDIUM (C4), six LOW, five INFO. Under the no-allowance rule the
branch is not mergeable until all twelve are closed. None needs a design change; C4 is a two-line move.

### Numbers

| What | Result |
|---|---|
| `./mvnw -B clean verify` (the CI command) | BUILD SUCCESS, 40 s |
| Tests at `50ed8d3` as delivered | 157 declared: **156 run, 0 failures, 1 skipped** (`CipherProbeFinalSpringAiTest` self-skips without the Spring AI autoconfigure jar) |
| Tests with this pass's probes | **169 run, 0 failures, 1 skipped** (core 123, starter 45+1, sample 1) |
| Coverage at `50ed8d3` (core module, the only module with JaCoCo) | line **89.49 %** (1397/1561), branch **78.48 %** (372/474) — the builder's 89.5 / 78.5 confirmed; gate is line ≥ 0.80 |
| Coverage with this pass's probes | line 90.52 %, branch 79.75 % |
| Existing `CipherProbe*` classes re-run unchanged | 13 classes, all green: Jdbc(4) ReverifyJdbc(2) FinalJdbc(2) ApprovalGate(10) AuditChain(1) Redactor(5) Endpoints(1) Mcp(4) SpringAi(3) ReverifySpringAi(4) FinalSpringAi(2) JedisFactory(2) Properties(3) |
| `-Ppinning-probe` (skipped by the last two passes) | run: `CipherProbeJedisPinningTest` 2/2 green, 12.7 s |
| Real Spring AI autoconfig probe (skipped in the default run) | run with `-Dmaven.test.additionalClasspath=…spring-ai-autoconfigure-model-tool-2.0.1.jar`: 2/2 green, 0 skipped — the R1 chokepoint still holds |

### Supply chain — all pins verified against upstream, not just present

| Pin | Verified |
|---|---|
| `actions/checkout@11d5960a…`, `setup-java@cf277c60…`, `upload-artifact@ea165f8d…` | equal to `gh api repos/<a>/git/ref/tags/v4` today; tag kept in a comment |
| `distributionSha256Sum=0d7125e8…` | downloaded `apache-maven-3.9.11-bin.zip` and hashed it: match (the upstream `.sha256` sidecar 404s; hashed the artifact instead) |
| `postgres:16-alpine@sha256:57c72fd2…`, `redis:7-alpine@sha256:6ab0b6e7…` | equal to `docker image inspect --format '{{index .RepoDigests 0}}'`; used in all five test classes and the sample compose |
| `permissions: contents: read` | present, top level, in both workflows |
| WireMock | now used (`NotifiersTest`), so the unused-dependency point is closed |

### Hexagonal rule

`domain` imports nothing outside the JDK: the only non-`java.*` imports in the package are `javax.crypto.Mac` and
`javax.crypto.spec.SecretKeySpec` (java.base since JDK 9), used by the keyed chain. That is compliant — but see
C11 for how the ArchUnit rule was made to accept it. No JDBC test class initialisation errors: every Testcontainers
class started and ran (47 container lines in the log, `JdbcAdaptersIntegrationTest` 6/6, `SchemaStepIntegrationTest`
1/1, the three JDBC probe classes 8/8).

### New findings

| Id | Sev | Title | Probe |
|---|---|---|---|
| C4 | MEDIUM | The arguments are parsed before the size cap refuses them | `probe_arguments_are_parsed_before_the_size_cap_refuses_them` |
| C1 | LOW | An unpaired surrogate and `?` share one arguments hash | `probe_an_unpaired_surrogate_and_a_question_mark_share_one_arguments_hash` |
| C2 | LOW | `userPassword`, `myApiKey`, `password_confirmation` are not masked | `probe_camel_case_and_suffixed_sensitive_keys_are_not_masked` |
| C5 | LOW | Four-eyes is bypassed by a differently cased approver id | `probe_four_eyes_is_bypassed_by_a_differently_cased_approver_id` |
| C7 | LOW | A timed-out Redis call stays queued on an unbounded queue | `probe_a_timed_out_redis_call_stays_queued_on_an_unbounded_queue` |
| C9 | LOW | An approver without a tenant reads (and decides) every tenant | `probe_an_approver_without_a_tenant_reads_every_tenant` |
| C11 | LOW | The domain ArchUnit rule was weakened to let `javax.crypto` in | git diff (rule change) |
| C3 | INFO | The parser accepts text that is not JSON | `probe_the_parser_accepts_text_that_is_not_json` |
| C6 | INFO | Enabling the audit HMAC secret reports the existing trail BROKEN | `probe_enabling_the_audit_hmac_secret_reports_the_existing_trail_as_broken` |
| C8 | INFO | The platform-thread executor is never shut down | `probe_the_platform_thread_executor_is_never_shut_down` |
| C10 | INFO | The pending inbox is filtered after the store limit | `probe_the_pending_inbox_is_filtered_after_the_store_limit` |
| C12 | INFO | Audit hashes the raw arguments, decisions hash the canonical form | `probe_the_audit_row_hashes_the_raw_arguments…` |

### Open items — exact fixes (all required before merge)

| Id | Sev | Exact fix |
|---|---|---|
| C4 | MEDIUM | `ToolGuard.gate`: move the `options.maxArgumentBytes()` check to the **first** statement, before `ArgumentCanonicalizer.hash`. Today the hash (a full parse into a `JsonNode` tree) runs first, so the cap that exists to bound model-supplied text no longer bounds anything: measured here, 4 MB of valid JSON becomes ~163 MB of live nodes in ~230 ms — ~40x amplification, and one such call per tool call. Apply the same cap in `dispatch` (the ALLOW path has no size check at all today) before anything hashes or previews the arguments. |
| C1 | LOW | `JsonText.escape`: emit `\uXXXX` for any unpaired surrogate (they are invalid JSON output anyway), or hash `canonical.getBytes(UTF_16BE)` in `Hashes`. Today `String.getBytes(UTF_8)` turns every unpaired surrogate into `'?'`, so `{"path":"\ud800"}` and `{"path":"?"}` have one `argsHash`: the second call is deduped onto the first one's decision and answered with its stored result without running, and `PendingDecision.argumentsIntact()` accepts the swap. |
| C2 | LOW | `ArgumentRedactor.isSensitive`: split the key on `_ - .` **and** camel-case boundaries and mask when any part is a sensitive key. Today the match is a whole-word suffix, so `userPassword`, `myApiKey`, `password_confirmation` and `token_value` are printed in the clear into previews, `LoggingNotifier`, the webhook body and `agentguard_decision.args_preview`. Keep the current behaviour for `user_password` and `api_key` (asserted in the probe). |
| C5 | LOW | `ApprovalService.fourEyes`: compare `approver.strip()` with `decision.principal().id().strip()` using `equalsIgnoreCase`. Today `equals` alone means an operator on a case-insensitive IdP (LDAP, e-mail logins, Keycloak's default username handling) approves their own agent's parked call by logging in as `ALICE`; a trailing space does the same. |
| C7 | LOW | `JedisBudgetStore.run`: `future.cancel(true)` in the `TimeoutException` branch, and build the pool as a `ThreadPoolExecutor(threads, threads, …, new ArrayBlockingQueue<>(threads), new AbortPolicy())` with `RejectedExecutionException` mapped to `AG-GUARD-001`. Today a timed-out call is abandoned on a `newFixedThreadPool` with an unbounded queue: while Redis is slow every guarded call adds a task nobody waits for, the queue grows without bound, and every later call queues behind the backlog and times out too — the guard stays failed-closed for the whole application long after Redis recovers. |
| C9 | LOW | `AgentGuardEndpoints`: `agentguard.endpoints.require-tenant` (default `true` when `tenant-scoped`); an approver whose `PrincipalResolver` yields no tenant gets 403 instead of everything. Today tenant scoping only applies when the approver *has* a tenant, so a missing claim, a service account or a mis-wired `TenantResolver` silently reads every tenant's previews and audit rows and can approve them: the scoping fails open. |
| C11 | LOW | `HexagonalArchitectureTest`: restore the blanket `"javax.."` ban on `..domain..` and carve out only `javax.crypto..` (`dependOnClassesThat(resideInAnyPackage("javax..").and(not(resideInAnyPackage("javax.crypto..")))`). `50ed8d3` replaced `"javax.."` with three named packages so the keyed chain would pass, which also re-permits `javax.naming`, `javax.management`, `javax.net` and `javax.xml` (XXE) in the domain. The code is fine; the guard rail was widened instead of narrowed. |
| C3 | INFO | `JsonText`: `digits()` must accept only `'0'..'9'` (`Character.isDigit` accepts every Unicode decimal digit, so `{"a":١٢}` parses), and a `\u` escape must be four `[0-9a-fA-F]` (`Integer.parseInt` accepts a sign, so `"\u+041"` becomes `A` and `"\u-001"` becomes U+FFFF). No leak follows — the redactor is *more* permissive than Jackson, never less — but the guard and the tool must agree on what is valid JSON. |
| C6 | INFO | Store the chain version per row (`ag1`/`ag2h`, a column on `agentguard_audit`) and verify each row with the version it was written with; document that `agentguard.audit.hmac-secret` is a one-way switch. Today enabling the key makes every pre-key row recompute wrong: the verifier reports `BROKEN` at sequence 1, which is exactly what a rewrite looks like. |
| C8 | INFO | `JedisBudgetStore implements AutoCloseable` (`executor.shutdownNow()`), and let the bean definition pick the destroy method up. Today the executor is created per store and never shut down, so every context that builds one leaks `agentguard-redis` platform threads (devtools restarts, `@DirtiesContext` suites, any app that reopens a context). |
| C10 | INFO | Push the tenant into the query — `DecisionStore.findByState(state, tenantId, limit)` and `AuditReader.latest(tenantId, limit)` — instead of filtering the page after the store's `limit`. Today three of a neighbour's decisions hide a tenant's own pending approval at `limit=3`: an approval inbox that silently omits work. |
| C12 | INFO | `AuditRecorder.record`: hash `ArgumentCanonicalizer.canonical(argumentsJson)`. Today the audit row hashes the raw text while the decision hashes the canonical form, so `agentguard_audit.args_hash` and `agentguard_decision.args_hash` differ for the same call whenever the model emitted whitespace or another key order — the join an auditor uses to tie a trail row to the approval that allowed it finds nothing. |

### Attacked and found sound (no change needed)

Parser: trailing garbage rejected; a BOM makes the text unparseable and the redactor full-masks (`"***"`); depth
capped at 64 (65 rejected, no `StackOverflowError`); control, format, NEL, LS/PS and bidi characters stripped;
duplicate keys collapse last-wins, the same way Jackson hands them to the tool, so preview and execution agree.
Webhook: `https` (or loopback) enforced at construction, signature `v1=hex(HMAC-SHA256(secret, ts + "." + body))`
over the exact body, timestamp header sent, legacy token only behind its flag, `userinfo@host` cannot fake a
loopback host, verification snippet and window documented. Audit: schema and sink take the **same** advisory lock
(`0x41474741554449` = 18374244850549833) and `initializeSchema` runs the whole script in one transaction
(`setAutoCommit(false)`), so `pg_advisory_xact_lock` really holds; triggers created only when absent; the anchor
monotonic trigger refuses any UPDATE that is not `+1` row with a new head. Keyed chain: min 32 bytes enforced,
key cloned, domain-separated version string (`ag2h`), secret only via a property whose name Spring Boot's
actuator sanitiser already masks. Run-as: constructor package-private, `setAuthenticated(true)` throws,
`writeObject`/`readObject` throw `NotSerializableException`. Schema: eight concurrent first starts on an empty
database and a schema run concurrent with appends both end `ok` (`CipherProbeFinalJdbcTest`), and the step runs
once per `DataSource`.

### Not covered

Real OpenAI/Anthropic `ChatModel` end to end (no API key, no network in tests) — unchanged from the earlier
passes. The anchor's residual: a role holding `DELETE` on `agentguard_audit_anchor` can still delete and re-insert
it, which the monotonic trigger (BEFORE UPDATE only) does not see; the documented grant is INSERT/SELECT, so this
is only a warning to keep `DELETE` off that table — no probe written, no code change asked for.
