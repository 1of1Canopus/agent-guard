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

## Re-verification (6f026ff)

2026-09-07 · Cipher · branch `feat/agent-guard-core`, HEAD `6f026ff` (Isis's five commits on top of the
clean-verdict pass `538c91a`). `./mvnw -B clean verify`, Docker up.

### Build, as run

| | Tests | Failures | Errors | Skipped |
|---|---|---|---|---|
| `6f026ff` as delivered | 169 | 0 | 0 | 1 |
| with this pass's four probes | 173 | 0 | 0 | 1 |

Core line coverage 90.20%, branch 78.04% (JaCoCo gate 80% line: met). The one skip is
`CipherProbeFinalSpringAiTest`, self-skipping without Spring AI's real `ToolCallingAutoConfiguration` on the test
classpath — unchanged, and still not a passing test.

### C1–C12: all twelve confirmed closed

Every `CipherProbe*` class was re-run unchanged and is green: `CipherProbeCleanTest` 5/5,
`CipherProbeCleanGuardTest` 3/3, `CipherProbeCleanRedisTest` 2/2, `CipherProbeCleanEndpointsTest` 2/2,
`CipherProbeApprovalGateTest` 10/10, `CipherProbeEndpointsTest` 1/1, `CipherProbeMcpTest` 4/4,
`CipherProbeSpringAiTest` 3/3, `CipherProbeReverifySpringAiTest` 4/4, `CipherProbeFinalSpringAiTest` 2/2 (1
skipped), `CipherProbeJedisFactoryTest` 2/2, `CipherProbePropertiesTest` 3/3.

Each C1–C12 probe was diffed against `538c91a`. Every one is the same scenario with the assertion inverted (or,
for `CipherProbeApprovalGateTest`, one extra constructor argument for the new `version` component) — no probe was
narrowed, no `@Disabled`, no dropped assertion. One material exception, recorded as V5 below:
`CipherProbeJedisFactoryTest.burst` raised `maxTotal` from 4 to 200.

The fixes were read in code, not taken on trust: C4 (`ToolGuard.gate`/`dispatch` call `rejectIfTooLarge` as their
first statement — see V1 for where the cap still is not first), C1 (`JsonText.isUnpairedSurrogate` + `\u` escape),
C2 (`WORD_BOUNDARY` split plus a re-joined-pair pass), C5 (`strip` + NFKC + `equalsIgnoreCase`), C7
(`ThreadPoolExecutor` with `ArrayBlockingQueue(n)` and `AbortPolicy`, `RejectedExecutionException` mapped to
`AG-GUARD-001`, a timed-out `Future` cancelled and removed from the queue), C9 (`MissingTenantException` → 403
`AG-HTTP-403`), C11 (blanket `javax..` ban with a `javax.crypto..` carve-out), C3 (`isAsciiDigit`/`isHexDigit`),
C6 (`chain_version` column, backfilled `ag1`, applied per row — see V2), C8 (`AutoCloseable`), C10 (`tenant_id`
in the SQL, before `LIMIT`), C12 (`AuditRecorder.record` hashes the canonical form).

### New findings (4 with probes, 1 without)

Probes assert today's behaviour and are green; Isis flips each assertion when the fix lands.

| Id | Sev | Finding | Probe |
|---|---|---|---|
| V1 | MEDIUM | C4 residual: the cap is first in `gate`/`dispatch`, but `ToolGuard.guarded` audits — and therefore canonicalises and *parses* — the arguments on the two paths that run **before** either of them, the unregistered-tool denial and the policy denial. Both are reachable by a caller with no role and no policy, so the cheapest path into the guard is the one that parses unbounded model-supplied text into a `JsonNode` tree. Repro: a 4 KB payload to an unregistered tool under a 32-byte cap comes back `AG-POLICY-001`, and the audit row's `args_hash` is the *canonical* hash — the parse ran. | `CipherProbeReverifyTest.probe_the_denial_paths_parse_arguments_of_any_size` |
| V2 | MEDIUM | New in C6: `AuditChainVerifier.chainFor` picks the hash function from the row's own `chain_version` column. That column is part of what an attacker rewrites, and the version a row *claims* is not itself protected by the key. Stamping rewritten rows `ag1` makes the verifier recompute them with plain SHA-256, which needs no secret — the residual the schema documents ("a role that owns the table can DISABLE TRIGGER") is handed straight back, and `agentguard.audit.hmac-secret` stops being a control. Repro: write a keyed trail, rewrite every row relinked unkeyed, verify with the keyed chain → `INTACT`. | `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` |
| V3 | LOW | New in C4/C12: `recordOversized` hashes the raw text, every other row hashes the canonical form, and both land in the same `args_hash` column with no domain separation. Canonicalisation is not size-preserving — after the C1 fix an unpaired surrogate goes from one UTF-8 byte (`?`) to six — so a payload under the 64 KB cap has a canonical form over it, and that canonical form replayed as raw text is refused as oversized with *exactly* the same `args_hash` as the allowed call. An auditor joining rows by `args_hash` conflates a denial with an execution. | `CipherProbeReverifyTest.probe_an_oversized_denial_shares_an_args_hash_with_an_allowed_call` |
| V4 | LOW | The C9 opt-out is silent. `AgentGuardStartupCheck` exists to "warn about configurations that quietly weaken the guard" and does so for empty `approval-required-for`, empty `sensitive-keys`, `store=MEMORY`, a missing notifier, a missing `TenantResolver` and a runtime role that owns the audit table — but says nothing when `endpoints.tenant-scoped=false` or `endpoints.require-tenant=false` turns every approver into a cross-tenant approver. The sample opts out in a YAML comment; a running process says nothing. | `CipherProbeReverifyStartupTest.probe_a_cross_tenant_approver_opt_out_is_silent_at_startup` |
| V5 | LOW | Probe coverage lost: `CipherProbeJedisFactoryTest.burst` raised `maxTotal` from 4 to 200 because `JedisBudgetStoreFactory` sizes the platform-thread pool *and* its now-bounded queue from `maxTotal`, so a 4-connection setting would legitimately reject the 200-thread burst. The change is honest, but it also removes the Jedis connection-pool contention that H3/R6 was about: 200 callers now each get their own connection and the pool's growth lock is never contended. No probe (the finding is about a probe). | — |

### Exact fixes

- **V1** — `ToolGuard.guarded`: call `rejectIfTooLarge(invocation, toolName)` before `policies.resolve`, and
  return its result; `gate`/`dispatch` may keep their now-redundant check. The two denial audits then route
  through `AuditRecorder.recordOversized` like the gate path already does. Flip
  `probe_the_denial_paths_parse_arguments_of_any_size` to assert `APPROVAL_ARGS_TOO_LARGE` and a raw `args_hash`.
- **V2** — `AuditChainVerifier.verify`: the version may only move forward. Carry a `boolean keyedSeen` through the
  walk; when a `KEYED_VERSION` row verifies, set it, and from then on a `CANONICAL_VERSION` row is `BROKEN` at its
  sequence rather than unkeyed-verified. C6's migration case (an unkeyed prefix, then keyed rows) still reports
  `INTACT`, and rewriting the prefix still breaks the first keyed row's `prevHash`, which is under the HMAC.
  Document in SECURITY-NOTES that `hmac-secret` is a one-way switch — which it already says.
- **V3** — domain-separate the two hashes: `Hashes.sha256Hex("agraw1:" + argumentsJson)` in
  `AuditRecorder.recordOversized` against `sha256Hex("agcanon1:" + canonical)` in `ArgumentCanonicalizer.hash`
  (a hash-format change: note it in CHANGELOG, it does not invalidate existing chains because the chain hashes
  the row, not the arguments). Optionally also cap `canonical(...)`, since the 6x expansion means
  `maxArgumentBytes` does not bound what the guard hashes.
- **V4** — `AgentGuardStartupCheck.afterSingletonsInstantiated`: when `endpoints.enabled` and either
  `!tenantScoped` or `!requireTenant`, `log.warn` naming the property and the consequence ("approvers see and
  decide every tenant's decisions and audit rows"). Then flip the probe to `anyMatch`.
- **V5** — decouple the two pools: give `AgentGuardProperties.Pool` a separate `platform-threads` size (default
  `maxTotal`, and the executor queue sized from it), or have `JedisBudgetStoreFactory` size the executor from
  `max(maxTotal, 32)`. Restore `burst` to `maxTotal=4` so the H3/R6 contention scenario is tested again.

### Attacked and found sound (no change asked for)

- **Oversized raw hash, collisions.** Two different oversized payloads cannot share `args_hash`: it is a plain
  SHA-256 of the text. The only cross-row equality is the canonical/raw domain overlap of V3, and it cannot hide a
  payload — the oversized row is always `DENIED`, is always written before the denial returns, and no call runs.
- **Mixed chain versions, keyed → unkeyed prefix.** An unkeyed prefix followed by keyed rows verifies correctly,
  and the version string is inside the hashed material (`canonical()` starts with it), so a row cannot be
  re-labelled without changing its own hash. The one gap is the verifier's *trust* in the label, which is V2.
- **NFKC four-eyes, the opposite failure.** NFKC does collapse distinct strings (`alice`/`alicｅ`, `office`/`oﬃce`,
  `user1`/`user₁`, `bob`/`𝐁ob` all compare equal). The failure direction is fail-closed: two distinct humans
  judged the same identity produce a `SelfApprovalException`, i.e. a refused approval, never an accepted one.
  `sameIdentity` is used by `fourEyes` only, and nowhere on a grant path. Worth a line in the docs (an IdP that
  issues homoglyph-adjacent usernames can lock an approver out of one decision); not a finding.
- **Surrogate escaping determinism.** `String.format("\\u%04x", …)` is locale-independent — `Formatter` localises
  digits for `%d` only, not for `%x` — verified under `en-US`, `ar-SA-u-nu-arab`, `tr-TR`, `hi-IN-u-nu-deva`, all
  producing `\ud800`. `String.equalsIgnoreCase` is likewise locale-independent, so the Turkish-I trap does not
  apply to `sameIdentity`. Canonicalisation is idempotent: re-parsing `\ud800` yields the same escape.
- **Tenant filter inside the queries.** `JdbcDecisionStore.findByState` and `JdbcAuditSink.latest` take the
  `tenant_id = ?` branch only when `tenantId != null`, and the null branch is reachable only when the deployment
  opted out (`tenant-scoped=false` or `require-tenant=false`). `IS NOT DISTINCT FROM` is therefore not needed and
  would be wrong: a tenanted approver must not see rows with a NULL tenant. `LIMIT` is applied after the filter
  (C10), and both queries stay parameterised.
- **Bounded Redis executor, rejection path.** `RejectedExecutionException` becomes `AG-GUARD-001`
  `GuardUnavailable`: the call is not run, so a saturated pool fails closed. A timed-out `Future` is cancelled and
  removed from the queue, and `getQueue().remove(future)` matches the object `submit` enqueued. `close()`
  `shutdownNow()`s the pool. Ceiling is `2n` in-flight calls (`n` running, `n` queued) — deliberate.
- **`require-tenant` default.** `true`, and `AgentGuardEndpoints`' 6-argument constructor defaults it `true`, so
  anyone wiring the endpoints by hand keeps the safe posture. `approverTenant()` is called by `pending`, `audit`
  and `load`, so `approve`/`reject`/`arguments`/`get` are all covered through `load`. The sample's and
  `AgentGuardEndpointsTest`'s opt-outs are correct for what they test; V4 is only that they are quiet.

### Not covered

Real OpenAI/Anthropic `ChatModel` end to end (no key, no network) — unchanged from every prior pass. V2 was
reproduced against `InMemoryAuditSink`, not against a PostgreSQL trail with the append-only triggers disabled: the
verifier logic is store-independent and `JdbcAuditSink` round-trips `chain_version` verbatim, but the physical
DISABLE TRIGGER step was not performed. V5 is asserted by reading `JedisBudgetStoreFactory`, not by a probe.

### Verdict: MERGE WITH FIXES

No HIGH. Two MEDIUM (V1, V2) and three LOW (V3, V4, V5), each with a named fix and, for four of them, a probe to
flip. C1–C12 are genuinely closed and the fixes are the right ones; V1 and V2 are the new surfaces those fixes
opened, and V2 in particular voids a control an operator explicitly turned on, so it does not wait.

## Final verification (9ebaad0)

Branch `feat/agent-guard-core`, HEAD `9ebaad0`. Full `./mvnw clean verify` on Docker, twice: once on the tree as
pushed, once with this pass's new probe class added.

| Run | Tests | Failed | Errors | Skipped | Line | Branch |
|---|---|---|---|---|---|---|
| `9ebaad0` as pushed | 175 | 0 | 0 | 1 | 90.32% | 77.72% |
| `9ebaad0` + `CipherProbeAnchorKeyingJdbcTest` | 182 | 0 | 0 | 1 | 90.38% | 78.57% |

Both green, JaCoCo gate (80% line) passed. The one skipped test is the pre-existing
`CipherProbeFinalSpringAiTest` assumption (`-Dmaven.test.additionalClasspath=spring-ai-autoconfigure-model-tool`),
unchanged from earlier passes; a skipped test is not a passing one and is counted as skipped here. Isis reported
line 90.98%; the measured figure on a clean `verify` is **90.32%** (branch matches exactly at 77.72%). Not a
finding, but the reported number is 0.66 points optimistic.

### Probes: nothing was narrowed

Every `CipherProbe*` class diffed against `fa9feb7`. Seven files changed; all seven changes are assertion flips
that record a fix landing, an anchor-record arity change (`Anchor(hash, count)` → `Anchor(hash, count, null)`), or
a strengthening. In detail:

- `CipherProbeJdbcTest`, `CipherProbeReverifyJdbcTest` — the new `keyedFromSeq` component only. No assertion lost.
- `CipherProbeReverifyTest` — V1 and V3 flipped to the fixed expectation. The V2 probe
  `probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` was re-scoped to the *partial* downgrade and the
  original whole-trail repro restored beside it as
  `probe_a_fully_downgraded_trail_verifies_as_broken_not_intact`. Both now assert BROKEN. Net coverage is wider,
  not narrower.
- `CipherProbeCleanTest` — V3 domain prefix folded into the expectation. Same property asserted.
- `CipherProbeReverifyStartupTest` — V4 flipped from "nothing warns" to "warns", on both `tenant-scoped` and
  `require-tenant`.
- `CipherProbeJedisFactoryTest` (V5) — **checked specifically for weakening, and it is the reverse.** The burst was
  previously forced to run with `max-total = 200` because worker count was tied to it; it now runs 200 concurrent
  virtual threads × 5 calls against a connection pool of **4**, with the worker pool and its bounded queue sized
  from their own properties. Every assertion is unchanged (zero errors, exact final counter of 1000, calls on
  platform threads below JDK 24). This is the H3/R6 contention scenario the earlier round asked to restore.

### C6's test change is a re-modelling, not a weakening

`CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail` changed from
"verify an unkeyed trail with a keyed verifier and no further appends → INTACT" to "restart the sink with the key,
append one row, verify → INTACT with 3 rows". Under Dollar's ruling that first shape can no longer be INTACT by
construction: a key given with `keyed_from_seq` still null is `UNKEYED` by design. That exact shape is not dropped
— it is asserted by `AuditChainVerifierTest.a_key_given_to_the_verifier_but_never_used_by_the_sink_reports_unkeyed`,
which pins it to `UNKEYED` and, crucially, **not** to `BROKEN`, which is the false alarm C6 existed to prevent. The
new form additionally exercises the restarted-sink path that a real migration takes. Accepted.

### V1, V3, V4, V5 — verified in code and by probe

- **V1** (raw byte cap after the unregistered-tool lookup). `ToolGuard.guard` now calls `rejectIfTooLarge` as the
  first statement, before `policies.resolve`. Both no-policy and no-role paths are covered by the flipped probe;
  the audit row carries the raw-domain hash, proving nothing parsed the payload. Closed.
- **V3** (no domain separation between the canonical and raw `args_hash`). `ArgumentCanonicalizer.hash` prefixes
  `agcanon1:`, `AuditRecorder.recordOversized` prefixes `agraw1:`; the two hash over disjoint material. Separately,
  `rejectIfTooLarge` now also bounds the *canonical* length, closing the non-size-preserving-canonicalisation gap
  that V3 rode in on. Closed.
- **V4** (cross-tenant approver opt-outs were silent). `AgentGuardStartupCheck` warns on both
  `endpoints.tenant-scoped=false` and `endpoints.require-tenant=false`, gated on the endpoints being enabled.
  Observed live in the sample app's startup log during `verify`. Closed.
- **V5** (worker pool tied to `max-total`). `platform-thread-count` and `platform-thread-queue-size` with
  `@Min(1)`, defaulting to `max-total` and to the effective thread count respectively; `JedisBudgetStoreFactory`
  passes both through to the new `onPlatformThreads(jedis, threads, queueSize, maxWait)` overload. Closed, and the
  probe now exercises a genuinely contended connection pool.

### V2's new surface: four findings

New probe class `agent-guard-core/src/test/java/com/housedevinci/agentguard/adapter/jdbc/CipherProbeAnchorKeyingJdbcTest.java`
— seven tests, all green, against real PostgreSQL 16 with the append-only triggers physically disabled where the
attack needs it (the step the previous round listed as not covered). Four `probe_*` tests assert today's broken
behaviour so the suite stays green; Isis flips each assertion when the fix lands.

- **F1 — MEDIUM. `keyed_from_seq` is written as `row_count + 1`, not the row's real `seq`.**
  `JdbcAuditSink.append` computes `keyedFromSeq = count + 1` from the anchor's row *count*, but the verifier
  compares it against `agentguard_audit.seq`, a `bigserial`. The two diverge on the first gap in the sequence, and
  a rolled-back INSERT leaves a gap — a role holding **exactly** the documented runtime grant can burn sequence
  values at will (proved: `confirms_the_documented_runtime_role_can_burn_sequence_values_but_not_touch_the_trigger`),
  and an ordinary failed append does it by accident. The keying transition is then recorded at a sequence belonging
  to an older, legitimately unkeyed row, and the verifier reports **BROKEN on a trail nobody touched** —
  permanently, because the extended trigger makes the column immutable once set. An attacker cannot turn this into
  a false INTACT (`count + 1 ≤ seq` always), but they can permanently disable the control, which is the same
  outcome for an operator who learns to ignore it.
  *Fix:* do the `INSERT … RETURNING seq` first and write the anchor with the returned sequence in the same
  transaction — the advisory lock already serialises appends, so ordering the two statements the other way is safe.
  *Test:* `probe_a_bigserial_gap_makes_an_untampered_keyed_trail_report_broken`, asserting `INTACT`.

- **F2 — MEDIUM. The schema's anchor seed forgets `keyed_from_seq`, and it beats the sink's re-derivation.**
  `JdbcAuditSink.append` re-derives `keyed_from_seq` as `min(seq) WHERE chain_version = 'ag2h'` when the anchor row
  is missing, but the schema step's seed (`INSERT INTO agentguard_audit_anchor (id, head_hash, row_count,
  updated_at) SELECT …`) does not. Startup runs the schema before any append, so on an installation whose anchor
  row was lost — a restore from a pre-anchor dump, the "pre-anchor installation" both the code and the schema
  explicitly anticipate — the seed wins and the sink's re-derivation never runs. A genuinely keyed trail comes back
  with `keyed_from_seq` NULL and every row claiming `ag2h`: **BROKEN**. The next append then stamps
  `keyed_from_seq` with the current (wrong) sequence and the trigger freezes the mistake in place.
  *Fix:* derive it in the seed too — add `(SELECT min(seq) FROM agentguard_audit WHERE chain_version = 'ag2h')` as
  the seeded `keyed_from_seq`, matching the sink exactly.
  *Test:* `probe_the_schema_anchor_seed_forgets_keyed_from_seq_and_breaks_a_keyed_trail`, asserting `INTACT`.

- **F3 — MEDIUM. Nothing refuses DELETE on the anchor, and the verifier's fallback is silent.**
  `agentguard_audit` has a row trigger *and* a TRUNCATE trigger; `agentguard_audit_anchor` has a `BEFORE UPDATE`
  trigger only. With the anchor row gone, `AuditChainVerifier` sets `anchorKnowsKeying = false`, drops back to the
  in-trail `keyedSeen` rule and reports the whole-trail downgrade as **INTACT** again — the exact V2 result the fix
  closed — and the head-hash/row-count check disappears in the same breath, so tail deletion goes undetected too.
  There is no distinct status, no field on `Report`, and no log line: an unanchored verification is
  indistinguishable from an anchored one. Two ways in: the table owner (a documented residual — the runtime role is
  confirmed unable to DELETE the anchor, replace the trigger function, or `DISABLE TRIGGER`), and, needing no
  privilege at all, any `AuditReader` that does not implement `AuditAnchor`, which `AuditChainVerifier.of` accepts
  and silently downgrades via `Optional::empty`.
  *Fix, two parts:* (a) refuse DELETE and TRUNCATE on `agentguard_audit_anchor` with the same trigger pattern used
  on `agentguard_audit`; (b) make the fallback loud — a distinct `Status.NO_ANCHOR`, or an `anchored` flag on
  `Report`, whenever `anchor.anchor()` is empty, so an unanchored verification can never render as INTACT.
  *Test:* `probe_deleting_the_anchor_row_restores_the_whole_trail_downgrade_to_intact`, asserting the new status.

- **F4 — LOW. A rolling restart while the secret is being enabled corrupts the trail permanently.**
  Nothing stops a still-unkeyed instance appending after another instance has set `keyed_from_seq`. During a
  rolling restart that turns `agentguard.audit.hmac-secret` on — the ordinary way to deploy it — one unkeyed row
  lands after the keying point and the trail is **BROKEN forever**: the row cannot be deleted (append-only) and
  `keyed_from_seq` cannot be moved (immutable). The documented migration story ("enabling the HMAC key is a one-way
  step, safely") does not say the step has to be atomic across instances.
  *Fix:* `JdbcAuditSink.append` refuses to append with an unkeyed chain when the anchor already carries a non-null
  `keyed_from_seq` — fail closed on the misconfigured instance rather than corrupt the trail — plus a line in
  `docs/index.md` and `SECURITY-NOTES.md` that enabling the secret requires a stop-start, not a rolling restart.
  *Test:* `probe_an_unkeyed_instance_appending_after_the_keying_point_breaks_the_trail_forever`, asserting the
  unkeyed append throws.

### Attacked and found sound (kept as regression cover)

- **`keyed_from_seq` race between two sink instances at the first keyed append.** The transaction-scoped advisory
  lock in `JdbcAuditSink.append` covers the read of `keyed_from_seq`, the anchor upsert and the row INSERT as one
  unit. Twelve concurrent appends across two sink instances: exactly one write, value equal to the lowest keyed
  sequence, no immutability-trigger rejection, trail INTACT.
  (`confirms_concurrent_first_keyed_appends_set_keyed_from_seq_exactly_once`)
- **Trigger extension via `CREATE OR REPLACE FUNCTION` on an existing database.** Reproduced against a database
  carrying the pre-V2 function body (under which `keyed_from_seq` was freely movable, and was moved). Running the
  new schema replaces the body in place and the existing trigger, which references the function by oid, picks it up
  without being recreated: the very next attempt to move `keyed_from_seq` is refused. Upgraded installations get
  the protection, not only fresh ones. The runtime role cannot replace the function — it is not the owner.
  (`confirms_the_extended_monotonic_trigger_applies_to_an_upgraded_database`)
- **What the documented runtime role can and cannot do.** With exactly the grant in docs "Database roles": DELETE
  on the anchor is `permission denied`, `CREATE OR REPLACE FUNCTION` on the monotonic trigger fails, `ALTER TABLE …
  DISABLE TRIGGER ALL` fails. Only the sequence burn of F1 gets through.
  (`confirms_the_documented_runtime_role_can_burn_sequence_values_but_not_touch_the_trigger`)
- **UNKEYED vs INTACT reporting paths.** `UNKEYED` is returned only after the whole trail has recomputed, so it
  never masks a break, and `Report.intact()` deliberately returns `false` for it. No production code calls
  `AuditChainVerifier.verify()` — it is an operator-facing API, not wired to an endpoint or to startup — so there
  is no path on which `UNKEYED` is mistaken for a failure by the module itself. An operator alerting on
  `!report.intact()` will be paged for the window between setting the secret and the first tool call; that is the
  designed, documented, conservative behaviour, and it is fail-loud in the safe direction. Not a finding.
- **JDBC read-and-append of `keyed_from_seq` in one transaction.** Covered by the advisory lock as above; the
  anchor upsert and the audit INSERT are in the same transaction and roll back together.

### Not covered

Real OpenAI/Anthropic `ChatModel` end to end (no key, no network) — unchanged from every prior pass. The table-owner
residual (owner drops the anchor trigger and rewrites `keyed_from_seq` alongside the trail) is accepted by design
and was not probed beyond confirming the runtime role cannot reach it. `keyed_from_seq` behaviour was not exercised
under a PostgreSQL logical restore or a `pg_dump`/`pg_restore` cycle — F2 models the outcome (a lost anchor row),
not the mechanism. Sequence-burn was proved against `bigserial` gaps generally, not against every way one can
arise (sequence caching under `CACHE > 1`, a failover replica's sequence advance).

### Verdict: MERGE WITH FIXES

No HIGH. V1, V3, V4, V5 are genuinely closed, in code and by probe, and none of the existing probes was narrowed —
the V5 and V2 probes are both wider than they were. V2's chosen mechanism is the right one: `keyed_from_seq` is
outside the rows an attacker rewrites, the advisory lock makes its one write atomic, the monotonic trigger holds on
upgraded databases as well as fresh ones, and the runtime role cannot touch it. What is not right yet is its
plumbing: it is written from the wrong number (F1), forgotten by the seed that re-creates the anchor (F2), and both
it and the head/count check evaporate without a word when the anchor row is absent (F3). F1 and F2 turn a control
an operator explicitly turned on into a permanent false alarm; F3 hands the original V2 attack back to anyone
holding the table or supplying their own reader. Three MEDIUM and one LOW, each with a named fix and a probe to
flip. Under the no-allowance rule all four ship before merge.

## Design change: keyed-from-birth (Dollar ruling)

Rather than iterate the sequence-position anchor mechanism (`agentguard_audit_anchor.keyed_from_seq`) once more to
close F1/F2/F3/F4, Dollar and Souhaile decided the design itself: **a trail is keyed from row 1 or unkeyed
forever.** No mixing, no later switch, no accommodating "enabling the key on a running installation" (the old C6
goal). `agentguard.audit.hmac-secret` is required by default; missing, startup fails naming the property and the
remedy (`openssl rand -base64 32`). The explicit opt-out for local development, `agentguard.audit.unkeyed=true`,
starts unkeyed but warns at every startup. Which mode a trail is in is recorded once, at the first append, as a
plain `agentguard_audit_anchor.keyed` boolean (immutable afterwards via the anchor's existing monotonic trigger,
Cipher R4); every later append, from any instance, must agree with it or is refused
(`AgentGuardException`/`AG-AUDIT-001`), which is what makes a rolling restart that flips `hmac-secret` fail loud on
the mismatched instance instead of corrupting the trail — the exact hole F4 named. `AuditChainVerifier.verify`
checks every row's `chain_version` against what `keyed` says the whole trail must be, and, given a key, refuses to
render an unanchored check as `INTACT` (a distinct `Status.NO_ANCHOR`, WARN-logged) — this closes F3(b)
independently of the migration. F3(a) — BEFORE DELETE/TRUNCATE triggers on the anchor table — ships unchanged by
the redesign, since it was always independent of the sequence-position mechanism.

F1 and F2 do not carry forward: both were about deriving a *sequence position* correctly (from `row_count` vs.
`seq`, and re-deriving it when the anchor row was lost). With no sequence position left to derive — `keyed` is a
constant boolean for the trail's whole lifetime — there is nothing analogous to get wrong the way F1 and F2 did.
The schema seed still derives `keyed` from the trail's own head for a lost-anchor installation, and is covered by a
new regression test, but this is routine correctness, not a named finding.

Old probe → new probe map (`CipherProbeAnchorKeyingJdbcTest` unless noted):

| Old (this pass) | New | Why |
|---|---|---|
| `probe_a_bigserial_gap_makes_an_untampered_keyed_trail_report_broken` (F1) | *(removed, no replacement)* | No sequence position is derived any more; a `bigserial` gap cannot corrupt a constant boolean. |
| `probe_the_schema_anchor_seed_forgets_keyed_from_seq_and_breaks_a_keyed_trail` (F2) | `the_schema_seed_derives_keyed_correctly_for_a_keyed_trail_with_a_lost_anchor` | Same shape (lost anchor, re-seeded by the schema step), asserting the boolean is derived correctly rather than a sequence number. |
| `probe_deleting_the_anchor_row_restores_the_whole_trail_downgrade_to_intact` (F3, first half) | `the_whole_trail_downgrade_is_broken_because_the_anchor_says_keyed` | Anchor stays intact (DELETE is now refused); asserts the version-vs-`keyed` mismatch is caught without any hash recomputation needed. |
| `probe_deleting_the_anchor_row_restores_the_whole_trail_downgrade_to_intact` (F3, second half) | `anchor_delete_and_truncate_are_refused` | F3(a): DELETE/TRUNCATE on the anchor now raise, matching `agentguard_audit`'s own triggers. |
| *(new)* | `a_key_given_with_no_anchor_reader_reports_no_anchor_never_intact` (this class) and `AuditChainVerifierTest.a_key_given_with_no_anchor_reports_no_anchor_never_intact` | F3(b): a reader that is not an `AuditAnchor`, or has no anchor row, reports `NO_ANCHOR`, replacing the old `Status.UNKEYED` probe (`a_key_given_to_the_verifier_but_never_used_by_the_sink_reports_unkeyed`), which tested a scenario (`keyed_from_seq` null) that no longer exists. |
| `probe_an_unkeyed_instance_appending_after_the_keying_point_breaks_the_trail_forever` (F4) | `an_unkeyed_instance_is_refused_once_the_trail_is_keyed` | Same rolling-restart scenario; asserts the append (now the construction) is refused with `AG-AUDIT-001`, not that the trail ends up `BROKEN`. |
| *(new, F4's mirror image, not covered before since one-way "enable the key" was the only direction considered)* | `a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed` | A newly-keyed instance must not silently start signing a trail that began unkeyed. |
| *(new)* | `the_mismatch_is_also_refused_on_append_not_only_at_construction` | The refusal is not only a startup check: an instance constructed while the trail was still empty must also be refused on its first append once another instance has keyed it. |
| `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail` (C6) | `CipherProbeAnchorKeyingJdbcTest.a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed` (message assertions) | C6's premise — accommodating a later-enabled key on an existing unkeyed trail — is invalid under keyed-from-birth; the replacement asserts the refusal and its remedy message instead. |
| `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` / `probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` | *(kept, unchanged assertions)* | Both already modelled the whole/partial downgrade against an immutable external anchor field; only the javadoc referring to `keyed_from_seq` was updated to `keyed`. Still pass unmodified against the new verifier logic. |
| `AgentGuardAutoConfigurationTest.hmac_secret_must_be_long_enough_and_keys_the_chain` | *(kept, unchanged)* | Length validation is orthogonal to the required-by-default change. |
| *(new)* | `AgentGuardAutoConfigurationTest.missing_hmac_secret_fails_startup_naming_the_property_and_the_remedy` | `agentguard.audit.hmac-secret` required by default. |
| *(new)* | `AgentGuardAutoConfigurationTest.unkeyed_opt_out_starts_but_warns_every_time` | The explicit `agentguard.audit.unkeyed=true` opt-out, warning at every startup. |

### Amendment (Dollar, after Cipher's design review of keyed-from-birth)

Five additions to the ruling above, folded into the same branch before push:

1. **Key id per row, inside the hashed material, from v1.** `agentguard_audit.key_id` (`'none'` for unkeyed rows);
   `AuditChain`'s canonical form now includes it (`version|key_id|timestamp|…`). `keyed` still decides *whether* a
   key is required (immutable); `key_id` only says *which* key signed a row. `AuditChainVerifier` holds a keyring
   (`agentguard.audit.hmac-key-id`/`hmac-secret` plus every `agentguard.audit.hmac-keys.<id>`); an id it does not
   hold is `BROKEN`. Rotation is then a config change, not a trail migration.
2. **Missing anchor on a non-empty trail refuses to append**, on both `JdbcAuditSink` (construction and every
   append) and the schema seed. The "re-anchor from the trail head" fallback and its `WARNED_MISSING_ANCHOR`
   one-time-log guard are removed entirely; the schema seed's `INSERT … ON CONFLICT DO NOTHING` no longer derives
   values from an existing trail — it only ever matches a genuinely empty one.
3. **`NO_ANCHOR` unconditionally**, not only when a key is given: an unanchored verification is never `INTACT`
   (or now `INTACT_UNKEYED`) regardless of whether the trail is meant to be keyed.
4. **The `Report` carries the trail's mode** (`anchored`, `keyed`, `keyIds`); an unkeyed trail's clean result is
   the distinct `Status.INTACT_UNKEYED`, replacing the deleted `Status.UNKEYED` (which was about a different,
   now-impossible situation — a key configured on the verifier that no row ever used) with an honest rendering of
   the common case (a real, by-design unkeyed deployment).
5. **"Start a new trail" is defined** in docs/index.md and SECURITY-NOTES.md as an owner-run procedure (archive
   `agentguard_audit`/`agentguard_audit_anchor`, re-run the schema step), and the startup-failure message only
   fires when an anchor exists and disagrees — a fresh install with a secret starts fine. Documented: the secret
   must not live in the same store as the datasource credentials, or it is a second factor over nothing.

Old-probe → new-probe map, additions to the table above (`CipherProbeAnchorKeyingJdbcTest` unless noted):

| Old / superseded | New | Why |
|---|---|---|
| `an_unkeyed_instance_is_refused_once_the_trail_is_keyed` (unchanged assertions) | *(kept)* | Append-time refusal is orthogonal to key ids: a keyed-vs-unkeyed mismatch, not a key-id mismatch. |
| `the_schema_seed_derives_keyed_correctly_for_a_keyed_trail_with_a_lost_anchor` (this amendment's own first draft, never shipped) | `an_orphaned_keyed_trail_without_an_anchor_refuses_to_append` | Point 2: the schema no longer re-derives `keyed` for a lost anchor on a non-empty trail; it refuses instead. |
| `CipherProbeReverifyJdbcTest.trail_without_anchor_row_continues_from_the_real_head` (R2) | `CipherProbeReverifyJdbcTest.a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor` | Same point 2, on the unkeyed side: a non-empty trail that loses its anchor is refused, not continued. |
| `CipherProbeFinalJdbcTest.concurrent_first_starts_seed_one_consistent_anchor_while_appends_run` | `concurrent_first_starts_and_appends_never_abort_each_other_on_an_anchored_trail` | The probe used to delete the anchor from a non-empty trail to model "pre-anchor install"; that scenario is now a refusal, not a race to re-seed. Kept the still-valid part: concurrent schema runs and appends on an *anchored* trail never abort each other (R11). |
| *(new)* | `mixed_key_rows_verify_intact_with_both_keys_in_the_keyring` | Point 1: a trail with rows signed under two different key ids, both known to the verifier, is `INTACT`. |
| *(new)* | `an_unknown_key_id_is_broken` | Point 1: a row's `key_id` absent from the keyring is `BROKEN`, not skipped. |
| *(new)* | `a_stale_key_second_instance_appends_but_only_verifies_with_its_own_id_in_the_keyring` | Point 1: a rotation window (two keyed instances, different ids) appends fine on both; verifying with only the new key reports `BROKEN` at the old instance's row, naming the sequence. |
| `AuditChainVerifierTest.a_key_given_to_the_verifier_but_never_used_by_the_sink_reports_unkeyed` (`Status.UNKEYED`, already replaced above) | `AuditChainVerifierTest.an_unkeyed_trail_never_renders_plain_intact` (new) | Point 4: the deleted `UNKEYED` status is not reused; a genuinely unkeyed, by-design trail gets its own honest status instead. |
| all `Status.INTACT` assertions against an unkeyed sink across `CipherProbeJdbcTest`, `CipherProbeReverifyJdbcTest`, `CipherProbeFinalJdbcTest`, `AuditChainVerifierTest` | `Status.INTACT_UNKEYED` | Point 4, mechanical rename following the `Report` widening; `Status.INTACT` on a keyed sink is unchanged. |

## Verification of keyed-from-birth (722e9a5)

Cipher, 2026-09-08. Branch `feat/agent-guard-core`, HEAD `722e9a5`, diffed against `25da6af`.
Full `./mvnw clean verify`, Docker up, no skipped module.

**Verdict: MERGE WITH FIXES.** No HIGH. Two MEDIUM (both in the schema step, both reproduced),
two LOW and two INFO. The keyed-from-birth design itself holds: every point of the ruling and of the
amendment is implemented as described, and every attack against the runtime path failed.

### Numbers

| | Isis reported (722e9a5) | Cipher measured (722e9a5) | With Cipher's probes |
|---|---|---|---|
| Tests run | 190 | 190 | 206 |
| Failed | 0 | 0 | 0 |
| Skipped | 1 | 1 (`CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on`, `assumeTrue` on the Spring AI tool autoconfiguration) | 1 |
| Line coverage (`agent-guard-core/target/site/jacoco/jacoco.csv`) | 90.48% | 90.48% (1550/1713) | 90.60% (1552/1713) |
| Branch coverage | 78.14% | 78.14% (461/590) | 78.14% (461/590) |
| JaCoCo 80% line gate | — | met (`All coverage checks have been met`) | met |

All 20 `CipherProbe*` classes green, none narrowed. New this pass:
`CipherProbeKeyedBirthJdbcTest` (7), `CipherProbeKeyringTest` (6), `CipherProbeMemoryParityTest` (3).

### Probe map walk

Every removed probe has its replacement and every replacement tests the equivalent property under
the new rule, not a weaker one:

- F1's removal is correct: `git grep keyed_from_seq` returns only the schema's `DROP COLUMN IF
  EXISTS` line. There is no sequence position left to derive, so there is nothing for the old probe
  to assert.
- F2 → `an_orphaned_keyed_trail_without_an_anchor_refuses_to_append` is **stronger**: the old probe
  asserted the seed derived a value correctly; the new one asserts it derives nothing and refuses.
- F3(a) → `anchor_delete_and_truncate_are_refused`: same property, now enforced. Independently
  re-confirmed — my own probes had to `DISABLE TRIGGER` to remove an anchor row at all.
- F3(b) → `a_key_given_with_no_anchor_reader_reports_no_anchor_never_intact` plus
  `AuditChainVerifierTest.a_key_given_with_no_anchor_reports_no_anchor_never_intact`: wider than the
  deleted `UNKEYED` probe, because `NO_ANCHOR` is now returned before the key is even consulted.
- F4 → `an_unkeyed_instance_is_refused_once_the_trail_is_keyed`, plus its mirror
  `a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed` and
  `the_mismatch_is_also_refused_on_append_not_only_at_construction`: three refusals where the old
  probe asserted one corruption. Stronger.
- C6's replacement is legitimate. C6's premise (a key enabled later on an existing unkeyed trail)
  is invalid under keyed-from-birth; asserting the refusal and its remedy text is the right
  successor, not a narrowing.
- `CipherProbeReverifyJdbcTest.trail_without_anchor_row_continues_from_the_real_head` (R2) →
  `a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor`: the old behaviour was the
  hole; refusing is strictly stronger.
- The `INTACT` → `INTACT_UNKEYED` sweep across `CipherProbeJdbcTest`,
  `CipherProbeReverifyJdbcTest`, `CipherProbeFinalJdbcTest` and `AuditChainVerifierTest` is a
  mechanical rename; no keyed-sink `INTACT` assertion was weakened.

### Design points verified in code

| Point | Verified |
|---|---|
| Secret required by default, exact startup message | `AgentGuardAutoConfiguration.auditChain` throws `AgentGuardConfigurationException` naming `agentguard.audit.hmac-secret`, `agentguard.audit.unkeyed` and `openssl rand -base64 32`. Yes |
| `audit.unkeyed=true` WARNs every startup | WARN is unconditional on the branch, not guarded by a one-time flag; `unkeyed_opt_out_starts_but_warns_every_time` counts ≥2 occurrences across two context starts. Yes |
| Anchor `keyed` set at first append under the advisory lock | `JdbcAuditSink.append` takes `pg_advisory_xact_lock(LOCK_KEY)` first, then INSERTs the anchor with `keyed`; `ON CONFLICT DO UPDATE` deliberately does not list `keyed`. Yes |
| `keyed` immutable via trigger | `agentguard_audit_anchor_monotonic` raises on `NEW.keyed IS DISTINCT FROM OLD.keyed`. Yes |
| Mismatch refused at construction AND every append (`AG-AUDIT-001`) | `refuseIfMismatched` is called from the constructor and from inside the append transaction, after the lock. Yes |
| Missing anchor on non-empty trail refuses (`AG-AUDIT-002`) | Both call sites; the schema's `ON CONFLICT DO NOTHING` seed is gone entirely. Yes for the runtime |
| No re-derivation path anywhere, including the schema seed | **No** — see G2: the schema still derives `keyed` from the trail head. |
| `key_id` inside `canonical()` and the hashed material | `canonical(e, version, keyId)` appends `keyId` as the first length-prefixed field, before the timestamp; `hashOfEvent` signs that string. Yes |
| Keyring verification; unknown id → BROKEN; `none` only on unkeyed trails | `chainForRow` returns `null` for an unknown id, for `none` on a keyed trail, and for a real id on an unkeyed trail; `null` → `BROKEN`. Yes |
| `NO_ANCHOR` unconditional; `of` never renders a non-anchor reader INTACT | `verify()` returns `NO_ANCHOR` before reading the keyring at all; `of` falls back to `Optional::empty`, which is the `NO_ANCHOR` path. Yes |
| `INTACT_UNKEYED` never rendered as `INTACT` | Distinct enum constant; `AuditChainVerifier` is not exposed by any endpoint, so there is no second rendering to check. Yes |
| DELETE/TRUNCATE guards on the anchor | `agentguard_audit_anchor_no_delete` / `_no_truncate`. Yes |
| Schema idempotent on an existing database | **No** — see G1 and G2. Idempotent on a *current* non-empty database (`confirms_the_schema_step_is_idempotent_on_a_current_non_empty_database`), but it aborts on one written before `key_id`/`keyed` existed. |

### Attacks that failed (kept as regression cover)

- **Two-instance stale key.** Two keyed sinks, ids `k1` and `k2`, both append to the same trail;
  rows carry the id that wrote them; the full keyring verifies `INTACT`, a keyring missing `k1`
  reports `BROKEN` at seq 1, never `INTACT`.
  (`confirms_two_keyed_instances_with_different_ids_both_append_and_verify_together`.)
- **Key id relabel by a table owner.** With the append-only trigger disabled, relabelling a row's
  `key_id` to another id the verifier *does* hold still fails to recompute (the id is inside the
  signed material): `BROKEN` at exactly that sequence. Relabelling to an unheld id is `BROKEN` too.
  (`confirms_a_key_id_relabel_to_a_held_key_still_breaks_the_hash`,
  `confirms_a_key_id_relabel_to_an_unheld_key_is_broken`.)
- **`hmac-keys` parsing.** A short secret in the ring fails startup naming the id and not the value;
  the reserved id `none` is refused both as `hmac-key-id` and as a ring entry; a blank
  `hmac-key-id` is refused. (`confirms_a_short_retired_key_is_refused`,
  `confirms_the_reserved_none_id_is_refused`, `confirms_a_blank_key_id_is_refused`.)
- **Secret and key id present but the ring missing the appending id.** Not reachable:
  `auditKeyring` always seeds the appending id from `hmac-secret` before adding the retired ones.
- **Message leakage.** No `AG-AUDIT-001`/`AG-AUDIT-002` message, no startup failure and no captured
  log line contains secret bytes; the length-validation message names the property, not the value.
  (`confirms_no_refusal_message_carries_key_material`,
  `confirms_no_startup_message_carries_the_secret`.)
- **`InMemoryAuditSink` parity on the refusals.** It has no persisted state, so neither
  `AG-AUDIT-001` nor `AG-AUDIT-002` has a reachable analogue; it does carry `key_id` per row and
  reports `INTACT_UNKEYED` for an unkeyed trail. Parity accepted, with the H7 caveat below.
  (`confirms_an_unkeyed_memory_trail_is_intact_unkeyed`,
  `confirms_a_keyed_memory_trail_carries_the_key_id`.)

### Findings

**G1 — MEDIUM — the schema step cannot run against a database written before `key_id` existed.**
`ALTER TABLE agentguard_audit ADD COLUMN IF NOT EXISTS key_id …` is followed by
`UPDATE agentguard_audit SET key_id = CASE … WHERE key_id IS NULL`. On any database that already
ran an earlier build of this branch, `agentguard_audit_append_only` (BEFORE UPDATE, FOR EACH ROW) is
already present, so that UPDATE raises `agentguard_audit is append-only (attempted UPDATE)` and the
whole schema transaction aborts — the module cannot start at all. Repro:
`CipherProbeKeyedBirthJdbcTest.probe_an_existing_database_with_rows_cannot_run_the_new_schema_step`.
Fix (Isis): delete the backfill and the `ADD COLUMN`/`SET NOT NULL` pair; declare
`key_id varchar(64) NOT NULL` in the `CREATE TABLE agentguard_audit` body. There is no backward
compatibility to keep on an unreleased branch, and guessing `'k1'` for historical keyed rows is the
same "invent a value for rows we did not write" the amendment removed from the anchor seed. The
existing "start a new trail" procedure in `docs/index.md` is the documented answer for a database
written by an earlier build.

**G2 — MEDIUM — the anchor's `keyed` backfill is both refused by its own trigger and a surviving
re-derivation path.** `UPDATE agentguard_audit_anchor a SET keyed = COALESCE((SELECT
t.chain_version = 'ag2h' … ORDER BY t.seq DESC LIMIT 1), false) WHERE a.id = 1 AND a.keyed IS NULL`
does not advance `row_count`, so `agentguard_audit_anchor_monotonic` raises
`agentguard_audit_anchor only advances by one row` and the schema step aborts. Repro:
`CipherProbeKeyedBirthJdbcTest.probe_an_existing_anchor_row_cannot_be_backfilled_with_keyed`.
Separately from the abort, this statement is the re-derivation of `keyed` from row data —
specifically from `chain_version`, the column the design explicitly calls untrustworthy — that
amendment point 2 and `ErrorCodes.AUDIT_ANCHOR_MISSING`'s javadoc both state no longer exists
anywhere. Fix (Isis): delete the `UPDATE`, delete `ALTER TABLE … ADD COLUMN IF NOT EXISTS keyed` /
`ALTER COLUMN keyed SET NOT NULL`, and declare `keyed boolean NOT NULL` in the
`CREATE TABLE agentguard_audit_anchor` body. Keep the `DROP COLUMN IF EXISTS keyed_from_seq` line
only if the intent is to let an owner clean up by hand; it is inert either way.

**H1 — LOW — a retired key entry can silently shadow the appending key.**
`AgentGuardAutoConfiguration.auditKeyring` puts the appending key first and then lets every
`agentguard.audit.hmac-keys.<id>` overwrite it. `hmac-key-id=k1` with `hmac-keys.k1=<a different
secret>` leaves the verifier holding the wrong secret for `k1`, so every row this instance writes
verifies `BROKEN` — an integrity alarm caused by configuration, exactly the false positive that
trains an operator to ignore the real one. It is a plausible slip: `docs/index.md`'s rotation recipe
tells the operator to add `hmac-keys.k1=<old secret>` and change `hmac-key-id`; forgetting the
second half produces this. The properties javadoc's "redundant, not an error" is only true when the
secrets are identical, which nothing checks. Repro:
`CipherProbeKeyringTest.probe_a_retired_key_entry_can_shadow_the_appending_key`. Fix (Isis): in
`auditKeyring`, throw `AgentGuardConfigurationException` when an `hmac-keys` entry uses the
appending `hmac-key-id` with different bytes, naming the id and telling the operator to give the new
key a new id; an entry with identical bytes may stay a no-op.

**H2 — LOW — `agentguard.audit.unkeyed=true` together with `hmac-secret` is silently resolved.**
`auditChain` tests the secret first, so the secret wins and the `unkeyed` flag is never read: the
context starts keyed with no WARN and no failure. The direction is the safe one, but an operator who
believes they are running unkeyed gets a keyed trail — or, against an existing unkeyed trail, an
`AG-AUDIT-001` refusal whose message tells them to check a property they did set. Repro:
`CipherProbeKeyringTest.probe_unkeyed_true_with_a_secret_is_silently_ignored`. Fix (Isis): fail
startup on the contradiction — `agentguard.audit.unkeyed=true` with a non-blank
`agentguard.audit.hmac-secret` is a configuration error; say which two properties conflict and that
one of them must go.

**H3 — INFO — `InMemoryAuditSink` implements `AuditAnchor` by deriving it from the list it
anchors.** `keyed` comes from the live chain and `headHash`/`rowCount` from the last element, so a
memory trail that has lost its tail reports `INTACT` with `anchored()` true, where the JDBC sink
would report `ANCHOR_MISMATCH`. Development-only store, so this is not a runtime risk; it is a
claim the class makes that it does not keep. Repro:
`CipherProbeMemoryParityTest.probe_a_memory_trail_has_no_external_anchor`. Fix (Isis): one sentence
in the class javadoc and in `SECURITY-NOTES.md` — the memory store has no external anchor and
therefore no tail-deletion detection; it is not a substitute for the JDBC store in any deployment
where the audit trail matters.

**H4 — INFO — `SECURITY-NOTES.md` line 86 lists the verifier's statuses as `EMPTY` / `INTACT` /
`BROKEN` / `ANCHOR_MISMATCH` / `NO_ANCHOR` and omits `INTACT_UNKEYED`,** which the same document
introduces 45 lines later. Fix (Isis): add it to the list.

### Not verified

- PostgreSQL 16 only (the pinned Testcontainers digest). No other server version, and no test
  against a managed Postgres where the runtime role's grants differ from the documented ones.
- The rolling-restart scenarios are same-JVM, different `JdbcAuditSink` instances against one
  database. That exercises the refusal logic exactly, but not the surrounding deployment.
- G1/G2 were reproduced by removing the new column from a current database rather than by checking
  out `25da6af`, initialising, and upgrading. The mechanism (a pre-existing trigger versus the
  backfill statement) is identical and the raised messages are the schema's own.
- The sample app runs with `agentguard.audit.unkeyed=true`; its end-to-end test therefore covers the
  unkeyed path only.

## Clean verdict (f27c45e)

Cipher, 2026-09-08. Branch `feat/agent-guard-core`, HEAD `f27c45e`, diffed against `79d05be`.
Full `./mvnw clean verify`, Docker up, no module skipped.

**Verdict: MERGE WITH FIXES.** All six prior findings (G1, G2, H1, H2, H3, H4) are closed — verified
in the code and each one re-attacked with a probe. No HIGH, no MEDIUM. One new LOW, **J1**, in the
schema guard that the G1/G2 fix introduced: it is not schema-scoped, so a stale copy of the table in
another PostgreSQL schema blocks a fresh install. Under the no-allowance rule that is a fix list,
not a merge.

### Numbers

| | Isis reported (f27c45e) | Cipher measured (f27c45e) | With Cipher's probes |
|---|---|---|---|
| Tests run | 207 | 207 (151 core + 55 starter + 1 sample) | 215 (156 + 58 + 1) |
| Failed | 0 | 0 | 0 |
| Skipped | 1 | 1 (`CipherProbeFinalSpringAiTest`, `assumeTrue` on the Spring AI tool autoconfiguration) | 1 |
| Line coverage (`agent-guard-core/target/site/jacoco/jacoco.csv`) | 90.60% | 90.60% (1552/1713) | 90.60% (1552/1713) |
| Branch coverage | 78.14% | 78.14% (461/590) | 78.14% (461/590) |
| JaCoCo 80% line gate | — | met (`All coverage checks have been met`) | met |

All 23 `CipherProbe*` classes green (89 probe tests). Probe-method diff `79d05be..f27c45e`: two
additions, **zero deletions**, no narrowing. `probe_a_retired_key_entry_can_shadow_the_appending_key`
and `probe_unkeyed_true_with_a_secret_is_silently_ignored` were inverted from "asserts the hole" to
"asserts the refusal", which is the correct direction, and H1 gained
`confirms_a_retired_key_entry_matching_the_appending_secret_is_a_noop` as cover for the no-op the
fix must not break. New this pass: `CipherProbeCleanVerdictJdbcTest` (5),
`CipherProbeCleanVerdictStartupTest` (3).

### The six, verified

| Finding | Fix | Verified in code | Verified by probe |
|---|---|---|---|
| G1 MEDIUM — `key_id` backfill refused by the append-only trigger | `5d627ce` | `key_id varchar(64) NOT NULL` is in the `CREATE TABLE agentguard_audit` body; the `ADD COLUMN` / `UPDATE … WHERE key_id IS NULL` / `SET NOT NULL` trio is gone (`git grep` finds no backfill of either column) | `CipherProbeKeyedBirthJdbcTest.probe_an_existing_database_with_rows_cannot_run_the_new_schema_step` now asserts the new message, green |
| G2 MEDIUM — anchor `keyed` backfill re-derived from `chain_version` | `5d627ce` | `keyed boolean NOT NULL` in the `CREATE TABLE agentguard_audit_anchor` body; the `UPDATE agentguard_audit_anchor … chain_version = 'ag2h'` statement is deleted. **No re-derivation path is left anywhere** — this was the one "No" in the design table of the previous pass, and it is now Yes | `probe_an_existing_anchor_row_cannot_be_backfilled_with_keyed`, green |
| H1 LOW — a retired key entry shadows the appending key | `488fdcd` | `auditKeyring` throws `AgentGuardConfigurationException` when an `hmac-keys` entry uses the appending `hmac-key-id` with different bytes; identical bytes still fall through as a no-op | `probe_a_retired_key_entry_can_shadow_the_appending_key` (fails startup naming both properties) and `confirms_a_retired_key_entry_matching_the_appending_secret_is_a_noop`, both green; my own `probe_a_same_secret_ring_duplicate_is_a_no_op` confirms the ring still holds the appending secret under `k1` alongside a genuine retired `k0` |
| H2 LOW — `unkeyed=true` + `hmac-secret` silently resolved | `488fdcd` | the contradiction is the **first** statement in `auditChain`, before the secret-required branch | `probe_unkeyed_true_with_a_secret_is_silently_ignored` (inverted), green |
| H3 INFO — `InMemoryAuditSink`'s self-derived anchor | `b311974` | class javadoc "No external anchor (Cipher H3)" plus a `SECURITY-NOTES.md` bullet, both saying the trail cannot detect its own tail being trimmed and is not a substitute for the JDBC store | doc-only; `CipherProbeMemoryParityTest` unchanged and green |
| H4 INFO — `INTACT_UNKEYED` missing from the status list | `b311974` | `SECURITY-NOTES.md` line 86 now lists `EMPTY / INTACT / INTACT_UNKEYED / BROKEN / ANCHOR_MISMATCH / NO_ANCHOR` | n/a |

### G1/G2 — the four extra checks

- **Idempotent three times.** `JdbcSupport.initializeSchema` three times on a fresh database created
  by this version, then two keyed appends, then three more times: row count, `head_hash` and
  `keyed` are byte-identical after the last run.
  (`probe_schema_step_is_idempotent_three_times_empty_and_non_empty`.)
- **Concurrent starts on an empty database.** Twelve threads released together against one empty
  database: zero failures, one table set, and a first append lands normally afterwards — the
  `pg_advisory_xact_lock(18374244850549833)` at the top of the script still serialises the whole
  step, and the new `DO $$` guard sits inside that lock, not before it.
  (`probe_concurrent_schema_steps_on_an_empty_database_all_succeed`.)
- **A fresh empty database never trips the detection.** The guard fires only when the table exists
  *and* the column does not; on an empty database neither `EXISTS` clause holds.
  (`probe_a_fresh_empty_database_never_trips_the_predates_guard`.)
- **The message offers no in-place upgrade.** `audit schema predates keyed-from-birth; archive the
  table and start a new trail (see SECURITY-NOTES)` — asserted to contain "archive the table and
  start a new trail" and to contain none of "upgrade", "migrate", "add column", "backfill".
  (`probe_the_predates_message_offers_no_in_place_upgrade`.)

### Final attack on what changed

- **Startup-check ordering.** The unkeyed+secret contradiction fires before anything touches the
  database. Proven, not argued from bean declaration order: a context with a real `DataSource`,
  `agentguard.store=JDBC`, `unkeyed=true` and a secret fails, and `to_regclass('agentguard_audit')`
  is still null afterwards — the schema step never ran.
  (`probe_the_unkeyed_contradiction_fires_before_the_database_is_touched`.)
- **Same-secret ring duplicate.** A pure no-op: startup succeeds, the ring holds exactly `{k1, k0}`
  and `k1` is the appending secret. (`probe_a_same_secret_ring_duplicate_is_a_no_op`.)
- **Secret bytes in messages.** Neither new message carries key material, and neither does the full
  stack trace behind it: the H2 contradiction, the H1 shadowing refusal and the short-retired-key
  refusal were each rendered to a string and asserted not to contain the secret or the short value.
  Both new messages name property *names* and the key *id* only.
  (`probe_no_startup_failure_message_carries_key_material`.)

### Finding

**J1 — LOW — the pre-redesign guard is not schema-scoped, so a stale copy in another schema blocks a
fresh install.** The new `DO $$` block matches `information_schema.tables WHERE table_name =
'agentguard_audit'` with no `table_schema` filter, while every other statement in the step
(`CREATE TABLE IF NOT EXISTS agentguard_audit`, the triggers, the anchor) is unqualified and
therefore search_path-relative. The two disagree. Create a schema `oldcopy` holding a pre-redesign
`agentguard_audit` and run the step against a completely empty `public`: it raises `audit schema
predates keyed-from-birth` and the module cannot start, even though the schema it would actually
write is fresh. Repro:
`CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`
(written green, asserting today's behaviour — the fix inverts it to `doesNotThrowAnyException`).
Two ways an operator reaches this: `docs/index.md` tells them to archive by "rename or drop", and
`ALTER TABLE agentguard_audit SET SCHEMA archive` is a rename most DBAs would reach for — after
which the guard permanently refuses startup, telling them to do the thing they just did; or a
schema-per-tenant database where one tenant has been migrated and another has not. No integrity
impact — it is a denial of startup, and it fires in the safe direction — hence LOW.
Fix (Isis): resolve the table through the search_path instead of scanning every schema. Replace both
`EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = …)` tests with
`to_regclass('agentguard_audit') IS NOT NULL` / `to_regclass('agentguard_audit_anchor') IS NOT NULL`,
and both column tests with a lookup against that same oid — `EXISTS (SELECT 1 FROM pg_attribute WHERE
attrelid = to_regclass('agentguard_audit') AND attname = 'key_id' AND NOT attisdropped)` and the
equivalent for `agentguard_audit_anchor` / `keyed`. That is the same object the rest of the script
creates and alters, so the guard and the script can no longer disagree. Invert the probe named above
to `assertThatCode(...).doesNotThrowAnyException()` and keep the four G1/G2 checks as they are.

### Not verified

- Unchanged from the previous pass: PostgreSQL 16 only (the pinned Testcontainers digest); no
  managed-Postgres run where the runtime role's grants differ; the rolling-restart scenarios remain
  same-JVM, different sink instances against one database; the sample app still runs
  `agentguard.audit.unkeyed=true`, so its end-to-end test covers the unkeyed path only.
- The G1/G2 pre-redesign scenarios are still reproduced by dropping the new column from a current
  database rather than by checking out `25da6af`, initialising, and starting this build against it.
  The condition the guard tests (table present, column absent) is identical either way.
- The concurrency check is twelve threads in one JVM against one database, which exercises the
  advisory lock exactly; it is not twelve separate processes or pods.

### What the audit trail guarantees today, in plain words

Once J1 is fixed this is ready to merge, and here is what it will mean. Every audit row is signed
with a secret the database never sees, and each row's signature covers the row before it, so the
trail is a chain: change one row, or delete one from the middle, and the next row stops matching. A
separate anchor row — which the database itself refuses to let anyone update backwards, delete, or
truncate — records the head of the chain and its length, so cutting rows off the *end*, the one
attack a chain alone cannot see, is caught too. The decision the last two rounds settled is that a
trail is keyed from its very first row or unkeyed forever: there is no switching, no guessing, and
no code path anywhere that infers whether a trail was keyed by looking at the rows themselves —
that inference was the last hole and it is now gone. An instance configured differently from the
trail it finds refuses to start and refuses to append, rather than quietly writing rows nobody can
verify later. Rotating the signing key is ordinary data, not a break: each row records which key id
signed it, the verifier holds the old keys as well as the new one, and a row naming a key nobody
holds reads as broken rather than being skipped. Running without a key at all is still possible for
local development, but it is now an explicit property that warns at every single startup, and
asking for both at once is refused outright.
The documented residuals, unchanged and accepted: a database role that *owns* these tables can turn
the guard triggers off and rewrite the chain and its anchor together — so run the application with a
narrower role that can only insert and read; a role with only that narrow grant can still append one
hand-written, correctly-linked row, which is detected at the next verification rather than
prevented; a point-in-time restore of the trail and its anchor together is invisible from inside the
database, so the head hash should be exported off-box on a schedule; and the in-memory store, for
tests and development only, derives its anchor from the very list it anchors and therefore cannot
detect its own tail being trimmed. There is no upgrade path from a database written by an earlier
build of this unreleased branch: such a database is refused at startup and the operator archives it
and starts a new trail, deliberately, by hand.

## Final verdict (05f209d)

Cipher, 2026-09-08. Branch `feat/agent-guard-core`, HEAD `05f209d`, diffed against `11dc8c3`.
Full `./mvnw -B clean verify`, Docker up, no module skipped.

**Verdict: MERGE WITH FIXES.** J1 is genuinely improved and its probe is correctly inverted, but it
is not closed: the new guard is scoped to search_path *visibility*, and the statement it is
protecting is scoped to the search_path's *creation* schema. Those are different sets, and a stale
pre-redesign table in the gap between them still refuses a fresh install. One new LOW, **K1**, no
HIGH, no MEDIUM. Under the no-allowance rule that is a fix list, not a merge. The fix is one clause
in one SQL file and it changes no existing probe's expected outcome.

### Numbers

| | Isis reported (05f209d) | Cipher measured (05f209d) | With Cipher's probes |
|---|---|---|---|
| Tests run | 215 | 215 (156 core + 58 starter + 1 sample) | 220 (161 + 58 + 1) |
| Failed | 0 | 0 | 0 |
| Skipped | 1 | 1 (`CipherProbeFinalSpringAiTest`, `assumeTrue` on the Spring AI tool autoconfiguration) | 1 |
| Line coverage (`agent-guard-core/target/site/jacoco/jacoco.csv`) | 90.60% | 90.60% (1552/1713) | 90.60% (1552/1713) |
| Branch coverage | 78.14% | 78.14% (461/590) | 78.14% (461/590) |
| JaCoCo 80% line gate | — | met | met |

Every number Isis reported reproduces exactly. Coverage is unchanged from `11dc8c3`, as it should be
for a two-clause SQL rewrite that adds no Java branch.

### Probe diff against `11dc8c3`

`git diff 11dc8c3 05f209d` touches exactly one test file, `CipherProbeCleanVerdictJdbcTest`, and
within it exactly one method: `probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`,
inverted from `assertThatThrownBy(...).hasMessageContaining("audit schema predates keyed-from-birth")`
to `assertThatCode(...).doesNotThrowAnyException()` — the J1 inversion and nothing else. No probe
was deleted, renamed, weakened or narrowed. All 25 `CipherProbe*` classes (97 probe tests) are green,
including the two same-schema G1/G2 probes
(`probe_a_fresh_empty_database_never_trips_the_predates_guard`,
`probe_the_predates_message_offers_no_in_place_upgrade`), which are byte-identical to `11dc8c3`.

### J1, verified in code

The `DO $$` guard in `agent-guard-core/src/main/resources/com/housedevinci/agentguard/schema-postgresql.sql`
now reads both existence checks through `to_regclass('agentguard_audit')` and
`to_regclass('agentguard_audit_anchor')`, and both column checks through
`pg_attribute WHERE attrelid = to_regclass(…) AND attname = … AND attnum > 0 AND NOT attisdropped`.
`git grep information_schema` over the module returns nothing. The guard still sits inside the
`pg_advisory_xact_lock` at the top of the script, so the serialisation the previous pass verified is
untouched. That is the fix as prescribed, applied literally.

### The attack on the change

Run directly against PostgreSQL 16 as a truth table, once with the shipped guard and once with the
fix proposed below, over the seven scenarios that matter:

| Scenario | Correct answer | Shipped guard | With the K1 fix |
|---|---|---|---|
| Fresh empty database | allow | allow | allow |
| Pre-redesign `agentguard_audit` in the current schema | refuse | refuse | refuse |
| Pre-redesign `agentguard_audit_anchor` in the current schema | refuse | refuse | refuse |
| Pre-redesign copy in a schema **off** the search_path (the J1 probe) | allow | allow | allow |
| Pre-redesign copy in a schema **on** the search_path, behind the creation schema | allow | **refuse** | allow |
| Pre-redesign copy in the creation schema itself (`search_path = archive, public`) | refuse | refuse | refuse |
| Current-schema table that already has `key_id` | allow | allow | allow |

One row is wrong, and it is K1. The other four attacks Dollar named came back clean:

- **`to_regclass` with a quoted / mixed-case name.** `to_regclass('agentguard_audit')` parses its
  argument with ordinary identifier rules and folds it to lower case — the same folding the
  unquoted `CREATE TABLE IF NOT EXISTS agentguard_audit` in the same script applies. A table created
  as `"AgentGuard_Audit"` is a different object to both, trips nothing, and is not shadowed by
  anything. The argument is a literal in a resource file, never operator or model input, so there is
  no injection surface to fold a name into either. The replaced `information_schema` predicate
  compared against the stored, already-folded `table_name`, so this is a behavioural no-change, not
  a regression. (`confirms_a_quoted_mixed_case_lookalike_table_does_not_trip_the_guard`.)
- **`pg_attribute` on a dropped-and-re-added column.** Correct in both directions. A dropped column
  leaves a `pg_attribute` row whose `attname` is rewritten to `........pg.dropped.N........`, so
  `attname = 'key_id'` could not match it even without the `NOT attisdropped` clause; the guard
  fires, which is right, because the column really is gone. Re-adding `key_id` inserts a fresh live
  row and the guard goes quiet. `attnum > 0` excludes the system columns, none of which can collide
  with these names. (`confirms_a_dropped_and_readded_key_id_column_is_read_correctly`.)
- **App role without SELECT on `pg_catalog`.** **Fails closed.** With the default PUBLIC grant on
  `pg_attribute` revoked and a pre-redesign table present, the `DO` block raises `permission denied
  for table pg_attribute`, `JdbcSupport.initializeSchema` propagates it, and startup aborts. It
  never silently decides the column is absent, and never silently decides it is present. On an empty
  schema the `to_regclass` test short-circuits before `pg_attribute` is read, so a fresh install on a
  hardened database still works — which is the right shape: the catalog is only consulted when there
  is something to guard. Worth knowing that this is a behavioural *improvement* over the replaced
  code: `information_schema.tables` and `.columns` are privilege-filtered views that show a role only
  what it has some privilege on, so the old guard's answer depended on the runtime role's grants,
  while `pg_attribute` returns the true column set regardless. Revoking the catalog grant is a
  deliberate, non-default hardening step and the failure is loud and legible, so this is recorded,
  not raised. (`confirms_the_guard_fails_closed_when_the_role_cannot_read_pg_catalog`.)
- **Temp-table shadow.** `pg_temp` is searched ahead of everything for name *resolution* but is never
  the target of an unqualified `CREATE TABLE`. A session-local `CREATE TEMP TABLE agentguard_audit`
  therefore makes `to_regclass` return the temp table while `current_schema()` still says `public`,
  and the shipped guard refuses. Demonstrated at the SQL level only, not as a Java probe: it needs
  the temp table and the schema step on one connection, and `initializeSchema` takes its own. It is
  not separately exploitable — an attacker who can run DDL in the schema step's own session has more
  direct options — but it is the same root cause as K1 and the same fix closes it.

### Finding

**K1 — LOW — the guard is scoped to search_path visibility, but the statement it protects is scoped
to the creation schema; a stale copy in the gap still blocks a fresh install.** `to_regclass` resolves
a name the way a *reference* resolves: the first schema on the search_path that holds it, anywhere
along the path. `CREATE TABLE IF NOT EXISTS agentguard_audit` does not do that — an unqualified
CREATE targets `current_schema()`, the first *existing* entry of the search_path, and creates there
regardless of what a later entry holds (PostgreSQL documents `current_schema()` as exactly "the
schema that will be used for any tables or other named objects that are created without specifying a
target schema"). So with `search_path = public, archive` and a pre-redesign `agentguard_audit` sitting
in `archive`, the guard sees it and refuses, while the step it is guarding would have created a
brand-new, fully correct table in `public`. Verified that the refusal is a false positive and not a
protection: with the guard removed, that exact database installs the whole schema cleanly, the new
`public.agentguard_audit` has `key_id`, and every unqualified reference afterwards — the two `ALTER
TABLE … ADD COLUMN IF NOT EXISTS`, both triggers, and the sink's `INSERT` — resolves to `public`, not
to the stale copy. This is J1's own symptom, narrowed from "any schema the role can see" to "any
schema on the search_path" rather than closed, and it still lands on the two operators J1 named: the
one who archived by `ALTER TABLE agentguard_audit SET SCHEMA archive` and keeps `archive` on the
role's search_path, and the schema-per-tenant database where an unmigrated tenant's schema is on the
path behind the current one. No integrity impact, denial of startup, fires in the safe direction —
LOW. Repro:
`CipherProbeFinalVerdictJdbcTest.probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install`
(written green, asserting today's behaviour — the fix inverts it), with
`confirms_a_pre_redesign_copy_behind_the_creation_schema_is_harmless_to_the_install` as the proof
that the refusal has nothing to protect.

Fix (Isis): scope both lookups to the creation schema instead of to visibility. Bind the two oids
once, in a `DECLARE`, and test against those:

```sql
DO $$
DECLARE
  a oid := to_regclass(quote_ident(current_schema()) || '.agentguard_audit');
  n oid := to_regclass(quote_ident(current_schema()) || '.agentguard_audit_anchor');
BEGIN
  IF (a IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM pg_attribute
                      WHERE attrelid = a AND attname = 'key_id'
                        AND attnum > 0 AND NOT attisdropped))
     OR (n IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM pg_attribute
                      WHERE attrelid = n AND attname = 'keyed'
                        AND attnum > 0 AND NOT attisdropped)) THEN
    RAISE EXCEPTION
      'audit schema predates keyed-from-birth; archive the table and start a new trail (see SECURITY-NOTES)';
  END IF;
END $$;
```

`quote_ident` is required, not decoration: a schema named with capitals or a dot would otherwise be
re-parsed as a different name. Binding the oids in `DECLARE` also removes the shipped guard's second
`to_regclass` call per branch. Then invert
`probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install` to
`assertThatCode(...).doesNotThrowAnyException()`. Every other probe keeps its current expectation —
this fix was run against all seven scenarios in the table above and changes exactly the one wrong
row. In particular the J1 probe
(`CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`)
and both G1/G2 same-schema probes stay green untouched.

### Not verified

Unchanged from the previous pass, and repeated here so nothing is carried silently:

- PostgreSQL 16 only — the Testcontainers digest is pinned to `postgres:16-alpine@sha256:57c72f…`.
  `to_regclass`, `current_schema()` and `pg_attribute` behave the same on 13–17, but that is read,
  not run.
- No run against a managed PostgreSQL where the runtime role's grants differ from the owner's. The
  catalog-permission case above is the closest this pass gets, and it is a hand-built role in a
  container, not a real managed instance.
- The rolling-restart scenarios are still same-JVM, different sink instances against one database;
  they are not separate processes or pods.
- The G1/G2 and J1/K1 pre-redesign scenarios are reproduced by building a table that lacks the
  column, not by checking out `25da6af`, initialising, and starting this build against it. The
  condition the guard tests — table present, column absent — is identical either way.
- The concurrency check remains twelve threads in one JVM against one database, which exercises the
  advisory lock exactly and nothing beyond it.
- The sample app still runs with `agentguard.audit.unkeyed=true`, so its end-to-end test covers the
  unkeyed path only.

### What the audit trail guarantees today, in plain words

Once K1 is fixed this is ready to merge, and here is what it will mean. Every audit row is signed
with a secret the database never sees, and each row's signature covers the row before it, so the
trail is a chain: change one row, or delete one from the middle, and the next row stops matching. A
separate anchor row — which the database itself refuses to let anyone update backwards, delete, or
truncate — records the head of the chain and its length, so cutting rows off the *end*, the one
attack a chain alone cannot see, is caught too. The decision the last two rounds settled is that a
trail is keyed from its very first row or unkeyed forever: there is no switching, no guessing, and
no code path anywhere that infers whether a trail was keyed by looking at the rows themselves —
that inference was the last hole and it is now gone. An instance configured differently from the
trail it finds refuses to start and refuses to append, rather than quietly writing rows nobody can
verify later. Rotating the signing key is ordinary data, not a break: each row records which key id
signed it, the verifier holds the old keys as well as the new one, and a row naming a key nobody
holds reads as broken rather than being skipped. Running without a key at all is still possible for
local development, but it is now an explicit property that warns at every single startup, and
asking for both at once is refused outright.

The documented residuals, unchanged and accepted: a database role that *owns* these tables can turn
the guard triggers off and rewrite the chain and its anchor together — so run the application with a
narrower role that can only insert and read; a role with only that narrow grant can still append one
hand-written, correctly-linked row, which is detected at the next verification rather than
prevented; a point-in-time restore of the trail and its anchor together is invisible from inside the
database, so the head hash should be exported off-box on a schedule; and the in-memory store, for
tests and development only, derives its anchor from the very list it anchors and therefore cannot
detect its own tail being trimmed. There is no upgrade path from a database written by an earlier
build of this unreleased branch: such a database is refused at startup and the operator archives it
and starts a new trail, deliberately, by hand. K1 is the last thing standing between that sentence
and a merge, and it is one clause of SQL.
