# STATUS.md — Module B · Agent Guard, free core (run 7: V2 closed in full, external anchor)

Branch `feat/agent-guard-core` in `modules/B-agent-guard/`, pushed to `origin`
(https://github.com/1of1Canopus/agent-guard.git). Pro edition out of scope.

## Summary (run 7)
**Done.** Dollar's ruling on QUESTIONS.md #20 closes V2 (MEDIUM) in full: `agentguard_audit_anchor` gets a
`keyed_from_seq` column, set once — in the same transaction as the first row a sink appends under a keyed chain —
and made immutable afterwards by extending the anchor's existing monotonic trigger (Cipher R4). Row data alone can
never tell a whole-trail downgrade to GENESIS apart from a deployment that legitimately never used HMAC (the case
`CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail`, C6, must keep
reporting `INTACT`); the external, attacker-unwritable `keyed_from_seq` is what tells the two apart.
`AuditChainVerifier` now requires every row before `keyed_from_seq` to be unkeyed and every row from it onward to
be keyed, reports a new `Status.UNKEYED` when a key is given but never used by the trail, and keeps the prior
in-trail forward-only rule as a fallback for readers without an anchor. `InMemoryAuditSink` carries the same
bookkeeping (plus a seeding constructor for continuing an existing trail under a new chain) so the fix is
store-independent. Both of Cipher's V2 scenarios — the tail-only downgrade and the original whole-trail-from-GENESIS
repro — are proven to fail (report `INTACT`) against the pre-anchor code and pass (report `BROKEN`) against this
one. `./mvnw -B clean verify` is green: **175 tests** (core 128, starter 46 + 1 self-skipping — needs Spring AI's
real `ToolCallingAutoConfiguration` on the test classpath — sample 1 end-to-end), core line coverage 90.98% /
branch 77.72% (gate 80% line, held), spotless, Error Prone, enforcer, JaCoCo gate.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| V2 | MEDIUM (closed in full) | `agentguard_audit_anchor.keyed_from_seq`: null → set once at the first keyed append, immutable after (extended monotonic trigger); `AuditChainVerifier.verify` requires rows before it unkeyed, rows from it onward keyed, else `BROKEN`; a key given with no keyed row and `keyed_from_seq` null reports `Status.UNKEYED` | `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` (partial/tail downgrade), `CipherProbeReverifyTest.probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` (Cipher's original whole-trail repro), `AuditChainVerifierTest.a_key_given_to_the_verifier_but_never_used_by_the_sink_reports_unkeyed` |

## Summary (run 6, prior)
Cipher's re-verification pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, `## Re-verification (6f026ff)`)
found five new issues (V1 MEDIUM, V2 MEDIUM, V3 LOW, V4 LOW, V5 LOW) after the clean-verdict round. V1, V3, V4, V5
were closed on the branch, each with its probe flipped. V2 was fixed only for the *detectable* form of the attack
(a partial downgrade); the whole-trail scenario is closed in run 7 above.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| V1 | MEDIUM | `ToolGuard.guarded` applies `rejectIfTooLarge` as its first statement, before `policies.resolve` — the unregistered-tool and policy-denial paths no longer canonicalise oversized arguments | `CipherProbeReverifyTest.probe_the_denial_paths_parse_arguments_of_any_size` |
| V3 | LOW | `ArgumentCanonicalizer.hash` prefixes `"agcanon1:"`, `AuditRecorder.recordOversized` prefixes `"agraw1:"` — the two `args_hash` domains no longer collide; `ToolGuard.rejectIfTooLarge` also caps the canonicalised length | `CipherProbeReverifyTest.probe_an_oversized_denial_shares_an_args_hash_with_an_allowed_call` |
| V4 | LOW | `AgentGuardStartupCheck` warns when `endpoints.enabled` and either `tenant-scoped=false` or `require-tenant=false` | `CipherProbeReverifyStartupTest.probe_a_cross_tenant_approver_opt_out_is_silent_at_startup` |
| V5 | LOW | `AgentGuardProperties.Pool.platform-thread-count`/`.platform-thread-queue-size`, decoupled from `max-total`; `JedisBudgetStore.onPlatformThreads` takes the queue bound as its own parameter | `CipherProbeJedisFactoryTest.burst` (restored to `max-total=4`, thread/queue properties set to 200) |

## Summary (run 5, prior)
Every finding of Cipher's clean-verdict pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, on
`50ed8d3`) is closed on the branch: C4 (MEDIUM), C1/C2/C5/C7/C9/C11 (LOW), C3/C6/C8/C10/C12 (INFO), each with its
probe flipped (renamed without `probe_`, assertion inverted). `./mvnw -B clean verify` was green: **169 tests** (core
123, starter 45 + 1 self-skipping — needs Spring AI's real `ToolCallingAutoConfiguration` on the test classpath —
sample 1 end-to-end), core line coverage 90.2% / branch 77.7% (gate 80% line, held), spotless, Error Prone,
enforcer, JaCoCo gate, THIRD-PARTY-NOTICES.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| C4 | MEDIUM | `ToolGuard.gate`/`.dispatch` check `maxArgumentBytes` as the first statement, before any parse; the oversized-rejection audit row hashes the raw text directly (`AuditRecorder.recordOversized`), never through the canonical parser | `CipherProbeCleanGuardTest.the_size_cap_refuses_arguments_before_they_are_parsed` |
| C1 | LOW | `JsonText.escape` `\u`-escapes unpaired surrogates instead of letting UTF-8 collapse them to `?` | `CipherProbeCleanTest.an_unpaired_surrogate_and_a_question_mark_do_not_share_one_arguments_hash` |
| C2 | LOW | `ArgumentRedactor.isSensitive` also splits on `_ - .` and camel-case boundaries | `CipherProbeCleanTest.camel_case_and_suffixed_sensitive_keys_are_masked` |
| C5 | LOW | `ApprovalService.fourEyes` compares approver/requester trimmed, case-folded, NFKC-normalised | `CipherProbeCleanGuardTest.four_eyes_rejects_a_differently_cased_approver_id` |
| C7 | LOW | bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to the pool, `AbortPolicy`); a timed-out call is cancelled and removed from the queue | `CipherProbeCleanRedisTest.a_timed_out_redis_call_does_not_stay_queued` |
| C9 | LOW | `agentguard.endpoints.require-tenant` (default `true` when `tenant-scoped`): no tenant → 403 | `CipherProbeCleanEndpointsTest.an_approver_without_a_tenant_is_refused` |
| C11 | LOW | ArchUnit rule bans `javax..` again, carve-out only for `javax.crypto..` | `HexagonalArchitectureTest` (no dedicated probe; the rule itself is the fix) |
| C3 | INFO | `JsonText.digits()`/`\u` escape restricted to ASCII `0`-`9` / `[0-9a-fA-F]` | `CipherProbeCleanTest.the_parser_rejects_text_that_is_not_json` |
| C6 | INFO | `agentguard_audit.chain_version` per row (backfilled `ag1`); `AuditChainVerifier` applies each row's own version | `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail` |
| C8 | INFO | `JedisBudgetStore implements AutoCloseable`, `close()` shuts the pool down | `CipherProbeCleanRedisTest.the_platform_thread_executor_is_shut_down_on_close` |
| C10 | INFO | `DecisionStore.findByState(state, tenantId, limit)`, `AuditReader.latest(tenantId, limit)` filter in the query | `CipherProbeCleanEndpointsTest.the_pending_inbox_is_filtered_by_the_store_before_the_limit` |
| C12 | INFO | `AuditRecorder.record` hashes `ArgumentCanonicalizer.canonical(argumentsJson)` | `CipherProbeCleanTest.the_audit_row_hashes_the_same_canonical_form_as_the_decision` |

Versions unchanged: Spring Boot 4.0.8, Spring Framework 7.0.9, Spring Security 7.0.7, Spring AI 2.0.1
(+ `spring-ai-client-chat`, optional), MCP Java SDK 2.0.0, Jedis 7.5.2, Testcontainers 2.0.5, Java 21.

## Interface changes run 6 (all additive or default-preserving)
- `ArgumentCanonicalizer.hash` and `AuditRecorder.recordOversized` now hash a domain-prefixed input
  (`"agcanon1:"` / `"agraw1:"`); `ArgumentCanonicalizer.CANONICAL_HASH_DOMAIN` is package-visible for tests.
  Stored `args_hash` values are unaffected (the chain hashes the row, not the arguments) but cannot be
  recomputed from raw text without the prefix.
- `AgentGuardProperties.Pool` gained `platformThreadCount`/`platformThreadQueueSize` (both `Integer`, null =
  "use max-total", the prior behaviour) and `effectivePlatformThreadCount()`/`effectivePlatformThreadQueueSize()`.
- `JedisBudgetStore.onPlatformThreads(UnifiedJedis, int threads, Duration maxWait)` is unchanged (delegates to
  the queue-bound-equals-threads case); a new overload
  `onPlatformThreads(UnifiedJedis, int threads, int queueSize, Duration maxWait)` is used by the factory.

## Interface changes this run (run 5, prior)
- `DecisionStore.findByState(DecisionState, int)` is now a default method delegating to the new
  `findByState(DecisionState, String tenantId, int)` with `tenantId=null` (every tenant); both in-memory and JDBC
  implementations override the new one directly.
- `AuditReader.latest(int)` is now a default method delegating to the new `latest(String tenantId, int)`, same
  pattern.
- `ApprovalService.pending(int)` delegates to the new `pending(int limit, String tenantId)`.
- `AgentGuardEndpoints` gained a `requireTenant` constructor parameter (a 6-arg overload still defaults it `true`,
  the previous safe posture is unchanged for anyone constructing it directly outside the auto-configuration).
- `AuditEvent` gained a `version` component (position: after `actorId`, before `prevHash`/`hash`); `AuditChain`
  writes it on link. `agentguard_audit` gained `chain_version varchar(8) NOT NULL DEFAULT 'ag1'` via an idempotent
  `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
- `JedisBudgetStore` now implements `AutoCloseable`; its platform-thread pool is a `ThreadPoolExecutor` instead of a
  `newFixedThreadPool` (same field name/type `ExecutorService`, so nothing outside the class needed to change).

## A default-behaviour change that surfaced during this run (C9)
`agentguard.endpoints.require-tenant` defaults `true` whenever `tenant-scoped` is on (the existing default). A
deployment with `tenant-scoped=true` (the default) and **no** `TenantResolver` bean previously fell back to
`Optional.empty()` and was treated as "no scoping" (every approver saw everything); it now gets 403. This is the
C9 fix working as intended, but it meant:
- The sample app (`agent-guard-sample`, no `TenantResolver`, no tenant concept anywhere) needed
  `agentguard.endpoints.tenant-scoped=false` added to `application.yml` to declare itself single-tenant — the
  correct, existing way to opt out, not a new escape hatch. Without it every endpoint call in the sample's
  end-to-end test got 403.
- `AgentGuardEndpointsTest.list_arguments_approve_reject_and_audit` (pre-existing, not a Cipher probe) exercises a
  deliberate cross-tenant approver (no principal or approver in that test has a tenant); it now sets
  `agentguard.endpoints.require-tenant=false` at the class level. The other test method in the same class,
  `approvers_only_see_their_own_tenant_and_cannot_approve_their_own_call`, never logs in with a tenant-less
  approver, so this class-level property does not weaken its assertions.
- `CipherProbeJedisFactoryTest` (unrelated to C9; broken by C7's bounded queue) had its pool size raised from a
  fixed 4 to match its 200-virtual-thread burst, since each virtual thread has at most one call in flight at a
  time — the real concurrency ceiling is the thread count, not an arbitrary small pool racing an unbounded queue
  that no longer exists.

None of these are findings closed with a weaker check; they are the pre-existing (non-Cipher) tests and the sample
app being brought into line with the now-correct, fail-closed default.

## Acceptance checks (SPEC)
- [x] Sample MCP server: read tool allowed, write tool parked, approval via endpoint (attested hash, CSRF token,
  four-eyes) resumes and executes once as the agent, second approval is a no-op, audit shows the chain with the
  approver, budget of 3 calls blocks the 4th with a structured error. Proof: `./mvnw -B -pl agent-guard-sample test`.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo — release plumbing, not this run.
- [x] Docs page, CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown.
- [ ] Gate (90 days) — not applicable yet.

## Proof commands
```bash
./mvnw -B clean verify                                       # 175 tests, all gates
./mvnw -B -pl agent-guard-core -Ppinning-probe test          # + the 2 child-JVM pinning probes (~25 s)
./mvnw -B -pl agent-guard-spring-boot-starter test           # 46 + 1 skip (incl. every flipped Cipher probe)
./mvnw -B -pl agent-guard-sample test                        # 1 end-to-end through a real MCP client
```

## Still open (outside the review)
Release plumbing (Maven Central signing, org decision), async (WebFlux) MCP servers (fail startup today),
Micrometer metrics, `@Internal` API pass. Cipher's real-`ToolCallingAutoConfiguration` probe needs
`-Dmaven.test.additionalClasspath=<spring-ai-autoconfigure-model-tool-2.0.1.jar>` and self-skips otherwise.
C11 has no dedicated `CipherProbe*` test (the finding table lists its probe as "git diff"): the fix is entirely in
`HexagonalArchitectureTest`'s rule definition, verified by the ArchUnit rule itself passing/failing.

## Pain points (plain words) — run 7
- Making C6's test pass again after adding `keyed_from_seq` meant changing what "enabling the key" means inside
  the test: not just reconfiguring a verifier with a key nothing ever used, but a second sink instance genuinely
  continuing the trail under a keyed chain (the in-memory analogue of restarting the app with the secret set).
  That is a more faithful model of the real operation than the old test, but it did mean adding a seeding
  constructor to `InMemoryAuditSink` (`InMemoryAuditSink(List<AuditEvent>, AuditChain)`) that did not exist before
  — a small, narrowly-scoped addition to make the in-memory store capable of the same "continue an existing
  trail" scenario `JdbcAuditSink` already handles by construction (a new instance over the same table).

## Pain points (plain words) — run 6 (superseded above)
- V2's described fix ("version may only move forward") cannot make its own probe's exact scenario report
  `BROKEN`: a fully-keyed 2-row trail downgraded entirely back to `ag1` is byte-for-byte the same data as a
  trail that legitimately never used HMAC, verified after a key is later configured — the case C6 exists to
  keep `INTACT`. Implemented the fix as literally described (it is correct and valuable for the *detectable*
  half of the attack — a genuine keyed prefix with a downgraded tail, which is what an attacker who joins an
  already-running deployment can actually do without breaking the earlier rows' own hashes) and changed the
  probe to rewrite the tail instead of the head, with a javadoc explaining why. Full write-up: QUESTIONS.md #20.
  **Superseded in run 7:** Dollar's ruling found the external anchor already existed (R4's anchor row) and
  directed using it, closing the whole-trail case too.

## Pain points (plain words) — run 5, prior
- Fixing C12 (audit hashes canonical, not raw) meant every `AuditRecorder.record` call now parses the arguments —
  reintroducing C4's amplification risk on paths that were never covered by the `maxArgumentBytes` check (the early
  policy-denied / unregistered-tool paths in `ToolGuard.guarded`). Rather than widen C4's fix into those paths (not
  asked for, and they don't reach the dedup hash the finding measured), the oversized-rejection path got its own
  `AuditRecorder.recordOversized`, which hashes the raw text directly and never canonicalises it — so a rejected
  call is bounded by definition, on every path that can reject for size, without touching the paths the finding
  didn't ask about.
- C7's bounded queue is a real behaviour change under load, not just a bug fix: a burst past `max-total` concurrent
  callers now gets `AG-GUARD-001` (guard fails closed) instead of eventually succeeding once Redis catches up. This
  is the intended trade-off (unbounded queueing was the vulnerability), but it means `max-total` sizing now matters
  for availability, not just latency — documented in `SECURITY-NOTES.md`.
- Optional dependencies again: a bean method whose return type references `spring-ai-client-chat` made the whole
  Spring AI auto-configuration fail to load in the sample; the advisor now lives in its own class-conditional
  auto-configuration. Rule of thumb for this codebase: one optional library, one auto-configuration class.
- Testcontainers refuses `image:tag@sha256:…` for `PostgreSQLContainer` without `asCompatibleSubstituteFor`, and
  Boot's `@ServiceConnection` refuses the tag+digest form altogether; the sample uses `postgres@sha256:…`.
- The JSON parser in the domain is ~200 lines of hand-written code so the core stays free of Jackson; it is strict
  RFC 8259 and depth-limited (64), and unparseable arguments are masked whole rather than guessed at.
