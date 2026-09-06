# STATUS.md — Module B · Agent Guard, free core (run 4: no-allowance round)

Branch `feat/agent-guard-core` in `modules/B-agent-guard/`, pushed to `origin`
(https://github.com/1of1Canopus/agent-guard.git). Pro edition out of scope.

## Summary
**Done.** Every row of Cipher's "Open items" table (final verdict, commit `ecd925a`) is closed on the branch:
L1–L10, I1–I9, R3, R4, R6–R11, each with its probe flipped (or, for R3, renamed and kept as documentation).
`./mvnw -B clean verify` is green: **157 tests** (core 113, starter 43 — one self-skipping probe that needs
Spring AI's real `ToolCallingAutoConfiguration` on the test classpath — sample 1 end-to-end), core line coverage
89.5% / branch 78.5% (gate 80%), spotless, Error Prone, enforcer, JaCoCo gate,
THIRD-PARTY-NOTICES. The 25 s child-JVM pinning probe stays behind `-Ppinning-probe`.

| Id | Fix | Proof |
|---|---|---|
| L1 | `SelfApprovalException` (`AG-APPROVAL-011`, 403), `agentguard.approval.allow-self-approval` | `CipherProbeApprovalGateTest.self_approval_is_refused_unless_allowed`, `AgentGuardEndpointsTest` |
| L2 | `AuditDecision.TAMPERED` row with actor; decision closed (`executed`, denied result) | `…tamper_detection_is_audited_and_closes_the_decision` |
| L3 | `PrincipalRefresher` SPI; `DecisionResumer` re-evaluates the policy before running | `…policy_is_re_evaluated_at_resume_with_a_refreshed_principal` |
| L4 | `findLatest(…, createdAfter)`, `agentguard.approval.replay-window` | `…dedup_is_bounded_by_the_replay_window` |
| L5 | `JsonText`/`JsonNode` parser in the domain, `ArgumentRedactor` walks the tree | `CipherProbeRedactorTest` (4 flipped), `ArgumentRedactorTest` |
| L6 | https check at startup, HMAC signature + timestamp headers, legacy token opt-in | `NotifiersTest` (WireMock), `AgentGuardAutoConfigurationTest.insecure_webhook_url…` |
| L7 | `@DurationMin(message = "agentguard.… must be positive")`, startup WARNs for empty sets | `CipherProbePropertiesTest` (2 flipped, `OutputCaptureExtension`) |
| L8 | purge every 1000 increments, `key text`, subjects > 128 chars hashed | `CipherProbeJdbcTest.expired_budget_rows_are_purged_and_long_subjects_fit` |
| L9 | `csrf.ignoringRequestMatchers("/mcp/**")`, README note | `SampleEndToEndTest` (`.with(csrf())`) |
| L10/R11 | advisory lock first in the schema, triggers created only when absent, once per DataSource, owner WARN | `CipherProbeFinalJdbcTest` (both flipped: every outcome `ok`), `SchemaStepIntegrationTest` |
| I1 | `ArgumentCanonicalizer` (sorted keys, compact) for `argsHash` | `ToolGuardTest.whitespace_and_key_order_do_not_create_a_second_decision` |
| I2 | `Failed.retryable` (false after approval), FAQ | `ToolGuardTest`, docs |
| I3 | `SecurityContextPrincipalResolver.of(auth)` with the anonymous check, used by the `AuthorizationManager` | `ToolPolicyAuthorizationManagerTest` |
| I4 | tenant-scoped endpoints (404 for another tenant) | `AgentGuardEndpointsTest.approvers_only_see_their_own_tenant…` |
| I5 | `Errors.describe` → class + correlation id; `agentguard.errors.include-tool-message` | `ToolGuardTest.tool_failure_becomes_structured_error…` |
| I6 | `ToolPolicyRegistry.register` refuses a different rule for the same name | `ToolPolicyAnnotationScannerTest.conflicting_policies…` |
| I7 | `AuditChain.keyed(secret)` (`ag2h`), `agentguard.audit.hmac-secret` | `AuditChainVerifierTest.keyed_chain_verifies_only_with_the_key`, `AgentGuardAutoConfigurationTest.hmac_secret…` |
| I8 | kind/scope validation; `AgentGuardUsageAdvisor` (`CallAdvisor` + `StreamAdvisor`) | `AgentGuardAutoConfigurationTest.limit_kind_and_scope…`, `AgentGuardUsageAdvisorTest` (fake ChatModel through ChatClient) |
| I9 | `permissions: contents: read`, SHA-pinned actions, wrapper checksum, digest-pinned images, WireMock now used | `.github/workflows/*`, `.mvn/wrapper/maven-wrapper.properties`, test files, compose |
| R3 | startup log names the wrapped delegate + caveat; probe renamed as documentation | `CipherProbeReverifySpringAiTest.hand_built_manager_outside_the_context_is_documented_as_unguarded` |
| R4 | `agentguard_audit_anchor_monotonic` trigger | `CipherProbeReverifyJdbcTest.anchor_cannot_be_reset_to_hide_a_tail_deletion` |
| R6 | `JedisBudgetStore.onPlatformThreads` (JDK < 24, `agentguard.redis.pool.platform-threads`) | `CipherProbeJedisFactoryTest.factory_without_prefill_still_completes_under_virtual_threads` |
| R7 | WARN CONVERSATION without PRINCIPAL | `AgentGuardAutoConfigurationTest.conversation_limit_without_principal_limit_warns` |
| R8 | `countPending(principal, tenant)` | `JdbcAdaptersIntegrationTest`, `InMemoryDecisionStore` |
| R9 | FAILED row before rethrow | `ToolGuardTest.guard_exception_from_the_tool_path_leaves_a_failed_row…` |
| R10 | package-private constructor, `writeObject`/`readObject` throw, `setAuthenticated(true)` refused | `CipherProbeFinalSpringAiTest.run_as_token_is_package_private_non_serializable…` |

Versions unchanged: Spring Boot 4.0.8, Spring Framework 7.0.9, Spring Security 7.0.7, Spring AI 2.0.1
(+ `spring-ai-client-chat`, optional), MCP Java SDK 2.0.0, Jedis 7.5.2, Testcontainers 2.0.5, Java 21.

## Acceptance checks (SPEC)
- [x] Sample MCP server: read tool allowed, write tool parked, approval via endpoint (attested hash, CSRF token,
  four-eyes) resumes and executes once as the agent, second approval is a no-op, audit shows the chain with the
  approver, budget of 3 calls blocks the 4th with a structured error. Proof: `./mvnw -B -pl agent-guard-sample test`.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo — release plumbing, not this run.
- [x] Docs page, CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown.
- [ ] Gate (90 days) — not applicable yet.

## Proof commands
```bash
./mvnw -B clean verify                                       # 157 tests, all gates
./mvnw -B -pl agent-guard-core -Ppinning-probe test          # + the 2 child-JVM pinning probes (~25 s)
./mvnw -B -pl agent-guard-spring-boot-starter test           # 43 (incl. every flipped Cipher probe)
./mvnw -B -pl agent-guard-sample test                        # 1 end-to-end through a real MCP client
```

## Still open (outside the review)
Release plumbing (Maven Central signing, org decision), async (WebFlux) MCP servers (fail startup today),
Micrometer metrics, `@Internal` API pass. Cipher's real-`ToolCallingAutoConfiguration` probe needs
`-Dmaven.test.additionalClasspath=<spring-ai-autoconfigure-model-tool-2.0.1.jar>` and self-skips otherwise.

## Pain points (plain words)
- Optional dependencies again: a bean method whose return type references `spring-ai-client-chat` made the whole
  Spring AI auto-configuration fail to load in the sample; the advisor now lives in its own class-conditional
  auto-configuration. Rule of thumb for this codebase: one optional library, one auto-configuration class.
- Testcontainers refuses `image:tag@sha256:…` for `PostgreSQLContainer` without `asCompatibleSubstituteFor`, and
  Boot's `@ServiceConnection` refuses the tag+digest form altogether; the sample uses `postgres@sha256:…`.
- The JSON parser in the domain is ~200 lines of hand-written code so the core stays free of Jackson; it is strict
  RFC 8259 and depth-limited (64), and unparseable arguments are masked whole rather than guessed at.
