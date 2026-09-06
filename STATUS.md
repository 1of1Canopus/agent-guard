# STATUS.md — Module B · Agent Guard, free core (run 2: Cipher fix list)

Branch `feat/agent-guard-core` in `modules/B-agent-guard/` (own git repo, never pushed). Pro edition out of scope.

## Summary
**Done.** Cipher's review (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, verdict NOT MERGEABLE: 3 HIGH, 7 MEDIUM)
is addressed on the same branch: every HIGH and MEDIUM is fixed and its `CipherProbe*` test flipped to assert the
fixed behaviour; the LOW probes (L1–L4, L5, L7, L8) stay in place as documentation of open items.
`./mvnw -B clean verify` is green: **129 tests** (core 103, starter 25, sample 1 end-to-end through a real MCP
client), core line coverage 90.8% / branch 82.1% (gate 80%), spotless, Error Prone, enforcer, JaCoCo gate,
THIRD-PARTY-NOTICES. The 25 s child-JVM pinning probe runs only with `-Ppinning-probe`.

| Finding | Fix | Proof |
|---|---|---|
| H1 wrong identity/context at resume | executor per decision id, released after the run; `ResumeContextProvider` SPI + `SecurityContextResumeContextProvider` / `RunAsAuthentication` (stored principal, approver context restored); parking caller's `ToolContext` / MCP exchange captured with the decision | `CipherProbeApprovalGateTest.resume_runs_the_closure_captured_when_that_decision_was_parked`, `CipherProbeSpringAiTest.resume_runs_with_the_parking_callers_tool_context_and_identity` |
| H2 silent coverage gaps | `GuardedToolCallingManager` at the Spring AI chokepoint (+ guarded `ToolCallbackResolver`, default manager bean); single MCP spec beans wrapped; async specs fail startup; `GuardCoverage` + `AgentGuardStartupCheck` with `agentguard.strict=true` | `CipherProbeSpringAiTest.inline_tool_objects_are_guarded_through_the_tool_calling_manager`, `CipherProbeMcpTest.single_spec_beans_are_guarded_and_async_specs_fail_startup`, `…strict_mode_refuses_unguarded_policies` |
| H3 Redis + virtual threads deadlock | `agentguard.redis.pool.*`, `min-idle = max-total`, `preparePool()` at startup from the platform thread; docs + SECURITY-NOTES rewritten with the real site (commons-pool2 growth lock) and numbers | `AgentGuardAutoConfigurationTest.jedis_pool_is_prefilled_by_default_and_sized_from_properties`; `-Ppinning-probe` mitigations probe |
| M1 approver not in the chain | `AuditEvent.actorId` in the canonical form, schema `actor_id`, APPROVED/REJECTED/FAILED rows carry the approver | `CipherProbeApprovalGateTest.approver_identity_is_part_of_the_hash_chained_audit` |
| M2 weak chain | length-prefixed canonical (`ag1`), millisecond truncation in `AuditEvent`, `BEFORE TRUNCATE` trigger, anchor row, `Report.status` (EMPTY/INTACT/BROKEN/ANCHOR_MISMATCH), least-privilege roles documented | `CipherProbeAuditChainTest`, `CipherProbeJdbcTest` (1–3), `AuditChainVerifierTest.anchor_mismatch_is_reported_when_the_tail_is_gone` |
| M3 client-controlled / skipped budgets | MCP conversation = server session id, `_meta` ignored; `MissingSubjectPolicy` (DENY under strict, `AG-BUDGET-002`); TENANT-without-resolver warning | `CipherProbeMcpTest.steps_budget_uses_the_server_side_session_id`, `CipherProbeApprovalGateTest.conversation_budget_denies_without_an_id`, `BudgetEnforcerTest.missing_conversation_subject_…` |
| M4 unbounded parking, cross-tenant dedup | budget reserved before parking (not again at resume), `max-pending-per-principal` (`AG-APPROVAL-008`), `max-argument-bytes` (`AG-APPROVAL-009`), tenant in `findLatest` + index | `CipherProbeApprovalGateTest.parking_is_budgeted_and_capped_per_principal`, `…same_principal_id_in_another_tenant_gets_its_own_decision` |
| M5 lossy preview, id-only attestation | `ArgumentRedactor.redact` (complete), `GET /decisions/{id}/arguments`, `approve(id, approver, argsHash)` (`AG-APPROVAL-010`), endpoint requires `argsHash` | `CipherProbeApprovalGateTest.approver_sees_the_full_redacted_arguments_and_attests_their_hash`, `AgentGuardEndpointsTest`, `SampleEndToEndTest` |
| M6 raw guard failures | `ToolGuard.execute`, `GuardedToolCallback`, `McpToolGuard` catch everything → `GuardResult.GuardUnavailable` (`AG-GUARD-001` + correlation id), cause logged at ERROR | `CipherProbeSpringAiTest.guard_infrastructure_failure_is_a_structured_error_without_internal_details`, `CipherProbeMcpTest.guard_infrastructure_failure_is_a_structured_error_result` |
| M7 anonymous approver | endpoints refuse `anonymous` with 401 unless `agentguard.endpoints.allow-anonymous=true` | `CipherProbeEndpointsTest.anonymous_approver_is_refused_with_401_and_nothing_runs` |

Versions unchanged: Spring Boot 4.0.8, Spring Framework 7.0.9, Spring Security 7.0.7, Spring AI 2.0.1, MCP Java
SDK 2.0.0, Jedis 7.5.2, Testcontainers 2.0.5, Java 21.

## Acceptance checks (SPEC)
- [x] Sample MCP server: read tool allowed, write tool parked, approval via endpoint (with attested hash) resumes and
  executes once as the agent, second approval is a no-op, audit shows the chain with the approver, budget of 3
  calls blocks the 4th with a structured error. Proof: `./mvnw -B -pl agent-guard-sample test`.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo — not this run.
- [x] Docs page, CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown.
- [ ] Gate (90 days) — not applicable yet.

## Proof commands
```bash
./mvnw -B clean verify                                       # 129 tests, all gates
./mvnw -B -pl agent-guard-core -Ppinning-probe test          # + the 2 child-JVM pinning probes (~25 s)
./mvnw -B -pl agent-guard-spring-boot-starter test           # 25 (incl. 11 flipped Cipher probes)
./mvnw -B -pl agent-guard-sample test                        # 1 end-to-end through a real MCP client
```

## Still open (LOW / INFO from the review, plus earlier items)
L1 self-approval, L2 tamper detection not audited, L3 policy not re-evaluated at resume, L4 dedup unbounded in
time, L5 redactor gaps, L6 webhook signature, L7 property messages naming the property, L8 budget table hygiene,
L9 sample CSRF note, L10 `initialize-schema` default; I1–I9. Token auto-recording (QUESTIONS #8), async MCP servers,
metrics, `@Internal` pass, release plumbing.

## Pain points (plain words)
- `ToolCallingChatOptions` has no setter; rebuilding the prompt through `mutate()` is the only way to swap
  callbacks at the chokepoint. Works on 2.0.1; a `ToolCallingChatOptions` implementation without a
  `ToolCallingChatOptions.Builder` would throw (caught and returned as `AG-GUARD-001`).
- Spring AI's `ToolCallingAutoConfiguration` is not on the starter's classpath, so the guarded default
  `ToolCallingManager` bean is ordered `before` it by name; when Spring AI's own manager wins, the bean post-processor
  wraps it. Both paths are covered by tests, but the ordering deserves a look in a real Spring AI app.
- Google-java-format rewrites made every scripted edit fragile; nothing functional, just time.
