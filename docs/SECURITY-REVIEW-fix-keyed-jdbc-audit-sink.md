# Security review: keyed default JDBC audit sink and startup check AG-AUDIT-003 (PR 45)

## 2026-10-16, pass 1

**Verdict: FIX LIST.** No HIGH. Two MEDIUM, four LOW, one INFO. Every one is fixed before
merge (no-allowance rule). The fix for the original finding works: on the default store with
the secret set, the trail is keyed from row 1. The new startup check has gaps around it.

Reviewed tree: `e6aa5cb` (`fix/keyed-jdbc-audit-sink`, PR 45 head). Scope: the wiring change in
`AgentGuardAutoConfiguration.jdbcAuditSink`, the new `AuditSinkKeyCheck`, `isKeyed()` on the two
sinks, error code `AG-AUDIT-003`, the advisory in SECURITY-NOTES, CHANGELOG, README and
docs/index.md.

### Grade of the original finding, B-SMP-1: HIGH, confirmed

On 0.1.0, 0.1.1 and 0.1.2 the starter built the default `JdbcAuditSink` with the one-argument
constructor (checked at each tag). That constructor is unkeyed. A set
`agentguard.audit.hmac-secret` was used by the verifier and never by the sink. The keyed mode is
the control against a database writer who rewrites the trail and recomputes the hashes. It was
off on the default path, with no signal, while the README said "keyed from its first row". A
documented integrity control that is silently off by default is HIGH in this studio's grading.

A plain CVSS 3.1 base score is lower, because the attacker needs database write rights and the
power to switch the guard triggers off: `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N`, 4.9. The advisory
must say both (finding B-KS-6).

Reproduced twice:

- The sample harness (MCP server, four guarded calls, real PostgreSQL) with its workaround bean
  removed, on the published 0.1.2 jars: the verifier says `INTACT_UNKEYED` where the test expects
  `INTACT`. Same harness on the branch build: `INTACT`, keyed, key ids `[k1]`, 5 rows verified.
- The README sentence "keyed with HMAC from its first row" is true again on this branch: the
  harness reads `key_id=k1` on every row, with the secret set and no sink bean of its own.

### Numbers

| Check | Result |
|---|---|
| `./mvnw -B clean verify` (Docker up, run once) | exit 0; core 206, starter 112 (1 skipped), sample 4; 0 failures, 0 errors; JaCoCo gate met |
| Skipped test | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` (needs an extra Spring AI jar; skipped since it was written, not passing) |
| Existing `CipherProbe*` classes | all green, unchanged |
| Sample harness, 0.1.2, workaround removed | FAIL: `INTACT_UNKEYED` (defect reproduced) |
| Sample harness, branch build, workaround removed | PASS: `INTACT`, keyed, key ids `[k1]` |
| Builder mutation 1 (wiring removed) | reproduces: 3 of 14 red |
| Builder mutation 2 (wiring removed, check blind) | not re-run; mutation 1 already shows the tests catch the defect without the check (two row-one tests red) |
| Reviewer mutations | 3 run, 3 survive (B-KS-7) |
| New probes this pass | 6 `probe_` tests, all red on `e6aa5cb`; 1 `attempt_` test, green by design |

### Findings

| Id | Severity | Class | Probe | Status |
|---|---|---|---|---|
| B-KS-1 | MEDIUM | lock/window | `probe_unkeyed_sink_writes_a_row_during_startup_before_the_check_refuses` | open |
| B-KS-2 | MEDIUM | framework-path bypass | `probe_unverifiable_sink_starts_by_default_with_a_secret_set`, `probe_scoped_proxy_hides_an_unkeyed_sink_from_the_startup_check` | open |
| B-KS-3 | LOW | boundary validation | `probe_unkeyed_opt_out_and_secret_together_start_with_an_application_chain` | open |
| B-KS-4 | LOW | docs vs code | `probe_upgrade_refusal_hides_the_advisory_and_offers_to_drop_the_trail` | open |
| B-KS-5 | INFO | error classification | `probe_keyed_application_chain_without_a_secret_fails_with_a_null_pointer` | open |
| B-KS-6 | LOW | docs vs code | text check, no test | open |
| B-KS-7 | LOW | false completion | three surviving mutants | open |

All probes are in one class, `CipherProbePr45StartupTest` (internal probe folder). The fix pass
adds it to `agent-guard-spring-boot-starter/src/test/java/com/housedevinci/agentguard/autoconfigure/`
before touching production code.

#### B-KS-1, MEDIUM: a sink used during context start writes before the check

The check records sinks while the context starts and checks them only in
`afterSingletonsInstantiated`. Any bean that audits from an init callback (`InitializingBean`,
`@PostConstruct`, an earlier `SmartInitializingSingleton`) runs before that. Repro: secret set,
an application `JdbcAuditSink` built with the one-argument constructor, and a bean that records
one call in `afterPropertiesSet`. Startup is refused with `AG-AUDIT-003`, but one row with
`key_id=none` is already written, and the anchor is fixed to `keyed=false`. The anchor cannot
change, so the trail is unkeyed forever: once the sink is fixed, the next start fails with
`AG-AUDIT-001` and the operator must start a new trail. The control promises "refused before any
row"; here the refusal comes after an irreversible write.

Fix (`AuditSinkKeyCheck.see`): decide a sink whose mode is known (`KEYED` or `UNKEYED`) at once,
in `postProcessBeforeInitialization` and `postProcessAfterInitialization`, whatever `started`
says, and throw before the bean is handed to the container. Keep the end-of-start pass for the
lazy beans and for the opt-out WARN. The probe goes green: refused, zero rows. Document the
residual: a bean created before this post-processor is registered (a dependency of another
priority-ordered post-processor) is seen only at the end-of-start pass.

#### B-KS-2, MEDIUM: a sink the check cannot read starts by default

With the secret set, a sink whose mode the starter cannot read starts with a WARN only. The
builder rates this as a gap until 0.2.0 adds `isKeyed()` to the `AuditSink` port. Two repros:

1. An application `AuditSink` class (any class but the two known ones): starts, WARN.
2. A known unkeyed `InMemoryAuditSink` behind a scoped proxy (`@Scope("thread", proxyMode =
   INTERFACES)`). The proxy has no singleton target, so the check reads "unknown" and the context
   starts. The unkeyed sink is created and refused only at its first use, at run time. This path
   is missing from the PR's paths table.

Ruling on the gap. A WARN is not enough. It is the original B-SMP-1 failure (a silently unkeyed
trail with the secret set) moved from the default path to every custom, composite or scoped
sink. The secure mode must be the default; the weaker mode must be an explicit property that
WARNs at every start. The gap is acceptable until 0.2.0 only in that shape.

Fix (`AuditSinkKeyCheck.check`, `AgentGuardProperties.Audit`): a sink whose mode is `UNKNOWN`
is refused with `AG-AUDIT-003`, secret set or not, unless its bean name is listed in a new
property `agentguard.audit.unverified-sinks` (a list of bean names). Each listed sink WARNs at
every startup, naming the bean and saying the starter cannot verify it is keyed. The refusal
message names the property. CHANGELOG: an application with its own sink class must list it after
the upgrade. Turn the builder's test
`an_unknown_sink_type_with_a_secret_starts_and_warns_it_cannot_be_verified` into a refused case
plus a listed case that starts and WARNs. Both probes go green (the scoped proxy reads unknown
and is refused at startup). Record `isKeyed()` on the port for 0.2.0 in QUESTIONS; that design
page comes to the security review before code.

#### B-KS-3, LOW: contradictory properties start with an application chain

`agentguard.audit.hmac-secret` set and `agentguard.audit.unkeyed=true` at once is refused only
inside the starter's own `auditChain` bean. An application `AuditChain` bean replaces that bean,
so the contradiction starts. With a keyed application chain the context starts and logs "the
audit trail is unkeyed" about a keyed trail.

Fix: refuse the contradiction in `AuditSinkKeyCheck.afterSingletonsInstantiated` (and at the
first sink seen, per B-KS-1), before the WARN, whoever built the chain. Same message as today's
refusal. Test with both a keyed and an unkeyed application chain.

#### B-KS-4, LOW: the upgrade refusal does not say what happened, and offers to drop the trail

After the upgrade, a 0.1.x trail with the secret set is refused with `AG-AUDIT-001`. The message
speaks of "a rolling restart that changes agentguard.audit.hmac-secret". It never says the
likely cause: the trail was written unkeyed by 0.1.0 to 0.1.2 although the secret was set. It
then offers "a renamed/dropped one". docs/index.md, "Starting a new trail", says "rename or drop
them". Dropping destroys the old rows, which the advisory says to keep as evidence.

Fix: in `JdbcAuditSink` (the branch where the anchor is unkeyed and the chain is keyed), add one
sentence: "If this trail was written by agent-guard 0.1.0 to 0.1.2 with
agentguard.audit.hmac-secret set, it was never keyed: see SECURITY-NOTES.md, advisory 'unkeyed
audit trail with the default store'." Replace "renamed/dropped" with "rename the pair and keep
it; never drop it, it is the audit record" in the message (both mismatch branches), and the same
in docs/index.md "Starting a new trail" and the advisory's option 1 (say "rename", not
"archive"). Check that the existing tests that match the old text still pass.

#### B-KS-5, INFO: keyed application chain without a secret fails with a NullPointerException

An application `AuditChain` bean that is keyed, with `agentguard.audit.hmac-secret` unset:
`auditKeyring` calls `getBytes` on the null secret. Startup fails, which is safe, but with a
`NullPointerException`, no error code and no property named. Present on 0.1.2 too; reached now
through the paths table's "application AuditChain bean" row.

Fix (`AgentGuardAutoConfiguration.auditKeyring`): when the chain is keyed and the secret is null
or blank, throw `AgentGuardConfigurationException` saying the chain is keyed but
`agentguard.audit.hmac-secret` is not set, so the verifier cannot hold its key.

#### B-KS-6, LOW: the advisory has no severity and one line is wrong for 0.1.0 and 0.1.1

The advisory states no severity. It says the unkeyed trail is "still behind the 0.1.2 guard
triggers", but on 0.1.0 and 0.1.1 those triggers may be missing (the earlier advisory). Versions
affected (0.1.0, 0.1.1, 0.1.2) and "MEMORY not affected" are correct (checked at each tag).
Roles only: yes. No over-claim found otherwise.

Fix (SECURITY-NOTES, this advisory): add "Severity: High. CVSS 3.1
AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N (4.9); graded High because the control was off by default
while documented as on." Change the trigger sentence to "on 0.1.2, and on 0.1.0 or 0.1.1 only if
the guard triggers are present (see the advisory 'audit trail guards on 0.1.0 and 0.1.1')". At
release, a repository advisory with the same severity and vector is the maintainer's step.

#### B-KS-7, LOW: three mutants of the check survive

Each was applied alone to `AuditSinkKeyCheck` and `AuditSinkKeyCheckTest` run; all 14 stay
green.

- M2, `secretSet` always false: no test has an unkeyed sink with the secret set and
  `unkeyed=true` (reachable with an application chain).
- M3, lazy sinks not created at the end of start (`getBeansOfType` removed): no test has a lazy
  sink. The paths table says "covered by the shared lifecycle; no new test".
- M4, `postProcessBeforeInitialization` records nothing: the wrapper test wraps after our own
  after-hook, so the before-hook is never needed. A wrapper added by an application
  post-processor ordered before ours is not tested.

Fix (`AuditSinkKeyCheckTest`): add (a) an unkeyed application chain plus secret plus
`unkeyed=true`, refused (also B-KS-3); (b) an unkeyed `@Lazy` sink bean, refused at startup with
no row; (c) a `PriorityOrdered` post-processor at `HIGHEST_PRECEDENCE`, declared by the
application, that wraps an unkeyed sink in its after-hook, refused. Show each mutant red in the
PR body.

### Attacks that did not break

- **Keyed with a known key** (`attempt_known_key_chain_never_verifies_intact`): an application
  chain keyed with a key other than the secret passes AG-AUDIT-003, but the verifier's keyring
  holds the secret under `k1`, so the trail never verifies `INTACT`. Detected, not silent.
  Closed, not a finding. An empty key is refused by `AuditChain.keyed` (32-byte minimum); a blank
  secret counts as unset.
- **CGLIB proxy of a one-argument `JdbcAuditSink`**: both sinks are `final`, so a class proxy
  cannot be built. A JDK proxy is unwrapped (builder's test). Not reachable.
- **Sink registered under the interface type only**: the check matches on `AuditSink`, and the
  builder's tests declare beans as `AuditSink`. Covered.
- **Composite sink**: a composite whose parts are beans has each part checked. A composite that
  builds its parts inside is an unknown sink: B-KS-2.
- **Memory store path**: keyed with the secret, refused when an application memory sink is
  unkeyed. Covered by the builder's tests.
- **`unkeyed=true` plus a secret with the starter's chain**: refused by the `auditChain` bean.
  Only the application-chain path starts (B-KS-3).
- **Upgrade preserves the old rows**: the refusal comes before any write, so the old trail is
  untouched. The advice to drop it is B-KS-4.

### Next

Fix pass on every finding above, probes added first. Pass 2 re-runs the six probes, the three
mutants and the harness on the new head.
