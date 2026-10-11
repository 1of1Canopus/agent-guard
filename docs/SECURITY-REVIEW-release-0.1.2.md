# Security review: release candidate 0.1.2 (whole-module pass)

## 2026-10-11, pass 1

**Verdict: HOLD.** One MEDIUM and two LOW findings. Every finding is fixed before the
`v0.1.2` tag (no-allowance rule). B-RC12-1 is a design stop (a design page, then a build).

Reviewed tree: `050b0a6` (`docs/advisory-link-and-wording`, PR 35 head = main + final docs).
Scope since 0.1.1: PR 31 (claims wording), PR 34 (schema gate, `GuardCensus`), PR 33 (Grype
before signing), PR 35 (wording, advisory link). Threat list: the module spec, section "Threats".
Method: attacks where the mechanisms meet, each one run, not read.

### Numbers

| Check | Result |
|---|---|
| `./mvnw verify` (Docker up, run once) | exit 0; 278 tests, 0 failures, 0 errors, 1 skipped |
| Skipped test | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` (assumption: needs an extra Spring AI jar on the classpath; skipped since it was written, not passing) |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` (run once) | exit 0; fixed 73, still weak 0 |
| `tools/check-private-references.sh --tree` | tree clean |
| New probes this pass | 4, all RED on `050b0a6` |

### Findings

| Id | Severity | Class | Probe | Status |
|---|---|---|---|---|
| B-RC12-1 | MEDIUM | framework path / docs vs code | `CipherProbeRc012StartupTest.probe_own_audit_sink_on_a_second_datasource_starts_on_an_unguarded_trail`, `probe_own_jdbc_audit_sink_under_store_memory_is_never_checked` | open, DESIGN STOP |
| B-RC12-2 | LOW | restricted-role visibility | `CipherProbeRc012JdbcTest.probe_member_of_the_owner_role_can_disable_the_guard_and_is_not_warned` | open |
| B-RC12-3 | LOW | release pipeline | `probe_grype_negligible_is_listed_not_blocking` (internal probe file `cipher-probe-rc012-round1.sh`) | open |

#### B-RC12-1 (MEDIUM): the gate checks a DataSource, not the one the audit sink uses

The gate (`AgentGuardSchemaGate`) verifies `ObjectProvider<DataSource>.getIfAvailable()`, and
decides from properties alone whether to check at all. Two paths start an application whose
audit sink writes into an unguarded trail:

- (a) The application keeps a primary DataSource for business data and wires its own
  `JdbcAuditSink` on a second DataSource (a separate audit database is a common layout). The
  gate verifies the primary, logs "audit trail guards verified at startup", and the sink writes
  into the second database. Repro: primary = a guarded database, audit = the 0.1.x archive-remedy
  state (live pair with no guard). The context starts.
- (b) `agentguard.store=MEMORY` and `agentguard.budgets.store=MEMORY` with an application
  `JdbcAuditSink` bean. No check runs. The starter's MEMORY warning is the only signal, and it
  disappears when the application also supplies its own `DecisionStore`.

Why it matters: SECURITY-NOTES and CHANGELOG state the check runs "also when the application
supplies its own store beans". On path (a), an operator upgrading a 0.1.x installation with a
separate audit database stays in exactly the state the advisory describes, and the log says the
guards were verified.

**DESIGN STOP.** The fix needs a new mechanism, so no code is prescribed here. Property that must
hold: every JDBC audit, decision and budget adapter the context will call runs over a DataSource
whose guards passed the census in this context, or the context refuses to start
(`AG-SCHEMA-003` or `AG-SCHEMA-005`). Paths the design must cover, one test each: starter-built
stores; an application bean of each JDBC adapter type on the primary DataSource, on a second
DataSource bean, and on a DataSource that is not a bean; a DataSource wrapped by a proxy
(`TransactionAwareDataSourceProxy`, `LazyConnectionDataSourceProxy`, a pool around a pool); an
application `AuditSink` that decorates or delegates to a `JdbcAuditSink` (not visible by type);
store properties set to MEMORY with JDBC adapter beans present; lazy initialization; a child
context. If the design refuses a path by design instead of covering it, the public text says so
in the same PR. Owner of the design page: the builder; the security review reads it before code.

#### B-RC12-2 (LOW): the owner warning misses a member of the owning role

`JdbcSupport.runtimeRoleOwnsAuditTable` runs
`SELECT tableowner = current_user FROM pg_tables WHERE tablename = 'agentguard_audit'`.
A runtime role that is a member of the owning role holds every owner privilege. The probe makes
`rc12_rt` a member of `rc12_owner`, gives the tables to `rc12_owner`, gets `false` from the
method, then runs `ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only` as
`rc12_rt` with success. The read is also not scoped to `current_schema()` (a second schema with
the same table name answers with an arbitrary row) and is not `pg_catalog`-qualified, unlike every
other read of the check.

Fix (correction, the fix pass): in `JdbcSupport.runtimeRoleOwnsAuditTable`, resolve the table against
`current_schema()` through `pg_catalog.to_regclass(pg_catalog.quote_ident(pg_catalog.current_schema()) || '.agentguard_audit')`
and test `pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER')` on `pg_catalog.pg_class`.
Change the WARN text in `AgentGuardSchemaGate.warnIfOwner` to "owns agentguard_audit or is a
member of the role that owns it". Probe above goes green; add one case for the second schema.

#### B-RC12-3 (LOW): a Grype "Negligible" match blocks the release as UNRATED

`findings_from_grype` in `tools/check-vulnerability-report.py` calls `_normalise_name` first,
which returns `None` for `NEGLIGIBLE` (not in `RANK`), so the value becomes `UNRATED` and counts
at HIGH. The `if name == "NEGLIGIBLE"` branch after it can never run. Repro: a report with one
`Negligible` match, valid SBOM and digests: exit 1, printed `UNRATED`. A MEDIUM-only and a
LOW-only report exit 0 and are listed in the summary file, as intended. Fails closed, hence LOW,
but a release can be blocked by the least severe class Grype reports, and the code says otherwise.

Fix (correction, the fix pass): in `findings_from_grype`, upper-case the raw severity, map `NEGLIGIBLE`
to `LOW` before `_normalise_name`, delete the dead branch. Add a `--self-test` case
"grype negligible lists as LOW", and add the internal probe to `tools/cipher-probe-release-pipeline.sh`.

### Attacked, no finding (repro attempted)

- **Schema gate vs the AG-AUDIT-002 archive-and-rerun path.** `initialize-schema=true` on the
  archive state repairs the live pair and starts; `false` refuses with the archive sentence and
  creates nothing (`SchemaGuardBootPathTest`, green in this run).
- **Second schema and `search_path`.** The census reads `current_schema()`; the unqualified store
  statements resolve to the first schema on the path that holds the table. When the current schema
  holds the tables both agree; when it does not, the census refuses (fails closed). Covered by
  `CipherProbePr34JdbcTest.confirm_second_schema_with_the_same_names_is_judged_by_current_schema_only`
  and the B-38-10 decoy test in `SchemaGuardCensusJdbcTest`, green in this run.
- **Escaping in the refusal.** `display()` escapes C0, DEL, U+0085, U+2028, U+2029 and backslash,
  which are every line terminator Java and the usual log layouts honour; no forged log line.
  Other C1 controls and bidi format characters pass through. Reclassified, not a finding: a name
  in the refusal is a trigger, rule or policy name on the four tables, a schema, role or database
  name, and creating any of them on the tables needs the owner, who can already disable the guards.
- **Grype step.** Empty report, non-JSON report, missing `matches`, missing or mismatched SBOM,
  missing `--min-artifacts` or `--expect-digests`: exit 2. A missing binary is a non-zero `rc` and
  the step stops. The `| tee` runs under `set -euo pipefail` (pipefail survives `set +e`/`set -e`),
  so exit 1 or 2 fails the step. MEDIUM-only: exit 0, one summary line, carried into the step
  summary and the release evidence.
- **Reproducibility script vs bundle.** `verify-reproducible.sh` passes vacuously on zero
  artifacts and compares one way only, but the bundle step after `deploy` refuses any bundle entry
  with no recorded checksum (`NO RECORD`) and any jar absent from `scanned-sha256.txt`. Fails
  closed downstream; not a finding.
- **Reference guard** on the new docs: tree clean.
- **Claims wording** in README, SECURITY-NOTES, CHANGELOG, `docs/index.md`, `docs/upgrading-0.1.2.md`
  against the forbidden list: no hit used as a claim. Hits read and kept: "not guaranteed"
  (negative), "only proof for the exact" (limiting), two historical CHANGELOG lines where a test or
  a script "proves" a build property, "approve" as the HTTP action. The repository URL slug is a
  coordinate, not a name in text.
- **Advisory text (GHSA-xc43-5ch5-2pfq) vs code.** Affected range `<= 0.1.1`, patched `0.1.2`,
  both artifacts; the description of the bug, of the script fix and of the startup refusal matches
  the code. The advisory makes no claim about application-supplied stores; SECURITY-NOTES and
  CHANGELOG do, which is B-RC12-1.

### Ruling on B-RL-033 (no preflight job, no replay refusal)

The register row asks this pass whether the 0.1.2 tag may go out without it. Ruling: **yes, for
0.1.2 only**, under the conditions below. Reasoning:

1. What the preflight would assert holds today, checked live on 2026-10-11 through the API: the
   `release` environment has a required reviewer (the maintainer) and a branch policy; the `main`
   ruleset requires Build & test, DCO sign-off, Cipher probes, Vulnerability scan and Reference
   guard. The missing control is the automation of that check, not the property.
2. Replay refusal protects a version that already exists. `0.1.2` has no tag and no deployment yet,
   and Central refuses a second upload of a released version.
3. The tag is verified against the signing key fingerprint, so only the key holder starts a real
   release run.
4. 0.1.2 carries the fix for a published advisory; holding it for an unrelated pipeline mechanism
   leaves users on the vulnerable version longer.

Conditions: re-run the three API reads immediately before pushing the tag and refuse if any
differs; one release run for 0.1.2; if a run fails after upload, no re-run until the Portal
deployment list has been read by hand for an existing agent-guard 0.1.2 deployment. B-RL-033 stays
open and must close before the 0.2.0 tag. This ruling does not lift the HOLD above.

### Probe suite and new probes

The existing suite ran unchanged with Maven probes on: 73 fixed, 0 still weak. The four new
probes ran on `050b0a6` with Docker up: 4 of 4 RED (the two starter contexts started; the owner
check returned `false` after the runtime role disabled the append-only trigger; the gate exited 1
on a Negligible-only report). Java probes are on branch `review/rc-0.1.2`; copies and the shell
probe are in the internal probes folder for the fix pass.

## 2026-10-11, note on a smaller fix for B-RC12-1

Question: for 0.1.2 only, replace the design stop with (a) the gate also runs when any
`JdbcAuditSink` bean exists, whatever the store property; (b) startup refused with
`AG-SCHEMA-007` when a `JdbcAuditSink` bean runs on a DataSource other than the checked one,
unless `agentguard.schema.gate.datasource=<beanName>` names the DataSource to check; (c) docs state
the exact coverage.

**Answer: yes, accepted for 0.1.2.** It closes both reproduced paths with a loud refusal. It also
keeps the secure default: the property chooses which DataSource is checked and never skips the check.
Conditions:

1. **Not inside the gate's constructor.** The starter's `jdbcAuditSink` bean needs the gate. A gate
   that looks up every `JdbcAuditSink` while it is being built creates a circular reference. The
   comparison runs after the beans exist: a `BeanPostProcessor` on `JdbcAuditSink`, or a
   `SmartInitializingSingleton`, chosen by the builder. It stays eager under lazy initialization. The
   sink exposes its DataSource for the comparison, and the comparison is by identity. A proxy
   around the checked DataSource is therefore refused with 007, loudly, and the docs say so.
2. **Every `JdbcAuditSink` bean**, not just the first one. Two sinks on two DataSources are refused
   unless both are the named one. An unknown bean name in the property refuses at startup.
3. **Docs (c)** replace "also when the application supplies its own store beans" in
   SECURITY-NOTES, CHANGELOG and the upgrade note with the exact coverage: `JdbcAuditSink` beans
   are checked. The docs also name what stays outside: a `JdbcAuditSink` built inside another bean
   and never exposed as a bean, which must call `JdbcSupport.verifyGuards` itself, as the docs
   already require for non-Spring use. On re-verification I try that path and either reclassify it
   or row it for 0.2.0.

**Probes.** Both existing probes must flip:
- `probe_own_audit_sink_on_a_second_datasource_starts_on_an_unguarded_trail` flips by refusal
  with `AG-SCHEMA-007`.
- `probe_own_jdbc_audit_sink_under_store_memory_is_never_checked` flips by refusal with
  `AG-SCHEMA-003`.

The third probe, `probe_named_audit_datasource_is_the_one_checked`, asserts all of these:
- A primary DataSource that is guarded, plus a `JdbcAuditSink` on a second DataSource bean, with
  no property: the context fails. The root cause carries `AG-SCHEMA-007` and names both bean names.
- The same context with the property naming the second DataSource, when that DataSource is in the
  archive state: the context fails with `AG-SCHEMA-003`.
- The property naming a guarded second DataSource: the context starts.
- The property naming a bean that does not exist: the context fails.

**Routing.** This is a fix list for the builder, not the fix pass, because it extends the gate the builder built. No
separate design page is needed, because conditions 1 to 3 fix the property and the paths. The PR
body must name the hook chosen and must show each of the three probes RED before the fix
(mutation rule). Two passes as usual. The HOLD stands until the three probes are green and
B-RC12-2 and B-RC12-3 are closed.

## Re-verification (2026-10-11)

Tree: PR 37 head `667573e` (`fix/schema-gate-covers-every-jdbc-sink`, main merged in: the wording
PR, the B-RC12-2/3 fixes, and the bounded B-RC12-1 fix). Verdict first: **HOLD**. The three
reproduced B-RC12-1 paths and both LOWs are closed and proven by mutation. Two new paths around the
new check were reproduced (B-RC12-5), and B-RC12-4 is a real gap that the same hook closes. Under the
no-allowance rule both are fixed before the tag.

### Numbers

| Check | Result |
|---|---|
| `./mvnw verify` (Docker up) | BUILD SUCCESS. Core 206 tests, starter 84 (1 skipped), sample 3. 0 failures. JaCoCo gate met |
| Skipped test | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` (needs the real Spring AI jar on the classpath; skipped as before, not passing) |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` | 74 fixed, 0 still weak |
| New probe file | `CipherProbeRc012ReverifyStartupTest`: 8 tests, 3 probes fail on this tree, 5 checks pass |

### Prior findings, by probe and by mutation

Each fix was reverted once. The probe went red, then the fix was restored.

| Finding | Probe on `667573e` | Mutation | Probe under mutation |
|---|---|---|---|
| B-RC12-1 | `probe_own_audit_sink_on_a_second_datasource_starts_on_an_unguarded_trail`, `probe_own_jdbc_audit_sink_under_store_memory_is_never_checked`, `probe_named_audit_datasource_is_the_one_checked`: green | identity compare in `AgentGuardSchemaGate.checkSink` disabled | second-DataSource and named-DataSource probes red. The store=MEMORY probe stays green: it flips through the 003 census, not the compare. Expected |
| B-RC12-2 | `probe_member_of_the_owner_role_can_disable_the_guard_and_is_not_warned`: green | old `JdbcSupport.runtimeRoleOwnsAuditTable` restored (reverse of 503d1c0) | red, and `owner_check_is_judged_by_the_current_schema_only` red |
| B-RC12-3 | `probe_grype_negligible_is_listed_not_blocking`: PASS | old NEGLIGIBLE mapping restored (reverse of 503d1c0) | FAIL (rc=1) |

B-RC12-2 and B-RC12-3: **closed**.

### The three accepted conditions

1. A proxy around the checked DataSource is refused with `AG-SCHEMA-007`. Verified by
   `SchemaGateSinkCoverageTest.a_proxy_around_the_checked_datasource_is_refused` (green) and by the
   mutation above.
2. Every `JdbcAuditSink` bean is checked, not only the first. Verified by
   `every_sink_is_checked_not_only_the_first` (two application sinks, the second one bad, refused
   naming `zSink`). An unknown bean name in `agentguard.schema.gate.datasource` refuses
   (`an_unknown_name_refuses_even_without_a_jdbc_store`, and the third RC12 probe).
3. Docs: SECURITY-NOTES, CHANGELOG, `docs/index.md` and `docs/upgrading-0.1.2.md` state the exact
   coverage. The inner-sink statement is accurate (point 3 below). Child contexts are not mentioned
   (see B-RC12-4).

### Paths attacked

- **(3) Inner sink.** A bean that builds a `JdbcAuditSink` inside itself on an unguarded trail starts.
  That matches the docs. The remedy the docs give works: the same holder calling
  `JdbcSupport.verifyGuards(ds)` (public) first is refused with `AG-SCHEMA-003`. Check:
  `verify_inner_sink_gap_is_as_documented_and_the_remedy_works`. **Reclassified: documented
  coverage, not a finding.**
- **(4) Lazy initialization.** Global lazy initialization with the starter's JDBC store on an
  unguarded trail is refused at startup (`verify_lazy_initialization_still_checks_the_starter_store_at_startup`).
  The lazy application sink case is the builder's `a_lazy_sink_nothing_injects_is_checked_at_startup` (green). Holds.
- **(5) Circular reference.** The starter's own sink plus an application `JdbcAuditSink` bean (not an
  autowire candidate, so both coexist). On a second DataSource: refused with 007, naming `userSink`.
  On the checked DataSource: starts. No cycle (`verify_starter_sink_and_application_sink_are_both_checked`). Holds.
- **Wrapped or early sinks.** Two paths escape the check. This is B-RC12-5 below.

### B-RC12-5 (LOW): a `JdbcAuditSink` bean that the check never sees as one

`JdbcAuditSinkDataSourceCheck` records a sink only in `postProcessAfterInitialization`, and only when
`bean instanceof JdbcAuditSink`. It implements no `Ordered`. Two framework paths escape:

- **Wrapped.** An ordered application post-processor wraps every `AuditSink` bean (metrics,
  tracing, or an AOP JDK proxy under `spring.aop.proxy-target-class=false`). The check then receives
  the wrapper. The sink is never compared. Probe:
  `probe_sink_wrapped_by_a_post_processor_is_never_checked`. An archived (unguarded) trail starts.
- **Created early.** An ordered application post-processor depends on the `AuditSink`. Spring
  creates the sink before the check is registered. The sink is never recorded.
  `afterSingletonsInstantiated` checks recorded sinks only. Probe:
  `probe_sink_created_before_the_check_is_registered_is_never_checked`. An archived trail starts.

Both are `JdbcAuditSink` beans, which the docs now say are checked. LOW: each needs an application
post-processor that wraps or depends on the sink. Fix (correction inside the B-RC12-1 hook, so it
goes to the builder who wrote it): the check implements `PriorityOrdered` at highest precedence. It
records in `postProcessBeforeInitialization` (the raw instance, before any after-initialization
wrapper) as well as after initialization (a `FactoryBean` product only gets the after call). In
`afterSingletonsInstantiated` it also checks every singleton from
`getBeansOfType(JdbcAuditSink.class, true, false)` that is not already recorded. Docs: one line
saying a sink created as a dependency of a post-processor that is itself ordered before the check
and also wrapped is outside coverage, if the builder cannot cover it. Both probes must flip by
refusal with `AG-SCHEMA-003`. Mutation rule: show each red before the fix.

### Ruling on B-RC12-4: fix in 0.1.2, do not carry

Not closed as documented coverage, and not carried. Reasoning:

- The census already checks the decision and budget tables (ordinary, logged, no rule, no row-level
  security, no inheritance). An application `JdbcDecisionStore` or `JdbcBudgetStore` on another
  DataSource skips that census entirely. That is the B-RC12-1 weakness on the approval and budget
  tables. Reproduced: `probe_decision_store_on_a_second_datasource_is_never_compared`. A second
  DataSource whose `agentguard_decision` is `UNLOGGED` starts. Crash recovery would empty the
  approvals table.
- The hook that closes it exists now. Extending it is a correction, not a new mechanism: give
  `JdbcDecisionStore` and `JdbcBudgetStore` a public `dataSource()` accessor, and have
  `JdbcAuditSinkDataSourceCheck` compare beans of those two types by identity, exactly like sinks
  (same 007 message, same named-DataSource property). Carrying it to 0.2.0 would be "fix later" for
  a reproduced gap, which the no-allowance rule refuses.
- **Child contexts: reclassified, documented coverage.** Checked: a child context that runs the
  auto-configuration has its own gate and refuses an unguarded child sink (003). A child without the
  auto-configuration starts. That is code without the starter, the same case as the inner sink.
  Check: `verify_child_context_with_and_without_the_starter`. Docs fix: SECURITY-NOTES and
  `docs/index.md` add one sentence. Each application context is checked by the auto-configuration
  in it. A context without it must call `JdbcSupport.verifyGuards`. The register row claimed the
  docs already said this. They do not.

Probe to flip: `probe_decision_store_on_a_second_datasource_is_never_compared` by refusal with
`AG-SCHEMA-007`. The fixer adds a budget-store twin of it.

### Release-time text (point 7)

"(not yet released)" in SECURITY-NOTES (line 192) is **not** the only change. The release commit
also needs these:

- `CHANGELOG.md`: `## [Unreleased]` becomes `## [0.1.2] - <date>`, with a fresh empty
  `## [Unreleased]` above it (RELEASING step 2).
- `README.md:38` and `docs/index.md:17`: the dependency snippet says `<version>0.1.1</version>`.
  It becomes `0.1.2`.

Nothing else found. The pom stays `0.1.0-SNAPSHOT`, because the version comes from the tag.

### Probe file

The internal probe file is `CipherProbeRc012ReverifyStartupTest.java`. The fixer adds it to the
starter test tree before touching production code. The three probes must flip, and the five checks
must stay green.

### Verdict

**HOLD.** Open: B-RC12-5 (LOW) and B-RC12-4 (LOW, decision and budget stores). Both are corrections
to the PR 37 hook, so they are one fix pass on the same branch. Then a second pass from me, with
these probes only. B-RC12-1, B-RC12-2 and B-RC12-3 are closed.

## Third pass (2026-10-12)

Scope: probes only, on PR 37 head `63453ea` (`fix/schema-gate-covers-every-jdbc-sink`). No new
attack surface was searched in this pass.

### Numbers

| Item | Result |
|------|--------|
| `CipherProbeRc012ReverifyStartupTest` (7 tests) | 7 run, 0 failures |
| `SchemaGateSinkCoverageTest` | 17 run, 0 failures |
| Docker | up; nothing skipped in these two classes |

The probe file in the tree matches the internal one except for formatting and unused imports.

### Mutations (one per finding, each restored after the run)

| Mutation in `JdbcAuditSinkDataSourceCheck` | Tests that went red |
|------|------|
| Drop the decision-store compare (`JdbcDecisionStore` maps to no store) | `probe_decision_store_on_a_second_datasource_is_never_compared`, `a_decision_store_on_a_second_datasource_is_refused_by_name` |
| Remove the singleton sweep in `afterSingletonsInstantiated` | `a_sink_created_before_any_post_processor_is_registered_is_swept` |
| Remove `PriorityOrdered` (plain `BeanPostProcessor`) | `a_sink_created_early_and_wrapped_is_checked_by_the_priority_ordered_check` |

Each control has at least one test that fails without it. As the builder noted, my two B-RC12-5
probes alone do not catch the sweep or the priority-order removal: recording before
initialization and the sweep cover each other there. The builder's dedicated tests close that.

### Documented gap

The statement is: a store created before the check is registered, and wrapped by a post-processor
registered even earlier, is not checked. Accepted by reading, without a probe (budget). Such a bean
gets no callback from the check. The sweep looks it up by store class. A wrapper that is not an
instance of the store class is not found. The statement is accurate and appears in
`SECURITY-NOTES.md` and `docs/index.md`.

### Child contexts

The sentence exists in `SECURITY-NOTES.md`, `docs/index.md` (line 197) and
`docs/upgrading-0.1.2.md` (line 15): each context is checked by the auto-configuration in it, and a
context without it must call `JdbcSupport.verifyGuards`.

### Findings

| ID | Severity | Status |
|----|----------|--------|
| B-RC12-4 | LOW | closed: probe green, mutation red |
| B-RC12-5 | LOW | closed: probes green, sweep and priority-order mutations red |

No finding is open on the 0.1.2 candidate.

### Verdict

**RELEASE.** Agent names in this document were replaced by roles in this pass.
