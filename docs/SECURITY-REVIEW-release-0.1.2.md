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

Fix (correction, Isis): in `JdbcSupport.runtimeRoleOwnsAuditTable`, resolve the table against
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

Fix (correction, Isis): in `findings_from_grype`, upper-case the raw severity, map `NEGLIGIBLE`
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
   `SmartInitializingSingleton`, chosen by Thor. It stays eager under lazy initialization. The
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

**Routing.** This is a fix list for Thor, not Isis, because it extends the gate he built. No
separate design page is needed, because conditions 1 to 3 fix the property and the paths. The PR
body must name the hook chosen and must show each of the three probes RED before the fix
(mutation rule). Two passes as usual. The HOLD stands until the three probes are green and
B-RC12-2 and B-RC12-3 are closed.
