# Security review: fix/schema-trigger-guards (PR 34, release 0.1.2)

## Pass 1 (2026-10-08)

Reviewer: security review. Head reviewed: `0e0b3c8`. Scope: the startup guard census, the corrected
schema script, the starter gate, the non-owner boot path (plan condition 3), the startup-only
limitation, and the 0.1.2 public text. Every finding below was reproduced by a probe that fails on
the reviewed head; every "confirmed" item was measured by a probe that passes.

### Verdict: MERGE WITH FIXES

No HIGH. Two MEDIUM, two LOW. All four are fixed before merge (no allowance). The fix of the
advisory itself holds: every trigger state the brief named is refused, the archive-remedy state is
refused and repaired by the corrected script, and the census cannot be answered by a shadow function.

### Numbers

`CIPHER_PROBE_MAVEN=1 ./mvnw verify`, Docker up, Testcontainers PostgreSQL 16 (pinned digest).

| Run | core | starter | sample |
|---|---|---|---|
| Baseline, head `0e0b3c8`, no review probes | 191 run, 0 fail, 0 skip | 69 run, 0 fail, 1 skip | 3 run, 0 fail |
| With the review probes | 202 run, 2 fail (CP34-2, CP34-3) | 70 run, 1 fail (CP34-1), 1 skip | 3 run, 0 fail |

Existing `CipherProbe*` tests re-run unchanged: 71 in core, 32 in the starter, all green. The one
skip is the pre-existing assumption-guarded Spring AI tool probe (needs an extra classpath jar),
skipped on `main` too; it is not passing, it is not run.

Probe files, handed to the fix pass, which adds them to the suite at these paths before touching
production code: `agent-guard-core/src/test/java/com/housedevinci/agentguard/adapter/jdbc/CipherProbePr34JdbcTest.java`
(2 probes, 9 confirmations) and
`agent-guard-spring-boot-starter/src/test/java/com/housedevinci/agentguard/autoconfigure/CipherProbePr34StartupTest.java`
(1 probe); the public-text probe for CP34-4 is a shell check kept with the internal review material.

### Findings

#### CP34-1 (MEDIUM) - user-supplied JDBC stores never build the gate

Repro: `probe_user_supplied_jdbc_stores_start_on_an_unguarded_trail`. Database in the 0.1.x
archive-remedy state (zero triggers on the live pair). Context with `agentguard.store=JDBC`,
`agentguard.budgets.store=MEMORY`, `initialize-schema=false`, and the application's own
`DecisionStore` and `AuditSink` beans (`new JdbcDecisionStore(ds)`, `new JdbcAuditSink(ds)`): the
context **starts**. `AgentGuardSchemaGate` is `@Lazy` and only the starter's three store bean
methods pull it; all three are `@ConditionalOnMissingBean`, so supplying the stores removes every
edge to the census. The design page, section 3 (b), names this exact case as the reason the gate is
unconditional; the CHANGELOG claims the check runs "on every boot path that uses a JDBC store".

Fix (builder, the run that built the gate): implement section 3 (a) and (b) as written.
`AgentGuardAutoConfiguration.agentGuardSchemaGate` loses `@Lazy` and is registered
unconditionally; the gate's constructor decides "JDBC in use" from the properties (`store=JDBC`,
or `budgets.store` resolving to `JDBC`) and, if so, resolves the `DataSource` and runs the script
and census as today; if not, it holds nothing and `dataSource()` throws
`AgentGuardConfigurationException`. Replace the store-type `LazyInitializationExcludeFilter` with
one on `AgentGuardSchemaGate`'s type (keep the stores eager too, it costs nothing). Keep
`memory_only_context_never_builds_the_check_and_needs_no_data_source` green by asserting "gate
holds no DataSource" instead of "gate not built". Probe flips green. Add one sentence to the
"Startup guard check" paragraph in `docs/index.md`: an application that constructs a JDBC adapter
outside the starter's beans with `store=MEMORY` set, or without Spring, must call
`JdbcSupport.verifyGuards(dataSource)` first (the bare-`DataSource` constructors go in 0.2.0).
Mutation row: gate back to `@Lazy`, probe RED.

#### CP34-2 (MEDIUM) - an UNLOGGED trail passes the census

Repro: `probe_unlogged_trail_and_anchor_pass_the_guard_check`: after `ALTER TABLE agentguard_audit
SET UNLOGGED` and the same on the anchor, `JdbcSupport.verifyGuards` returns clean and the starter
would log "audit trail guards verified". Consequence measured in
`confirm_unlogged_trail_and_anchor_are_emptied_by_crash_recovery`: one row in each table,
`CHECKPOINT`, `kill -9` of one backend; after crash recovery the counts are `0/0`, no trigger fired,
and the census is still clean. Trail and anchor vanish together, so the anchor cannot tell, and the
next append starts a new chain at GENESIS. An unlogged table is also not replicated, so a failover
gives the same result. This needs the table owner, but it is a persistent state (a DBA can set it
for write speed with no intent) that the startup check blesses at every boot.

Fix (builder): add the relation leg of the design page section 4.2 item 1 to `GuardCensus.tables`:
select `c.relkind` and `c.relpersistence`; for each of the four tables present, a finding when
`relkind <> 'r'` or `relpersistence <> 'p'` (`"<schema>.<table> is UNLOGGED (relpersistence=u); a
crash empties it with no trigger firing"`, and the relkind equivalent). `AG-SCHEMA-003`, same
remedy plus "`ALTER TABLE ... SET LOGGED`". Add both to the list of what is checked in CHANGELOG,
SECURITY-NOTES, `docs/index.md` and the upgrade note's code table. Test: unlogged audit, unlogged
anchor, unlogged budget table each refused. Mutation row: leg removed, probe RED.

#### CP34-3 (LOW) - catalogue names reach the refusal raw

Repro: `probe_catalogue_names_reach_the_refusal_with_control_characters`: a trigger named
`"x<LF>agentguard: audit trail guards verified at startup"` on `agentguard_budget` is refused
(correctly), and the refusal message carries the raw line feed, so the startup failure log shows a
forged "verified" line. Same for rule, policy, child-table, schema, role and database names.

Fix (fix pass): in `GuardCensus`, one private `display(String)` that replaces every character
`< 0x20`, `0x7F`, U+0085, U+2028 and U+2029 with `\uXXXX`; apply it to every value read from the
catalogue or session before it enters a finding or the `where` string (`tables`, `triggers`,
`rules`, `policies`, `inheritance`, `where`, `captureAndPin`'s schema). Probe flips green.

#### CP34-4 (LOW) - public text: unqualified "append-only", advisory unnamed and unlinked

Repro: the public-text probe exits 1 on the head: `README.md:18` ("a hash-chained, append-only
PostgreSQL table") and `docs/index.md:295` ("append-only chained audit") carry no fixing version,
no startup-only qualifier and no advisory link; the advisory is called `"schema trigger guards"` in
CHANGELOG and SECURITY-NOTES and `"the bundled schema step can install an audit trail with no
append-only guards"` in `docs/upgrading-0.1.2.md`; no file links it, and the repository has no
published advisory yet.

Fix (fix pass, then the maintainer for the advisory): one title everywhere; the advisory published
(or its draft URL fixed) before the tag and linked from CHANGELOG, SECURITY-NOTES and the upgrade
note; README line 18 becomes "... in a hash-chained PostgreSQL table, append-only from 0.1.2 and
checked at startup (0.1.0 and 0.1.1: see the security advisory, link)"; `docs/index.md:295` the
same qualifier. Probe exits 0. No other wording issue: no "is protected" or "cannot be altered",
roles only, no agent or person name in the diff.

### Plan condition 3: the non-owner with `initialize-schema=true`

The builder's claim is **confirmed by measurement** (`confirm_011_script_as_a_non_owner_never_succeeded_on_a_guarded_schema`):
the released 0.1.1 script, run as a non-owner on a guarded schema, fails with SQLState `42501`
("must be owner"), with and without `CREATE` on the schema; 0.1.1's `initializeSchema` ran it in one
transaction and rethrew, so that configuration never booted on 0.1.1. No healthy installation is
lost. The alternative the PR body offers (run the `ALTER` only when `tgenabled <> 'A'`) would not
change this: with the five `ALTER` statements removed altogether, the 0.1.2 script still fails
`42501` for the non-owner before reaching them
(`confirm_conditional_alter_would_not_let_a_non_owner_boot`). Ruling: **keep `AG-SCHEMA-006`**, no
change. It meets the condition's second branch (coded, never a raw SQL error: measured, the message
carries the SQLState and not the driver text), and `006` rather than `003` is right on a guarded
schema, where the owner step is not the remedy.

### Confirmed (probes pass on the head)

| State | Result | Probe |
|---|---|---|
| one guard dropped | `003`, names it missing | `confirm_one_missing_trigger_is_refused` |
| one guard `DISABLE` (`tgenabled = 'D'`) | `003`, `tgenabled=D` | `confirm_one_disabled_trigger_is_refused` |
| same trigger name, no-op function in `public`; same function name in another schema | `003`, names the function and schema | `confirm_same_named_trigger_on_a_different_function_is_refused` |
| partitioned `agentguard_audit` carrying both guards `ALWAYS` | `003` through the `pg_inherits` edge to the partition | `confirm_partitioned_trail_is_refused_through_its_partition` |
| unguarded pair in `public`, guarded pair in `s2` | `currentSchema=s2` clean; `public` and `public,s2` refused | `confirm_second_schema_with_the_same_names_is_judged_by_current_schema_only` |
| owner disables a guard after the check, deletes, re-enables | not detected; next census clean | `confirm_owner_ddl_after_the_check_goes_unnoticed_until_next_start` |

The last row is the stated residual (plan condition 4). It is stated in CHANGELOG, SECURITY-NOTES,
`docs/index.md` and the upgrade note ("checked at startup only"; the owner can disable a trigger
after startup). Accepted for 0.1.2; PR 2 closes it.

### Attacks attempted that produced no finding

- Shadowing the census: every call `pg_catalog.`-qualified, `search_path` pinned with readback,
  operators resolve in `pg_catalog`; the builder's mutation M6/M7 covers it and the code matches.
- View instead of the trail table: a view cannot carry `BEFORE ROW` or `TRUNCATE` triggers, so the
  set check refuses it (read, and covered by CP34-2's relkind leg once added).
- Foreign key from the trail with `ON DELETE CASCADE` / `SET NULL`: the cascade fires the row guard
  (`ALWAYS`), so it refuses, not deletes. Internal triggers are correctly outside the set.
- Creation path: script and census in one transaction under the advisory lock; a census refusal
  rolls the script back (`AgentGuardException` path reaches the `rollback` in `finally`).
- `pg_temp.agentguard_audit` on a pooled connection after startup diverts appends for a role holding
  `TEMPORARY`: a post-startup action, inside "checked at startup only", and PR 2's qualification
  (design page section 13). Not a PR 1 finding.
- Static `SCRIPT_DONE` set kept (design page 3 (d) removes it): the census now runs on every boot
  regardless, so a stale or colliding entry can only skip a repair and refuse; availability only.

## Pass 2 (2026-10-08)

Head reviewed: `49c8dcb`. Last pass on this PR (two-pass cap).

### Verdict: MERGE

Condition, not a finding: merge after the evidence-claim PR (#31), which adds the
`SECURITY-NOTES.md` heading every advisory link in this PR points to
(`#advisory-audit-trail-guards-on-010-and-011`). Merged first, this PR ships dead links.

### Numbers

| Run | core | starter | sample |
|---|---|---|---|
| `CIPHER_PROBE_MAVEN=1 ./mvnw verify`, Docker up, head as pushed | 204 run, 0 fail | 71 run, 0 fail, 1 skip | 3 run, 0 fail |
| Pass 1 probes (`CipherProbePr34JdbcTest`, `CipherProbePr34StartupTest`) | 11/11 green | 1/1 green | - |
| Pass 2 probes (below) | 5/5 green | 3/3 green | - |

Core coverage 91 % line. The one skip is the existing Spring AI tool auto-configuration probe
(assumption-guarded, extra classpath jar), skipped on `main` too.

### Prior findings

| Finding | Status | Evidence |
|---|---|---|
| CP34-1 (MEDIUM) | closed | probe green; M21 re-applied (`@Lazy` back on the gate, gate type off the lazy-init exclude): pass 1 probe RED, 2 of 3 pass 2 probes RED, restored green |
| CP34-2 (MEDIUM) | closed | probe green; M22 re-applied (both relkind and relpersistence tests disabled): 2 pass 1 tests and 4 pass 2 tests RED, restored green |
| CP34-3 (LOW) | closed | probe green; M23 re-applied (`display()` returns the raw value): pass 1 probe and the pass 2 U+2028/backslash test RED, restored green |
| CP34-4 (LOW) | closed for the code; the advisory link moves to the tag blockers | public-text probe legs (a) and (b) pass; leg (c) RED only on "no advisory link" in CHANGELOG, SECURITY-NOTES and the upgrade note, because no GHSA advisory exists yet |

Under M21 the pass 2 test that survives is the starter's own budget store with
`budgets.store=JDBC`: that bean pulls the gate itself, so the mutation cannot reach it. Expected;
the two cases where the application supplies the stores went RED.

### Pass 2 probes (internal, `internal/agent-guard/probes/`)

- `CipherProbePr34Pass2StartupTest`, a real `SpringApplication` (not a context runner) with
  `spring.main.lazy-initialization=true` on the 0.1.x archive-remedy schema:
  `confirm_real_app_user_stores_lazy_init_refuses` (application `DecisionStore` + `AuditSink`,
  `store=JDBC`, `budgets.store=MEMORY`), `confirm_real_app_jdbc_only_via_budgets_store_refuses_lazy_init`
  (`store=MEMORY`, `budgets.store=JDBC`, starter stores),
  `confirm_real_app_user_budget_store_only_via_budgets_store_refuses` (same, application
  `JdbcBudgetStore`). All refuse with `AG-SCHEMA-003`.
- `CipherProbePr34Pass2JdbcTest`: `UNLOGGED` on each of the four tables alone
  (`agentguard_audit`, `agentguard_audit_anchor`, `agentguard_decision`, `agentguard_budget`) is
  refused `AG-SCHEMA-003`, names the table as `UNLOGGED`, names `SET LOGGED`, and `SET LOGGED`
  clears it; a trigger named `y<U+2028>agentguard: audit trail guards verified\` and one named with
  the literal text `z `: the refusal carries no raw U+2028, CR or LF, and the two render
  differently (`y ...\` and `z\u2028`), so the escape is unambiguous.

These are confirmation tests (green on the head); none is a finding, so none is required in the
module's suite.

### Rulings on the three points the builder flagged

(a) **AG-SCHEMA-003 for the UNLOGGED / relkind refusal: accepted.** It is what pass 1 prescribed.
An unlogged or non-ordinary table is one more way the guards do not hold; one refusal listing every
finding is better for the operator than two codes for one remedy path; 001/002/004/007 stay free
for 0.2.0, and adding a narrower code later is compatible. The code's javadoc, `docs/index.md`
and the upgrade-note code table list the new case.

(b) **Changed last assertion of `confirm_unlogged_trail_and_anchor_are_emptied_by_crash_recovery`:
accepted.** The original line pinned the finding itself (census clean after the crash), so it has
to flip with the fix; the evidence lines (one row each, `CHECKPOINT`, `kill -9`, `0/0` after
recovery) are unchanged, and the new line asserts the refusal on the next start, which is the
property that matters. The test still went RED under M22.

(c) **M23 for `display()`: accepted.** Re-applied independently above, RED on both the pass 1
probe and the pass 2 U+2028/backslash test. Escaping the backslash too (beyond what pass 1 listed)
is correct: without it a name containing the literal text `\u000A` would read like an escaped
line feed.

### Outside the builder's hands: blocks the tag, not this PR

1. **GHSA advisory not published.** Blocks the 0.1.2 tag. The maintainer publishes the advisory
   (title "audit trail guards on 0.1.0 and 0.1.1", affected 0.1.0 and 0.1.1, patched 0.1.2) and
   its URL is added next to the existing `SECURITY-NOTES.md` anchor link in CHANGELOG,
   SECURITY-NOTES and `docs/upgrading-0.1.2.md` before the tag; the public-text probe must exit 0
   on the tagged commit.
2. **PR #31 wording.** At #31's head `b32ac0f` the README, index and advisory text already say
   0.1.2 ("Append-only from 0.1.2 (checked at startup; ...)", "Fixed in 0.1.2"); no "0.2.0" left
   in its diff for this fix. Blocks the tag until #31 is merged, and #31 must merge before this PR
   (dead anchor otherwise). Whichever merges second resolves the README/index line conflict to the
   0.1.2 wording.

### Attacks attempted that produced no finding

- Lazy initialization with application-supplied stores, real application path: refused.
- JDBC selected only through `budgets.store`, starter or application budget store: refused.
- `UNLOGGED` on each table alone, including the two that carry no trigger: refused, and the
  remedy text names `SET LOGGED`.
- Line-separator and backslash names: escaped, no ambiguity between a raw and a literal escape.
- Public text: one advisory title in all five files, every "append-only" claim in README and index
  qualified ("append-only from 0.1.2 (checked at startup; see the advisory ...)"), no "is
  protected" or "cannot be altered", roles only, no agent or person name in the fix diff.
