# Security review — branch `docs/runtime-role-grants` (PR #24)

## 2026-09-26 — first pass

Scope: the documentation fix for the runtime role's missing sequence grant. Diff against `main`
(914bc14) is two files, no production code: `docs/index.md` ("Database roles") and `CHANGELOG.md`.

Verdict: **MERGE WITH FIXES** — one MEDIUM (C-1).

### Numbers

| What | Result |
|---|---|
| `agent-guard-core` tests (`mvnw -pl agent-guard-core test`) | 161 run, 0 failures, 0 errors, 0 skipped |
| Existing `CipherProbe*` tests, re-run unchanged | all green (JDBC, application, domain) |
| Production code changed by this branch | none |
| Grant-block probe against PostgreSQL 16.14 (pinned digest) | 8 write-path checks pass, 17 refusal checks pass, 1 write-path check fails (C-1) |

### How the fix was verified

Throwaway container `postgres:16-alpine@sha256:57c72fd2…` (the digest the module already pins).
Two roles, as the documentation prescribes: `agentguard_owner` owns the database and ran the
bundled `schema-postgresql.sql` once; `agentguard_runtime` was created with **exactly** the three
statements of the new grant block, extracted programmatically from the fenced `sql` block in
`docs/index.md` so the pasted text, not a paraphrase, is what was applied:

```
GRANT SELECT, INSERT ON agentguard_audit TO agentguard_runtime;
GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO agentguard_runtime;
GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_budget, agentguard_audit_anchor TO agentguard_runtime;
```

Resulting privileges, read back from `information_schema`: audit `INSERT,SELECT`; anchor
`INSERT,SELECT,UPDATE`; budget `INSERT,SELECT,UPDATE`; decision `INSERT,SELECT,UPDATE`; sequence
`agentguard_audit_seq_seq` `USAGE`. Nothing else.

Then, as `agentguard_runtime`, the exact statements the adapters issue (`JdbcAuditSink.append`,
`JdbcDecisionStore.save`/`transition`, `JdbcBudgetStore.incrementAndGet`):

| Write path | Expected | Observed |
|---|---|---|
| `SELECT pg_advisory_xact_lock(18374244850549833)` | allowed | allowed |
| anchor upsert, first append | allowed | allowed |
| `INSERT INTO agentguard_audit … RETURNING seq` | allowed | **allowed** (the fix; this is what failed before) |
| decision upsert | allowed | allowed |
| decision state transition (`UPDATE`) | allowed | allowed |
| budget upsert `… ON CONFLICT … RETURNING used` | allowed | allowed |
| second append, anchor advances by one | allowed | allowed |
| chain verifier read of `agentguard_audit` | allowed | allowed |

The sequence grant is the one the branch adds, and with it the first guarded call's audit insert
succeeds. Before it, the same insert failed with `permission denied for sequence
agentguard_audit_seq_seq`, which is the defect this branch closes. Confirmed fixed.

Tamper and DDL attempts by the same role, all refused:

| Attempt | Refused by |
|---|---|
| `DELETE FROM agentguard_audit` | `permission denied for table` (no grant) |
| `TRUNCATE agentguard_audit` | `permission denied for table` |
| `UPDATE agentguard_audit SET hash = …` | `permission denied for table` |
| `UPDATE agentguard_audit SET prev_hash = …` | `permission denied for table` |
| `DELETE FROM agentguard_audit_anchor` | `permission denied for table` |
| `TRUNCATE agentguard_audit_anchor` | `permission denied for table` |
| anchor rewind (`row_count` 2 → 1) | `agentguard_audit_anchor only advances by one row` |
| anchor `keyed` flip (f → t) | `agentguard_audit_anchor.keyed is immutable once set` |
| `ALTER TABLE agentguard_audit DISABLE TRIGGER …` / `… TRIGGER ALL` | `must be owner of table` |
| `DROP TRIGGER agentguard_audit_append_only` | `must be owner of relation` |
| `DROP TRIGGER agentguard_audit_anchor_monotonic` | `must be owner of relation` |
| `CREATE OR REPLACE FUNCTION agentguard_audit_append_only()` (neuter the trigger) | `permission denied for schema public` |
| `DROP TABLE agentguard_audit` / `ALTER TABLE … DROP COLUMN hash` | `must be owner of table` |
| `ALTER SEQUENCE agentguard_audit_seq_seq RESTART WITH 1` | `must be owner of sequence` |
| `setval('agentguard_audit_seq_seq', 1)` | `permission denied for sequence` |
| `CREATE TABLE …` in `public` | `permission denied for schema public` |

The last two matter for the new grant: `USAGE` is the right sequence privilege. `GRANT ALL` or
`GRANT USAGE, UPDATE` would have let the runtime role `setval` the sequence backwards and reuse
`seq` values under the append-only trigger. The block grants `USAGE` only, and `setval` is refused.
No over-granting found: every privilege in the block is exercised by a statement in the adapters,
and nothing in the block is unused.

### C-1 — MEDIUM — the grant block omits `DELETE` on `agentguard_budget`, and the runtime path needs it

The block was checked against the schema for what is still missing, not only for what the branch
added. One statement in the runtime write path is not covered.

`JdbcBudgetStore.incrementAndGet` purges its own expired counters itself, inline, every
`PURGE_EVERY` (1000) calls:

```java
if (calls.incrementAndGet() % PURGE_EVERY == 0) {
  purgeExpired(now);          // DELETE FROM agentguard_budget WHERE expires_at < ?
}
```

There is no `try`/`catch` around it, so `JdbcSupport.JdbcAccessException` propagates out of budget
enforcement. With the documented grants the 1000th budget-consuming guarded call fails:

```
ERROR: permission denied for table agentguard_budget
  at JdbcBudgetStore.lambda$purgeExpired$1(JdbcBudgetStore.java:66)
```

Repro, SQL level: as `agentguard_runtime`, after the block above,
`DELETE FROM agentguard_budget WHERE expires_at < now() - interval '1 day'` → `permission denied for
table agentguard_budget`. All other statements of the same path succeed.

Repro, code level (probe, `internal/agent-guard/probes/CipherProbeRuntimeRoleGrantsTest.java`,
`probe_budget_purge_is_denied_to_the_documented_runtime_role`): Testcontainers PostgreSQL, owner
runs the schema, runtime role gets exactly the three documented statements, then 1000
`incrementAndGet` calls on one key. Red on the current text with the stack trace above.

Same defect class as the sequence grant this branch fixes, in the same block: a hardened
installation that pastes the documented grants breaks on a documented code path. It is not the same
severity as an audit-integrity break — the failure is fail-closed (the exception is raised before
the counter is incremented, so the tool does not run and no budget is silently consumed) — but it is
a deterministic, recurring failure of the configuration the documentation tells operators to use,
and it also surfaces a raw PostgreSQL permission message to whatever handles the guard's failure.

Least privilege is not weakened by the fix: the role already holds `UPDATE` on
`agentguard_budget`, so it can already set `used` to zero. `DELETE` on a counter table grants no new
capability, and the audit tables keep `INSERT, SELECT` only.

Fix (documentation only, no mechanism, no code change — Isis):
1. `docs/index.md`, "Database roles": add `DELETE` for `agentguard_budget` to the block. Keep the
   audit and anchor grants untouched. Suggested shape:
   ```sql
   GRANT SELECT, INSERT ON agentguard_audit TO agentguard_runtime;
   GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO agentguard_runtime;
   GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_audit_anchor TO agentguard_runtime;
   GRANT SELECT, INSERT, UPDATE, DELETE ON agentguard_budget TO agentguard_runtime;
   ```
2. Same section: one sentence saying why the counter table is the exception — the budget store
   deletes its own expired counters every 1000 calls, `DELETE` there adds nothing a role with
   `UPDATE` on the same table could not already do, and the audit tables still get no `DELETE`.
3. `CHANGELOG.md`, `[Unreleased]` → `Fixed`: extend the existing entry to name the budget `DELETE`
   alongside the sequence `USAGE`.
4. Re-verification: `probe_budget_purge_is_denied_to_the_documented_runtime_role` must go green
   with the grant block re-extracted from the updated documentation.

### Public text

The two lines this branch adds to `docs/index.md` and the `CHANGELOG.md` entry carry no agent or
person name; the finding is attributed as "a security review". Checked for absolute home paths and
internal identifiers: none. (`tools/cipher-probe-*.sh` appears in older CHANGELOG entries as a
committed file path; unchanged by this branch and out of its scope.)

### Noted, out of scope, not a finding against this branch

`AgentGuardAutoConfiguration.jdbc(…)` only calls `runtimeRoleOwnsAuditTable` inside the
`initialize-schema=true` branch. An operator who follows this very section — separate owner role,
then `initialize-schema=false` — never reaches the check, so an installation that runs the
application as the table owner by mistake gets no startup warning at all, which is exactly the case
the warning exists for. That is a code change in the starter, a different mechanism from this
docs PR; raised for the module's backlog rather than attached to PR #24.
