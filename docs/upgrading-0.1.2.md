# Upgrading to 0.1.2

0.1.2 fixes the defect described in the security advisory "audit trail guards on 0.1.0 and 0.1.1" (affects 0.1.0 and 0.1.1; see
[the advisory](../SECURITY-NOTES.md#advisory-audit-trail-guards-on-010-and-011)). It changes two things an operator sees:

1. The bundled `schema-postgresql.sql` creates each of its five guard triggers whenever that trigger is missing **on
   its own table** (0.1.x looked the name up across the whole database), and then sets all five to `ENABLE ALWAYS`.
2. At startup, whenever a JDBC store is in use, the application checks the guards and refuses to start with
   `AG-SCHEMA-003` when they do not hold. There is no property that turns this into a warning.

**Every 0.1.x installation that uses a JDBC store has one step to do before the 0.1.2 application starts**: apply the
0.1.2 `schema-postgresql.sql` once as the role that owns the tables (step 3). 0.1.x left the guards at plain
`ENABLE`, and 0.1.2 refuses anything but `ENABLE ALWAYS`. An installation whose application role owns the tables and
keeps `agentguard.jdbc.initialize-schema=true` gets this done by the first 0.1.2 startup. If your installation is affected (step 1), do
step 2 **before** that first startup, since it repairs the guards without asking.

The check runs **at startup only**. A role that owns the tables can still disable a trigger after startup, and
`ENABLE ALWAYS` does not stop the table owner. Run the application as a role that does not own the tables (docs,
"Database roles").

## Steps, in order

Run steps 1 to 4 as the **table owner**, connected to the database the application uses, with `search_path` set to
the schema the application uses. Every name below is qualified on purpose: an unqualified `count(*)` or
`current_schema()` resolves along `search_path` and can be answered by a same-named function.

**1. Detect.**

```sql
SELECT n.nspname, t.tgname, t.tgrelid::regclass AS on_relation, t.tgenabled
  FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE NOT t.tgisinternal
   AND t.tgname LIKE 'agentguard%'
 ORDER BY 1, 2;
```

Read `nspname`, never the `on_relation` rendering alone. You are **affected** if fewer than five rows have `nspname`
equal to the schema the application uses, or if any of the five names appears under another schema (for example
`archive`). Five rows under your schema at `O` and nothing else is an unaffected 0.1.x installation: go to step 3.

Then, with your schema written out:

```sql
SELECT pg_catalog.count(*) AS rows_in_trail FROM <your schema>.agentguard_audit;
SELECT head_hash, row_count, keyed FROM <your schema>.agentguard_audit_anchor WHERE id = 1;
```

**2. If affected, record before you repair.** Run the chain verifier and keep its output. Record `rows_in_trail`
against the anchor's `row_count`, with the dates of the window in which the trail ran unguarded. **Keep any
disagreement; never rewrite the anchor to match the trail.** A trail shorter than `row_count` is the tail-deletion
signature the anchor exists to leave; it is evidence. Where the trail evidences a control to an auditor, disclose the
window as a period in which the append-only property was not enforced. Rows written in that window are as
trustworthy as the application process was then; no repair changes that.

**3. Apply the 0.1.2 `schema-postgresql.sql` once, as the owner.** It is in the `agent-guard-core` jar at
`com/housedevinci/agentguard/schema-postgresql.sql`, or call `JdbcSupport.initializeSchema(dataSource)` with the owner's
`DataSource`. It creates any guard 0.1.x skipped and sets all five to `ENABLE ALWAYS`. It changes no row of the trail
or the anchor and no guard-function body, and it leaves archived copies alone.

**4. Check again.** Step 1's query must return five rows under your schema, every `tgenabled` = `A`.

**5. Deploy 0.1.2.** With a non-owner application role, keep `agentguard.jdbc.initialize-schema=false`: with `true`,
0.1.2 refuses that role with `AG-SCHEMA-006` (0.1.x failed the same way, with the driver's raw permission error).

**6. Start.** A refusal names the code, the schema, the database and the role, lists every finding, and prints the
remedy:

| Code | Means | Do |
|---|---|---|
| `AG-SCHEMA-003` | a guard is missing, extra, disabled, at `O`/`R`/`D`, has a `WHEN` clause or a column list, points at another function or body; or a rule, row level security, a policy or an inheritance child sits on one of the four tables; or one of the four is `UNLOGGED` or not an ordinary table | step 3 for the triggers; drop the extra objects it names; `ALTER TABLE ... SET LOGGED` on a table named `UNLOGGED`; restart |
| `AG-SCHEMA-005` | the check could not complete (a catalogue the role cannot read, no current schema, a damaged jar) | fix what it names; it is never treated as a pass |
| `AG-SCHEMA-006` | `initialize-schema=true` and the script failed as the application's role | set `initialize-schema=false`, apply the script as the owner |

**7. Run the chain verifier again** and keep both outputs.

## The installation that followed the archive remedy

Under 0.1.x, `AG-AUDIT-002` (a trail with rows and no anchor row) told the operator to archive `agentguard_audit` and
`agentguard_audit_anchor` and re-run the schema step. `ALTER TABLE ... SET SCHEMA archive` carries the triggers along,
so the re-run found all five names on the archived copies and created none on the fresh pair; the application then
wrote a trail with no guard. The same happens when any relation in the database carries a trigger of one of the five
names.

0.1.2 refuses this state with `AG-SCHEMA-003`, and the message says so. The repair is steps 2 to 4 above. The archived
copies can stay: a trigger name is unique per relation, so the five on the archived tables and the five on the live
ones are different triggers and neither set masks the other. After step 3, step 1's query shows ten rows: five under
your schema at `A`, five under `archive` at `O`. Renaming the archived triggers is tidier, not required.

The script does not touch the anchor or the trail rows, so it does not "fix" a `row_count` that disagrees with the
trail. That disagreement is the record that rows were lost; keep it (step 2).

## Rolling back

The 0.1.1 script contains no statement that changes a trigger's enabled state, so a schema repaired by 0.1.2 keeps
its five guards at `A` if 0.1.1 is started on it again. 0.1.1 checks nothing at startup, though, so a guard removed
later goes unnoticed again. Rolling back is advised against.
