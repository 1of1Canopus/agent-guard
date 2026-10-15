# SECURITY-NOTES.md — Agent Guard (module B), free core

Skeleton for the adversarial security review required before every public release. Each threat from the module spec, what the code
does about it, and what still needs a reviewer's eye.

## Threat 1 — Prompt-injected tool calls
- **Mitigation:** policy is evaluated on the *actual* call (`ToolGuard.execute` receives the tool name and the exact
  arguments the framework is about to execute), never on model intent. Nothing in the pipeline reads the prompt.
- **Test:** `ToolGuardTest`, `GuardedToolCallbackTest`, `McpToolGuardTest`.
- **Open:** the tool *name* is taken from the framework's `ToolDefinition` / `McpSchema.Tool`, not from the model
  message, so a model cannot rename a tool. Reviewer: confirm the `DefaultToolCallingManager` resolves callbacks by
  name from the configured set only (it does in 2.0.1).

## Threat 2 — Argument tampering between approval and execution
- **Mitigation:** `PendingDecision.argsHash = SHA-256(argumentsJson)`; `DecisionResumer` recomputes the hash of the
  stored arguments before running (`ArgumentsTamperedException`, `AG-APPROVAL-004`); a re-call by the agent only
  resumes when the new arguments hash to the approved hash, otherwise a new decision is parked. The approver
  attests the hash they reviewed: `POST /decisions/{id}/approve?argsHash=` is required, a mismatch is a 409
  (`AG-APPROVAL-010`) and nothing runs; `GET /decisions/{id}/arguments` returns the **complete** redacted
  arguments (never truncated) so no key is hidden from the reviewer (M5).
- **Residual:** the raw arguments are stored in `agentguard_decision.arguments_json` (needed to execute later). Protect
  the table like any other sensitive table; there is no encryption at rest in core (pro candidate).
- **Test:** `ToolGuardTest.tampered_arguments_between_approval_and_execution_are_refused`.

## Threat 3 — Replay of approvals, wrong identity at resume
- **Mitigation:** `DecisionStore.markExecutedOnce` is a single conditional `UPDATE ... WHERE executed = false`
  (processed-event-ledger pattern); the state machine forbids leaving a terminal state; a second approve returns the
  stored result and runs nothing.
- **Identity and context at resume (H1):** the executor closure (the parking caller's `ToolContext` / MCP
  exchange) is registered **per decision id** and released after the run; the call executes inside a security
  context rebuilt from the stored principal (`RunAsAuthentication`, via the `ResumeContextProvider` SPI), never as
  the approver, and the approver's context is restored afterwards. Closures live in memory: a decision parked
  before a restart cannot be resumed (`AG-APPROVAL-007`). The approved call runs on the approver's request thread.
- **Test:** `JdbcAdaptersIntegrationTest.mark_executed_once_wins_exactly_once_under_concurrency` (50 threads),
  `GuardedToolCallbackTest`, `SampleEndToEndTest`.

## Threat 4 — Log injection
- **Mitigation:** `ArgumentRedactor` parses the JSON (dependency-free parser in the domain) and masks the whole
  value of a sensitive key whatever its shape; keys are compared after unescaping; bearer-like tokens are masked in
  any string; `\p{Cc}\p{Cf}` and U+0085/2028/2029 are stripped; unparseable input is masked whole; the preview is
  capped at 512 chars, the approver's view is not. Only the preview reaches logs, webhooks and the endpoints; the raw
  arguments never do. Exceptions reach the model as `class: message` (300 chars), never a stack trace.
- **Test:** `ArgumentRedactorTest`, `NotifiersTest`.
- Tool exception messages stay server-side by default (`agentguard.errors.include-tool-message=false`).

## Threat 5 — Privilege escalation via tool chaining, budget evasion
- **Mitigation:** every call is evaluated on its own with the caller's principal; budgets have a `CONVERSATION`
  scope (`kind: STEPS`) so a chain cannot loop forever inside one conversation.
- **Subject is server-side (M3):** on MCP the conversation is the server's session id
  (`McpSyncServerExchange.sessionId()`); client `_meta` is ignored. On Spring AI it is the `ToolContext` key set by
  server code. When a configured scope has no subject the call is **denied** (`AG-BUDGET-002`) under
  `agentguard.strict=true` (`agentguard.budgets.missing-subject` = `DENY` | `FALLBACK_TO_PRINCIPAL` | `SKIP`); a
  TENANT limit without a `TenantResolver` bean warns at startup.
- **Parking is bounded (M4):** a parked call consumes the call budget (its later execution is not charged
  again), pending decisions are capped per principal (`agentguard.approval.max-pending-per-principal`, default 20,
  `AG-APPROVAL-008`), arguments are capped (`max-argument-bytes`, default 64 KiB, `AG-APPROVAL-009`), and the
  dedup key includes the tenant so `admin@tenant-2` never receives `admin@tenant-1`'s stored result.
- **The size cap is first on every path, including the two that need no policy at all (V1):**
  `ToolGuard.guarded` applies `rejectIfTooLarge` before `policies.resolve`, so an unregistered tool or a rule with
  no matching role — both reachable by any caller — are refused as oversized before anything canonicalises
  (parses) the arguments. Previously only `gate`/`dispatch` (the policy-matched paths) capped first; the two
  denial paths above them canonicalised the full payload for their audit row regardless of size.
- **Coverage is checked (H2):** Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline
  `.tools(obj)` / `ToolCallbacks.from` / resolver-by-name included); MCP single and list specification beans are
  wrapped; async (WebFlux) specifications fail startup; `agentguard.strict=true` fails startup when a scanned
  `@ToolPolicy` is not reachable through a guarded path, and the startup log lists the guarded tools.
- **Tenant scoping fails closed (C9):** `agentguard.endpoints.require-tenant` defaults `true` whenever
  `tenant-scoped` is on: an approver whose `TenantResolver` yields no tenant (missing claim, service account,
  misconfigured resolver) is refused (403, `AG-HTTP-403`) instead of silently seeing and deciding every tenant's
  decisions and audit rows. A genuinely single-tenant deployment (no `TenantResolver`, as in the sample) should set
  `agentguard.endpoints.tenant-scoped=false` explicitly; set `require-tenant=false` only for a deliberate
  cross-tenant approver role. **The opt-out is no longer silent (V4):** `AgentGuardStartupCheck` warns at
  startup when `endpoints.enabled` and either `tenant-scoped=false` or `require-tenant=false`, naming the property
  and the consequence, alongside its existing warnings for an empty `approval-required-for`, an empty
  `sensitive-keys`, `store=MEMORY`, a missing notifier, a missing `TenantResolver` and a runtime role that owns the
  audit table. The tenant filter is also pushed into the store query
  (`DecisionStore.findByState(state, tenantId, limit)`, `AuditReader.latest(tenantId, limit)`, finding C10) instead of
  applied after the page's `limit`, so a busy neighbour tenant cannot hide a tenant's own pending work.

## Threat 6 — Audit tampering
- **Mitigation:** hash chain (`hash = SHA-256(canonical(row) || prevHash)`) with a **length-prefixed** canonical form
  (`ag1|<len>:<value>|…`, nulls as `-`), so no rewrite can move a boundary between fields (M2); the approver
  is part of the material (`actor_id`, finding M1); timestamps are truncated to milliseconds in `AuditEvent` so every
  store round-trips them; appends are serialised by a PostgreSQL transaction-scoped advisory lock; triggers refuse
  UPDATE, DELETE **and TRUNCATE**; a separate **anchor row** (`agentguard_audit_anchor`: head hash, row count and
  `keyed`) is written in the same transaction, and `AuditChainVerifier` reports `EMPTY` / `INTACT` / `INTACT_UNKEYED`
  / `BROKEN` / `ANCHOR_MISMATCH` / `NO_ANCHOR` — tail deletion, truncation, or a downgraded keyed chain, by a role that can
  disable triggers, is detected; a missing anchor is reported, not silently guessed past.
- **Residual (R4):** a role that owns the tables can disable the guard triggers and rewrite
  chain, anchor **and** `keyed` consistently — run the application with a least-privilege role (INSERT + SELECT on
  `agentguard_audit`, INSERT/SELECT/UPDATE on the anchor, no DDL, not the table owner) and keep
  `agentguard.jdbc.initialize-schema` for a migration step run by the owner role; log or export the head hash
  periodically. The anchor's `agentguard_audit_anchor_no_delete`/`_no_truncate` triggers (F3(a)) mean that
  role cannot lose the anchor row even by accident.
- **Startup guard check (0.1.2, security advisory "audit trail guards on 0.1.0 and 0.1.1"; see [the advisory](#advisory-audit-trail-guards-on-010-and-011), also [published on GitHub](https://github.com/1of1Canopus/agent-guard/security/advisories/GHSA-xc43-5ch5-2pfq)).** 0.1.0 and 0.1.1 created each guard
  trigger only when no trigger of that name existed anywhere in the database, so an archived copy of the trail (the
  `AG-AUDIT-002` remedy) or any same-named trigger on another relation left the live trail with no guard, silently.
  From 0.1.2 the script scopes each check to its relation, arms all five guards `ENABLE ALWAYS` (they then also fire
  for a replication apply worker, a replica-mode session and `pg_restore --disable-triggers`), and the starter refuses
  to start (`AG-SCHEMA-003`) unless the guard set, its functions and bodies are exactly the bundled ones and no rule,
  row level security, policy or inheritance edge sits on the four tables, and each of the four is an ordinary, logged
  table: an `UNLOGGED` trail and anchor are both emptied by crash recovery with no trigger firing, so the anchor
  cannot tell. The check runs on every boot whose properties name a JDBC store, and on every boot whose context holds
  a `JdbcAuditSink`, `JdbcDecisionStore` or `JdbcBudgetStore` bean, whatever the store properties say. It checks one `DataSource`: the one named by
  `agentguard.schema.gate.datasource`, else the primary one. Every audit sink, decision store and budget store bean
  (the starter's or the application's, wrapped by a post-processor or created before it) must use that same
  `DataSource` object, or startup is refused with `AG-SCHEMA-007`, naming both beans. The comparison is by identity,
  so a proxy or a pool around the checked `DataSource` is refused too. Outside the check: a store built inside another
  bean and never exposed as a bean (it must call `JdbcSupport.verifyGuards` itself, as code without Spring must), and
  a store created before the check is registered that a post-processor registered even earlier also wraps.
  Each application context is checked by the auto-configuration in it: a child context that runs the auto-configuration checks its own store beans, and one without it is outside coverage, like code without the starter, and must call `JdbcSupport.verifyGuards`.
  Names read from the catalogue are escaped in the refusal so none can forge a log line. The check's own catalogue reads are
  `pg_catalog`-qualified and run with `search_path` pinned to `pg_catalog`, so a role cannot answer them with
  same-named functions of its own.
- The owner warning at `initialize-schema=true` covers ownership and role membership: a runtime role that is a member
  of the role owning `agentguard_audit` holds every owner privilege and is warned too (read scoped to the current
  schema, `pg_catalog`-qualified, `search_path` pinned).
- **Residual (0.1.2):** the check runs at startup only. An application role that owns the tables can still disable a
  trigger after startup; `ENABLE ALWAYS` does not defend against the table owner. Not covered by the check, by design:
  event triggers, `session_replication_role` changes and executor hooks, all of which need a superuser. Rows written
  while a trail was unguarded are not made trustworthy by any repair. 0.2.0 is planned to add the startup checks on
  the role itself (no ownership, no excess privilege) and to stop running DDL with the application's credentials by default.
- **Keyed-from-birth (design change, superseding the earlier per-row-version design and
  findings C6/V2/F1-F4):** a trail is keyed from row 1 or unkeyed forever — no mixing, no later switch.
  `agentguard.audit.hmac-secret` is **required by default**; missing, startup fails naming the property and the
  remedy (`openssl rand -base64 32`). The explicit local-dev opt-out, `agentguard.audit.unkeyed=true`, starts
  unkeyed but warns at every startup, not only the first. Which mode a trail is in is recorded once, at the first
  append, on `agentguard_audit_anchor.keyed` (a plain boolean that cannot change after that: the anchor's
  monotonic trigger refuses the update — the same protection `head_hash`/`row_count` already had). Every later append, from this
  instance or any other, must agree with it or is refused with `AG-AUDIT-001`, naming the property and the remedy
  (start a new trail — see below). This is what makes a **rolling restart that changes
  `agentguard.audit.hmac-secret` unsafe by itself**: stop every instance before starting the first one with the
  new setting, or the mismatched instance is refused rather than silently corrupting the trail (the earlier
  per-row-version design could not detect this at all).
- **Key rotation, from row 1 (amendment, after further design review):** the key id
  (`agentguard.audit.hmac-key-id`, default `k1`) is baked into every row's hashed material — the canonical form is
  `version|key_id|timestamp|…`, so relabelling a row's `key_id` without the matching secret still fails to
  recompute the hash. This makes rotation data, not a chain-format break: `agentguard_audit.key_id` records which
  key signed each row (`'none'`/`AuditChain.UNKEYED_KEY_ID` for unkeyed rows); `AuditChainVerifier` holds a
  keyring (the current key plus every id in `agentguard.audit.hmac-keys.<id>`) and picks the right secret per row
  by its `key_id`. A row claiming an id the keyring does not hold is `BROKEN`, not skipped or treated as unkeyed.
  This is not a second mode switch on top of keyed-from-birth: `keyed` still only says whether the trail is keyed
  at all (set once, at the first append); `key_id` says which already-trusted key signed a given row within that mode, and a
  table-owning attacker can only relabel to an id whose secret they also hold.
- **Anchor-missing refused, never guessed (amendment, superseding the F1/F2 sequence-position mechanism and the
  prior schema-seed-from-an-existing-trail behaviour):** `JdbcAuditSink` no longer re-derives a lost anchor's
  state from the trail head — that was exactly the kind of guess the anchor exists to make unnecessary, the same
  class of gap the retired `keyed_from_seq` findings were about. A trail with rows but no anchor row is refused
  with `AG-AUDIT-002`, on both the next append and at the next startup; the schema step's seed only ever creates
  the anchor row for a genuinely empty trail (`INSERT … WHERE NOT EXISTS (SELECT 1 FROM agentguard_audit)`), never
  by deriving `keyed`/`head_hash`/`row_count` from existing rows. Recovery is an owner-run procedure — see
  "Starting a new trail" in docs/index.md — not something an application instance does for itself.
- **`NO_ANCHOR` unconditionally, keyed or unkeyed (amendment, widening finding F3(a)):** the first version of this
  fix only refused to render `INTACT` when a key was *given* to the verifier; an unkeyed verification against an
  unanchored reader still silently fell back to the old in-trail rule. `AuditChainVerifier.verify` now reports the
  distinct `Status.NO_ANCHOR` whenever the reader is not an `AuditAnchor`, or has no anchor row, and the trail is
  not empty — regardless of whether a key was configured. The `Report` also now carries the trail's mode
  (`anchored`, `keyed`, `keyIds`), and an unkeyed trail's clean result renders as the distinct `Status.INTACT_UNKEYED`,
  never plain `INTACT` — an operator glancing at a status word can no longer mistake "nothing is signing this
  trail" for "the signature checked out". A table-owning attacker's row-level rewrite (even a whole-trail
  downgrade to `ag1`/GENESIS from a genuinely keyed trail — the original V2 repro) cannot also flip `keyed`,
  which lives outside the rows they rewrite.
  **Residual, unchanged from R4:** the table owner can disable the anchor's trigger and rewrite `keyed` along with
  everything else; run the application with a role that does not own the tables (see "Database roles" below).
- **`InMemoryAuditSink` has no external anchor (finding H3, doc-only):** its `anchor()` is derived from the very
  events list it anchors (`headHash`/`rowCount` from the last event, `keyed` from the instance's own `AuditChain`),
  not a separate record like `JdbcAuditSink`'s anchor row. It therefore cannot detect its own tail being trimmed —
  a trimmed in-memory trail still verifies `INTACT`/`INTACT_UNKEYED` with `anchored() == true`. Tests and
  development only; not a substitute for the JDBC store in any deployment where the audit trail matters.
- **Test:** `AuditChainVerifierTest.a_key_given_with_no_anchor_reports_no_anchor_never_intact`,
  `AuditChainVerifierTest.an_unkeyed_trail_never_renders_plain_intact`,
  `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` (partial downgrade),
  `CipherProbeReverifyTest.probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` (the original
  whole-trail repro), `CipherProbeAnchorKeyingJdbcTest` (F1–F4 replacements: mismatched instances refused at
  startup and on append, anchor DELETE/TRUNCATE refused, `NO_ANCHOR`, an orphaned keyed trail refusing to append,
  mixed-key rows verifying `INTACT` with both keys in the keyring, an unknown key id reporting `BROKEN`, a
  stale-key second instance during a rotation), `CipherProbeReverifyJdbcTest
  .a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor`,
  `AgentGuardAutoConfigurationTest.missing_hmac_secret_fails_startup_naming_the_property_and_the_remedy`,
  `AgentGuardAutoConfigurationTest.unkeyed_opt_out_starts_but_warns_every_time`.
- **Two `args_hash` domains (V3):** `ArgumentCanonicalizer.hash` (used for every decision and normal audit
  row) hashes `"agcanon1:" + canonical(argumentsJson)`; `AuditRecorder.recordOversized` (the size-cap denial)
  hashes `"agraw1:" + argumentsJson`. Before this, both landed in the same SHA-256 space with no domain separation,
  and canonicalisation is not size-preserving (an unpaired surrogate is 1 raw UTF-8 byte, 6 after the `\u` escape),
  so a payload under the cap could have a canonical form over it — replayed raw, it hashed identically to its own
  denial. `ToolGuard.rejectIfTooLarge` also checks the canonicalised length once the raw check has already bounded
  the parse cost, so that payload is refused as oversized on the canonical check too, not silently allowed through.

## Advisory: unkeyed audit trail with the default store on 0.1.0 to 0.1.2
Affects 0.1.0, 0.1.1 and 0.1.2 with `agentguard.store=JDBC` (the default) and the starter's own audit sink. Not
affected: `agentguard.store=MEMORY`, and an application that declares its own `JdbcAuditSink` bean with the
`AuditChain` bean. Fixed in the next release (see the CHANGELOG).

What went wrong. The starter built the default `JdbcAuditSink` with its one-argument constructor, which is unkeyed. A
set `agentguard.audit.hmac-secret` was used by the verifier but never by the sink. Every row carries `key_id=none`,
the anchor records the trail as unkeyed, and the verifier reports `INTACT_UNKEYED`. No startup message said so.

What it means. The trail is still hash-chained and still behind the 0.1.2 guard triggers. But its integrity rests
only on database privileges, not on a secret: a role that can write the tables and switch off the triggers can
rewrite rows and recompute every hash, and the verifier will not see it. That is the protection of an unkeyed trail,
not of a keyed one.

How to tell. Run the chain verifier: `INTACT_UNKEYED` means unkeyed. Or, as any role that can read the tables:

```sql
SELECT keyed FROM agentguard_audit_anchor WHERE id = 1;            -- false: the trail is unkeyed
SELECT key_id, pg_catalog.count(*) FROM agentguard_audit GROUP BY 1; -- 'none' on every row: unkeyed
```

What cannot be done. Existing rows cannot be keyed after the fact. A trail is keyed from row 1 or unkeyed forever.
A key applied today to old rows would only prove what the rows say today, not what they said when written.

After the upgrade, with the secret still set, the starter builds a keyed sink. The sink sees the unkeyed anchor and
refuses to start with `AG-AUDIT-001`, before any traffic. Choose one:

1. Keep the old trail and start a new keyed one. Run the verifier on the old trail and keep its output. Archive
   `agentguard_audit` and `agentguard_audit_anchor`, then let the schema step create an empty pair (docs/index.md,
   "Starting a new trail", including its trigger check). The new trail is keyed from row 1. The archived trail stays
   unkeyed and verifies as `INTACT_UNKEYED`.
2. Keep running unkeyed, on purpose. Remove `agentguard.audit.hmac-secret` and set `agentguard.audit.unkeyed=true`.
   The application WARNs at every startup. Only for a deployment that accepts an unkeyed trail.

If the trail is used to evidence a control to an auditor, disclose the period in which it was unkeyed although a
secret was configured.

The fix also adds a startup check, `AG-AUDIT-003`. It refuses an audit sink bean that is unkeyed while the secret is
set, or unkeyed without `agentguard.audit.unkeyed=true`. It sees the starter's sinks and an application's own
`JdbcAuditSink` or `InMemoryAuditSink` bean, also behind a Spring AOP proxy. It cannot see into a sink class it does
not know: such a sink starts, with a WARN at every startup that names the bean. It cannot see a sink built inside
another bean and never exposed as a bean.

## Advisory: audit trail guards on 0.1.0 and 0.1.1
In 0.1.0 and 0.1.1 the bundled `schema-postgresql.sql` creates each of its five trigger guards inside a condition that
names no relation. A trigger with the same name on any other relation in the database suppresses the real guard, and the
schema step still reports success. On an affected installation the application's runtime role can `UPDATE` and `DELETE`
audit rows, and the anchor has no monotonic guard and no no-delete guard. Append-only is therefore **not guaranteed on
0.1.x**. Fixed in 0.1.2. The most likely way in is the library's own `AG-AUDIT-002` remedy: archiving
the two tables and re-running the schema step moves the guards to the archived copies and leaves the fresh trail with
none.
Repairing the schema protects rows from the moment of repair; rows written while the guards were missing are not
protected afterwards.

What still holds on a keyed trail: a party without the HMAC key cannot edit, insert or reorder a row without the
verifier reporting `BROKEN`.

To check an installation, run as the table owner:

```sql
SELECT n.nspname, t.tgname, t.tgrelid::regclass AS on_relation, t.tgenabled
  FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE NOT t.tgisinternal
   AND t.tgname LIKE 'agentguard%'
 ORDER BY 1, 2;
```

Expect five rows whose `nspname` is the schema your application uses. Fewer than five rows with `nspname` equal to your
schema means you are affected. The same names under another schema (for example an archived copy) are expected after
the archive remedy and are not a problem by themselves.

To repair without upgrading, do it by hand. To upgrade, see [upgrading to 0.1.2](docs/upgrading-0.1.2.md). As the owner of the two tables, run the following in one session, with
`SET search_path TO <your schema>;` first and kept for the whole block (the `EXECUTE FUNCTION` names resolve on it and
are then frozen; without it a trigger can be armed onto a same-named function in another schema with no error):

```sql
CREATE TRIGGER agentguard_audit_append_only
  BEFORE UPDATE OR DELETE ON agentguard_audit
  FOR EACH ROW EXECUTE FUNCTION agentguard_audit_append_only();

CREATE TRIGGER agentguard_audit_no_truncate
  BEFORE TRUNCATE ON agentguard_audit
  FOR EACH STATEMENT EXECUTE FUNCTION agentguard_audit_append_only();

CREATE TRIGGER agentguard_audit_anchor_monotonic
  BEFORE UPDATE ON agentguard_audit_anchor
  FOR EACH ROW EXECUTE FUNCTION agentguard_audit_anchor_monotonic();

CREATE TRIGGER agentguard_audit_anchor_no_delete
  BEFORE DELETE ON agentguard_audit_anchor
  FOR EACH ROW EXECUTE FUNCTION agentguard_audit_anchor_append_only();

CREATE TRIGGER agentguard_audit_anchor_no_truncate
  BEFORE TRUNCATE ON agentguard_audit_anchor
  FOR EACH STATEMENT EXECUTE FUNCTION agentguard_audit_anchor_append_only();

ALTER TABLE agentguard_audit        ENABLE ALWAYS TRIGGER agentguard_audit_append_only;
ALTER TABLE agentguard_audit        ENABLE ALWAYS TRIGGER agentguard_audit_no_truncate;
ALTER TABLE agentguard_audit_anchor ENABLE ALWAYS TRIGGER agentguard_audit_anchor_monotonic;
ALTER TABLE agentguard_audit_anchor ENABLE ALWAYS TRIGGER agentguard_audit_anchor_no_delete;
ALTER TABLE agentguard_audit_anchor ENABLE ALWAYS TRIGGER agentguard_audit_anchor_no_truncate;
```

Then re-run the check above: five rows for your schema, `tgenabled` = `A` on every one. `ENABLE ALWAYS` makes the guards
fire for a replication apply worker, a session in replica mode and `pg_restore --disable-triggers`. It does not stop
the table owner, who can still disable a trigger; if the application's own role owns these tables, the guards are
advisory against the application.

Do not rewrite the anchor. Before and after the repair, run the chain verifier and keep both outputs, and record
`SELECT pg_catalog.count(*) FROM <your schema>.agentguard_audit;` against the anchor's `row_count`, with the dates of
the window. A trail shorter than `row_count` is the tail-deletion signature the anchor exists to leave behind. Neither
this repair nor 0.1.2 changes the anchor or the trail rows, by design; rewriting the anchor to agree with a shortened
trail destroys the only record that rows were lost. If the trail is used to evidence a control to an auditor, disclose
the window as a period in which append-only was not enforced.

## Operational hazards
- **Redis + virtual threads on JDK 21–23 (H3).** The pin is not in Jedis itself but in commons-pool2's growth
  path: `GenericObjectPool.create()` holds a monitor (`makeObjectCountLock`) around the Jedis handshake I/O. A virtual
  thread blocked on that `monitorenter` pins its carrier; once every carrier is pinned the threads doing the handshake
  never get scheduled again and the JVM hangs. Reproduced with 64 virtual threads on a cold pool of 4: zero
  completions after 10 s; the same on platform threads completes in 62 ms (`CipherProbeJedisPinningTest`, profile
  `pinning-probe`). It recurs every time the pool has to grow (idle eviction after 60 s, Redis restarts). **Fix
  shipped:** the pool is pre-filled at startup from the platform startup thread (`min-idle = max-total`,
  `prepare-pool=true`, `agentguard.redis.pool.*`) so it never grows under load; size `max-total` at or above peak
  concurrent tool calls. Proven: 200 virtual threads on 8 pre-filled connections finish in 76 ms. JDK 24 (JEP 491)
  removes the pinning. Residual (R6): after a Redis restart or failover the destroyed connections are
  re-created on the next borrow, so the growth path (and the pin) is possible for that window; running
  `JedisBudgetStore` calls on a small platform-thread executor is the belt-and-braces option.
- **The platform-thread pool fails closed, on purpose (C7/C8):** the pool backing `JedisBudgetStore` is a
  bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to `agentguard.redis.pool.max-total`, `AbortPolicy`), not
  an unbounded queue: a call that misses `maxWait` is cancelled and removed from the queue instead of being
  abandoned there, and a saturated pool refuses new calls immediately with `AG-GUARD-001` rather than queueing
  behind a growing backlog. This means a burst well past `max-total` concurrent callers gets guard-unavailable
  errors (the guard fails closed, denying the tool call) instead of eventually succeeding once Redis catches up —
  size `max-total` at or above the real peak concurrency, the same sizing guidance as above. `JedisBudgetStore`
  implements `AutoCloseable` and its `close()` shuts the pool down; the auto-configured bean is picked up by
  Spring's default inferred destroy method, so a context that rebuilds it (devtools restart, `@DirtiesContext`) does
  not leak `agentguard-redis` threads.
- **Platform-thread pool sizing is decoupled from the Redis connection pool (V5):**
  `agentguard.redis.pool.platform-thread-count` and `.platform-thread-queue-size` (both default `max-total` when
  unset) size the worker pool and its bounded queue independently of `max-total` (the Jedis connection pool). A
  small, deliberately contended connection pool (to exercise H3/R6-style contention) and a large burst of
  concurrent virtual-thread callers are two different numbers: workers just block on the connection pool, the way
  a virtual thread must never be allowed to.
- **Hand-built managers (R3):** a `DefaultToolCallingManager` built in code and handed to a `ChatModel`
  builder never passes through the context, so it is not guarded and strict mode cannot see it. Use the
  `ToolCallingManager` bean or wrap yours with `AgentGuard.guard(manager)`.
- **Guard failures are structured (M6):** any failure of the guard's own infrastructure (store, audit sink,
  notifier, JSON, security context) becomes `{"error":"GUARD_UNAVAILABLE","code":"AG-GUARD-001","correlationId":…}`
  on both paths; the cause is logged server-side at ERROR with that correlation id, and the tool is not run. Tool
  authors' own exception messages still reach the model (300 chars): do not put secrets in exception messages.
- **Endpoints refuse anonymous approvers (M7):** 401 unless `agentguard.endpoints.allow-anonymous=true`
  (trial only). Still put Spring Security in front of `/agentguard/**` (the sample: `hasRole("APPROVER")`).

- **Reproducible-build hazard: a plugin bound to `package` can register `target/` as a live
  project resource for every other plugin bound to the same phase (2026-09-10 post-release
  finding).** `license-maven-plugin`'s `add-third-party` execution defaults
  `addOutputDirectoryAsResourceDir` to `true` and adds `target/**/*.txt` to
  `project.getResources()` at runtime; `maven-source-plugin`'s `jar-no-fork` execution, bound
  to the same `package` phase, reads that list at the moment it runs and archives whatever
  matches into the sources jar - `THIRD-PARTY-NOTICES.txt` deterministically, but also
  `target/surefire-reports/*.txt` whenever tests ran first, which is never byte-identical run
  to run. `scripts/verify-reproducible.sh` runs with `-DskipTests` and never saw it; the real
  release job does run tests and failed the post-deploy checksum comparison on both sources
  jars (run 34419387032). Fixed by setting `addOutputDirectoryAsResourceDir` to `false` on
  that execution. General lesson: a Maven "reproducibility" check is only proof for the exact
  invocation it runs; two plugins sharing a phase can pick up in-memory project state that a
  `-DskipTests` build never populates.

## Review status
The adversarial security review (seven passes): H1–H3, M1–M7, R1, R2, R5
fixed and re-verified; under the no-allowance rule every LOW and INFO of the first four passes (L1–L10, I1–I9, R3,
R4, R6–R11) and every finding of the clean-verdict pass (C4 MEDIUM; C1, C2, C5, C7, C9, C11 LOW; C3, C6, C8, C10,
C12 INFO) is fixed on the branch with its probe flipped. The re-verification round (V1 MEDIUM, V2 MEDIUM, V3 LOW,
V4 LOW, V5 LOW) is fixed on the branch, with its probes flipped. V2's first fix (the `keyed_from_seq` anchor field) was itself re-verified and found to have its own plumbing wrong (F1/F2 MEDIUM: written from the
wrong sequence, forgotten by the schema seed) and its silent-fallback gap unclosed (F3 MEDIUM: no DELETE/TRUNCATE
guard on the anchor, no distinct status for an unanchored verification) and a rolling-restart hole (F4 LOW). Rather
than patch the sequence-position mechanism further, the design changed: **keyed-from-birth** — a trail is keyed from row 1 or unkeyed forever, recorded once as a plain
`agentguard_audit_anchor.keyed` boolean, `agentguard.audit.hmac-secret` required by default. This closes V2 in
full (including the original whole-trail repro) more simply than the sequence-position design did, and closes
F3(a) (the anchor DELETE/TRUNCATE guard, independent of the migration) directly; F1/F2/F4 against the old mechanism
no longer apply (there is no sequence arithmetic and no accommodating-a-later-key-enable left to get wrong) — see
the audit-tampering section above. Documented residuals that remain by design: a role that *owns* the tables can drop the
guard triggers, rewriting the trail, the anchor's head/count *and* `keyed` consistently (split
roles, see docs "Database roles"); a `ToolCallingManager` built by hand and handed to a `ChatModel` builder is
outside the guard (use the bean or `AgentGuard.guard(manager)`); on JDK 21–23 Redis calls run on platform threads so
the pool's growth lock is never touched by a virtual thread; a burst past `agentguard.redis.pool.max-total`
concurrent callers now fails closed (`AG-GUARD-001`) instead of queueing unboundedly, by design (C7) — size
the pool at or above real peak concurrency, and size `platform-thread-count`/`platform-thread-queue-size` (V5)
at or above real peak concurrent tool calls independently of `max-total` if the connection pool itself is
deliberately smaller.

## Release pipeline: vulnerability scan before signing
The release workflow scans, with a pinned and checksum-verified Grype, the main and sources jars of
`agent-guard-core` and `agent-guard-spring-boot-starter` plus every jar of their resolved runtime
dependency set, before anything is signed or uploaded. The scanned digests are written to
`scanned-sha256.txt` and the step that compares the uploaded `central-bundle.zip` requires every
non-javadoc jar in it to appear there. Documented residues: `provided` and `optional` dependencies
(supplied by the host) and the sample are not scanned here (the pull-request OSV-Scanner check
covers the tree); javadoc jars are neither scanned nor bound (no runtime code, not reproducible);
the digest comparison runs after the upload, so a red comparison means the deployment is dropped
on the Portal and never published; the scanner's installability is proved inside the signing job
(before the key is imported), not in a separate secret-free job.

## Reviewer checklist (before the first public release)
- [ ] Dependency scan (`./mvnw -Psecurity-scan verify`) clean or triaged.
- [x] Fuzz `ArgumentRedactor` with adversarial JSON (L5 closed with the JSON-aware redactor).
- [ ] Confirm no secret / PII reaches logs in the sample run (grep the log for `hunter2`, `Bearer `, IBAN-like patterns).
- [ ] Two-role database setup documented and used by the sample compose file.
- [x] Threat model the webhook (L6 closed: https, HMAC signature, timestamp).
