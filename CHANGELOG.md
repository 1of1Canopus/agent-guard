# Changelog

All notable changes to Agent Guard. Format: Keep a Changelog; versions: SemVer. `-SNAPSHOT` is never published.

## [Unreleased]

### Security (Cipher final verdict on `05f209d`: K1 LOW closed)
- **K1 (LOW):** the J1 fix scoped the schema-predates guard to search_path *visibility*
  (`to_regclass('agentguard_audit')`, which resolves like a reference — the first schema on the search_path that
  holds the name, anywhere along the path), while the unqualified `CREATE TABLE IF NOT EXISTS agentguard_audit` in
  the same script targets only `current_schema()`, the first *existing* entry. The two are not the same set: a
  stale pre-redesign copy sitting in a schema that is on the search_path but *behind* the creation schema (e.g.
  `search_path = public, archive` with a pre-redesign `agentguard_audit` left in `archive`) was still visible to
  `to_regclass` and refused a fresh install that would have created a brand-new, fully correct table in `public`
  and never touched the stale copy — J1's own symptom, narrowed rather than closed. Both oids are now resolved
  once, in a `DECLARE`, against `to_regclass(quote_ident(current_schema()) || '.agentguard_audit')` /
  `... '.agentguard_audit_anchor'` — the same schema the unqualified `CREATE TABLE` targets — with `quote_ident`
  required so a schema named with capitals or a dot is not re-parsed as a different name. No integrity impact
  (denial of startup, fails in the safe direction) — hence LOW.
- **Test:**
  `CipherProbeFinalVerdictJdbcTest.probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install`
  inverted from asserting the refusal (the reproduction) to `assertThatCode(...).doesNotThrowAnyException()` (the
  fix); J1's own probe
  (`CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`) and both
  G1/G2 same-schema probes are unchanged and still green.

### Security (Cipher clean verdict on `f27c45e`: J1 LOW closed)
- **J1 (LOW):** the schema step's pre-redesign guard matched `information_schema.tables`/`.columns` with no
  `table_schema` filter, while every other statement in the step (`CREATE TABLE IF NOT EXISTS agentguard_audit`,
  the triggers, the anchor) is unqualified and therefore search_path-relative — a stale pre-redesign copy of
  `agentguard_audit` sitting in another schema the role can see (reached, for example, by following
  `docs/index.md`'s "archive by rename or drop" via `ALTER TABLE agentguard_audit SET SCHEMA archive`, or in a
  schema-per-tenant database where one tenant has migrated and another has not) permanently blocked a fresh
  install in the current schema. The guard now resolves both tables via `to_regclass(...)`, the same
  search_path-relative resolution the rest of the step uses, and checks for `key_id`/`keyed` via `pg_attribute`
  against that same oid (`attnum > 0 AND NOT attisdropped`) instead of scanning `information_schema` unscoped.
  No integrity impact (denial of startup, fails in the safe direction) — hence LOW.
- **Test:** `CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`
  inverted from asserting the refusal to `doesNotThrowAnyException()`; the G1/G2 same-schema pre-redesign probes
  (column absent in the current schema still refuses) are unchanged and still pass.

### Security (Cipher verification of keyed-from-birth, `722e9a5`: G1/G2 MEDIUM, H1/H2 LOW, H3/H4 INFO closed)
Cipher's verification pass on the keyed-from-birth design (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`,
"Verification of keyed-from-birth") found two MEDIUM in the schema step and two LOW/two INFO in configuration and
docs. Dollar ruled: this branch is unreleased, so there is no upgrade path from a pre-redesign database — no
backfill is added back.
- **G1/G2 (MEDIUM):** the schema step's backfills of `agentguard_audit.key_id` and `agentguard_audit_anchor.keyed`
  were both refused by the tables' own triggers (an UPDATE against the append-only trigger; a plain UPDATE that
  does not advance the anchor's `row_count`), aborting startup on any database written by an earlier build of this
  branch — and the anchor backfill was itself a re-derivation of `keyed` from `chain_version`, the exact guess the
  amendment removed. Both backfills, and their `ADD COLUMN IF NOT EXISTS`/`ALTER COLUMN … SET NOT NULL` pairs, are
  deleted; `agentguard_audit.key_id` and `agentguard_audit_anchor.keyed` are declared `NOT NULL` directly in the
  `CREATE TABLE` bodies (still idempotent — `CREATE TABLE IF NOT EXISTS` is a no-op on a database created by this
  version). The schema step now checks up front whether either table exists without its keyed-from-birth column
  and fails startup with a clear, actionable message ("audit schema predates keyed-from-birth; archive the table
  and start a new trail (see SECURITY-NOTES)") instead of aborting later on a trigger or a missing-column INSERT
  error.
- **H1 (LOW):** an `agentguard.audit.hmac-keys.<id>` entry reusing the appending `hmac-key-id` with a different
  secret used to silently replace the appending key in `AuditChainVerifier`'s keyring — every row this instance
  writes would then fail to verify, an integrity alarm caused by configuration. `auditKeyring` now fails startup
  when this happens, naming both properties; an entry with the identical secret is still accepted as a no-op.
- **H2 (LOW):** `agentguard.audit.unkeyed=true` together with a non-blank `agentguard.audit.hmac-secret` used to
  resolve silently to keyed (the safe direction, but with no WARN and no failure). `auditChain` now fails startup
  on the contradiction, naming both properties.
- **H3 (INFO, doc-only):** `InMemoryAuditSink`'s `AuditAnchor` is derived from the very event list it anchors
  (`headHash`/`rowCount` from the last event, `keyed` from the instance's `AuditChain`), so it cannot detect its
  own tail being trimmed — unlike `JdbcAuditSink`'s separate, append-only-guarded anchor row. Documented in the
  class javadoc and SECURITY-NOTES; development/test store only, behaviour unchanged.
- **H4 (INFO, doc-only):** SECURITY-NOTES' status list is missing `INTACT_UNKEYED`; added.
- **Test:** `CipherProbeKeyedBirthJdbcTest.probe_an_existing_database_with_rows_cannot_run_the_new_schema_step` /
  `.probe_an_existing_anchor_row_cannot_be_backfilled_with_keyed` now assert the new clear-message refusal instead
  of the old trigger-abort message; `CipherProbeKeyringTest.probe_a_retired_key_entry_can_shadow_the_appending_key`
  / `.probe_unkeyed_true_with_a_secret_is_silently_ignored` now assert startup failure naming both properties,
  plus a new `confirms_a_retired_key_entry_matching_the_appending_secret_is_a_noop` regression test.

### Security (Cipher review of `feat/agent-guard-core`, all HIGH and MEDIUM fixed)
- H1: executors are registered per decision id and released after the run; approved calls execute inside a
  security context rebuilt from the stored principal (`ResumeContextProvider` SPI, `RunAsAuthentication`), with the
  parking caller's `ToolContext` / MCP exchange, never as the approver.
- H2: Spring AI tools are guarded at the `ToolCallingManager` chokepoint (inline `.tools(obj)`,
  `ToolCallbacks.from`, resolver-by-name included); single MCP specification beans are wrapped; async (WebFlux)
  specifications fail startup; `agentguard.strict=true` (default) fails startup when a scanned `@ToolPolicy` is not
  reachable through a guarded path; the startup log lists the guarded tools.
- H3: `agentguard.redis.pool.{max-total,min-idle,max-wait,prepare-pool}`; the Jedis pool is pre-filled at startup
  so it never grows under virtual threads (commons-pool2 growth lock pins JDK 21–23 carriers).
- M1: the approver (`actor_id`) is part of every APPROVED / REJECTED audit row and of the hash chain.
- M2: length-prefixed canonical form (`ag1`), millisecond timestamps everywhere, `BEFORE TRUNCATE` trigger, anchor
  row (`agentguard_audit_anchor`), verifier statuses `EMPTY` / `INTACT` / `BROKEN` / `ANCHOR_MISMATCH`.
- M3: MCP conversation id is the server-side session id (client `_meta` ignored); missing budget subjects are
  denied under strict (`agentguard.budgets.missing-subject`, `AG-BUDGET-002`); TENANT limits without a
  `TenantResolver` warn at startup.
- M4: parking consumes the call budget (execution is not charged again); pending decisions capped per principal
  (`AG-APPROVAL-008`); arguments capped (`AG-APPROVAL-009`); dedup key includes the tenant.
- M5: `GET /decisions/{id}/arguments` returns the complete redacted arguments; `POST …/approve` requires the
  attested `argsHash` (409 `AG-APPROVAL-010` on mismatch).
- M6: every guard-infrastructure failure becomes a structured `AG-GUARD-001` error with a correlation id.
- M7: endpoints refuse anonymous approvers (401) unless `agentguard.endpoints.allow-anonymous=true`.
- R1 (re-verification): the guarded default `ToolCallingManager` no longer competes with Spring AI's
  `ToolCallingAutoConfiguration` (`@ConditionalOnMissingClass`); Spring AI's manager, with
  `spring.ai.tools.limits.*` and `resolution.fallback`, is wrapped by the bean post-processor instead.
- R2 (re-verification): the schema seeds `agentguard_audit_anchor` from an existing trail, and `JdbcAuditSink`
  re-anchors from the table head (WARN once) when the anchor row is missing, so upgraded installations stay INTACT.
- R5 (re-verification): `RunAsAuthentication` keeps the tenant during a resumed call (`SecurityContextPrincipalResolver`
  short-circuits on it, `NoTenantResolver` understands it).

### Security (no-allowance round: every LOW / INFO of the review closed)
- L1 four-eyes: the parking principal cannot approve/reject its own call (`AG-APPROVAL-011`, 403;
  `agentguard.approval.allow-self-approval=false`).
- L2 tamper detection is audited (`AuditDecision.TAMPERED`, with actor) and closes the decision.
- L3 policy re-evaluated at resume with a refreshed principal (`PrincipalRefresher` SPI); a revoked role or a
  tightened rule denies, audited with the approver as actor.
- L4 dedup bounded by `agentguard.approval.replay-window` (default = ttl).
- L5 JSON-aware redactor: dependency-free parser in the domain, sensitive keys mask their whole value whatever its
  shape, keys compared after unescaping, `\p{Cc}\p{Cf}` + U+0085/2028/2029 stripped, unparseable input fully masked.
- L6 webhook: https required (loopback or `webhook-allow-insecure` excepted), `X-AgentGuard-Timestamp` +
  `X-AgentGuard-Signature: v1=HMAC-SHA256(secret, ts.body)`; static token only with `webhook-legacy-token`.
- L7 duration properties fail naming the property; empty `approval-required-for` / `sensitive-keys` warn.
- L8 expired budget rows purged every 1000 increments, `key` column `text`, long subjects hashed.
- L9 sample keeps CSRF on for the approval endpoints; README says the demo credentials are demo-only.
- L10/R11 schema step runs once per DataSource, under the sink's advisory lock, creating triggers only when absent
  (no deadlock with appends, eight concurrent first starts succeed); WARN when the runtime role owns the audit table.
- I1 arguments hashed in canonical form (sorted keys, no whitespace): key order and spacing share one decision.
- I2 `Failed.retryable=false` after an approval; documented.
- I3 anonymous tokens map to the anonymous principal in the `AuthorizationManager` too.
- I4 endpoints are tenant-scoped (`agentguard.endpoints.tenant-scoped=true`): other tenants' decisions are 404.
- I5 tool exception messages stay server-side (`agentguard.errors.include-tool-message=false`); the model gets the
  class name and the correlation id.
- I6 two different policies for one tool name fail at startup.
- I7 optional keyed chain (`agentguard.audit.hmac-secret`, >= 32 bytes, version `ag2h`).
- I8 `STEPS` only with `CONVERSATION`, `TOOL_CALLS` only with `PRINCIPAL`/`TENANT` (fail fast);
  `AgentGuardUsageAdvisor` records model tokens for `TOKENS` budgets (closes QUESTIONS #8).
- I9 workflows: `permissions: contents: read`, actions pinned by SHA, wrapper `distributionSha256Sum`, container
  images pinned by digest.
- R3 startup log names the wrapped manager and the hand-built-manager caveat.
- R4 `agentguard_audit_anchor` only advances by one row (trigger).
- R6 Redis calls run on a bounded platform-thread pool on JDK 21-23 (`agentguard.redis.pool.platform-threads`).
- R7 WARN when a CONVERSATION limit has no PRINCIPAL limit.
- R8 pending cap counted per principal and tenant.
- R9 an `AgentGuardException` from the tool path leaves a FAILED row before failing closed.
- R10 `RunAsAuthentication`: package-private constructor, never serializable, cannot be re-authenticated.

### Security (clean-verdict round: C1-C12, all closed)
- C4 (MEDIUM) `ToolGuard.gate` and `.dispatch` refuse arguments over `agentguard.guard.max-argument-bytes` as their
  first step, before anything parses them; the audit row for that refusal hashes the raw text directly instead of
  through the canonical parser, so a rejected call never triggers the amplification it was rejected for.
- C1 unpaired UTF-16 surrogates are `\u`-escaped in `JsonText.escape` instead of silently colliding with a literal
  `?` under UTF-8 encoding, so they no longer dedup two different calls onto one decision.
- C2 sensitive-key matching also splits on `_ - .` and camel-case boundaries (`userPassword`, `myApiKey`,
  `password_confirmation` now mask); the existing whole-word-suffix rule is unchanged.
- C5 four-eyes (`ApprovalService.fourEyes`) compares approver and requester trimmed, case-folded and NFKC-normalised.
- C7 a Redis call that misses `maxWait` is cancelled and removed from the queue; the platform-thread pool is a
  bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to the pool, `AbortPolicy`) instead of an unbounded
  `newFixedThreadPool`, so a saturated pool refuses immediately (`AG-GUARD-001`) instead of queueing forever.
- C9 `agentguard.endpoints.require-tenant` (default `true` when `tenant-scoped`): an approver whose resolver yields
  no tenant gets 403 instead of every tenant's decisions and audit rows; set `false` only for a deliberate
  cross-tenant approver role.
- C11 the domain ArchUnit rule bans `javax..` again, with an explicit carve-out for `javax.crypto..` (the keyed
  chain's only use) instead of the three named packages that also re-permitted `javax.naming` / `javax.management` /
  `javax.net` / `javax.xml`.
- C3 the hand-written JSON parser accepts only ASCII `0`-`9` as digits and only `[0-9a-fA-F]` in a `\u` escape, so it
  never treats text Jackson would refuse as structured.
- C6 the audit chain records the version (`ag1` / `ag2h`) each row was actually written with (`agentguard_audit.
  chain_version`, backfilled `ag1`) and the verifier applies that row's version instead of whatever chain it is
  configured with today, so enabling `agentguard.audit.hmac-secret` no longer reports the pre-key trail BROKEN.
- C8 `JedisBudgetStore implements AutoCloseable`; the platform-thread pool is shut down on close (Spring's default
  inferred destroy method picks it up).
- C10 `DecisionStore.findByState(state, tenantId, limit)` and `AuditReader.latest(tenantId, limit)` push the tenant
  filter into the store query instead of filtering the page after `limit`, so a busy neighbour tenant can no longer
  hide a tenant's own pending work.
- C12 `AuditRecorder.record` hashes `ArgumentCanonicalizer.canonical(argumentsJson)`, the same form the decision
  store hashes, so `agentguard_audit.args_hash` and `agentguard_decision.args_hash` join for the same call again.

### Security (re-verification round: V1-V5, all closed or scoped)
- V1 (MEDIUM) `ToolGuard.guarded` now applies the raw byte cap (`rejectIfTooLarge`) as the first statement on
  every path into the guard, including the unregistered-tool and policy-denial paths — both reachable with no
  role and no policy at all. Those two denials previously canonicalised (parsed) the arguments before the cap
  ran; `gate`/`dispatch` keep their now-redundant checks.
- V2 (MEDIUM) `AuditChainVerifier.verify` tracks whether a `KEYED_VERSION` row has verified while walking the
  trail; once it has, a later row claiming `CANONICAL_VERSION` is `BROKEN` at its own sequence instead of being
  silently re-verified with plain SHA-256. C6's migration case (an unkeyed prefix, then keyed rows) is unaffected.
  **Scope (superseded, see below):** as first fixed, this closed only a *partial* downgrade — a genuinely keyed
  prefix followed by a downgraded tail — because no purely row-embedded version scheme can tell a whole-trail
  downgrade to GENESIS apart from a deployment that has genuinely never used HMAC (QUESTIONS.md #20).

### Security (Dollar's ruling on QUESTIONS.md #20: V2 closed in full with an external anchor)
- `agentguard_audit_anchor` gets a `keyed_from_seq` column (nullable bigint): `null` until the sink appends the
  first row written under a keyed chain, then that row's sequence, set in the same transaction as the append.
  The anchor's monotonic trigger (Cipher R4) is extended so `keyed_from_seq` may go from `null` to a value exactly
  once and never change or return to `null` — the same trigger that already stops a runtime-role attacker from
  resetting `head_hash`/`row_count` now also stops them erasing where the keyed chain legitimately began.
- `AuditChainVerifier.verify` reads `keyed_from_seq` from the anchor: every row before it must be unkeyed and
  verify as such, every row from it onward must be keyed and verify with the given key; anything else — including
  a keyed row while `keyed_from_seq` is still `null` — is `BROKEN`. A key given to the verifier when
  `keyed_from_seq` is `null` and no keyed row exists reports the new `Status.UNKEYED`, distinct from `INTACT`, so
  an operator who believes `agentguard.audit.hmac-secret` is protecting a trail can see that it is not yet. The
  previous in-trail `keyedSeen` forward-only rule is kept as a fallback for readers that do not implement
  `AuditAnchor`. **This closes V2 in full**, including Cipher's original whole-trail-downgrade repro (a keyed
  trail rewritten entirely to `ag1`/GENESIS and re-verified with the key): the attacker's row-level rewrite cannot
  touch the anchor's `keyed_from_seq`, which lives outside the rows they rewrite.
- `InMemoryAuditSink` gets the same `keyed_from_seq` bookkeeping (and a seeding constructor,
  `InMemoryAuditSink(List<AuditEvent>, AuditChain)`, modelling a new sink instance continuing an existing trail —
  the in-memory analogue of restarting the app with the key now set), so the verifier's logic is exercised the
  same way regardless of store.
- `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail` (C6) now models
  "enabling the key" as a second sink instance continuing the same trail and appending under the keyed chain,
  matching how the anchor actually learns `keyed_from_seq`; it still reports `INTACT`, because the prefix really
  is a legitimately-unkeyed one written before the key was ever set.
- `CipherProbeReverifyTest.probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` restores Cipher's exact
  original repro alongside the existing tail-rewrite probe; both fail (report `INTACT`) against the pre-anchor
  fix and pass (report `BROKEN`) against this one.
- V3 (LOW) the two `args_hash` domains are separated with a fixed prefix hashed into the material:
  `AuditRecorder.recordOversized` hashes `"agraw1:" + argumentsJson`, `ArgumentCanonicalizer.hash` hashes
  `"agcanon1:" + canonical(argumentsJson)` — an oversized denial can no longer share `args_hash` with an allowed
  call. `ToolGuard.rejectIfTooLarge` additionally checks the canonical form's byte length (once the raw check has
  already bounded the cost of computing it), so a sub-cap raw payload whose canonical form exceeds the cap is also
  refused as oversized. **Hash-format change:** existing `args_hash` values are unaffected (the chain hashes the
  row, not the arguments), but a stored `args_hash` can no longer be recomputed from raw arguments text without
  the domain prefix.
- V4 (LOW) `AgentGuardStartupCheck` now warns when `agentguard.endpoints.enabled` and either
  `agentguard.endpoints.tenant-scoped=false` or `agentguard.endpoints.require-tenant=false`, naming the property
  and the consequence ("approvers see and decide every tenant's decisions and audit rows").
- V5 (LOW) `AgentGuardProperties.Pool` gets `platform-thread-count` and `platform-thread-queue-size`, decoupled
  from `max-total` (the Jedis connection pool size); both default to `max-total` when unset, preserving prior
  behaviour. `JedisBudgetStore.onPlatformThreads` takes the queue bound as its own parameter.
  `CipherProbeJedisFactoryTest.burst` is restored to `max-total=4` (the real H3/R6 connection-pool contention
  scenario) with `platform-thread-count`/`platform-thread-queue-size=200`, so the burst still passes without
  inflating the connection pool.

### Security (Cipher final verification + Dollar's design change: keyed-from-birth; QUESTIONS.md #20)
Cipher's final-verification pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, `25da6af`) found the
`keyed_from_seq` mechanism above had its own plumbing wrong (F1/F2 MEDIUM), its silent-fallback gap unclosed
(F3 MEDIUM) and a rolling-restart hole (F4 LOW). Rather than iterate that mechanism again, Dollar and Souhaile
ruled the design itself, then amended it once more after Cipher's design review.
- **Breaking (a trail is keyed from row 1 or unkeyed forever):** no mixing, no later switch, no accommodating
  "enabling the key on a running installation" (the C6 goal, invalid by design now). `agentguard.audit.hmac-secret`
  is **required by default**; missing, startup fails naming the property and the remedy (`openssl rand -base64 32`).
  `agentguard.audit.unkeyed=true` is the explicit, WARN-at-every-startup local-dev opt-out.
- `agentguard_audit_anchor.keyed_from_seq` (nullable bigint) is replaced by `agentguard_audit_anchor.keyed`
  (`boolean NOT NULL`): set once, at the first append, immutable afterwards via the anchor's existing monotonic
  trigger. Every append after that, from any instance, must agree with it or is refused with a structured
  `AgentGuardException` (`AG-AUDIT-001`), naming the property and the remedy — this is what actually closes F4
  (fail-closed, not detectable-after-the-fact).
- `AuditChainVerifier.verify` checks every row's `chain_version` against what `keyed` says the whole trail must
  be — a table-owning attacker's row-level rewrite (even a whole-trail downgrade, Cipher's original V2 repro)
  cannot flip `keyed`, which lives outside the rows they rewrite. F1/F2 do not carry forward: both were about
  deriving a sequence position correctly, and the new design has no sequence position left to derive.
- `agentguard_audit_anchor` gets `BEFORE DELETE`/`BEFORE TRUNCATE` triggers (F3(a), independent of the migration):
  nothing previously refused deleting the anchor row, which silently reopened the exact whole-trail-downgrade
  attack the anchor exists to close.
- **Amendment, after Cipher's design review:**
  - **Key rotation from v1:** `agentguard.audit.hmac-key-id` (default `k1`) is baked into every row's hashed
    material (`agentguard_audit.key_id`, `'none'` for unkeyed rows). `AuditChainVerifier` holds a keyring
    (current key plus every `agentguard.audit.hmac-keys.<id>`); a row's `key_id` absent from the keyring is
    `BROKEN`, not skipped. Rotation is a config change, not a trail migration; `keyed` still governs *whether* a
    key is required (immutable), `key_id` only *which* already-trusted key signed a row.
  - **Anchor-missing refuses, never guesses:** a trail with rows but no anchor row is refused (`AG-AUDIT-002`),
    on both the next append and at the next startup. The "re-anchor from the trail head" fallback and its
    one-time-warn guard are removed; the schema seed's `INSERT … ON CONFLICT DO NOTHING` no longer derives values
    from an existing, non-empty trail — it only ever matches a genuinely empty one.
  - **`NO_ANCHOR` unconditionally:** reported whenever the reader is not an `AuditAnchor`, or has no anchor row,
    and the trail is not empty — keyed or unkeyed, not only when a key was given (widening Cipher F3(a)).
  - **`Report` carries the trail's mode** (`anchored`, `keyed`, `keyIds`). `Status.INTACT_UNKEYED` replaces the
    deleted `Status.UNKEYED` (a different, now-impossible situation): an unkeyed trail's clean result never
    renders with the same word as a keyed trail's.
  - "Start a new trail" is documented as an owner-run procedure (archive `agentguard_audit`/
    `agentguard_audit_anchor`, re-run the schema step); the secret must not live in the same store as the
    datasource credentials.
- **Interface changes (breaking):** `AuditEvent` gains a `keyId` component (after `version`, before `prevHash`);
  `AuditChain.canonical`/`hashOfEvent` include it in the hashed material, so this is a chain-format addition —
  every row written by this version carries a `key_id`, and `AuditChain.keyed(byte[])` now defaults key id `k1`
  (use `keyed(byte[], String)` to choose one). `AuditAnchor.Anchor.keyedFromSeq` (`Long`) is replaced by
  `Anchor.keyed` (`boolean`). `AuditChainVerifier.Status.UNKEYED` is removed; `Status.INTACT_UNKEYED` is added.
  `AuditChainVerifier` gains a `Map<String, byte[]>`-keyring constructor/factory alongside the existing
  single-`AuditChain` ones (unchanged). `ErrorCodes.AUDIT_KEY_MISMATCH` (`AG-AUDIT-001`) and
  `ErrorCodes.AUDIT_ANCHOR_MISSING` (`AG-AUDIT-002`) are new.
- **Test:** `CipherProbeAnchorKeyingJdbcTest` replaces Cipher's F1–F4 probes in full (see
  `docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Design change: keyed-from-birth", for the old-probe →
  new-probe map); `AuditChainVerifierTest`, `CipherProbeReverifyJdbcTest`, `CipherProbeFinalJdbcTest`,
  `AgentGuardAutoConfigurationTest` updated or extended alongside it.

### Added
- `agent-guard-core` (Apache-2.0, no framework dependencies):
  - `@ToolPolicy(roles, scopes, tenants, sideEffect)` and `ToolPolicyRegistry`; `ToolPolicyEvaluator` with a stable
    decision (`ALLOW` / `DENY(code)` / `REQUIRE_APPROVAL`).
  - Approval gate: `PendingDecision`, `DecisionState` enum state machine (`PENDING -> APPROVED | REJECTED | EXPIRED`,
    everything else throws), `ApprovalService`, `DecisionResumer` (executes once, args hash verified), `Notifier` SPI
    with logging, webhook and composite implementations.
  - Audit: `AuditEvent` hash chain, `AuditSink` / `AuditReader` ports, `AuditChainVerifier`.
  - Budgets: `BudgetLimit` (PRINCIPAL / TENANT / CONVERSATION x TOOL_CALLS / STEPS / TOKENS), `BudgetEnforcer`
    enforced before dispatch, `BudgetStore` port.
  - Adapters: PostgreSQL (JDBC, append-only trigger, advisory-lock chain), Redis (Jedis, atomic Lua counter),
    in-memory.
  - Error codes `AG-POLICY-00x`, `AG-APPROVAL-001..011`, `AG-BUDGET-001/002`, `AG-TOOL-001`, `AG-GUARD-001`.
- `agent-guard-spring-boot-starter`:
  - `agentguard.*` properties (validated, documented metadata, fail-fast messages naming the property).
  - Spring AI 2.0.x: every `ToolCallback` / `ToolCallbackProvider` bean is decorated; `AgentGuard.guard(...)` for
    programmatic use.
  - MCP: every `@McpTool` (sync and stateless sync servers) is decorated; refusals return
    `CallToolResult(isError=true)` with structured JSON.
  - Spring Security: principal from the security context, `TenantResolver` SPI,
    `ToolPolicyAuthorizationManager` (`AuthorizationManager<ToolInvocation>`).
  - Opt-in endpoints: list / approve / reject decisions, audit query.
- `agent-guard-sample`: 60-line MCP server (one read tool, one write tool parked for approval, budget of 3) with an
  end-to-end test through a real MCP streamable-HTTP client and Testcontainers PostgreSQL.
