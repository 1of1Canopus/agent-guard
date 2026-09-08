# QUESTIONS.md — ambiguities met while building the free core (module B)

Decisions I took alone are marked **[decided]**; things I want a ruling on are marked **[ruling?]**.

## Spring AI 2.0.x API details (verified on Maven Central / by javap on the 2.0.1 jars)
1. **[decided]** Spring AI 2.0.1 ships its own MCP annotations: `org.springframework.ai:spring-ai-mcp-annotations` with
   `org.springframework.ai.mcp.annotation.McpTool`. The community `org.springaicommunity:mcp-annotations` artifact is
   not needed and is not declared. If a user still has the community jar, `@ToolPolicy` scanning only recognises the
   Spring AI annotation (the community one is ignored, the tool falls back to the method name).
2. **[decided]** The `@McpTool` path is intercepted at the `List<McpServerFeatures.SyncToolSpecification>` bean level
   (bean `toolSpecs` from `McpServerSpecificationFactoryAutoConfiguration`, bean `syncTools` from
   `ToolCallbackConverterAutoConfiguration`) via a `BeanPostProcessor` that rewraps every `callHandler`. This is the
   only public seam that sits between the annotation scanner and `McpServerAutoConfiguration`. It covers the sync
   streamable-HTTP / SSE servers and the stateless sync server. **Async (WebFlux) servers are not guarded yet**: a
   `McpServerFeatures.AsyncToolSpecification` wrapper is the same 30 lines, but the blocking JDBC/Redis stores would
   run on reactor threads; deferred until someone asks. Since Cipher H2, async specification beans **fail startup**
   instead of running unguarded.
3. **[decided]** MCP tool hints: only `readOnlyHint=true` is honoured (tool treated as READ when it has no
   `@ToolPolicy`). `destructiveHint` is not used because `@McpTool` defaults it to `true`, so every unannotated tool
   would silently become DESTRUCTIVE. Unannotated non-read-only tools follow `agentguard.policy.unregistered-tools`
   (default `DENY`).
4. **[ruling?]** Tool results on the Spring AI path are JSON-serialised by `MethodToolCallback` (a `String` result comes
   back as `"\"text\""`). The guard passes that through untouched; our structured errors are raw JSON objects. Both are
   what the model sees today; fine for me, but say if you want the errors wrapped the same way Spring AI does.
5. **[decided]** Spring AI's `ToolContext` carries no principal. The principal comes from `SecurityContextHolder`
   (`ROLE_x` -> role, `SCOPE_x` -> scope), tenant from a `TenantResolver` bean (default: none). For MCP over HTTP this
   works because the WebMVC transport handles the call on the request thread that Spring Security authenticated. For
   stdio servers there is no authentication: everything is `anonymous` and role-restricted tools are denied. Document
   or provide a `PrincipalResolver` bean.
6. **[decided]** The `AuthorizationManager<ToolInvocation>` bean (`ToolPolicyAuthorizationManager`) exposes the same
   policy to Spring Security method security / custom chains. The interceptor path calls the domain evaluator directly
   (same code, no double evaluation). If the SPEC meant "the interceptor must go through the AuthorizationManager
   bean", it is a one-line change.

## Product / behaviour
7. **[decided — coordinator ruling]** `agentguard.store=JDBC` stays the fail-closed default. The startup error names
   the trial setting explicitly: "no DataSource found; for a local trial set agentguard.store=memory - not for
   production." Implemented in `AgentGuardAutoConfiguration`, asserted in `AgentGuardAutoConfigurationTest`.
8. **[closed by the no-allowance round]** `AgentGuardUsageAdvisor` (CallAdvisor + StreamAdvisor bean) records model tokens after every response. Original note: Token budgets (`kind: TOKENS`) are enforced before dispatch and recorded through
   `BudgetEnforcer.recordTokens(...)`, but nothing calls `recordTokens` automatically yet: Spring AI usage metadata lives
   on the `ChatResponse`, not on the tool call, so it needs a `ChatClient` advisor or a `ChatModel` decorator. Proposed:
   an `AgentGuardUsageAdvisor` (CallAdvisor) in the starter next run.
9. **[decided]** Budget windows are fixed, epoch-aligned windows (not sliding). Counters count attempts that reached
   dispatch, and a refused attempt is not rolled back. Cheap, atomic, predictable.
10. **[decided, revised after Cipher M4]** A parked call consumes the call budget when it is parked; its later
    execution is not charged again (still "cap before dispatch": nothing runs without a reservation).
11. **[decided]** A REJECTED decision re-requested with identical arguments returns a structured rejection
    (`AG-APPROVAL-005`); an EXPIRED one is parked again. Different arguments always park a new decision.
12. **[decided — coordinator ruling]** The JSON approve / reject / audit-query endpoints stay in the free starter
    (behind `agentguard.endpoints.enabled`): a developer must be able to try the loop. The Pro line is the inbox UI,
    search/filters, exports, retention, per-tenant views.

## Clean-verdict round (Cipher, `50ed8d3`)
18. **[decided]** C9's `agentguard.endpoints.require-tenant=true` default (correctly) refuses an approver with no
    tenant when `tenant-scoped=true`. This is a genuine behaviour change for any `tenant-scoped=true` deployment
    that never wired a `TenantResolver` (previously treated as "no scoping needed"). Fixed by declaring intent
    explicitly rather than by relying on silent fallback: the sample app now sets
    `agentguard.endpoints.tenant-scoped=false` (it has no tenant concept at all), and
    `AgentGuardEndpointsTest`'s single-tenant test method sets `agentguard.endpoints.require-tenant=false` at the
    class level (its sibling method, which does exercise real per-tenant scoping, never logs in with a tenant-less
    approver, so the property does not weaken it). No probe assertion was weakened; see `STATUS.md`.
19. **[decided]** C4's fix, read literally, only moves the size check inside `gate()`/`dispatch()`. C12's fix makes
    `AuditRecorder.record` canonicalise (parse) every call's arguments, including the early
    policy-denied/unregistered-tool paths in `ToolGuard.guarded()` that C4 does not touch — which would have quietly
    reintroduced C4's amplification on the one path C4 itself creates (the oversized-rejection audit call). Closed
    with `AuditRecorder.recordOversized`, a narrow addition used only by the size-cap rejection, hashing the raw
    text directly instead of through `ArgumentCanonicalizer`. This is a smallest-correct-change addition, not a
    widening of either finding: it does not touch the Deny/PENDING/ALLOWED audit paths, which were never in scope
    for C4 and are unaffected by this addition.

## Re-verification round (Cipher, `6f026ff`)
20. **[closed — Dollar's ruling]** V2's exact repro (write a fully keyed 2-row trail, rewrite *every* row down to
    `ag1`, verify with the key) could not be made to report `BROKEN` by the described fix, or by any fix that only
    reads the version each row itself claims: that trail is byte-for-byte identical to
    `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail`'s scenario (a
    deployment that never used HMAC, verified after a key is later configured) — the whole point of C6, and a test
    this pass must not weaken. There is no cryptographic signal inside the row data that tells the two cases apart;
    that gap is the pre-existing table-owner residual already documented as Cipher R4 ("a role that owns the tables
    can rewrite chain and anchor consistently"). First round shipped only version-monotonicity *within the observed
    trail* (`AuditChainVerifier.verify`, `keyedSeen`) — once a row has actually verified as `KEYED_VERSION`, no
    later row may fall back to unkeyed and still be trusted — closing the partial-downgrade case (an attacker who
    joins an already-keyed trail partway through and downgrades the tail) but not the whole-trail one.

    **Dollar's ruling:** the analysis was right, and the external anchor named as the way out (R4's
    `agentguard_audit_anchor` row, protected by the BEFORE UPDATE monotonic trigger) already exists — use it.
    Implemented: `agentguard_audit_anchor` gets a nullable `keyed_from_seq` column, set once — in the same
    transaction as the first row a sink appends under a keyed chain — and never movable afterwards (the trigger
    now also refuses to change or null out `keyed_from_seq` once set, the same protection `head_hash`/`row_count`
    already had). `AuditChainVerifier.verify`, given a key, requires every row before `keyed_from_seq` to be
    unkeyed and every row from it onward to be keyed; anything else, including a keyed row while `keyed_from_seq`
    is still `null`, is `BROKEN`. A key given when `keyed_from_seq` is `null` and no keyed row exists reports the
    new `Status.UNKEYED` rather than `INTACT`, so an operator who believes the key is already active on a trail
    sees that it is not. `InMemoryAuditSink` carries the same bookkeeping (plus a seeding constructor modelling a
    new sink instance continuing an existing trail) so the logic is store-independent and unit-testable.

    This closes V2 in full, including Cipher's original whole-trail repro: the attacker's row-level rewrite (even
    of the genuinely keyed head) cannot also move the anchor's `keyed_from_seq`, which is not part of the
    `agentguard_audit` rows they rewrite. `CipherProbeReverifyTest` keeps the tail-rewrite probe
    (`probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed`) and restores Cipher's original whole-trail
    one (`probe_a_fully_downgraded_trail_verifies_as_broken_not_intact`); both fail (report `INTACT`) against the
    pre-anchor code and pass (report `BROKEN`) against this fix. C6's test was updated to model "enabling the key"
    as a second sink instance continuing the same trail and appending under the keyed chain — the scenario that
    actually sets `keyed_from_seq` — rather than a verifier alone reconfigured with a key that no row ever used;
    it still reports `INTACT`, because the earlier prefix genuinely is unkeyed. Residual, unchanged from R4: a
    role that *owns* the tables can disable the anchor's trigger and rewrite `keyed_from_seq` along with
    everything else — this closes the runtime-role attack, not the table-owner one.

    **Superseded (Cipher's final-verification round, HEAD `25da6af`):** the `keyed_from_seq` mechanism above was
    itself found to have its own plumbing wrong — F1 (MEDIUM, written from `row_count + 1` instead of the row's
    real `seq`, so a `bigserial` gap makes an untampered trail report permanently `BROKEN`), F2 (MEDIUM, the
    schema's anchor seed forgot to derive `keyed_from_seq`, beating the sink's own re-derivation on a lost-anchor
    installation), F3 (MEDIUM, no DELETE/TRUNCATE guard on the anchor table, and the verifier's fallback for a
    missing anchor was silent — reporting `INTACT` again, the original V2 result), and F4 (LOW, a still-unkeyed
    instance mid rolling-restart could append after the keying point and permanently break the trail). Isis closed
    F3(a) (the DELETE/TRUNCATE guard) and started on F1/F2/F4 before Dollar, with Souhaile, ruled the design
    itself rather than iterating the sequence-position mechanism again: **keyed-from-birth**.

    **Dollar's ruling (keyed-from-birth):** a trail is keyed from row 1 or unkeyed forever — no mixing, no later
    switch, no accommodating "enabling the key on a running installation" (the C6 goal, now invalid by design).
    `agentguard.audit.hmac-secret` is required by default (missing → startup fails naming the property and the
    remedy, `openssl rand -base64 32`); `agentguard.audit.unkeyed=true` is the explicit, WARN-every-startup local
    dev opt-out. Which mode a trail is in is recorded once, at the first append, as a plain
    `agentguard_audit_anchor.keyed` boolean, immutable afterwards via the anchor's existing monotonic trigger.
    Every append after that, from any instance, must agree with it or is refused
    (`AgentGuardException`/`AG-AUDIT-001`) — this is what actually closes F4 (a fail-closed refusal, not a
    detectable-after-the-fact break). `AuditChainVerifier` checks every row's `chain_version` against what
    `keyed` says the whole trail must be; a table-owning attacker's row-level rewrite (even a whole-trail
    downgrade — Cipher's original V2 repro) cannot flip `keyed`. F1 and F2 do not carry forward: both were about
    deriving a *sequence position* correctly, and there is no sequence position left in the new design to derive.
    F3(a) (anchor DELETE/TRUNCATE triggers) ships unchanged, independent of the migration.

    **Amendment (Dollar, after Cipher's design review of the above):** five additions, folded in before push. (1)
    A key id (`agentguard.audit.hmac-key-id`, default `k1`) is part of the hashed material from row 1
    (`agentguard_audit.key_id`, `'none'` for unkeyed rows); `AuditChainVerifier` holds a keyring
    (`hmac-secret`/`hmac-key-id` plus every `agentguard.audit.hmac-keys.<id>`), so rotation is a config change
    (add the new key, change the appending id) rather than a trail migration — an id the keyring does not hold is
    `BROKEN`, and this is not a second mode switch: `keyed` still says *whether* a key is required (immutable),
    `key_id` only says *which* already-trusted key signed a given row. (2) A missing anchor on a non-empty trail
    now refuses to append (`AG-AUDIT-002`) on both `JdbcAuditSink` and the schema seed, rather than being
    re-derived from the trail head — the "re-anchor from head" fallback and its one-time warn guard are removed
    entirely; the schema seed only ever creates the anchor row for a genuinely empty trail. (3) `NO_ANCHOR` is now
    reported unconditionally (keyed or unkeyed), not only when a key was given to the verifier. (4) `Report` now
    carries the trail's mode (`anchored`, `keyed`, `keyIds`); an unkeyed trail's clean result is the distinct
    `Status.INTACT_UNKEYED`, replacing the deleted `Status.UNKEYED` (a different, now-impossible situation) with
    an honest rendering of the common, by-design-unkeyed case. (5) "Start a new trail" is defined as an owner-run
    procedure (archive `agentguard_audit`/`agentguard_audit_anchor`, re-run the schema step); the startup-failure
    message only fires when an anchor exists and disagrees, so a fresh install with a secret starts fine; the
    secret must not live in the same store as the datasource credentials. Full write-up and the old-probe →
    new-probe map: `docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Design change: keyed-from-birth" and its
    "Amendment" subsection.

    **Cipher's verification of keyed-from-birth (`722e9a5`), all six closed by Isis:** G1/G2 (MEDIUM, the schema
    step's backfills were both refused by their own triggers, and the anchor backfill was a re-derivation of
    `keyed` from `chain_version` — exactly what the amendment removed) — no backfill added back, since this branch
    is unreleased and has no upgrade path from a pre-redesign database; `key_id`/`keyed` are declared `NOT NULL`
    directly in `CREATE TABLE`, and the schema step now fails startup with a clear message on a table that
    predates them. H1 (LOW, an `hmac-keys` entry could silently shadow the appending key) and H2 (LOW,
    `unkeyed=true` + `hmac-secret` silently resolved to keyed) both now fail startup naming the two properties.
    H3/H4 (INFO) were doc-only: `InMemoryAuditSink` javadoc + SECURITY-NOTES now say its anchor is self-derived
    and cannot detect tail deletion; SECURITY-NOTES' status list now includes `INTACT_UNKEYED`. No pushback filed
    — every fix matched Dollar's ruling as given. Full write-up: CHANGELOG "Cipher verification of keyed-from-birth
    (722e9a5)"; STATUS.md run 9.

## Build
13. **[decided]** Error Prone 2.50 on JDK 21 needs `.mvn/jvm.config` (add-exports) and
    `-XDaddTypeAnnotationsToSymbol=true`; both are in place. `maven-enforcer` `dependencyConvergence` is on.
14. **[decided]** JaCoCo gate is on `agent-guard-core` only (line >= 80%). The starter is covered by context tests but
    has no gate yet.
16. **[decided, Cipher review]** `agentguard.strict=true` by default: fail startup on unguarded `@ToolPolicy`
    tools and deny calls whose budget scope has no subject. Trial users set `agentguard.strict=false`.
17. **[decided, Cipher review]** The child-JVM virtual-thread pinning probe runs only with `-Ppinning-probe` (it
    hangs on purpose for 2 x 10 s).
15. **[decided]** Testcontainers 2.0.5 (Boot-managed): `testcontainers-postgresql` + `testcontainers-junit-jupiter`;
    Redis via `GenericContainer("redis:7-alpine")`.
18. **[decided]** Cipher's clean verdict on `f27c45e` (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Clean
    verdict (f27c45e)") found one new LOW, J1: the schema-predates guard matched `information_schema` unscoped
    while the rest of the step is search_path-relative, so a stale pre-redesign `agentguard_audit` in another
    visible schema permanently blocked a fresh install in the current one. Closed by Isis exactly as prescribed —
    both existence checks now go through `to_regclass('agentguard_audit')` /
    `to_regclass('agentguard_audit_anchor')`, both column checks through `pg_attribute` against that same oid
    (`attnum > 0 AND NOT attisdropped`) — no pushback filed. Full write-up: CHANGELOG "Cipher clean verdict on
    f27c45e (J1 LOW closed)"; STATUS.md run 10.
19. **[decided]** Cipher's final verdict on `05f209d` (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, final
    section) found one new LOW, K1: the J1 fix scoped the guard to search_path visibility (`to_regclass` resolves
    like a reference, the first schema on the search_path holding the name), while the unqualified `CREATE TABLE`
    it protects targets only `current_schema()` — a pre-redesign copy on the search_path but behind the creation
    schema still blocked a fresh install that would have been correct. Closed by Isis exactly as prescribed —
    both oids resolved via `to_regclass(quote_ident(current_schema()) || '.agentguard_audit')` /
    `... '.agentguard_audit_anchor'` in one `DECLARE` block — no pushback filed. Full write-up: CHANGELOG "Cipher
    final verdict on 05f209d (K1 LOW closed)"; STATUS.md run 11.

## Release pipeline (2026-09-08, `feat/release-pipeline`)
21. **[decided, needs Souhaile's confirmation]** POM `<developers>` email. Central requires
    developer contact details on the published POM, and that POM is public forever. I put
    `oss@housedevinci.com` rather than any personal address: a role mailbox can be forwarded,
    filtered or retired, a personal one cannot be taken back once it is in
    `agent-guard-core-0.1.0.pom` on repo1.maven.org. **This address does not exist yet.** It
    must forward somewhere before 0.1.0 is published, otherwise the security-contact path in
    a public library is a dead letter. Recommendation: a forwarding alias on the
    housedevinci.com mailbox, and the same address in `SECURITY.md`.
22. **[decided]** The licence gate is an allowlist, not a blocklist, and it runs on every
    build rather than only in the release profile. Allowed, after `licenseMerges` folds the
    forty-odd spellings onto five canonical names: `Apache-2.0`, `MIT` (incl. `MIT-0`),
    `BSD` (2- and 3-clause), `EPL-2.0`, `Public Domain` (incl. CC0). Everything else fails
    the build, GPL/LGPL/AGPL/MPL/CDDL/SSPL included.
    - Why an allowlist: the previous configuration was
      `excludedLicenses=GNU General Public License|GPL-2.0|GPL-3.0|AGPL-3.0`, which only
      catches copyleft licences spelled exactly the way we guessed. An allowlist catches the
      ones nobody thought of.
    - Why not release-only, as the brief asked: a copyleft dependency is cheap to remove on
      the PR that adds it and expensive to remove on release day. `./mvnw verify` semantics
      are unchanged, because this execution already ran at `package` before this branch.
    - `EPL-2.0` is there for the Jakarta APIs and Logback. Weak, file-level copyleft that
      does not reach our code across a link.
    - `Public Domain` is not in the list the brief named. `org.json:json` and the CC0 half of
      `HdrHistogram` declare it, and it carries fewer obligations than MIT. Flagging it
      because it is an addition, not because it is a risk.
    - Observed behaviour worth knowing: `license-maven-plugin` accepts a dependency when **any**
      one of its declared licences is allowed. `logback` (`EPL-2.0` OR `LGPL-2.1-only`) and
      `jakarta.annotation-api` (`EPL-2.0` OR `GPL-2.0-with-classpath-exception`) pass on their
      permissive half, which is legally the right answer for a dual-licensed artifact, but it
      does mean the gate would also pass an `Apache-2.0 OR GPL-3.0` dependency.
    - **Bug found and fixed:** the goal silently skips when `target/THIRD-PARTY-NOTICES.txt`
      is newer than the pom, so on any incremental local build the old blocklist checked
      nothing at all. `<force>true</force>` now makes it run every time. Verified both ways:
      with the allowlist narrowed to `MIT` the build fails with "There are 2 forbidden
      licenses used"; without `force` the same narrowing passes.
23. **[decided]** Keyserver: `keyserver.ubuntu.com`. Sonatype names it first and it has been
    reachable. `keys.openpgp.org` strips the user id from an uploaded key until the address is
    confirmed by email, which makes a key that looks anonymous to anyone verifying it.
24. **[decided]** The reproducibility check enforces the two `.jar` and two `-sources.jar`
    files and only reports on the javadoc jars. Javadoc output has historically embedded JDK
    build strings that `-notimestamp` does not remove. On this tree, on Temurin 21.0.10, all
    six jars including javadoc are byte-identical across two clean builds, so the exemption is
    currently unused; it is there so a JDK upgrade does not fail a release for something no
    consumer checks.
25. **[decided]** Publishing plugin: `org.sonatype.central:central-publishing-maven-plugin`
    0.11.0. It is the plugin Sonatype documents for the Central Portal
    (https://central.sonatype.org/publish/publish-portal-maven/ , read 2026-09-08; that page
    still shows 0.9.0 in its snippet, and 0.11.0 is the latest release on Maven Central as of
    the same date, published 2026-06-16). The old OSSRH path
    (`nexus-staging-maven-plugin` + oss.sonatype.org) is retired and is not an option. The
    plugin needs no `id-token` permission: it authenticates with the Central user-token pair,
    not OIDC, so the release workflow requests `contents: read` and nothing else.
26. **[open, low]** `THIRD-PARTY-NOTICES.txt` is generated into `target/` and uploaded as a
    workflow artifact; it is **not** placed inside the published jars under `META-INF/`.
    `specs/LICENSING.md` says the notices file is "shipped" without saying where.
    Recommendation: put it in `META-INF/` of both jars in a follow-up, once someone decides
    whether the starter's notices should list the whole Spring Boot tree (88 entries) or only
    what the starter itself adds. Deliberately out of scope here: it changes jar contents.
