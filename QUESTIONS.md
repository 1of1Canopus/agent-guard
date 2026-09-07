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
20. **[decided, scope note]** V2's exact repro (write a fully keyed 2-row trail, rewrite *every* row down to `ag1`,
    verify with the key) cannot be made to report `BROKEN` by the described fix, or by any fix that only reads the
    version each row itself claims: that trail is byte-for-byte identical to
    `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail`'s scenario (a
    deployment that never used HMAC, verified after a key is later configured) — the whole point of C6, and a test
    this pass must not weaken. A verifier that treated an all-unkeyed trail as `BROKEN` whenever it happens to be
    given a key would turn "I just set `agentguard.audit.hmac-secret`" into an outage on every existing installation.
    There is no cryptographic signal inside the row data that tells the two cases apart; that gap is the pre-existing
    table-owner residual already documented as Cipher R4 ("a role that owns the tables can rewrite chain and anchor
    consistently").
    Implemented instead: version-monotonicity *within the observed trail* (`AuditChainVerifier.verify`, `keyedSeen`)
    — once a row has actually verified as `KEYED_VERSION`, no later row may fall back to unkeyed and still be
    trusted. This closes the realistic and detectable form of the attack: an attacker who joins an already-keyed
    trail partway through (some genuine keyed rows exist and are left alone, since rewriting them would break their
    own HMAC) and downgrades the tail. `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed`
    was changed to rewrite the trail's tail (row 2 onward) rather than its head, so it exercises the case the fix
    actually closes; the full-trail-downgrade case is not, and cannot be, covered by a probe without an external
    anchor (SECURITY-NOTES already lists this as future pro-item work: "An HMAC-keyed chain and external anchoring
    stay pro items").

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
