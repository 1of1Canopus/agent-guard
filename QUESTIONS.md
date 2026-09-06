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
   run on reactor threads; deferred until someone asks.
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
8. **[ruling?]** Token budgets (`kind: TOKENS`) are enforced before dispatch and recorded through
   `BudgetEnforcer.recordTokens(...)`, but nothing calls `recordTokens` automatically yet: Spring AI usage metadata lives
   on the `ChatResponse`, not on the tool call, so it needs a `ChatClient` advisor or a `ChatModel` decorator. Proposed:
   an `AgentGuardUsageAdvisor` (CallAdvisor) in the starter next run.
9. **[decided]** Budget windows are fixed, epoch-aligned windows (not sliding). Counters count attempts that reached
   dispatch, and a refused attempt is not rolled back. Cheap, atomic, predictable.
10. **[decided]** Approved calls also consume budget at execution time (Peekflo "cap before dispatch" discipline).
11. **[decided]** A REJECTED decision re-requested with identical arguments returns a structured rejection
    (`AG-APPROVAL-005`); an EXPIRED one is parked again. Different arguments always park a new decision.
12. **[decided — coordinator ruling]** The JSON approve / reject / audit-query endpoints stay in the free starter
    (behind `agentguard.endpoints.enabled`): a developer must be able to try the loop. The Pro line is the inbox UI,
    search/filters, exports, retention, per-tenant views.

## Build
13. **[decided]** Error Prone 2.50 on JDK 21 needs `.mvn/jvm.config` (add-exports) and
    `-XDaddTypeAnnotationsToSymbol=true`; both are in place. `maven-enforcer` `dependencyConvergence` is on.
14. **[decided]** JaCoCo gate is on `agent-guard-core` only (line >= 80%). The starter is covered by context tests but
    has no gate yet.
15. **[decided]** Testcontainers 2.0.5 (Boot-managed): `testcontainers-postgresql` + `testcontainers-junit-jupiter`;
    Redis via `GenericContainer("redis:7-alpine")`.
