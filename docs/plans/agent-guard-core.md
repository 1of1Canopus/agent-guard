# Plan — Agent Guard free core (module B, first run)

Scope of this run: the five free-core items in `SPEC.md`. Pro edition out of scope.

## Verified coordinates (Maven Central, 2026-09-06)
- Spring Boot parent `4.0.8` (latest 4.0.x). Java 21.
- Spring AI BOM `2.0.1` (latest 2.0.x GA). Artifacts used:
  - `org.springframework.ai:spring-ai-model` — `ToolCallback`, `ToolCallbackProvider`, `ToolDefinition`, `ToolContext`, `@Tool`.
  - `org.springframework.ai:spring-ai-mcp-annotations` — `@McpTool` (package `org.springframework.ai.mcp.annotation`, has `annotations().readOnlyHint()/destructiveHint()`).
  - `org.springframework.ai:spring-ai-autoconfigure-mcp-server-common` — `McpServerSpecificationFactoryAutoConfiguration` publishes a bean `List<McpServerFeatures.SyncToolSpecification>` (`toolSpecs`) from `@McpTool` beans; `ToolCallbackConverterAutoConfiguration` publishes `syncTools` from `ToolCallback` beans; `McpServerAutoConfiguration` collects all `List<SyncToolSpecification>` beans into the `McpSyncServer`.
  - `io.modelcontextprotocol.sdk:mcp-core:2.0.0` (transitive) — `SyncToolSpecification(tool, callHandler)`, `CallToolRequest`, `CallToolResult.builder().isError(true)`.
  - `org.springframework.ai:spring-ai-starter-mcp-server-webmvc` for the sample (WebMVC streamable HTTP).
- The community `org.springaicommunity:mcp-annotations` artifact is NOT needed: Spring AI 2.0.x ships its own `spring-ai-mcp-annotations`.

## Architecture
```
agent-guard-core (no Spring)            agent-guard-spring-boot-starter           agent-guard-sample
  api/         @ToolPolicy, SideEffect     autoconfigure/  properties, beans         @McpTool read + write
  domain/      pure model + rules          ai/             GuardedToolCallback         SecurityConfig (basic auth)
  application/ ToolGuard, ApprovalService  mcp/            guarded SyncToolSpecification
  adapter/     jdbc (java.sql), redis      security/       AuthorizationManager, PrincipalResolver
               (Jedis, optional), notify   web/            approval + audit endpoints (opt-in)
```
ArchUnit: `..domain..` and `..application..` depend on nothing outside `java.*`, `..domain..`, `..application..`, `org.slf4j` (application only).

### Interception points
1. **Spring AI tool calling** — `BeanPostProcessor` wraps every `ToolCallback` and `ToolCallbackProvider` bean in `GuardedToolCallback`. Programmatic `AgentGuard.guard(...)` for callbacks passed directly to `ChatClient`.
2. **MCP `@McpTool`** — `BeanPostProcessor` wraps every `List<SyncToolSpecification>` / `List<McpStatelessServerFeatures.SyncToolSpecification>` bean, replacing each `callHandler` with a guarded one. Both paths call the same `ToolGuard`.
3. Policy lookup: `@ToolPolicy` on the tool method (scanned at startup by tool name from `@Tool`/`@McpTool`/method name) → programmatic `ToolPolicyRegistry` → MCP hints (`readOnlyHint`→READ, `destructiveHint`→DESTRUCTIVE) → `agentguard.policy.unregistered-tools` (default `DENY`, fail closed).

### Guard pipeline (`ToolGuard.execute`)
```
resolve principal → resolve rule → policy decision
  DENY            → audit DENIED, structured error {"error":"TOOL_DENIED",...}
  REQUIRE_APPROVAL→ existing decision for (principal, tool, argsHash)? resume : park (PendingDecision + Notifier), audit PENDING
  ALLOW           → budget reserve (before dispatch) → execute → audit ALLOWED (+ latency, result hash)
```
Budget exceeded → audit BUDGET_EXCEEDED, structured error `{"error":"BUDGET_EXCEEDED",...}`.

### Approval
- `DecisionState` enum SM: `PENDING → APPROVED | REJECTED | EXPIRED`; anything else throws `IllegalDecisionTransitionException`.
- `ApprovalService.approve(id, approver)`: PENDING→APPROVED then `DecisionResumer.resume(id)` which executes **once** (`DecisionStore.markExecutedOnce`, processed-event-ledger pattern) via the `ToolExecutorRegistry` and stores the result. Second approve → no-op returning the stored result. Reject after approve → throws.
- Args bound by SHA-256 hash; resume re-hashes stored args and compares (tamper check). Preview redacted + length-capped.
- `Notifier` SPI: `LoggingNotifier`, `WebhookNotifier` (JDK `HttpClient`, POST JSON), `CompositeNotifier`. Best effort, never throws.

### Audit
`AuditEvent` with `prevHash`/`hash` (SHA-256 over canonical fields + prevHash). JDBC sink serialises appends with `pg_advisory_xact_lock`; table has a trigger that rejects UPDATE/DELETE. `AuditChainVerifier` walks the chain. In-memory sink for tests/dev.

### Budgets
`BudgetLimit(scope PRINCIPAL|TENANT|CONVERSATION, kind TOOL_CALLS|STEPS|TOKENS, window, limit)`. `BudgetStore.incrementAndGet(key, window, amount)` (Redis `INCR`+`EXPIRE`, JDBC upsert). `BudgetPolicy.wouldExceed` copied from the kit's `UsageQuotaPolicy`. Enforced before dispatch; tokens recorded after the call from Spring AI usage metadata via `BudgetEnforcer.recordTokens`.

## Work order (TDD)
1. Root pom + core pom + ArchUnit test (red) → domain skeleton.
2. Policy evaluator + matrix test.
3. State machine + test. PendingDecision, ApprovalService, DecisionResumer + in-memory store tests.
4. Redaction + hash tests.
5. Audit event chain + verifier tests (in-memory), then JDBC sink with Testcontainers.
6. Budgets: policy + enforcer tests (in-memory), JDBC + Redis stores with Testcontainers, concurrency test with virtual threads.
7. Starter: properties + auto-config tests (ApplicationContextRunner), GuardedToolCallback test with fake ChatModel + DefaultToolCallingManager, MCP spec wrapper test.
8. Sample + end-to-end test (read allowed, write parked, approve executes once, second approve no-op, audit chain, budget of 3).
9. Docs, STATUS, QUESTIONS, SECURITY-NOTES, CHANGELOG, CI, Dependabot.
