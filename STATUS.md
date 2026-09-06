# STATUS.md — Module B · Agent Guard, free core (run 1)

Branch `feat/agent-guard-core` in `modules/B-agent-guard/` (own git repo, never pushed). Pro edition out of scope.

## Summary
**Done.** The five free-core items of the SPEC are built, tested and green under `./mvnw -B clean verify`
(96 tests: core 83, starter 12, sample 1 end-to-end; core line coverage 92.0%, branch 82.9%; spotless,
Error Prone, enforcer, JaCoCo gate >= 80%, THIRD-PARTY-NOTICES all pass).

| Item | Where | State |
|---|---|---|
| 1. Tool policy (`@ToolPolicy`, registry, `AuthorizationManager`, typed deny as structured error) | core `domain`, starter `security` | done |
| 2. Approval gate (PendingDecision, enum state machine, Notifier SPI log + webhook, approve/reject, resume once) | core `application`, `adapter.notify` | done |
| 3. Audit interceptor (principal, tenant, tool, args/result hash, latency, decision, correlation id; JDBC hash chain, append-only) | core `adapter.jdbc`, schema | done |
| 4. Budgets (principal / tenant / conversation; tool calls, steps, tokens; JDBC + Redis; before dispatch) | core `application`, `adapter.jdbc`, `adapter.redis` | done (token *recording* hook exists, automatic wiring pending — QUESTIONS #8) |
| 5. Auto-configuration `agentguard.*`, sample MCP server | starter, sample | done |

Versions: Spring Boot **4.0.8**, Spring Framework 7.0.9, Spring Security 7.0.7, **Spring AI 2.0.1**
(`spring-ai-model`, `spring-ai-mcp-annotations`, `spring-ai-autoconfigure-mcp-server-common`,
`spring-ai-starter-mcp-server-webmvc`, `spring-ai-starter-mcp-client` for the e2e test), MCP Java SDK 2.0.0
(`mcp-core`), Jedis 7.5.2, Testcontainers 2.0.5, Java 21.

## Acceptance checks (SPEC)
- [x] **Sample MCP server: read tool allowed, write tool parked, approval via endpoint resumes and executes once,
  second approval is a no-op, audit shows the chain, budget of 3 calls blocks the 4th with a structured error.**
  Proof: `./mvnw -B -pl agent-guard-sample test` → `SampleEndToEndTest` drives a real MCP streamable-HTTP client
  (`McpClient.sync(HttpClientStreamableHttpTransport)`) with HTTP Basic against the running sample on a random port
  and a Testcontainers PostgreSQL; MockMvc approves as `alice`; `AuditChainVerifier.verify().intact()` is asserted.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo — **not this run** (needs the
  org/group decision, GPG key, and the security review; group id `com.housedevinci` is set in the POM).
- [x] Docs page (`docs/index.md`), CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown —
  sample `src/main` is 69 lines including blank lines and imports (`find agent-guard-sample/src/main -name '*.java' | xargs wc -l`).
- [ ] Gate (90 days) — not applicable yet.

## Library definition of done (AGENTS.md)
- [x] Off by default (`agentguard.enabled=false`); misconfiguration fails fast naming the property
  (`AgentGuardAutoConfigurationTest`).
- [x] Hexagonal, ArchUnit-enforced: `domain` and `application` have no Spring / Jakarta / JDBC / Redis / MCP imports
  (`HexagonalArchitectureTest`, 3 rules).
- [x] Testcontainers for PostgreSQL and Redis; unit tests for the policy matrix (15 cases), state machine (13 illegal
  transitions), budget windows, redaction.
- [x] Concurrency: budget exhaustion under 200 virtual threads (in-memory), JDBC counter and execute-once under
  concurrency (Postgres), audit chain linear under 100 concurrent appends.
- [x] Javadoc on public types; configuration metadata JSON; CI + Dependabot + scheduled OWASP scan workflows.
- [ ] Public API stability review (`@Internal` marking) — not done; candidates: `Json`, `Errors`, `JdbcSupport`.
- [ ] Sample runs in < 2 minutes from clone — not timed; `docker compose up -d && ../mvnw spring-boot:run` documented.

## Proof commands
```bash
./mvnw -B clean verify                                   # everything, ~30 s after images are cached
./mvnw -B -pl agent-guard-core test                      # 83 tests, Testcontainers Postgres + Redis
./mvnw -B -pl agent-guard-spring-boot-starter test       # 12 tests (context runner, fake ChatModel tool loop, MCP specs, endpoints)
./mvnw -B -pl agent-guard-sample test                    # 1 end-to-end test through a real MCP client
open agent-guard-core/target/site/jacoco/index.html      # coverage
```

## Not done / next run
- Token budget auto-recording (ChatClient advisor), async (WebFlux) MCP servers, Micrometer metrics
  (`agentguard_*`) and an Actuator health contributor, `@Internal` pass, OpenAPI fragment for the endpoints.
- Release plumbing (Maven Central signing, org name), security review per `specs/RELEASE-PROCESS.md`.

## Pain points (plain words)
- **Spring AI 2.0.1 MCP internals had to be read from the jars**: the `@McpTool` path has no documented interception
  point. Guarding at the `List<SyncToolSpecification>` bean level works and is tested, but it is a seam, not an API.
- **Jedis + virtual threads deadlocked the first Redis test** (pinning on JDK 21). Real hazard for users; documented.
- **PostgreSQL `char(64)` pads short values**, which silently broke the hash chain in a test with short fake hashes;
  columns are `varchar(64)` now. Chain canonical form also had to truncate timestamps to milliseconds.
- **Optional dependencies bite at introspection time**: any auto-config method body that touches Jedis types made the
  whole class fail to load when Jedis was absent; the Redis factory is now a separate class.
- Boot 4 renamed things (`spring-boot-starter-webmvc`, `org.springframework.boot.webmvc.test.autoconfigure`,
  `org.springframework.boot.jdbc.autoconfigure`); nothing hard, just time.
