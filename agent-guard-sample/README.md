# Agent Guard sample — an MCP server that asks a human before it writes

Three files, about 60 lines of code: `SampleApplication`, `OrderTools` (one read tool, one
write tool marked `@ToolPolicy(sideEffect = WRITE)`), `SecurityConfig` (HTTP Basic: `agent`/`agent`
calls tools, `alice`/`alice` approves).

```bash
docker compose up -d                      # PostgreSQL on :5432
../mvnw spring-boot:run                   # MCP server on http://localhost:8080/mcp
```

What happens:

| Call | Result |
|---|---|
| `get_order` as `agent` | runs, audited `ALLOWED` |
| `refund_order` as `agent` | parked: `{"status":"AWAITING_APPROVAL","decisionId":...}`, logged at WARN, audited `PENDING` |
| `POST /agentguard/decisions/{id}/approve` as `alice` | runs **once**, audited `APPROVED`; a second POST returns the same result and runs nothing |
| 4th tool call within a minute | `{"status":"DENIED","error":"BUDGET_EXCEEDED","code":"AG-BUDGET-001",...}` |
| `GET /agentguard/audit` as `alice` | the hash-chained trail (`prevHash` / `hash` on every row) |

Demo only: the `{noop}` passwords and HTTP Basic are there to keep the sample to 60 lines; put real
authentication (OIDC, an API gateway) in front of a production deployment. CSRF still protects the
approval endpoints for any client that carries a session; a session-less HTTP Basic client (a plain
`curl`, as documented above) has no cookie to forge and no token endpoint to fetch one from, so
`/agentguard/**` exempts that one shape of request specifically (`csrf.ignoringRequestMatchers`
still exempts `/mcp/**` outright, unchanged) - see `SecurityConfig` (issue #18). Any other request
that is missing or has an invalid CSRF token now gets a 403 that names the reason, not a bare 401.

`SampleEndToEndTest` drives all of that through a real MCP streamable-HTTP client and MockMvc
against a Testcontainers PostgreSQL.
