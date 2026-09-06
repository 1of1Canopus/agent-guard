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

`SampleEndToEndTest` drives all of that through a real MCP streamable-HTTP client and MockMvc
against a Testcontainers PostgreSQL.
