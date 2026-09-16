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
| `POST /agentguard/decisions/{id}/approve?argsHash=<hash>` as `alice` | runs **once**, audited `APPROVED`; a second POST returns the same result and runs nothing |
| 4th tool call within a minute | `{"status":"DENIED","error":"BUDGET_EXCEEDED","code":"AG-BUDGET-001",...}` |
| `GET /agentguard/audit` as `alice` | the hash-chained trail (`prevHash` / `hash` on every row) |

Demo only: the `{noop}` passwords and HTTP Basic are there to keep the sample to 60 lines; put real
authentication (OIDC, an API gateway) in front of a production deployment. `/agentguard/**` exempts
CSRF for a session-less `Authorization: Basic` request (issue #18) - but "session-less" is not what
makes that safe: cached Basic credentials are themselves ambient (a browser re-attaches them the
same way it re-attaches a cookie), and this sample never issues a session cookie anyway, so every
real client here is session-less. What makes the carve-out safe is that approving needs two things
a forged cross-origin request cannot obtain: the decision id (an unguessable UUID handed only to
the caller that parked it) and `argsHash` (the SHA-256 of the arguments the approver reviewed).
Copy this pattern only onto an endpoint that requires an equivalent unguessable, cross-origin-unreadable
parameter on every state-changing call - without one, exempting CSRF would be a real hole. Every
other request on these endpoints, including one that does carry a session, still needs the CSRF
token, and a missing or invalid one now returns a 403 naming the reason instead of a bare 401.

`SampleEndToEndTest` drives all of that through a real MCP streamable-HTTP client and MockMvc
against a Testcontainers PostgreSQL.
