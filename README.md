# Agent Guard

Your MCP server has authentication. It has no authorization, no "ask a human before this
runs", no audit trail an auditor can read, and no budget that stops an agent at 3 a.m.
Agent Guard adds the four, as one Spring Boot starter, with the same policy engine for
Spring AI tool calling (`@Tool` / `ToolCallback`) and MCP servers (`@McpTool`).

[![Maven Central](https://img.shields.io/maven-central/v/com.housedevinci/agent-guard-spring-boot-starter.svg)](https://central.sonatype.com/artifact/com.housedevinci/agent-guard-spring-boot-starter)
[![Licence: FSL-1.1-ALv2](https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue.svg)](./LICENSE)
[![CI](https://github.com/1of1Canopus/agent-guard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/1of1Canopus/agent-guard/actions/workflows/ci.yml)

Full reference (all properties, all error codes, the FAQ): [`docs/index.md`](docs/index.md).

## What you get

- **Tool policy** — `@ToolPolicy(roles=…, scopes=…, tenants=…, sideEffect=…)` on a tool method, evaluated through Spring Security on the actual call, never on model intent.
- **Human approval gate** — a `WRITE`/`DESTRUCTIVE` tool call is parked until a human approves it; it then runs exactly once, under the identity of the principal that asked.
- **Tamper-evident audit trail** — every call is recorded in a hash-chained, append-only PostgreSQL table, keyed with HMAC from its first row.
- **Budgets** — per-principal, per-tenant and per-conversation limits on tool calls, steps and tokens, enforced before dispatch.

## Quickstart

```xml
<dependency>
  <groupId>com.housedevinci</groupId>
  <artifactId>agent-guard-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
@Component
public class OrderTools {

  @McpTool(name = "get_order", description = "Status of an order")
  @ToolPolicy(roles = "AGENT")                                  // READ: allowed, audited
  public String getOrder(@McpToolParam(description = "order id") String orderId) { ... }

  @McpTool(name = "refund_order", description = "Refund an order")
  @ToolPolicy(roles = "AGENT", sideEffect = SideEffect.WRITE)   // WRITE: parked until a human approves
  public String refundOrder(@McpToolParam(description = "order id") String orderId) { ... }
}
```

```yaml
agentguard:
  enabled: true
  store: JDBC                 # PostgreSQL via your DataSource; MEMORY for a quick try
  audit:
    hmac-secret: ${AGENTGUARD_AUDIT_SECRET} # required; generate with `openssl rand -base64 32`
                                             # — or, local trial only, `unkeyed: true` instead
  endpoints:
    enabled: true             # /agentguard/decisions, /agentguard/audit — protect them with Spring Security
  budgets:
    limits:
      - { scope: PRINCIPAL, kind: TOOL_CALLS, window: 1m, limit: 3 }
```

`agentguard.audit.hmac-secret` is required by default — it keys the audit chain from its
first row. Generate one with `openssl rand -base64 32` and pass it as an environment
variable; startup fails and names the property if it is missing. For a local trial only,
set `agentguard.audit.unkeyed=true` instead.

Approving a parked write call, from a terminal (an approver with role `APPROVER`):

```bash
# 1. the agent calls refund_order and gets back {"status":"AWAITING_APPROVAL","decisionId":"...", ...}

# 2. a human reads the complete, redacted arguments
curl -u alice:alice http://localhost:8080/agentguard/decisions/<id>/arguments

# 3. and approves, attesting the hash they reviewed
curl -u alice:alice -X POST "http://localhost:8080/agentguard/decisions/<id>/approve?argsHash=<hash from step 2>"
```

The call runs once, inside the identity of the principal that asked (never the
approver's). A second approval returns the same stored result and runs nothing. See
`agent-guard-sample/` for the runnable version (`docker compose up -d && ../mvnw spring-boot:run`).

## Requirements

- Java 21
- Spring Boot 4.0.x (Spring Framework 7)
- Spring AI 2.0.x, where Spring AI tool calling or MCP is used
- PostgreSQL for the `JDBC` store, or `MEMORY` for trying it out (not for production — see `docs/index.md`)

## How it is secured

- The audit chain is keyed with HMAC from its very first row; there is no unkeyed-to-keyed switch, and an unkeyed trail is a deliberate, WARNed-at-every-startup opt-out.
- A separate anchor row (head hash, row count, keyed/unkeyed) detects a trimmed tail or a truncated table; a missing anchor is refused, never guessed past.
- An approved call executes exactly once, under the identity of the principal that asked — never the approver's — and a second approval is a no-op that returns the stored result.
- Budgets and the argument-size cap are checked before the call runs; a guard failure (store, audit sink, notifier) denies the call rather than letting it through.
- No secret or raw argument value reaches a log line, webhook or endpoint response beyond the redacted, length-capped preview; tool exception messages stay server-side by default.

Full threat model and residual risks: [`SECURITY-NOTES.md`](./SECURITY-NOTES.md).

## Free core vs Pro

| | Core (FSL-1.1-ALv2) | Pro |
|---|---|---|
| `@ToolPolicy`, registry, Spring Security integration | yes | yes |
| Approval gate, log + webhook notifier, JSON endpoints | yes | + inbox UI, Slack/Teams/email with action links, SLA timers |
| Hash-chained audit in PostgreSQL, chain verifier | yes | + console, search, CSV/JSON export, retention, verification endpoint, per-tenant views |
| Budgets per principal / tenant / conversation, JDBC + Redis | yes | + cost-based, monthly caps with alerts, per-API-key, admin overrides |
| Policy as YAML with hot reload and dry-run | – | yes |
| Multi-tenant isolation (Tenantify), SSO | – | yes |
| Conformance suite (replay recorded tool calls) | – | yes |

Pro edition: coming, contact **oss@housedevinci.com**.

## Licence

Agent Guard is fair source, under the [Functional Source License, Version 1.1, ALv2 Future
License](./LICENSE) (FSL-1.1-ALv2): free to use, but not as a base for a competing product.
Each version becomes Apache-2.0 two years after its release. See [`NOTICE`](./NOTICE) for
the full statement.

## Contributing

Pull requests are welcome. Every commit must carry a `Signed-off-by` trailer under the
[Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`); CI
checks this on every commit in the PR. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the
full agreement and the commit convention.

## Security

Found a vulnerability? Do not open a public issue. Email **security@housedevinci.com**.
See [`SECURITY.md`](./SECURITY.md) for scope, supported versions and the disclosure window.

## Built by HouseDevinci

[https://housedevinci.com](https://housedevinci.com)
