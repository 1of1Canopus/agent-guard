# Agent Guard

Your MCP server has authentication. It has no authorization, no "ask a human before this
runs", no record of what an agent actually did, and no budget that stops an agent at 3 a.m.
Agent Guard adds the four, as one Spring Boot starter, with the same policy engine for
Spring AI tool calling (`@Tool` / `ToolCallback`) and MCP servers (`@McpTool`).

About the record: agent-guard writes a record of every agent tool call to your own PostgreSQL
database, inside your application's transaction. We never receive a copy. It is a library, not a
hosted service.

Each row is hash-chained and keyed with a secret only you hold. Without that key, an edited,
inserted or reordered row breaks the chain, and the verifier in the free module reports it. Your auditor
can check the chain with that verifier, given read access and the audit key.

You do not have to take our word for what the verifier checks: its source is public. The release
builds are reproducible: two clean builds of the same tag give byte-identical jars.

[![Maven Central](https://img.shields.io/maven-central/v/com.housedevinci/agent-guard-spring-boot-starter.svg)](https://central.sonatype.com/artifact/com.housedevinci/agent-guard-spring-boot-starter)
[![Licence: FSL-1.1-ALv2](https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue.svg)](./LICENSE)
[![CI](https://github.com/1of1Canopus/agent-guard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/1of1Canopus/agent-guard/actions/workflows/ci.yml)

Full reference (all properties, all error codes, the FAQ): [`docs/index.md`](docs/index.md).

## What you get

- **Tool policy** — `@ToolPolicy(roles=…, scopes=…, tenants=…, sideEffect=…)` on a tool method, evaluated through Spring Security on the actual call, never on model intent.
- **Human approval gate** — a `WRITE`/`DESTRUCTIVE` tool call is parked until a human approves it; it then runs exactly once, under the identity of the principal that asked.
- **Audit trail** — every call is recorded in a hash-chained PostgreSQL table, keyed with HMAC from its first row. From 0.1.2, database triggers refuse UPDATE, DELETE and TRUNCATE on the trail, and DELETE and TRUNCATE on its anchor, which may only move forward by one row, with its keyed flag fixed (the anchor is a separate row that stores the head hash, the row count and the keyed flag of the trail, written in the same transaction), and the application will not start if those triggers are missing or changed. This holds against a role that is not the owner, not a member of the owner role, and not a superuser. The table owner can still switch the triggers off after startup, so run the application as a separate role (see "Database roles" in docs/index.md and the residuals in SECURITY-NOTES.md). On 0.1.0 and 0.1.1 the triggers can be missing, and an upgraded trail is protected only from the repair onwards: see the [advisory "audit trail guards on 0.1.0 and 0.1.1"](SECURITY-NOTES.md#advisory-audit-trail-guards-on-010-and-011), also [GHSA-xc43-5ch5-2pfq](https://github.com/1of1Canopus/agent-guard/security/advisories/GHSA-xc43-5ch5-2pfq). The check runs at startup only: a trigger switched off later is not seen until the next start.
- **Budgets** — per-principal, per-tenant and per-conversation limits on tool calls, steps and tokens, enforced before dispatch.

## Compared with

Other projects secure Spring AI and MCP too. Each is for something different. Facts below were read on 2026-10-12.

| | agent-guard | mcp-security | Spring AI tool calling |
|---|---|---|---|
| Tool-call policy | yes | partial | partial (1) |
| Approval step | yes | no | no |
| Audit trail with database guards | yes | no | no |
| Budgets | yes | no | partial (1) |
| OAuth2 / JWT for the MCP endpoint | no (use mcp-security or Spring Security) | yes | no |
| API keys and session binding | no (use mcp-security or Spring Security) | yes | no |
| MCP client auth (OAuth2, dynamic client registration) | no (use mcp-security or Spring Security) | yes | no |

Caption: as read on 2026-10-12. "No" means not found in the README, the file tree or code search on that date.

(1) Spring AI tool calling has user-controlled tool execution and tool call limits. As read, it has no persistent trail and no approval gate.

### spring-ai-community/mcp-security

[mcp-security](https://github.com/spring-ai-community/mcp-security) is Apache-2.0 licensed. It adds HTTP-layer security to MCP servers and clients: OAuth2, API keys, origin validation and session binding. For tool calls, you put Spring Security annotations such as `@PreAuthorize` on the tool methods. As read, it has no approval step, no audit trail and no budgets. It secures who may call the server. agent-guard decides what a tool call may do and records it. You can use both.

### Spring AI tool calling

[Spring AI tool calling](https://docs.spring.io/spring-ai/reference/api/tools.html) has user-controlled tool execution and tool call limits. As read, it has no persistent audit trail and no approval gate of its own. It is the layer agent-guard plugs into.

Comparisons are as of the read date. If we got something wrong, please open an issue and we will correct it.

## Quickstart

```xml
<dependency>
  <groupId>com.housedevinci</groupId>
  <artifactId>agent-guard-spring-boot-starter</artifactId>
  <version>0.1.2</version>
</dependency>
```

## Try it in two minutes

```bash
cd agent-guard-sample
docker compose up -d                      # PostgreSQL on :5432
../mvnw spring-boot:run                   # MCP server on http://localhost:8080/mcp
```

Once an agent has called `refund_order` through an MCP client and got back
`{"status":"AWAITING_APPROVAL","decisionId":"..."}`, an approver reads the recorded
arguments before deciding:

```bash
curl -u alice:alice http://localhost:8080/agentguard/decisions/<decisionId>/arguments
```

Full walkthrough, including the approval call itself and the audit trail: [`agent-guard-sample/README.md`](agent-guard-sample/README.md).

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

## What the free core does, and what a paid edition would add

| | Core (FSL-1.1-ALv2) | Paid edition (planned) |
|---|---|---|
| `@ToolPolicy`, registry, Spring Security integration | yes | yes |
| Approval gate, log + webhook notifier, JSON endpoints | yes | + inbox UI, Slack/Teams/email with action links, SLA timers |
| Hash-chained audit in PostgreSQL, chain verifier | yes | + console, search, CSV/JSON export, retention, verification endpoint, per-tenant views |
| Budgets per principal / tenant / conversation, JDBC + Redis | yes | + cost-based, monthly caps with alerts, per-API-key, admin overrides |
| Policy as YAML with hot reload and dry-run | – | yes |
| Multi-tenant isolation (Tenantify), SSO | – | yes |
| Replay suite (replay recorded tool calls) | – | yes |

The core is complete for a single application. A paid edition for teams is planned. It would add an approval inbox with chat and email actions, an audit console with search and export, cost-based budgets, policy as YAML, multi-tenant isolation with SSO, and a replay suite. If you need one of the planned rows, write to oss@housedevinci.com and say which.

## Licence

Agent Guard is fair source, under the [Functional Source License, Version 1.1, ALv2 Future
License](./LICENSE) (FSL-1.1-ALv2): free to use for any purpose except a Competing Use -
offering a commercial product or service that substitutes for this one, substitutes for
anything we offer using it, or has the same or substantially similar functionality.
Each version becomes Apache-2.0 two years after its release. See [`NOTICE`](./NOTICE) for
the full statement.

## Contributing

Pull requests are welcome. Every commit must carry a `Signed-off-by` trailer under the
[Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`); CI
checks this on every commit in the PR. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the
full agreement and the commit convention.

Dependency updates come from Dependabot, 7 days after the upstream release. A patch or minor
bump that only changes `pom.xml` files merges itself once every required check is green.
Major bumps and GitHub Actions bumps wait for a maintainer.

## Security

Found a vulnerability? Do not open a public issue. Email **security@housedevinci.com**.
See [`SECURITY.md`](./SECURITY.md) for scope, supported versions and the disclosure window.

## Built by HouseDevinci

[https://housedevinci.com](https://housedevinci.com)
