# SPEC — Module B · Agent Guard (authorization, approval, audit, budgets for Spring AI / MCP)

Status: READY. First module to build (6 weeks). Reuse (per the 2026-09-06 study): from the kit take the roles/access-check pattern (`project`), the usage ledger + `UsageQuotaPolicy` for budgets, the processed-event ledger pattern for idempotent approvals, the notification port for notifiers, and the audit table as a base (add the hash chain). **The approval state machine is not in the kit any more — port the ~40-line enum version from Peekflo Core API.** The pro admin console ships as a small application built from the kit (Option B), not as a library.

## Why (plain words)
Spring AI 2.0 (GA June 2026) makes it easy to let an AI call tools in a Java app. The official security module gives authentication and `@PreAuthorize`. It has no per-tool authorization policy, no "ask a human before this runs", no audit trail an auditor can read, and no budget that stops an agent at 3 a.m. Spring AI 2.0.1 added a loop limit, which shows the team knows the pain and has not built the rest. Every existing tool for this is Python or Node.

## Scope
Works with (a) Spring AI tool calling (`ToolCallback` / `@Tool`) and (b) Spring AI MCP server annotations (`@McpTool`). Same policy engine for both.

### Free core (`agent-guard-core`, Apache-2.0)
1. **Tool policy** — `@ToolPolicy(roles=…, scopes=…, tenants=…, sideEffect=READ|WRITE|DESTRUCTIVE)` on tool methods, plus a programmatic `ToolPolicyRegistry`. Evaluated through Spring Security's `AuthorizationManager` so it composes with `@PreAuthorize`. Deny → typed `ToolDeniedException` returned to the model as a structured tool error (never a stack trace).
2. **Approval gate (basic)** — tools marked `WRITE`/`DESTRUCTIVE` require approval: the call is parked as `PendingDecision {id, principal, tool, argsHash, argsPreview (redacted), createdAt, expiresAt}`; a `Notifier` SPI (log + webhook implementations in core); `ApprovalService.approve/reject(id)`; the agent receives a structured "awaiting approval" tool result and can resume via a `DecisionResumer` (idempotent by decision id). State machine: `PENDING → APPROVED | REJECTED | EXPIRED` (custom enum SM, ~40 lines, as in Peekflo).
3. **Audit interceptor (basic)** — every tool invocation recorded: principal, tenant, tool, args hash, result hash, latency, decision (ALLOWED/DENIED/PENDING/APPROVED), correlation id; sink SPI with JDBC (Postgres) implementation; append-only table, hash-chained rows (reuse 14/spec 04 approach).
4. **Budgets (basic)** — per principal and per tenant: max tool calls per window, max steps per conversation, max tokens per day (token counts from Spring AI usage metadata); JDBC + Redis stores; exceeded → `BudgetExceededException` as structured tool error. Enforced **before dispatch** (Peekflo minute-cap discipline).
5. Auto-configuration, properties `agentguard.*`, sample app: a 60-line MCP server with one read tool, one write tool needing approval, and an audit query endpoint.

### Pro edition (`agent-guard-pro`)
- Approval inbox UI (from the kit: list, approve/reject with note, filters, SLA timers) + Slack/Teams/email notifiers with action links.
- Audit console: search by principal/tool/time, export CSV/JSON, retention policies, tamper-proof verification endpoint, per-tenant views.
- Policy as configuration (YAML) with hot reload, environment overrides, dry-run mode ("would have denied").
- Budgets: cost-based (per-model price table), monthly caps with alerts at 80/100%, per-API-key budgets, admin overrides with audit.
- Multi-tenant isolation via Tenantify; SSO via the kit.
- Conformance suite: a test kit teams run against their own agent to prove policies hold (replays recorded tool calls).
- Price: $249 solo · $499 team, one-time; support €1,200/yr.

## Domain model (core)
`Principal {id, roles, scopes, tenantId}` · `ToolRef {name, sideEffect}` · `PolicyDecision {ALLOW, DENY(reason), REQUIRE_APPROVAL}` · `PendingDecision` · `AuditEvent` · `Budget {scope, window, limit, used}`.

## Threats (security notes to write)
Prompt-injected tool calls (policy is evaluated on the *actual* call, never on model intent); argument tampering between approval and execution (args hash bound to the decision; resume verifies hash); replay of approvals (single-use decision ids); log injection (args preview redacted + length-capped); privilege escalation via tool chaining (policy evaluated per call, budgets per conversation).

## Tests
- Unit: policy evaluation matrix; state machine transitions (all illegal transitions throw); budget windows; redaction.
- Integration (Testcontainers Postgres/Redis): approval round-trip with resume; audit chain verify; budget exhaustion under concurrency (virtual threads).
- Sample: end-to-end with a fake `ChatModel` that requests tool calls.

## Docs and launch
Docs page + article: "Your MCP server has authentication. It has no authorization, no approval, no audit." Posts: r/java, r/SpringBoot, Spring AI community, Show HN.

## Acceptance checks
- [ ] Sample MCP server: read tool allowed, write tool parked, approval via endpoint resumes and executes once, second approval is a no-op, audit shows the chain, budget of 3 calls blocks the 4th with a structured error.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo with licence check.
- [ ] Docs page, CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown.
- [ ] Gate (90 days): 100 stars or 500 downloads AND 3 paid or 2 hosted-console asks.
