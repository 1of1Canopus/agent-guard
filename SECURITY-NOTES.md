# SECURITY-NOTES.md — Agent Guard (module B), free core

Skeleton for the adversarial pass required by `specs/RELEASE-PROCESS.md`. Each threat from the SPEC, what the code
does about it, and what still needs a reviewer's eye.

## Threat 1 — Prompt-injected tool calls
- **Mitigation:** policy is evaluated on the *actual* call (`ToolGuard.execute` receives the tool name and the exact
  arguments the framework is about to execute), never on model intent. Nothing in the pipeline reads the prompt.
- **Test:** `ToolGuardTest`, `GuardedToolCallbackTest`, `McpToolGuardTest`.
- **Open:** the tool *name* is taken from the framework's `ToolDefinition` / `McpSchema.Tool`, not from the model
  message, so a model cannot rename a tool. Reviewer: confirm the `DefaultToolCallingManager` resolves callbacks by
  name from the configured set only (it does in 2.0.1).

## Threat 2 — Argument tampering between approval and execution
- **Mitigation:** `PendingDecision.argsHash = SHA-256(argumentsJson)`; `DecisionResumer` recomputes the hash of the
  stored arguments before running (`ArgumentsTamperedException`, `AG-APPROVAL-004`); a re-call by the agent only
  resumes when the new arguments hash to the approved hash, otherwise a new decision is parked.
- **Residual:** the raw arguments are stored in `agentguard_decision.arguments_json` (needed to execute later). Protect
  the table like any other sensitive table; there is no encryption at rest in core (pro candidate).
- **Test:** `ToolGuardTest.tampered_arguments_between_approval_and_execution_are_refused`.

## Threat 3 — Replay of approvals
- **Mitigation:** `DecisionStore.markExecutedOnce` is a single conditional `UPDATE ... WHERE executed = false`
  (processed-event-ledger pattern); the state machine forbids leaving a terminal state; a second approve returns the
  stored result and runs nothing.
- **Test:** `JdbcAdaptersIntegrationTest.mark_executed_once_wins_exactly_once_under_concurrency` (50 threads),
  `GuardedToolCallbackTest`, `SampleEndToEndTest`.

## Threat 4 — Log injection
- **Mitigation:** `ArgumentRedactor` masks sensitive keys, masks bearer-like tokens anywhere, strips control characters
  and U+2028/2029, caps the preview at 512 chars. Only the preview reaches logs, webhooks and the endpoints; the raw
  arguments never do. Exceptions reach the model as `class: message` (300 chars), never a stack trace.
- **Test:** `ArgumentRedactorTest`, `NotifiersTest`.
- **Open:** key matching is regex-based on JSON text, not a JSON parser; nested arrays of objects are handled, but a
  value that itself contains `"password":` inside a string would also be masked (harmless). Reviewer: fuzz it.

## Threat 5 — Privilege escalation via tool chaining
- **Mitigation:** every call is evaluated on its own with the caller's principal; budgets have a `CONVERSATION`
  scope (`kind: STEPS`) so a chain cannot loop forever inside one conversation.
- **Open:** the conversation id must be supplied (Spring AI `ToolContext` key `agentguard.conversationId` or
  `chat_memory_conversation_id`; MCP `_meta.agentguard.conversationId`). Without it the STEPS limit is skipped.

## Threat 6 — Audit tampering
- **Mitigation:** hash chain (`hash = SHA-256(canonical(row) || prevHash)`), appends serialised by a PostgreSQL
  transaction-scoped advisory lock, table trigger raising on UPDATE/DELETE, `AuditChainVerifier`.
- **Residual:** a DBA with `DROP TRIGGER` rights can still rewrite; the chain makes it detectable, not impossible.
  Anchoring the head hash elsewhere (pro: export + external timestamp) is the answer.
- **Test:** `JdbcAdaptersIntegrationTest.audit_*`, `AuditChainVerifierTest`.

## Operational hazards found while building
- **Redis + virtual threads on JDK 21:** Jedis pools borrow connections under `synchronized`, which pins virtual threads.
  With more concurrent tool calls than carrier threads the JVM deadlocks. Either size `JedisPooled` above the expected
  concurrency, run tool execution on platform threads, or use JDK 24+ (JEP 491). The integration test uses platform
  threads on purpose.
- **Fail-closed on audit failure:** if the audit sink throws, the tool call fails (`AuditRecorder` propagates).
  Intentional; document for ops.
- **Endpoints:** `/agentguard/**` has no built-in authentication; the sample restricts it to `ROLE_APPROVER`. The
  starter must not ship without that sentence in the docs.

## Reviewer checklist (to complete before the first public release)
- [ ] Dependency scan (`./mvnw -Psecurity-scan verify`) clean or triaged.
- [ ] Fuzz `ArgumentRedactor` with adversarial JSON.
- [ ] Confirm no secret / PII reaches logs in the sample run (grep the log for `hunter2`, `Bearer `, IBAN-like patterns).
- [ ] Review `schema-postgresql.sql` grants: application role should have INSERT on `agentguard_audit`, no UPDATE/DELETE.
- [ ] Threat model the webhook (SSRF: the URL is operator-configured, not user-supplied; document).
