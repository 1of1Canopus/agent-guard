# Security review: docs/version-0.1.3-and-boot-line (PR 57)

## Pass 1 (2026-10-29)

Scope: docs only. README.md, docs/index.md, context7.json, CHANGELOG.md. Register row B-DOC-1.
Reviewed commit: 94b7b49.

**Verdict: MERGE.** No findings.

### 1. Version 0.1.2 to 0.1.3

- Latest tag: `v0.1.3`. Maven Central `maven-metadata.xml`: `latest` and `release` are `0.1.3`.
- The three changed coordinates now read 0.1.3.
- Every remaining `0.1.2` in `*.md` and `*.json` was read. Each one is deliberate: the
  upgrading guide file name and its text, the security advisories (affected ranges "0.1.0 to
  0.1.2"), the 0.1.2 changelog entry, and "from 0.1.2" feature history. No coordinate was missed.
  None of the deliberate references was changed.

### 2. Spring Boot 4.0.x to 4.1.x

- `pom.xml`: parent `spring-boot-starter-parent` 4.1.1, `spring-boot.version` 4.1.1.
- The resolved Boot 4.1.1 BOM pins Spring Framework 7.0.9, so "Spring Framework 7" stays right.
- `spring-ai.version` 2.0.1, so "Spring AI 2.0.x" stays right.
- No other "4.0.x" line remains in the public text.

### 3. Property row `agentguard.endpoints.require-tenant`

- `AgentGuardProperties.Endpoints.requireTenant` defaults to `true`. The row's meaning matches
  the javadoc and `AgentGuardEndpoints.approverTenant()`, which throws `MissingTenantException`
  (403, `AG-HTTP-403`) when tenant scoping is on and the resolver returns no tenant.
- Existing coverage: `CipherProbeCleanEndpointsTest.an_approver_without_a_tenant_is_refused`.
  It covers the list endpoint only.
- The row also says "deciding". The review therefore ran its own probe, kept outside the
  repository: a tenantless approver against all six paths (list, get, arguments, audit,
  approve, reject). Result: 403 on all six, and the decision stays `PENDING`. A control test
  (an approver with a tenant) gets 200.
- Mutation: with `agentguard.endpoints.require-tenant=false` the probe goes red
  (`expected 403 but was 200` on the list path). So the probe tests the rule.
- Existing probes re-run: `CipherProbeCleanEndpointsTest` (2) and
  `CipherProbeReverifyStartupTest` (1), green.

Recommendation, not a finding: add the six-path probe in its own test PR, so the approve
and reject paths have a regression test.

### Public text

- Changed lines name no person or agent and no machine path. The PR body uses no names.
- The only brand string in changed text is the Maven group id `com.housedevinci`, which is
  correct as written.
- No changed line says "compliant", "proof", "tamper-proof", "immutable", "secure",
  "guarantee" or a bare "append-only".
