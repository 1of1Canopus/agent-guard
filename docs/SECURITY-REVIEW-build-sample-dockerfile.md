# Security review: sample container over stdio (PR 56, `build/sample-dockerfile`)

## 2026-10-28, pass 1

**Verdict: MERGE.** Two LOW findings in this pull request, both in CI scripts, both fixed in
this pass by the security review (script fixes, probes red first). One MEDIUM finding outside
this diff (on main since 0.1.0) goes to its own pull request and blocks the next tag, not
this merge.

Reviewed tree: `fc4ac7f` (builder head). Review commits on top: `d3bec45` (probe, red),
`8c71437` (probe fix), `6b2145b` (check fix), and this document.
Threat list: the seven points of the review brief (profile reach, policy under stdio, stdout
purity, image, CI job, reference guard, release hygiene). Every point was run, not read.

### Numbers

| Check | Result |
|---|---|
| `./mvnw -B verify` (Docker up, tests run) | exit 0; core 206, starter 132 (1 skipped), sample 4; 342 tests, 0 failures, 0 errors |
| Skipped test | `CipherProbeFinalSpringAiTest` assumption skip (needs an extra Spring AI jar; skipped since it was written, not passing) |
| `./mvnw -B verify -Prelease -Dgpg.skip=true` (tests run again) | exit 0; same counts; 7 jars built |
| `Dockerfile`, `.dockerignore`, `check-sample-container`, `application-stdio`, `logback-spring` in core and starter jars (main, sources, javadoc) | 0 entries in each of the 6 published jars; the stdio profile and logback file are in the sample jar only (not published, `excludeArtifacts`) |
| `tools/check-private-references.sh --tree` | tree clean (before the push, this document included) |
| `tools/check-private-references.sh --jars agent-guard-core agent-guard-spring-boot-starter` | every built jar clean |
| `tools/cipher-probe-release-pipeline.sh` (no Maven probes; copies of the tree) | baseline and mutated `ci.yml` gave the same output before this pass; after: the two new probes FIXED, 0 new WEAK |
| `tools/cipher-probe-dependabot.sh` | 51 fixed, 0 weak (before and after) |
| `tools/check-sample-container.sh` on the built image | exit 0 |
| New probes this pass | 3, all RED on `fc4ac7f` |

### Findings

| Id | Severity | Class | Probe | Status |
|---|---|---|---|---|
| B-PR56-1 | LOW | CI gate wiring | `probe_sample_container_can_be_switched_off` (in `tools/cipher-probe-release-pipeline.sh`) | fixed in this pass (`8c71437`) |
| B-PR56-2 | LOW | test asserts half the claim | `probe_read_tool_open_to_anonymous_passes_the_check` (container mutation, below) | fixed in this pass (`6b2145b`) |
| B-PR56-3 | MEDIUM | fail-open default, silent | `probe_guard_switched_off_runs_annotated_tools_without_a_warning` (container run, below) | open, own pull request, blocks the next tag |

#### B-PR56-1 (LOW): the Sample container job could be switched off with every probe green

The job is listed in `.github/required-checks.txt`, so a rename is caught by the existing
drift probe. But a job-level `if: false` (GitHub counts a skipped job as a passed required
check), `continue-on-error: true`, `run: true # <command>` or `<command> || true` left both
probe suites unchanged. Repro: two copies of the tree, one with `run: true # CHECK_DEADLINE...`
on the check step; both suites printed the same result on both copies. (`if: false` alone
happens to be caught by actionlint's constant-condition rule; the other three forms are not.)

Fix (script, applied): `probe_sample_container_is_not_wired_unconditionally` requires the job
under its required-check name, no job-level guard, both `run:` values string-equal to the
build and check commands with no step guard (same helper as the reference guard, B-NG-4), and
an uncommented `docker run -i --rm --name "$name" --network none "$image"` in the check script.
`probe_sample_container_can_be_switched_off` applies seven edits (job `if: false`, job
`continue-on-error`, decorated run line, `|| true`, step `continue-on-error`, step `if: false`
on the build, display-name rename) to a scratch `ci.yml` and requires the wiring probe to go
WEAK on each. It was WEAK on `d3bec45` and FIXED on `8c71437`. Removing `--network none`
from the script turns the wiring probe WEAK (checked by hand on a copy).

#### B-PR56-2 (LOW): the container check asserted the refusal of one tool out of two

The profile comment, the Dockerfile and the CHANGELOG say every tool call is refused over
stdio. The check called only `refund_order`. Repro: a copy of the tree with `get_order`
reduced to `@ToolPolicy` (no roles, "no restriction"), image rebuilt; the check exited 0
while the probe client read `SHIPPED` from `get_order` with no principal.

Fix (script, applied): the check also calls `get_order` and requires `isError: true` with
`AG-POLICY-001`. On the rebuilt mutant it now exits 1 ("get_order (read only) was not refused
over stdio"); on the real image it exits 0. The other two mutations were re-run on the new
script and stay red: banner on stdout (`-Dspring.main.banner-mode=console`) fails with "stdout
carries a line that is not JSON-RPC"; profile `default` fails with no `initialize` answer.

#### B-PR56-3 (MEDIUM, not introduced here): the guard switched off runs annotated tools with no warning

`agentguard.enabled` defaults to `false`, and every auto-configuration of the starter is
conditional on it. With it off, a method carrying `@ToolPolicy(roles = "AGENT", sideEffect =
WRITE)` runs for anyone and the application logs nothing about it. Repro on the image of this
pull request: `docker run -i --network none -e AGENTGUARD_ENABLED=false <image>`; the probe
client called `refund_order` with no principal and got `refunded 42`, three times; stderr has
no WARN or ERROR about the guard. A developer who adds the starter and the annotations but
forgets one property gets no protection and no signal. This breaks the line's rule that a
weaker mode is explicit and warns at every start.

Not caused by this diff (on main since 0.1.0), so it is not fixed here (one mechanism per pull
request). Required property for its own pull request: when the guard is off and at least one
`@ToolPolicy` is present (MCP tool, Spring AI tool, or plain bean method), the application
logs a WARN at every start that names the policies left unenforced, and an explicit choice
exists to refuse the start instead. Whether the default itself should become fail-closed is a design question for the
builder's one-page design, reviewed before code. Paths the design must cover: MCP sync and
stateless specifications, Spring AI `ToolCallback` beans, `ChatClient` default tools.

### Points checked with no finding

1. **Profile reach.** `application-stdio.yml` and `logback-spring.xml` exist only in the
   sample module; neither is in a core or starter jar (listings above). The profile sets only
   properties that already existed (`agentguard.store=MEMORY`, `agentguard.endpoints.enabled=
   false`, web type none). It turns no control off: the policy refused both tools, the
   in-memory store printed its WARN, the unkeyed-audit WARN printed (from the sample's base
   `application.yml`). Copying the profile into another application keeps that application's
   policies; a tool with no roles would run for a stdio caller, which is the documented meaning
   of an empty `@ToolPolicy`, the same as over HTTP.
2. **Policy under stdio.** Run against the built image with no network: `get_order` and
   `refund_order` refused with `AG-POLICY-001`; `GET_ORDER`, `get_order ` (trailing space),
   fullwidth `ｇet_order`, `sample/get_order`, `refund_order` + NUL, `refund` + zero-width
   space + `_order`, missing name: all `-32602 Tool not found`, nothing run. JSON escape
   `get_order` and a duplicate `name` key (last wins: `refund_order`) both reach the
   policy under the name the SDK dispatches, and are refused. A 200 kB argument is refused
   with `AG-APPROVAL-009` before the policy. After all of that, `refund_order` is still
   refused. `resources/list` and `prompts/list` are empty. No stack trace or internal path on
   stdout. Stderr carries stack frames only for the malformed-input cases below.
3. **stdout purity.** 0 non-JSON-RPC lines on stdout across three runs (normal, abuse,
   guard off). The banner, the in-memory WARN and every Spring line went to stderr.
4. **Image.** Both base digests resolve (`docker buildx imagetools inspect`) to OCI
   multi-architecture indexes. Final image: user `10001:10001`, no exposed port, no
   HEALTHCHECK, `SPRING_PROFILES_ACTIVE=stdio` the only added variable. `/app` holds
   `app.jar`, `LICENSE`, `NOTICE`, all root-owned and not writable by uid 10001; no `/src`,
   no `.git`, no `.m2`, no `settings.xml`, no `.env`, no `mvnw`, no `unzip`. `.dockerignore`
   starts with `*` and re-admits only the build inputs; untracked files inside the module
   folders reach the build stage only, and the final stage copies three named files.
5. **CI job.** Network is off at run time (`--network none` in the script, now probed).
   Build-stage network is needed for Maven and is pinned by the wrapper checksum.
6. **Reference guard and public text.** Tree and jar guards exit 0. The PR body and every new
   file use roles only.
7. **Release hygiene.** See the jar listing row: no container file in a published jar.

### Reclassified after a repro attempt (no code change)

- **A truncated JSON line ends the stdio session.** `{"jsonrpc":"2.0","id":34,...,"params":{"name":`
  makes the SDK transport log `Error processing inbound message` and the process exits 0.
  Upstream SDK behaviour; a stdio server has exactly one client, which can only stop its own
  session. Not a finding.
- **`arguments` as a string returns JDK and SDK class names** (`java.util.LinkedHashMap`,
  `io.modelcontextprotocol.spec.McpSchema$CallToolRequest`) in the `-32603` message. Raised by
  the SDK before the guard runs; names of public open-source classes, no version, no path, no
  stack, no secret; same answer over HTTP. Not a finding.

### Hand-off

- B-PR56-1, B-PR56-2: fixed in this pass; no further action on this pull request.
- B-PR56-3: DESIGN STOP. The builder writes a one-page design (property and paths above),
  the security review reviews it, then the build in its own pull request before the next tag.
