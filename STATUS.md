# STATUS.md - Module B - Agent Guard, free core (run 16: Isis closes the clean-verdict pass findings)

Licensing (2026-09-08): free core switched from Apache-2.0 to FSL-1.1-ALv2 (Souhaile's decision); `LICENSE`/`NOTICE`/`pom.xml` updated, `./mvnw -B clean verify` and `-Prelease` re-confirmed green.

Branch `feat/release-pipeline` in `modules/B-agent-guard/`, cut from `main` at `f120608`
(merge of PR #8), pushed to `origin` (https://github.com/1of1Canopus/agent-guard.git).
Pro edition out of scope.

## Closed finding (Cipher, final confirmation pass at `cae839e`; fixed by Isis, 2026-09-09)
- **G3 (LOW)** closed — `ci.yml`'s `dco` job now exempts a merge only when it is a trivial
  back-merge of the base (`git merge-tree --write-tree` check). Confirmed by the probe and by
  six cases run against the committed step body, including an octopus merge, a two-parent
  merge whose second parent is not from the base, and a back-merge that smuggles an extra
  file past the tree check. All correct.

## Closed finding (Cipher, final verdict pass at `5cac151`; fixed by Isis, 2026-09-09)
- **G4 (LOW)** closed — `dco` step's `auto=` substitution is now guarded by an `if` so `git merge-tree`'s non-zero exit on a conflicted merge no longer trips `set -e`; `auto` stays empty and the merge falls through to the sign-off check with a visible `::error::` instead of the step aborting silently; probe `probe_dco_step_aborts_silently_on_a_conflicted_back_merge` now FIXED, suite reads `still weak: 0    fixed: 36`.

## Verdict (Cipher, final verdict pass at `3a0cb46`, 2026-09-09) — **MERGE**

Every finding opened on this branch is closed: M1–M7, L1–L7, I1–I4, N1–N11, F1–F9, G1–G4.
No HIGH, no MEDIUM, no LOW, no INFO open. Fresh clone at `3a0cb46`: `./mvnw -B clean verify`
**BUILD SUCCESS** 49.6 s, **220 tests, 0 failures, 1 documented assumption skip**, JaCoCo line
**90.60 %**, release profile green, **6 of 6 artifacts byte-identical** across two clean builds,
probe suite **`still weak: 0    fixed: 36`** exit 0, CI green on both jobs. G4 re-verified by the
probe, by a control run against the pre-fix step body, and by eight cases against the committed
`dco` step body. Detail and Souhaile's nine-step release checklist:
`docs/SECURITY-REVIEW-feat-release-pipeline.md`, "Final verdict (3a0cb46): MERGE".

## After merge
- Delete the `GRANDFATHER_SHA` exemption (env var + `git cat-file`/`merge-base --is-ancestor`
  block) from `ci.yml`'s `dco` job once PR #9 is merged into `main` — QUESTIONS.md #29/#33.

## Summary (run 16)
**Done.** Closed both findings from Cipher's clean-verdict pass at `fad6659`
(`docs/SECURITY-REVIEW-feat-release-pipeline.md`, "Clean-verdict pass (`fad6659`)"): G1
(MEDIUM), G2 (LOW). Full detail in `CHANGELOG.md`'s "Fixed (Cipher clean-verdict pass)"
entry; commits carry `Cipher-Finding:` footers per id.

`tools/cipher-probe-release-pipeline.sh` with `CIPHER_PROBE_MAVEN=1`: **34/34 probes
FIXED**, script exits **0**.

| Item | State |
|---|---|
| `./mvnw -B verify` (fresh state) | green, 220 run, 0 failures, 0 errors, 1 skipped (pre-existing, unrelated) |
| `./mvnw -B -Prelease -DskipTests -Dgpg.skip=true install` | green |
| `scripts/verify-reproducible.sh` | 6/6 jars byte-identical |
| `tools/check-third-party-licences.sh --self-test` | all cases correct, incl. G1's forward-forgery, legitimate nested-paren URL and parenthesised-name rows |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | 34/34 FIXED, exits 0 |
| Real corpus (`check-third-party-licences` Maven execution) | clean, 0 regressions |
| GitHub CI on the pushed branch, incl. `dco` job | see PR #9 checks |
| Docker | up; no test skipped for want of it |

QUESTIONS.md #29 ruling confirmed and recorded as #33: the `GRANDFATHER_SHA` exemption stays
for this PR; deletion is a follow-up PR after #9 merges (see "After merge" above).

## Summary (run 15)
**Done.** Closed all nine items from Cipher's final verification at `78c808e`
(`docs/SECURITY-REVIEW-feat-release-pipeline.md`, "Final verification (78c808e)"): F2
(MEDIUM), F1/F3/F4/F5/F7/F9 (LOW), F6/F8 (INFO). Full detail in `CHANGELOG.md`'s "Fixed
(Cipher final verification)" entry; commits carry `Cipher-Finding:` footers per id.

`tools/cipher-probe-release-pipeline.sh` with `CIPHER_PROBE_MAVEN=1`: **32/32 probes
FIXED**, script exits **0**.

| Item | State |
|---|---|
| `./mvnw -B clean verify` (3 consecutive runs) | green x3, no flake |
| `./mvnw -B clean verify -Prelease -Dgpg.skip=true` | green |
| `scripts/verify-reproducible.sh` | 6/6 jars byte-identical |
| `./mvnw -B verify` on a fresh `git clone` | green |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | 32/32 FIXED, exits 0 |
| `--self-test` | all cases correct, incl. F2/F4/F5's new rows |
| GitHub CI on the pushed branch | see PR #9 checks |
| Docker | up; no test skipped for want of it |

F3 additionally verified against two throwaway GPG keys (a primary-only key and a
primary-with-signing-subkey key), signing a real tag with `git tag -s -u <primary>` in both
cases: the fixed `VALIDSIG` match binds the primary fingerprint for both key shapes; the old
regex only matched the primary-only shape. F1 additionally verified with three real builds
against a scratch dependency under `com.housedevinci-evil`, `xcom.housedevinci`, and (control)
the real `com.housedevinci` groupId - see `CHANGELOG.md` for the outcomes.

`QUESTIONS.md` #28 (new): whether `license-maven-plugin`'s `excludedGroups` can exclude a
dependency from the licence *gate* without also excluding it from the *notices file* -
checked in the plugin's own bytecode; it cannot, one filter drives both. Not a live gap here:
the only excluded groupId is this project's own, which is correctly absent from a
*third*-party notices file.

## Summary (run 14)
**Done.** Closed all twelve items from Cipher's re-verification at `30aec6f`
(`docs/SECURITY-REVIEW-feat-release-pipeline.md`, "Re-verification (30aec6f)"): N1-N4
(MEDIUM), N5-N8 (LOW), N9-N12 (INFO, including I1 from the first pass, never actually closed
there). Full detail in `CHANGELOG.md`'s "Fixed (Cipher re-verification)" entry; commits
carry `Cipher-Finding:` footers per id.

N1 was flagged a merge blocker independent of severity - `./mvnw verify` failed on any
fresh clone, which meant `ci.yml` was red on every push of this branch. Proved fixed on an
actual fresh `git clone` + `./mvnw -B verify` (BUILD SUCCESS), not just by reading the diff.

`tools/cipher-probe-release-pipeline.sh` with `CIPHER_PROBE_MAVEN=1`: **23/23 probes FIXED**,
script exits **0**.

| Item | State |
|---|---|
| `./mvnw -B clean verify` | green |
| `./mvnw -B clean verify -Prelease -Dgpg.skip=true` | green |
| `scripts/verify-reproducible.sh` | 6/6 jars byte-identical |
| `./mvnw -B verify` on a fresh `git clone` | green (N1) |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | 23/23 FIXED, exits 0 |
| `deploy -Prelease` on a `versions:set 0.1.0` clone, fake token | bundle built at `target/central-publishing/central-bundle.zip` (45 files, no `agent-guard-sample`, all three coordinates present), upload stopped at the Portal's 401 - proves N4's assertion step now points at the real path |
| GitHub CI on the pushed branch | see PR #9 checks |
| Docker | up; no test skipped for want of it |

One correction made along the way, not a finding: the N11 fix's first pass introduced an
invalid `--` sequence inside an XML comment in `pom.xml` (illegal in XML comments), caught
by the fresh-clone `verify` run and fixed in a follow-up commit before the branch was
considered done - see the two `fix(release): ... N11 ...` commits.

## Summary (run 13)
**Done, under the no-allowance rule.** Closed every MEDIUM (M1-M7), every LOW (L1-L7) and
the one INFO that needed a code change (I4) from
`docs/SECURITY-REVIEW-feat-release-pipeline.md`. Full detail in `CHANGELOG.md`'s "Fixed
(Cipher security review)" entry; commits carry `Cipher-Finding:` footers per id.

`tools/cipher-probe-release-pipeline.sh`: **12 of 13 probes FIXED**, script still exits 1
(pass count is 1, not 0 - the inversion the script documents). The one remaining WEAK probe,
`probe_mvnw_skips_checksum_for_existing_distribution`, is a static check of the vendored
`mvnw` script's general behaviour (any Maven Wrapper script execs an already-unpacked
distribution with no re-check). I looked at patching `mvnw` to flip it and rejected the
patch: the only marker that would satisfy the probe (a sidecar checksum file written at
install time) is exactly as forgeable by the attacker M3 describes as the distribution
itself, so it would flip the probe without closing the actual threat - the same failure
mode as weakening a probe to make it pass, one level removed. The real fix for M3 is
applied and does close the threat: the signing job no longer caches or restores
`~/.m2/wrapper/dists`, and deletes any pre-existing one before `mvnw` runs, so the
unverified-exec branch is unreachable there. Full reasoning: QUESTIONS.md #27. Flagging
this first, as the one item not closed by a probe flip, per Isis's method step 3.

| Item | State |
|---|---|
| `./mvnw -B clean verify` | 220 tests, 1 skip, 0 failures |
| `./mvnw -B clean verify -Prelease -Dgpg.skip=true` | green |
| `scripts/verify-reproducible.sh` | 6/6 jars byte-identical, now also writes a checksum file |
| `tools/cipher-probe-release-pipeline.sh` | 12/13 FIXED (see above) |
| Coverage gate | unchanged, held |

One flaky-under-load test observed and not touched: `CipherProbeJedisFactoryTest` failed
once inside a full-suite `clean verify` run (a Redis-pool timing assertion), passed cleanly
both in isolation and on a second full-suite run. Not caused by anything in this run - no
Jedis/Redis code was touched - and not a probe this run owns; noted for whoever next
touches `agent-guard-spring-boot-starter`'s concurrency tests (see the parked Jedis 8
migration entry below).

### What only Souhaile can do (added this run, on top of run 12's list)
`docs/RELEASING.md` Part 1 step 6 and Part 2 step 1 have the full checklist. New since run 12:
1. Make the repository public before tagging `v0.1.0` (M5's `environment: release` and
   GitHub's tag rulesets do not exist on a private free-plan repo; L7).
2. Create the `release` environment with Souhaile as required reviewer, and move the four
   secrets from repository secrets into it (M5).
3. Set the `RELEASE_SIGNING_KEY_ID` repository **variable** (not secret) to the long id of
   the key release tags are signed with, and tag with `git tag -s`, not `-a` (M5).
4. Confirm `security@housedevinci.com` forwards, same as `oss@housedevinci.com` (`SECURITY.md`, L6).

## Summary (run 12)
**Done.** `agent-guard-core` and `agent-guard-spring-boot-starter` are one command away from
Maven Central. `./mvnw -B clean deploy -Prelease` builds, tests, licence-checks, signs and
uploads a bundle to the Sonatype Central Portal, where it stops: `autoPublish=false`, so the
last action is Souhaile pressing Publish. The sample is never published.

| Item | State | Proof |
|---|---|---|
| Central publishing plugin | `org.sonatype.central:central-publishing-maven-plugin` 0.11.0, `autoPublish=false`, `waitUntil=validated` | bundle built and rejected only at the Portal's 401 for a fake token |
| Publish set | parent POM + core + starter, 54 files | `unzip -l target/central-publishing/central-bundle.zip`: no `agent-guard-sample` |
| Signing | `maven-gpg-plugin` 3.2.8, key from `GPG_PRIVATE_KEY` | 9 `.asc` files, `gpg --verify` good, on a throwaway key |
| POM metadata | name, description, url, licence, developers, scm, inceptionYear, issueManagement | in the bundle's `agent-guard-core-0.1.0.pom` |
| Reproducible build | `project.build.outputTimestamp` from the commit date | `scripts/verify-reproducible.sh`: 6/6 jars byte-identical over two clean builds |
| Licence gate | allowlist `Apache-2.0 MIT BSD EPL-2.0 Public Domain`, `force=true` | narrowing to `MIT` fails the build; the old blocklist was a no-op on incremental builds |
| Workflow | `.github/workflows/release.yml`, tag `v*` or `workflow_dispatch` | actions pinned by full SHA, verified against the GitHub tag API |
| Full suite | 220 tests, 1 skip, 0 failures, under `-Prelease` too | `./mvnw -B clean verify -Prelease -Dgpg.skip=true`, BUILD SUCCESS in 51s |

`main` stays on `0.1.0-SNAPSHOT`. The release version comes from the tag (`v0.1.0` -> `0.1.0`)
or the workflow input, and the workflow rewrites the POMs inside the runner's checkout only;
nothing is committed back and a `-SNAPSHOT` can never be released.

### Numbers
| Run | Tests | Failures | Skips | Time |
|---|---|---|---|---|
| `./mvnw -B clean verify` (baseline, `f120608`) | 220 (core 161, starter 58, sample 1) | 0 | 1 | 1:06 |
| `./mvnw -B clean verify -Prelease -Dgpg.skip=true` | 220 | 0 | 1 | 0:51 |
| `scripts/verify-reproducible.sh` | n/a | 0 | n/a | 6/6 jars identical |

The one skip is pre-existing and unrelated: a starter context test that needs Spring AI's real
`ToolCallingAutoConfiguration` on the test classpath.

### What only Souhaile can do
The `com.housedevinci` namespace is verified (2026-09-08). What is left:
1. Add the four repository secrets: `CENTRAL_USERNAME`, `CENTRAL_TOKEN`, `GPG_PRIVATE_KEY`,
   `GPG_PASSPHRASE`.
2. Make sure the signing key is on `keyserver.ubuntu.com`.
3. Make `oss@housedevinci.com` forward somewhere real before 0.1.0 goes out (QUESTIONS #21).
4. Press Publish on the Portal, the first time and every time.
Full instructions: `docs/RELEASING.md`.

### Open questions from this run
QUESTIONS.md #21 (role email, needs confirmation), #22 (licence allowlist, decided),
#23 (keyserver, decided), #24 (javadoc reproducibility, decided), #25 (plugin choice, decided),
#26 (notices file inside the jars, open, low).

### Deliberately left out
- `THIRD-PARTY-NOTICES.txt` is not placed in `META-INF/` of the jars (QUESTIONS #26): it changes
  jar contents and needs a decision about what the starter's notices should list.
- No GitHub Release is created and no tag is pushed by the workflow. `permissions: contents: read`
  is worth more than the convenience, and the release notes are a human's job anyway.
- The workflow was not executed: it needs the four secrets. Everything it runs was executed
  locally instead, including the upload, which failed only at the Portal's authentication.

## Summary (run 11)
**Done.** Isis closed K1 (LOW) from Cipher's final verdict on `05f209d`
(`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, final section): the J1 fix scoped the schema-predates guard to
search_path *visibility* (`to_regclass`, which resolves like a reference — first schema on the search_path
holding the name, anywhere along the path), while the unqualified `CREATE TABLE IF NOT EXISTS agentguard_audit`
targets only `current_schema()`, the first *existing* entry — narrower than J1's original bug but not closed. A
pre-redesign copy in a schema on the search_path but behind the creation schema was still refused, even though
the step would have created a correct new table ahead of it. Fixed exactly as Cipher prescribed: both oids now
resolve via `to_regclass(quote_ident(current_schema()) || '.agentguard_audit')` /
`... '.agentguard_audit_anchor'`, declared once in a `DO $$ DECLARE` block, with `quote_ident` (required, not
decoration — a schema with capitals or a dot would otherwise be re-parsed as a different name).

`CipherProbeFinalVerdictJdbcTest.probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install`
inverted from asserting the refusal to `assertThatCode(...).doesNotThrowAnyException()`; J1's own probe
(`CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install`) and both
G1/G2 same-schema probes (`probe_a_fresh_empty_database_never_trips_the_predates_guard`,
`probe_the_predates_message_offers_no_in_place_upgrade`) are unchanged and still green, as are
`CipherProbeFinalVerdictJdbcTest`'s other three recorded (non-finding) probes K2–K4.

`./mvnw -B clean verify` is green: **220 tests** (core 161, starter 58 + 1 self-skipping — needs Spring AI's real
`ToolCallingAutoConfiguration` on the test classpath, pre-existing and unrelated to K1 — sample 1 end-to-end), 0
failures. Core line coverage **90.60%** (gate 80% line, held; JaCoCo CSV, `LINE_COVERED`/`(LINE_COVERED+LINE_MISSED)`
over `agent-guard-core/target/site/jacoco/jacoco.csv`) — unchanged from run 10, this is a two-clause SQL rewrite
plus one inverted probe, not a new production branch. No pushback filed; fix matched Cipher's prescription
exactly.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| K1 | LOW | Schema-predates guard resolves both oids via `to_regclass(quote_ident(current_schema()) || '.<table>')`, scoped to the creation schema instead of search_path visibility. | `CipherProbeFinalVerdictJdbcTest.probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install` |

Full table below (run 10 and earlier) unchanged.

## Summary (run 10)
**Done.** Isis closed J1 (LOW) from Cipher's clean verdict on `f27c45e`
(`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Clean verdict (f27c45e)"): the schema step's pre-redesign guard
matched `information_schema.tables`/`.columns` with no `table_schema` filter, so a stale `agentguard_audit` left in
another schema the role can see permanently blocked a fresh install in the current schema, even though every other
statement in the step is search_path-relative. Fixed as Cipher prescribed: both existence checks now resolve
through `to_regclass('agentguard_audit')` / `to_regclass('agentguard_audit_anchor')`, and both column checks look
up `key_id`/`keyed` via `pg_attribute` against that same oid (`attnum > 0 AND NOT attisdropped`) instead of
scanning `information_schema` unscoped.

`CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install` inverted from
asserting the refusal (the reproduction) to `assertThatCode(...).doesNotThrowAnyException()` (the fix); the G1/G2
same-schema probes (`probe_a_fresh_empty_database_never_trips_the_predates_guard`,
`probe_the_predates_message_offers_no_in_place_upgrade`) are unchanged and still green — a pre-redesign table in
the *current* schema is still refused with the same message.

`./mvnw -B clean verify` is green: **215 tests** (core 156, starter 58 + 1 self-skipping — needs Spring AI's real
`ToolCallingAutoConfiguration` on the test classpath, pre-existing and unrelated to J1 — sample 1 end-to-end), 0
failures. Core line coverage **90.60%** (gate 80% line, held; JaCoCo CSV, `LINE_COVERED`/`(LINE_COVERED+LINE_MISSED)`
over `agent-guard-core/target/site/jacoco/jacoco.csv`) — unchanged from run 9, this is a two-clause SQL rewrite plus
one inverted probe, not a new production branch.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| J1 | LOW | Schema-predates guard resolves both tables via `to_regclass(...)` and both columns via `pg_attribute` against that oid, instead of unscoped `information_schema`. | `CipherProbeCleanVerdictJdbcTest.probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install` |

Full table below (run 9 and earlier) unchanged.

## Summary (run 9)
**Done.** Isis closed all six findings from Cipher's verification of keyed-from-birth (`722e9a5`,
`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, "Verification of keyed-from-birth"): G1/G2 MEDIUM, H1/H2 LOW,
H3/H4 INFO. Dollar's ruling: this branch is unreleased, so there is no upgrade path from a pre-redesign database —
G1/G2's backfills are deleted, not repaired.

- **G1/G2:** `agentguard_audit.key_id` and `agentguard_audit_anchor.keyed` are now `NOT NULL` in the `CREATE TABLE`
  bodies, no backfill. The schema step checks up front whether either table exists without its keyed-from-birth
  column and fails startup with "audit schema predates keyed-from-birth; archive the table and start a new trail
  (see SECURITY-NOTES)" instead of aborting later on a trigger or a missing-column INSERT error. Still idempotent
  on a database created by this version.
- **H1:** `auditKeyring` fails startup when an `agentguard.audit.hmac-keys.<id>` entry reuses the appending
  `hmac-key-id` with a different secret, naming both properties; the identical-secret case stays a no-op.
- **H2:** `auditChain` fails startup when `agentguard.audit.unkeyed=true` and `agentguard.audit.hmac-secret` are
  both set, naming both properties.
- **H3:** `InMemoryAuditSink` javadoc + SECURITY-NOTES now say plainly that its anchor is self-derived and cannot
  detect its own tail being trimmed. Doc-only, no behaviour change.
- **H4:** SECURITY-NOTES' status list now includes `INTACT_UNKEYED`.

`./mvnw -B clean verify` is green: **207 tests** (core 151, starter 55 + 1 self-skipping — needs Spring AI's real
`ToolCallingAutoConfiguration` on the test classpath — sample 1 end-to-end), 0 failures. Core line coverage
**90.60%** / branch **78.14%** (gate 80% line, held; unchanged from Cipher's measurement — these are SQL/message
fixes plus one new regression test, not new production branches). Cipher's `CipherProbeKeyedBirthJdbcTest` (G1/G2)
and `CipherProbeKeyringTest` (H1/H2) probes updated in place to assert the new refusal instead of the old bug;
`CipherProbeMemoryParityTest` (H3) unchanged and still green (doc-only fix). Full table below the run-8 summary.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| G1 | MEDIUM | `agentguard_audit.key_id NOT NULL` in `CREATE TABLE`, no backfill; schema-predates guard fails startup with a clear message. | `CipherProbeKeyedBirthJdbcTest.probe_an_existing_database_with_rows_cannot_run_the_new_schema_step` |
| G2 | MEDIUM | `agentguard_audit_anchor.keyed NOT NULL` in `CREATE TABLE`, no backfill; same guard covers the anchor. | `CipherProbeKeyedBirthJdbcTest.probe_an_existing_anchor_row_cannot_be_backfilled_with_keyed` |
| H1 | LOW | `auditKeyring` fails startup on an id/secret mismatch with the appending key, naming both properties. | `CipherProbeKeyringTest.probe_a_retired_key_entry_can_shadow_the_appending_key`, `.confirms_a_retired_key_entry_matching_the_appending_secret_is_a_noop` |
| H2 | LOW | `auditChain` fails startup on `unkeyed=true` + `hmac-secret` set, naming both properties. | `CipherProbeKeyringTest.probe_unkeyed_true_with_a_secret_is_silently_ignored` |
| H3 | INFO | Javadoc + SECURITY-NOTES: `InMemoryAuditSink`'s anchor is self-derived, no tail-deletion detection. | `CipherProbeMemoryParityTest.probe_a_memory_trail_has_no_external_anchor` (unchanged, still documents the behaviour) |
| H4 | INFO | SECURITY-NOTES status list now lists `INTACT_UNKEYED`. | Manual doc review |

## Summary (run 8)
**Done.** Cipher's final-verification pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, `25da6af`) found run 7's
external anchor (`keyed_from_seq`) had its own plumbing wrong: F1 (MEDIUM, written from `row_count + 1` instead of
the row's real `seq`, so an ordinary sequence gap makes an untampered trail permanently `BROKEN`), F2 (MEDIUM, the
schema's anchor seed forgot to derive `keyed_from_seq`, beating the sink's own re-derivation on a lost-anchor
install), F3 (MEDIUM, no DELETE/TRUNCATE guard on the anchor and a silent fallback to `INTACT` when it is
missing), F4 (LOW, a still-unkeyed instance mid rolling-restart could append after the keying point and
permanently break the trail). Rather than iterate the sequence-position mechanism again, Dollar (with Souhaile)
ruled the design itself — **keyed-from-birth**: a trail is keyed from row 1 or unkeyed forever, no mixing, no
later switch. `agentguard.audit.hmac-secret` is required by default (missing → startup fails naming the property
and the remedy, `openssl rand -base64 32`); `agentguard.audit.unkeyed=true` is the explicit, WARN-every-startup
local-dev opt-out. Which mode a trail is in is recorded once, at the first append, as a plain
`agentguard_audit_anchor.keyed` boolean, immutable afterwards (the anchor's existing monotonic trigger); every
append after that, from any instance, must agree with it or is refused (`AgentGuardException`/`AG-AUDIT-001`) —
this closes F4 by construction (fail-closed, not detectable-after-the-fact). F1/F2 do not carry forward (no
sequence position is derived any more); F3(a) — anchor DELETE/TRUNCATE triggers — ships unchanged, independent of
the migration.

Dollar then amended the ruling once more after Cipher's design review of the above, before push: (1) a key id
(`agentguard.audit.hmac-key-id`, default `k1`) is baked into every row's hashed material from row 1
(`agentguard_audit.key_id`), so rotation is a config change (add a key to `agentguard.audit.hmac-keys.<id>`,
change the appending id) rather than a trail migration — `AuditChainVerifier` holds a keyring and reports `BROKEN`
for an id it does not hold; (2) a missing anchor on a non-empty trail refuses to append (`AG-AUDIT-002`) rather
than being re-derived from the trail head — the schema seed only ever creates the anchor row for a genuinely
empty trail; (3) `NO_ANCHOR` is reported unconditionally (keyed or unkeyed), not only when a key was given; (4)
`Report` carries the trail's mode (`anchored`, `keyed`, `keyIds`) and an unkeyed trail's clean result is the
distinct `Status.INTACT_UNKEYED`, never the same word as a keyed trail's `INTACT`; (5) "start a new trail" is
documented as an owner-run procedure. `./mvnw -B clean verify` is green: **190 tests** (core 141, starter 48 + 1
self-skipping — needs Spring AI's real `ToolCallingAutoConfiguration` on the test classpath — sample 1
end-to-end), core line coverage **90.48%** / branch **78.14%** (gate 80% line, held), spotless, Error Prone,
enforcer, JaCoCo gate.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| F1 | MEDIUM (superseded, does not carry forward) | Not applicable under keyed-from-birth: there is no sequence position (`keyed_from_seq`) left to derive incorrectly — `agentguard_audit_anchor.keyed` is a constant boolean for the trail's whole lifetime. | — |
| F2 | MEDIUM (superseded, does not carry forward) | Same reason as F1: the schema seed no longer derives any value from an existing trail — see "anchor-missing refuses" below. | — |
| F3(a) | MEDIUM | `BEFORE DELETE`/`BEFORE TRUNCATE` triggers on `agentguard_audit_anchor`, created only when absent | `CipherProbeAnchorKeyingJdbcTest.anchor_delete_and_truncate_are_refused` |
| F3(b) | MEDIUM | `AuditChainVerifier.verify` reports `Status.NO_ANCHOR` (never `INTACT`/`INTACT_UNKEYED`) whenever the reader is not an `AuditAnchor`, or has no anchor row, and the trail is not empty — unconditionally, keyed or unkeyed | `AuditChainVerifierTest.a_key_given_with_no_anchor_reports_no_anchor_never_intact`, `CipherProbeAnchorKeyingJdbcTest.a_key_given_with_no_anchor_reader_reports_no_anchor_never_intact` |
| F4 | LOW (closed by construction) | `JdbcAuditSink` refuses to append (or construct) when this instance's keyed state does not match the trail's recorded `keyed`, naming `agentguard.audit.hmac-secret` and the remedy (`AG-AUDIT-001`) | `CipherProbeAnchorKeyingJdbcTest.an_unkeyed_instance_is_refused_once_the_trail_is_keyed`, `.a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed`, `.the_mismatch_is_also_refused_on_append_not_only_at_construction` |
| — | design | `agentguard.audit.hmac-secret` required by default; `agentguard.audit.unkeyed=true` explicit opt-out, WARN every startup | `AgentGuardAutoConfigurationTest.missing_hmac_secret_fails_startup_naming_the_property_and_the_remedy`, `.unkeyed_opt_out_starts_but_warns_every_time` |
| — | amendment | Key id in the hashed material from row 1; verifier keyring; unknown id `BROKEN` | `CipherProbeAnchorKeyingJdbcTest.mixed_key_rows_verify_intact_with_both_keys_in_the_keyring`, `.an_unknown_key_id_is_broken`, `.a_stale_key_second_instance_appends_but_only_verifies_with_its_own_id_in_the_keyring` |
| — | amendment | Missing anchor on a non-empty trail refuses to append (`AG-AUDIT-002`), never re-derived | `CipherProbeAnchorKeyingJdbcTest.an_orphaned_keyed_trail_without_an_anchor_refuses_to_append`, `CipherProbeReverifyJdbcTest.a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor` |
| — | amendment | `Status.INTACT_UNKEYED` distinct from `Status.INTACT` | `AuditChainVerifierTest.an_unkeyed_trail_never_renders_plain_intact` |

## Summary (run 7, prior)
**Done.** Dollar's ruling on QUESTIONS.md #20 closes V2 (MEDIUM) in full: `agentguard_audit_anchor` gets a
`keyed_from_seq` column, set once — in the same transaction as the first row a sink appends under a keyed chain —
and made immutable afterwards by extending the anchor's existing monotonic trigger (Cipher R4). Row data alone can
never tell a whole-trail downgrade to GENESIS apart from a deployment that legitimately never used HMAC (the case
`CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail`, C6, must keep
reporting `INTACT`); the external, attacker-unwritable `keyed_from_seq` is what tells the two apart.
`AuditChainVerifier` now requires every row before `keyed_from_seq` to be unkeyed and every row from it onward to
be keyed, reports a new `Status.UNKEYED` when a key is given but never used by the trail, and keeps the prior
in-trail forward-only rule as a fallback for readers without an anchor. `InMemoryAuditSink` carries the same
bookkeeping (plus a seeding constructor for continuing an existing trail under a new chain) so the fix is
store-independent. Both of Cipher's V2 scenarios — the tail-only downgrade and the original whole-trail-from-GENESIS
repro — are proven to fail (report `INTACT`) against the pre-anchor code and pass (report `BROKEN`) against this
one. `./mvnw -B clean verify` is green: **175 tests** (core 128, starter 46 + 1 self-skipping — needs Spring AI's
real `ToolCallingAutoConfiguration` on the test classpath — sample 1 end-to-end), core line coverage 90.98% /
branch 77.72% (gate 80% line, held), spotless, Error Prone, enforcer, JaCoCo gate.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| V2 | MEDIUM (closed in full) | `agentguard_audit_anchor.keyed_from_seq`: null → set once at the first keyed append, immutable after (extended monotonic trigger); `AuditChainVerifier.verify` requires rows before it unkeyed, rows from it onward keyed, else `BROKEN`; a key given with no keyed row and `keyed_from_seq` null reports `Status.UNKEYED` | `CipherProbeReverifyTest.probe_a_keyed_trail_verifies_after_it_is_rewritten_as_unkeyed` (partial/tail downgrade), `CipherProbeReverifyTest.probe_a_fully_downgraded_trail_verifies_as_broken_not_intact` (Cipher's original whole-trail repro), `AuditChainVerifierTest.a_key_given_to_the_verifier_but_never_used_by_the_sink_reports_unkeyed` |

## Summary (run 6, prior)
Cipher's re-verification pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, `## Re-verification (6f026ff)`)
found five new issues (V1 MEDIUM, V2 MEDIUM, V3 LOW, V4 LOW, V5 LOW) after the clean-verdict round. V1, V3, V4, V5
were closed on the branch, each with its probe flipped. V2 was fixed only for the *detectable* form of the attack
(a partial downgrade); the whole-trail scenario is closed in run 7 above.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| V1 | MEDIUM | `ToolGuard.guarded` applies `rejectIfTooLarge` as its first statement, before `policies.resolve` — the unregistered-tool and policy-denial paths no longer canonicalise oversized arguments | `CipherProbeReverifyTest.probe_the_denial_paths_parse_arguments_of_any_size` |
| V3 | LOW | `ArgumentCanonicalizer.hash` prefixes `"agcanon1:"`, `AuditRecorder.recordOversized` prefixes `"agraw1:"` — the two `args_hash` domains no longer collide; `ToolGuard.rejectIfTooLarge` also caps the canonicalised length | `CipherProbeReverifyTest.probe_an_oversized_denial_shares_an_args_hash_with_an_allowed_call` |
| V4 | LOW | `AgentGuardStartupCheck` warns when `endpoints.enabled` and either `tenant-scoped=false` or `require-tenant=false` | `CipherProbeReverifyStartupTest.probe_a_cross_tenant_approver_opt_out_is_silent_at_startup` |
| V5 | LOW | `AgentGuardProperties.Pool.platform-thread-count`/`.platform-thread-queue-size`, decoupled from `max-total`; `JedisBudgetStore.onPlatformThreads` takes the queue bound as its own parameter | `CipherProbeJedisFactoryTest.burst` (restored to `max-total=4`, thread/queue properties set to 200) |

## Summary (run 5, prior)
Every finding of Cipher's clean-verdict pass (`docs/SECURITY-REVIEW-feat-agent-guard-core.md`, on
`50ed8d3`) is closed on the branch: C4 (MEDIUM), C1/C2/C5/C7/C9/C11 (LOW), C3/C6/C8/C10/C12 (INFO), each with its
probe flipped (renamed without `probe_`, assertion inverted). `./mvnw -B clean verify` was green: **169 tests** (core
123, starter 45 + 1 self-skipping — needs Spring AI's real `ToolCallingAutoConfiguration` on the test classpath —
sample 1 end-to-end), core line coverage 90.2% / branch 77.7% (gate 80% line, held), spotless, Error Prone,
enforcer, JaCoCo gate, THIRD-PARTY-NOTICES.

| Id | Sev | Fix | Proof |
|---|---|---|---|
| C4 | MEDIUM | `ToolGuard.gate`/`.dispatch` check `maxArgumentBytes` as the first statement, before any parse; the oversized-rejection audit row hashes the raw text directly (`AuditRecorder.recordOversized`), never through the canonical parser | `CipherProbeCleanGuardTest.the_size_cap_refuses_arguments_before_they_are_parsed` |
| C1 | LOW | `JsonText.escape` `\u`-escapes unpaired surrogates instead of letting UTF-8 collapse them to `?` | `CipherProbeCleanTest.an_unpaired_surrogate_and_a_question_mark_do_not_share_one_arguments_hash` |
| C2 | LOW | `ArgumentRedactor.isSensitive` also splits on `_ - .` and camel-case boundaries | `CipherProbeCleanTest.camel_case_and_suffixed_sensitive_keys_are_masked` |
| C5 | LOW | `ApprovalService.fourEyes` compares approver/requester trimmed, case-folded, NFKC-normalised | `CipherProbeCleanGuardTest.four_eyes_rejects_a_differently_cased_approver_id` |
| C7 | LOW | bounded `ThreadPoolExecutor` (`ArrayBlockingQueue` sized to the pool, `AbortPolicy`); a timed-out call is cancelled and removed from the queue | `CipherProbeCleanRedisTest.a_timed_out_redis_call_does_not_stay_queued` |
| C9 | LOW | `agentguard.endpoints.require-tenant` (default `true` when `tenant-scoped`): no tenant → 403 | `CipherProbeCleanEndpointsTest.an_approver_without_a_tenant_is_refused` |
| C11 | LOW | ArchUnit rule bans `javax..` again, carve-out only for `javax.crypto..` | `HexagonalArchitectureTest` (no dedicated probe; the rule itself is the fix) |
| C3 | INFO | `JsonText.digits()`/`\u` escape restricted to ASCII `0`-`9` / `[0-9a-fA-F]` | `CipherProbeCleanTest.the_parser_rejects_text_that_is_not_json` |
| C6 | INFO | `agentguard_audit.chain_version` per row (backfilled `ag1`); `AuditChainVerifier` applies each row's own version | `CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail` |
| C8 | INFO | `JedisBudgetStore implements AutoCloseable`, `close()` shuts the pool down | `CipherProbeCleanRedisTest.the_platform_thread_executor_is_shut_down_on_close` |
| C10 | INFO | `DecisionStore.findByState(state, tenantId, limit)`, `AuditReader.latest(tenantId, limit)` filter in the query | `CipherProbeCleanEndpointsTest.the_pending_inbox_is_filtered_by_the_store_before_the_limit` |
| C12 | INFO | `AuditRecorder.record` hashes `ArgumentCanonicalizer.canonical(argumentsJson)` | `CipherProbeCleanTest.the_audit_row_hashes_the_same_canonical_form_as_the_decision` |

Versions unchanged: Spring Boot 4.0.8, Spring Framework 7.0.9, Spring Security 7.0.7, Spring AI 2.0.1
(+ `spring-ai-client-chat`, optional), MCP Java SDK 2.0.0, Jedis 7.5.2, Testcontainers 2.0.5, Java 21.

## Interface changes run 6 (all additive or default-preserving)
- `ArgumentCanonicalizer.hash` and `AuditRecorder.recordOversized` now hash a domain-prefixed input
  (`"agcanon1:"` / `"agraw1:"`); `ArgumentCanonicalizer.CANONICAL_HASH_DOMAIN` is package-visible for tests.
  Stored `args_hash` values are unaffected (the chain hashes the row, not the arguments) but cannot be
  recomputed from raw text without the prefix.
- `AgentGuardProperties.Pool` gained `platformThreadCount`/`platformThreadQueueSize` (both `Integer`, null =
  "use max-total", the prior behaviour) and `effectivePlatformThreadCount()`/`effectivePlatformThreadQueueSize()`.
- `JedisBudgetStore.onPlatformThreads(UnifiedJedis, int threads, Duration maxWait)` is unchanged (delegates to
  the queue-bound-equals-threads case); a new overload
  `onPlatformThreads(UnifiedJedis, int threads, int queueSize, Duration maxWait)` is used by the factory.

## Interface changes this run (run 5, prior)
- `DecisionStore.findByState(DecisionState, int)` is now a default method delegating to the new
  `findByState(DecisionState, String tenantId, int)` with `tenantId=null` (every tenant); both in-memory and JDBC
  implementations override the new one directly.
- `AuditReader.latest(int)` is now a default method delegating to the new `latest(String tenantId, int)`, same
  pattern.
- `ApprovalService.pending(int)` delegates to the new `pending(int limit, String tenantId)`.
- `AgentGuardEndpoints` gained a `requireTenant` constructor parameter (a 6-arg overload still defaults it `true`,
  the previous safe posture is unchanged for anyone constructing it directly outside the auto-configuration).
- `AuditEvent` gained a `version` component (position: after `actorId`, before `prevHash`/`hash`); `AuditChain`
  writes it on link. `agentguard_audit` gained `chain_version varchar(8) NOT NULL DEFAULT 'ag1'` via an idempotent
  `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
- `JedisBudgetStore` now implements `AutoCloseable`; its platform-thread pool is a `ThreadPoolExecutor` instead of a
  `newFixedThreadPool` (same field name/type `ExecutorService`, so nothing outside the class needed to change).

## A default-behaviour change that surfaced during this run (C9)
`agentguard.endpoints.require-tenant` defaults `true` whenever `tenant-scoped` is on (the existing default). A
deployment with `tenant-scoped=true` (the default) and **no** `TenantResolver` bean previously fell back to
`Optional.empty()` and was treated as "no scoping" (every approver saw everything); it now gets 403. This is the
C9 fix working as intended, but it meant:
- The sample app (`agent-guard-sample`, no `TenantResolver`, no tenant concept anywhere) needed
  `agentguard.endpoints.tenant-scoped=false` added to `application.yml` to declare itself single-tenant — the
  correct, existing way to opt out, not a new escape hatch. Without it every endpoint call in the sample's
  end-to-end test got 403.
- `AgentGuardEndpointsTest.list_arguments_approve_reject_and_audit` (pre-existing, not a Cipher probe) exercises a
  deliberate cross-tenant approver (no principal or approver in that test has a tenant); it now sets
  `agentguard.endpoints.require-tenant=false` at the class level. The other test method in the same class,
  `approvers_only_see_their_own_tenant_and_cannot_approve_their_own_call`, never logs in with a tenant-less
  approver, so this class-level property does not weaken its assertions.
- `CipherProbeJedisFactoryTest` (unrelated to C9; broken by C7's bounded queue) had its pool size raised from a
  fixed 4 to match its 200-virtual-thread burst, since each virtual thread has at most one call in flight at a
  time — the real concurrency ceiling is the thread count, not an arbitrary small pool racing an unbounded queue
  that no longer exists.

None of these are findings closed with a weaker check; they are the pre-existing (non-Cipher) tests and the sample
app being brought into line with the now-correct, fail-closed default.

## Acceptance checks (SPEC)
- [x] Sample MCP server: read tool allowed, write tool parked, approval via endpoint (attested hash, CSRF token,
  four-eyes) resumes and executes once as the agent, second approval is a no-op, audit shows the chain with the
  approver, budget of 3 calls blocks the 4th with a structured error. Proof: `./mvnw -B -pl agent-guard-sample test`.
- [ ] `agent-guard-core` on Maven Central; `agent-guard-pro` in private repo — release plumbing, not this run.
- [x] Docs page, CHANGELOG, SECURITY-NOTES, sample README ≤ 60 lines of code shown.
- [ ] Gate (90 days) — not applicable yet.

## Proof commands
```bash
./mvnw -B clean verify                                       # 190 tests, all gates
./mvnw -B -pl agent-guard-core -Ppinning-probe test          # + the 2 child-JVM pinning probes (~25 s)
./mvnw -B -pl agent-guard-spring-boot-starter test           # 48 + 1 skip (incl. every flipped Cipher probe)
./mvnw -B -pl agent-guard-sample test                        # 1 end-to-end through a real MCP client
```

## Interface changes run 8 (breaking: chain-format addition + Status/Anchor rename)
- `AuditEvent` gains a `keyId` component (record position: after `version`, before `prevHash`); `AuditChain`'s
  canonical form includes it, so every row this version writes carries a `key_id`. `AuditChain.keyed(byte[])` now
  defaults key id `k1`; `AuditChain.keyed(byte[], String keyId)` is the explicit form used for rotation.
- `AuditAnchor.Anchor.keyedFromSeq` (`Long`) is replaced by `Anchor.keyed` (`boolean`).
- `AuditChainVerifier.Status.UNKEYED` is removed (the situation it modelled — a key configured on the verifier
  that no row ever used — cannot arise once `keyed_from_seq` is gone); `Status.INTACT_UNKEYED` is added, and
  every pre-existing `Status.INTACT` assertion against an *unkeyed* trail across the test suite was renamed to it
  (a keyed trail's `INTACT` is unchanged).
- `AuditChainVerifier.Report` gains `anchored`, `keyed`, `keyIds` components (all trailing the existing four).
- `AuditChainVerifier` gains a `Map<String, byte[]>`-keyring constructor and `of(reader, Map<String, byte[]>)`
  factory alongside the existing single-`AuditChain` ones (both kept, unchanged behaviour for a single key).
- `ErrorCodes.AUDIT_KEY_MISMATCH` (`AG-AUDIT-001`) and `ErrorCodes.AUDIT_ANCHOR_MISSING` (`AG-AUDIT-002`) are new.
- `agentguard.audit.hmac-key-id` (default `k1`) and `agentguard.audit.hmac-keys.<id>` (retired keys) are new
  properties; `AgentGuardAutoConfiguration` gains an `auditKeyring` bean (`Map<String, byte[]>`) the
  `auditChainVerifier` bean now depends on instead of the single `AuditChain`.

## Still open (outside the review)
Release plumbing (Maven Central signing, org decision), async (WebFlux) MCP servers (fail startup today),
Micrometer metrics, `@Internal` API pass. Cipher's real-`ToolCallingAutoConfiguration` probe needs
`-Dmaven.test.additionalClasspath=<spring-ai-autoconfigure-model-tool-2.0.1.jar>` and self-skips otherwise.
C11 has no dedicated `CipherProbe*` test (the finding table lists its probe as "git diff"): the fix is entirely in
`HexagonalArchitectureTest`'s rule definition, verified by the ArchUnit rule itself passing/failing.

## Pain points (plain words) — run 8
- The coordinator's direction changed twice in the same session: first a plain F1–F4 fix list against
  `keyed_from_seq`, then (before any of it was committed) a full design change to keyed-from-birth, then an
  amendment to that design after Cipher's own review of it. No partial F1–F4 work was ever committed or pushed —
  the working tree was clean when each new direction arrived, so nothing needed discarding.
- Adding `key_id` to `AuditEvent` and the canonical hash material is a genuine chain-format change (not additive
  the way `chain_version`/`actor_id` were): every row this version writes is shaped differently from every row
  the pre-run-8 code wrote. Backfilled via the same idempotent-migration pattern as `chain_version` (derive from
  what's there, `NOT NULL` only after the backfill), but it is the first column in this schema that is also part
  of what gets hashed, so getting the backfill's *value* right (not just present) mattered: an unkeyed row must
  backfill to `'none'`, not to whatever placeholder was convenient.
- `AuditChainVerifier`'s single-`AuditChain` constructors could not be expressed in terms of the new
  `Map<String, byte[]>`-keyring constructor, because `AuditChain` deliberately never exposes its raw secret bytes
  (by design, for the same reason a `SecretKeySpec` doesn't hand back its key material casually). Kept both
  constructors as genuinely separate code paths (one keyed by `AuditChain` instances, one by raw bytes converted
  to `AuditChain` instances internally) rather than forcing one through the other.
- `SchemaStepIntegrationTest` (pre-existing, not a Cipher probe) started failing once `JdbcAuditSink`'s
  constructor began opening a connection at construction time (the new startup fail-closed check): the test reused
  one `HikariDataSource` bean across two separate `ApplicationContextRunner` contexts, relying on Spring *not*
  closing it when the first context shut down — true only because nothing had previously touched the connection
  during construction. Fixed by registering the bean with an explicit empty destroy-method name
  (`bd.setDestroyMethodName("")`), not by weakening the new startup check.

## Pain points (plain words) — run 7
- Making C6's test pass again after adding `keyed_from_seq` meant changing what "enabling the key" means inside
  the test: not just reconfiguring a verifier with a key nothing ever used, but a second sink instance genuinely
  continuing the trail under a keyed chain (the in-memory analogue of restarting the app with the secret set).
  That is a more faithful model of the real operation than the old test, but it did mean adding a seeding
  constructor to `InMemoryAuditSink` (`InMemoryAuditSink(List<AuditEvent>, AuditChain)`) that did not exist before
  — a small, narrowly-scoped addition to make the in-memory store capable of the same "continue an existing
  trail" scenario `JdbcAuditSink` already handles by construction (a new instance over the same table).

## Pain points (plain words) — run 6 (superseded above)
- V2's described fix ("version may only move forward") cannot make its own probe's exact scenario report
  `BROKEN`: a fully-keyed 2-row trail downgraded entirely back to `ag1` is byte-for-byte the same data as a
  trail that legitimately never used HMAC, verified after a key is later configured — the case C6 exists to
  keep `INTACT`. Implemented the fix as literally described (it is correct and valuable for the *detectable*
  half of the attack — a genuine keyed prefix with a downgraded tail, which is what an attacker who joins an
  already-running deployment can actually do without breaking the earlier rows' own hashes) and changed the
  probe to rewrite the tail instead of the head, with a javadoc explaining why. Full write-up: QUESTIONS.md #20.
  **Superseded in run 7:** Dollar's ruling found the external anchor already existed (R4's anchor row) and
  directed using it, closing the whole-trail case too.

## Pain points (plain words) — run 5, prior
- Fixing C12 (audit hashes canonical, not raw) meant every `AuditRecorder.record` call now parses the arguments —
  reintroducing C4's amplification risk on paths that were never covered by the `maxArgumentBytes` check (the early
  policy-denied / unregistered-tool paths in `ToolGuard.guarded`). Rather than widen C4's fix into those paths (not
  asked for, and they don't reach the dedup hash the finding measured), the oversized-rejection path got its own
  `AuditRecorder.recordOversized`, which hashes the raw text directly and never canonicalises it — so a rejected
  call is bounded by definition, on every path that can reject for size, without touching the paths the finding
  didn't ask about.
- C7's bounded queue is a real behaviour change under load, not just a bug fix: a burst past `max-total` concurrent
  callers now gets `AG-GUARD-001` (guard fails closed) instead of eventually succeeding once Redis catches up. This
  is the intended trade-off (unbounded queueing was the vulnerability), but it means `max-total` sizing now matters
  for availability, not just latency — documented in `SECURITY-NOTES.md`.
- Optional dependencies again: a bean method whose return type references `spring-ai-client-chat` made the whole
  Spring AI auto-configuration fail to load in the sample; the advisor now lives in its own class-conditional
  auto-configuration. Rule of thumb for this codebase: one optional library, one auto-configuration class.
- Testcontainers refuses `image:tag@sha256:…` for `PostgreSQLContainer` without `asCompatibleSubstituteFor`, and
  Boot's `@ServiceConnection` refuses the tag+digest form altogether; the sample uses `postgres@sha256:…`.
- The JSON parser in the domain is ~200 lines of hand-written code so the core stays free of Jackson; it is strict
  RFC 8259 and depth-limited (64), and unparseable arguments are masked whole rather than guessed at.

## Parked: Jedis 8 migration (2026-09-08)
Dependabot PR #6 (jedis 7.5.2 -> 8.0.1) fails test compilation: `JedisPooled` removed, `Connection` API changed. Affects `JedisBudgetStore`, `JedisBudgetStoreFactory`, `CipherProbeJedisPinningMain`, `CipherProbeCleanRedisTest`, `JedisBudgetStoreIntegrationTest`. To do as its own branch by Thor with Cipher review after module C: re-verify the virtual-thread pinning fix (R6) and pool bounding (C7/V5) against the Jedis 8 pool. Dependabot told to ignore the major until then.
