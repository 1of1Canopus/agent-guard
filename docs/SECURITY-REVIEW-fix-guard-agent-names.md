# Security review: the reference guard refuses agent first names (PR 43)

## 2026-10-15, pass 1

**Verdict: FIX LIST.** No HIGH, no MEDIUM. Four LOW and four INFO findings. Every one is
fixed before merge (no-allowance rule), except B-NG-7, which is a design stop: it needs a new
scan input, so it gets its own design page and its own PR (see the note under it).

Reviewed tree: `91287db` (`fix/guard-agent-names`, PR 43 head). Scope: the new name group and
the check-name carve-out on the one `pattern=` line of `tools/check-private-references.sh`,
`grep -a` in the jar scan, the new self-test cases, and the new suite probe. The two sibling
repositories carry the same change; they get the verifier's numbers after this verdict.

In this document the twelve names are numbered as in the self-test: name 1 to name 11 in the
order of the `pattern=` line, name 12 is the name of the required security-probe check.
Method: every attack below was run against the real script (`--tree` or `--jars`, real exit
code), on BSD grep 2.6 and git 2.53 (macOS) and on GNU grep 3.11 and git 2.43 (Ubuntu 24.04,
locales `C` and `C.UTF-8`). Results are the same on both unless stated.

### Numbers

| Check | Result |
|---|---|
| `./mvnw -B verify` (Docker up, run once) | exit 0; 307 tests, 0 failures, 0 errors, 1 skipped |
| Skipped test | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` (assumption: needs an extra Spring AI jar on the classpath; skipped since it was written, not passing) |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` (run once) | exit 0; fixed 75, still weak 0 (the reference-guard probes included: 10 fixed) |
| `--self-test`, BSD and GNU | all cases correct |
| `--tree` on `91287db` | tree clean |
| `--jars` on the built core and starter jars | every built jar is clean |
| Builder mutations (two, pasted in the PR body) | both reproduce exactly (9 FAIL; 1 FAIL on GNU) |
| Reviewer mutations | 4 run; 3 caught, 1 survives (B-NG-3) |
| New probes this pass | 9, all WEAK on `91287db` (internal probe file `cipher-probe-reference-guard-names-pr43.sh`) |

### Findings

| Id | Severity | Class | Probe | Status |
|---|---|---|---|---|
| B-NG-1 | LOW | boundary validation | `probe_name_after_whitespace_control_byte_passes` | open |
| B-NG-2 | LOW | boundary validation | `probe_name_after_dot_or_slash_passes` | open |
| B-NG-3 | LOW | boundary validation / docs vs code | `probe_check_name_carve_out_admits_other_phrases`, `probe_self_test_misses_a_widened_carve_out` | open |
| B-NG-4 | LOW | release pipeline | `probe_reference_guard_job_disabled_passes` | open (gap is older than this PR) |
| B-NG-5 | INFO | boundary validation | `probe_lower_case_agent_address_passes` | open |
| B-NG-6 | INFO | copy/leak paths | `probe_nested_archive_in_jar_passes` | open |
| B-NG-7 | LOW | copy/leak paths | `probe_name_in_a_path_passes` | open, DESIGN STOP (gap is older than this PR) |
| B-NG-8 | INFO | docs vs code | `probe_ci_step_names_omit_agent_names` | open |

#### B-NG-1 (LOW): a tab, form feed, vertical tab or carriage return before a name hides it

The prefix class `[^[:alnum:][:cntrl:]_./]` skips every control byte, so that a class-file
length byte cannot read as the first letter of a name. But `[:cntrl:]` also holds the
whitespace control bytes. A Markdown line indented with a tab, a tab-separated table, or a
form feed before a name passes. Repro: plant `\t<name 1> wrote this` in a scratch repo, run
`--tree`: exit 0. Same for `\f`, `\v`, and `x\r<name 1>`.

The class-file case only needs the bytes that never occur in text: the byte before the
misread letter is the high length byte, `0x00` for any constant under 256 bytes.

Fix (builder): in both name groups, add whitespace back as a boundary:
`(^|[^[:alnum:][:cntrl:]_]|[[:space:]])` for the name group (see B-NG-2 for the dot and
slash), and the same `|[[:space:]]` alternative in the prefix of the name-12 group. Self-test:
red cases `agent-name-after-tab`, `agent-name-after-form-feed`, `agent-name-after-carriage-return`;
the jar green case `jar-length-byte-before-a-string` must stay green. Measured: zero new hits
on the three trees and on the six published main and sources jar pairs.

#### B-NG-2 (LOW): a name after `.` or `/` passes, for every name

The dot and slash exemption exists for one class: the JDK cipher class written qualified
(`javax.crypto.` plus name 12) and its class-file form (`javax/crypto/` plus name 12). It is
applied to all twelve names. None of names 1 to 11 has a JDK or library class (measured: zero
hits of names 1 to 11 after `.` or `/` in the three trees). Repro, each exit 0 on `--tree`:
`see docs/<name 1>`, `see /<name 1>`, `v1.<name 1> wrote it`, `https://example.org/reviews/<name 1>`,
`e.g.<name 3>`, and for name 12 itself `see docs/<name 12>`.

Fix (builder):
- names 1 to 11: drop `./` from the prefix class: `(^|[^[:alnum:][:cntrl:]_]|[[:space:]])`.
- name 12: keep the exemption only after the segment `crypto`, written as a hand-made
  look-behind in the same style as the existing look-ahead:
  `(^|[^[:alnum:][:cntrl:]_./]|[[:space:]]|(^|[^o]|(^|[^t])o|(^|[^p])to|(^|[^y])pto|(^|[^r])ypto|(^|[^c])rypto)[./])`
  before `[C]ipher`.
- Self-test: red cases for each repro above; the two existing JDK green cases stay green.
Measured with this exact prefix (together with B-NG-1 and B-NG-3): self-test green, BSD and
GNU; zero new hits on agent-guard and gdpr-shredding PR branches; on the stripe-einvoice PR
branch one new hit, which is B-NG-3's case, not this one; the six published jar pairs give
the same hits as the PR's pattern (only the known bare JDK class in a published 0.2.0 sources
jar, which the sibling PR fixes).

#### B-NG-3 (LOW): the check-name carve-out admits every phrase that starts with "name 12 probe"

The hand-written look-ahead stops after `prob` + `e`. So the carve-out is not the two-word
check name: it is any text that begins with name 12, a space, and `probe`. Repro, each exit 0
on `--tree`: `the <name 12> probe found it`, `<name 12> probed the branch`,
`<name 12> probe-verified, no findings`. The script header says "the name followed by
\" probe\"", the PR body says "only that two-word phrase", and the self-test pins the singular
form as green (`required-check-name` holds "... probe for PR 1"). The stripe-einvoice tree
already has a test javadoc in that form (author voice, not the check name).

Mutation survivor: replacing the look-ahead's ` p...` tail by nothing (any ` p` passes) leaves
the self-test all green, because no red case touches the carve-out edge.

Fix, preferred: rename the required check to a role ("Security probes"; ruleset change on
`main`, plus the job name, `.github/required-checks.txt` where present, and the suite's own
greps for the job name), then delete the carve-out: name 12 is refused like the others. This
is a ruleset decision for the maintainer.
Fix, if the rename is refused: narrow the look-ahead to the exact word `probes` by appending
`| probe$| probe[^s]| probes[[:alnum:]_]` after `| prob[^e]`; fix the header sentence; change
the green case to `the <name 12> probes job` only; add red cases for the three repros. With
the narrow form the remaining accepted text is "name 12 probes" as a word pair, which is the
check name and cannot be told apart from prose by a pattern (see "closed without a code
change"). The sibling PR in stripe-einvoice must then reword its singular javadoc.

#### B-NG-4 (LOW, older than this PR): the guard job and the jar steps can be switched off with the suite green

The suite proves the probe job is wired unconditionally (exact `run:` value, no `if:` or
`continue-on-error:` in the job, comments stripped). The Reference guard job and the two jar
steps only get a substring grep (`probe_reference_guard_is_not_its_own_job`,
`probe_jar_guard_is_not_run_on_the_jars`). Each of these edits to `ci.yml` leaves every
`reference_guard|jar_guard` probe FIXED: job-level `if: false` on `reference-guard`;
`run: "true" # tools/check-private-references.sh --tree`; `run: ... --tree || true`;
`continue-on-error: true` on the Build & test jar step. A job skipped by `if:` still
satisfies a required check. This PR widens what the guard protects, so the guard being
silently off now leaks names too.

Fix (builder, inside the probe mechanism it maintains): generalise
`_probe_suite_wired_unconditionally_in` to take the exact command, and make
`probe_reference_guard_is_not_its_own_job` require both `tools/check-private-references.sh --self-test`
and `--tree` by string equality in an unguarded `reference-guard` job, and
`probe_jar_guard_is_not_run_on_the_jars` require the `--jars` command by string equality in
an unguarded step of `ci.yml` and `release.yml`. Add a mutation probe in the style of
`probe_suite_probe_accepts_a_disabled_probes_job` covering the four edits above.

#### B-NG-5 (INFO): a lower-case agent address passes

Lower case is out of scope by design (see "closed without a code change"), with one
exception that is unambiguous: an agent's address. A pasted sign-off trailer
(`Signed-off-by: <name 1, lower case> <<name 1, lower case>@housedevinci.com>`) passes `--tree`.

Fix (builder): add one alternative to the pattern:
`(^|[^[:alnum:]._+-])([t]hor|[i]sis|[r]a|[a]thena|[o]din|[h]ermes|[h]arvey|[d]ollar|[b]rain|[b]rainus|[l]oki|[c]ipher)@housedevinci`.
Measured: zero hits on the three trees; the project and security addresses stay green.
Self-test: one red case (address form), one green case (the project address).

#### B-NG-6 (INFO): a name inside a nested archive in a jar passes

`scan_jars` unzips one level and reads every member with `grep -a`. A member that is itself
an archive is read as compressed bytes. Repro: a jar holding `lib/inner.jar`, whose entry says
"reviewed by <name 1>": `--jars` exit 0. Today no published jar holds a nested archive
(measured: zero `.jar` members in the core and starter jars), so this is latent.

Fix (builder): in `scan_jars`, after unzip, refuse (exit 1, "nested archive not scanned") any
extracted file whose first four bytes are `PK\x03\x04`. Fail closed, no recursion needed.
Self-test jar case `jar-nested-archive` red.

#### B-NG-7 (LOW, older than this PR, DESIGN STOP): names in file paths are never scanned

`git grep` reads contents, never paths; `grep -r` on the extracted jar reads contents, never
entry names. A file `docs/review-by-<name 1>.md` passes `--tree`; a jar entry
`META-INF/review-by-<name 1>.txt` passes `--jars`. The same gap covers the moved-private
document names: a committed file at one of those paths passes, only a reference to it is
refused.

Property that must hold: every path in the tree (`git ls-files`) and every entry name in
every scanned jar (`unzip -Z1`) is held to the same pattern as content. Paths it must cover:
tracked files, submodule paths, jar entry names in main and sources jars. Why a design page
and not a fix line: the public review documents live at paths the pattern refuses by content
(their prefix is one of the moved-private alternatives), so a path scan with the one pattern
is red on main today. The design must decide that conflict (rename the review documents, or
split the pattern, which breaks "defined exactly once"). This is a new scan input, so per the
one-mechanism rule it is its own PR with its own two passes. I do not hold PR 43 on it: the
gap exists on main in all three repositories and this PR does not change the scan inputs.
The maintainer's coordinator confirms or overrules that.

#### B-NG-8 (INFO): the CI step names describe the old scope

`ci.yml` and `release.yml` still say "Refuse a moved-private document reference or a
machine-local path" on the three guard steps. A reader of a red check is told the wrong cause.

Fix (builder): add "or an agent first name" to the three step names.

### Attacks closed without a code change

- Possessive, colon, closing and opening parenthesis, comma, end-of-sentence period, `@`,
  `#`, em dash, non-breaking space before the name: all refused. Correct.
- Identifier forms (`<name 1>_1`, `<name 1>1`, `<name 1>V2`, `_<name 1>`): pass. Same rule as
  the probe class identifiers the pattern must leave alone; not prose. Not a finding.
- Lower case in general: out of scope. The lower-case words are common English or code
  (`cipher`, `dollar`, `brain`, `ra` in `read -ra`, a Java pattern variable `ra`); measured
  zero lower-case agent mentions in prose on the three trees. The leaks this PR answers were
  capitalised prose. Only the address form is in scope (B-NG-5).
- HTML entities (`&#84;...`), zero-width and look-alike characters, split string literals
  folded by javac into one class-file constant: deliberate evasion, outside the accidental-leak
  threat model of this guard.
- A class-file constant that starts with a name (`"<name 1> wrote this"`, length byte before
  it) passes the main-jar scan. Every such constant comes from a source file that `--tree` and
  the sources-jar scan read in full; the only route around that is the deliberate split above.
  Repro run (javac, real jar, exit 0), not a finding.
- A name split across a wrapped `MANIFEST.MF` line passes. Every manifest value comes from the
  pom (title, vendor, version), which `--tree` reads unwrapped. Not a finding.
- `META-INF/maven/**/pom.xml` and the manifest are extracted and read: confirmed.
- A Latin-1 byte right before a name passes under `C.UTF-8` and on macOS, is refused under
  `C`. CI runs `C.UTF-8`. Non-UTF-8 text with no space before a name is not a realistic leak.
- An ANSI escape before a name passes (the byte before the name is the letter `m`): terminal
  escapes in committed prose are not the leak shape. Not a finding.
- "name 12 probes said X": once B-NG-3 is fixed by narrowing, this exact word pair is the
  required check's name and cannot be told apart by a pattern. Closed by the preferred fix
  (rename) or accepted as the check name.
- A roster file outside the module team (a personal tutoring agent) is not in the pattern
  and not in the header's excluded list. It never works in module repositories. Not a finding.
- Self-non-matching after the addition: holds (self-test and suite probe). Mutation "drop one
  bracket" turns both red.
- Pattern defined once: holds. A later reassignment would be caught by the name red cases,
  which run the real script.
- BSD versus GNU: every case above gives the same result on both, except the Latin-1 case.

### Mutations

| Mutation | Result |
|---|---|
| Builder 1: break name 3 and name 12 | self-test 9 FAIL; suite probe WEAK. Caught. |
| Builder 2: remove `-a` from the jar scan (GNU) | self-test 1 FAIL (`jar-length-byte-before-a-string`). Caught. |
| Reviewer 1: drop one bracket (`[T]` of name 1) | self-test FAIL "matches this script's own source"; suite probe WEAK. Caught. |
| Reviewer 2: drop `[:cntrl:]` from the name prefix | self-test 1 FAIL (jar green case). Caught. |
| Reviewer 3: delete the name-10 alternative | self-test 1 FAIL (`agent-name-10`); suite probe WEAK. Caught. |
| Reviewer 4: widen the carve-out to any ` p` | self-test all green. **Survives** (B-NG-3). |

### Fix list (all before merge)

1. B-NG-1, B-NG-2, B-NG-3, B-NG-5: pattern edits and self-test cases as written above (builder;
   B-NG-3 waits on the rename decision).
2. B-NG-4: probe hardening (builder).
3. B-NG-6: fail closed on a nested archive (builder).
4. B-NG-8: step names.
5. Add the nine internal probes to the suite first; each must be WEAK before the fix and
   FIXED after. B-NG-7's probe stays WEAK until its own PR.
6. Copy every change to the two sibling PRs before their verifier run.

## 2026-10-16, pass 2

**Verdict: MERGE.** B-NG-1 to B-NG-6 and B-NG-8 are closed. Each probe went from WEAK on
`91287db` to FIXED on `a5c8981`. B-NG-7 stays open as a design stop with its own PR, and it
does not hold this PR (the coordinator's decision of 2026-10-16).

Reviewed tree: `a5c8981` (fix commit `23eff45`, then a merge from main). The merge does not
touch the guard script (empty diff on `tools/check-private-references.sh`). The fix commit
does not touch this review document.

### Numbers

| Check | Result |
|---|---|
| Internal probe file (9 probes), on `a5c8981` | 8 FIXED, 1 WEAK (`probe_name_in_a_path_passes`, B-NG-7, expected) |
| The same file on `91287db` | 9 WEAK |
| Shipped suite, guard probes only (`CIPHER_PROBE_ONLY`) | 20 fixed, 0 weak |
| CI on `a5c8981` | 5 of 5 checks green |
| `--self-test`, BSD grep 2.6 and GNU grep 3.11 (`C`, `C.UTF-8`) | all cases correct |
| `--tree` on `a5c8981`, this document included | tree clean |
| Self-non-matching, defined exactly once | both hold (self-test lines, and `grep -c '^pattern='` = 1) |

One internal probe (`probe_self_test_misses_a_widened_carve_out`) first read WEAK on the
new head. That was my probe's fault: its mutation anchor no longer matched the longer
pattern, so the probe could not apply the mutation. With the anchor the shipped suite uses
(the look-ahead tail up to its closing parenthesis), it reads WEAK on `91287db` and FIXED on
`a5c8981`. The shipped probe has the right anchor and refuses (WEAK) if it cannot mutate.

### Closed

| Id | Closed by | Probe now |
|---|---|---|
| B-NG-1 | `[[:space:]]` is a boundary before every name; four red self-test cases | FIXED |
| B-NG-2 | names 1 to 11 have no dot or slash exemption; name 12 only after `crypto`; six red cases plus `javax.krypto.` | FIXED |
| B-NG-3 | fallback form: exact word `probes` only; four red cases (probe, probed, probe-verified, probesuite) | FIXED |
| B-NG-4 | guard job and jar steps checked by exact command in an unguarded job | FIXED |
| B-NG-5 | lower-case agent address refused; project addresses green | FIXED |
| B-NG-6 | a jar member starting with `PK\x03\x04` is refused | FIXED |
| B-NG-8 | the three step names now say "or an agent first name" | FIXED |

### Mutations, re-run on `a5c8981`

| Mutation | Result |
|---|---|
| Builder 1: break name 3 and name 12 | 16 FAIL. Caught. |
| Builder 2: remove `-a` from the jar scan (GNU) | 1 FAIL (`jar-length-byte-before-a-string`). Caught. |
| Reviewer 1: drop one bracket of name 1 | FAIL "matches this script's own source". Caught. |
| Reviewer 2: drop `[:cntrl:]` from the name prefix | 1 FAIL (jar green case). Caught. |
| Reviewer 3: widen the carve-out to any ` p` | 4 FAIL. Caught (it survived in pass 1). |
| Reviewer 4: delete name 10 | 1 FAIL (`agent-name-10`). Caught. |
| Extra: give names 1 to 11 the dot and slash exemption back | 5 FAIL. Caught. |
| Extra: drop the `crypto` look-behind for name 12 | 2 FAIL. Caught. |
| Extra: disable the nested-archive refusal | 1 FAIL (`jar-nested-archive`). Caught. |

### No exemption widened

I ran the 36 attack cases of pass 1 against `a5c8981` and against the candidate pattern I
measured in pass 1. The only difference is the lower-case address, which is now refused
(B-NG-5). Every case that was refused stays refused. The cases that pass are the ones closed
in pass 1 without a code change, plus the exact check-name word pair. BSD and GNU agree,
except the Latin-1 byte case under `C`, as in pass 1.

### The one new angle: a name at the start of a line

`[[:space:]]` includes the newline, so I checked that the new alternative does not change
how a line start is handled. Every case is refused on BSD and GNU (`C` and `C.UTF-8`):
a name after a line feed in the middle of a paragraph, after CRLF, as the first byte of the
file, after a blank line, after two spaces of indent, after a tab indent, after `> ` and
`- `, the short name 3 at a line start, name 12 at a line start. In a jar member, a
line-start name after LF and after CRLF is refused too. Only "name 12 probes" at a line start
passes, which is the check name.

### Still open

- B-NG-7 (LOW, DESIGN STOP): names and moved-private names in file paths and jar entry
  names are never scanned. Own design page and own PR.
- The required check is still named after a reviewer. The narrow carve-out stays until the
  check is renamed (a ruleset change for the maintainer).
