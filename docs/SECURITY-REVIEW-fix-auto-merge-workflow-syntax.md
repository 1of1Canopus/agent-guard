# Security review: auto-merge workflow rejected by GitHub (PR 48, finding B-DM3-1)

## 2026-10-17, pass 1

**Verdict: FIX LIST.** No HIGH, no MEDIUM. Three LOW, two INFO. Every one is fixed before
merge (no-allowance rule). The fix for the original finding works: the workflow is valid
again, and GitHub runs it on pull requests. The gaps are in what proves the fix stays in
place.

Reviewed tree: `ef2a161` (`fix/auto-merge-workflow-syntax`, PR 48 head). Scope: the marker
rewrite in the condition 7 step of `dependabot-auto-merge.yml`, the `actionlint` branch of
`tools/install-scanner.sh`, the two new probes in `tools/cipher-probe-dependabot.sh`, the two
new `ci.yml` lines, and the CHANGELOG entry. The weekly `security-scan.yml` was read for the
builder's note on the NVD secret.

### Grade of the original finding, B-DM3-1: LOW (proposed MEDIUM), confirmed

Reproduced. actionlint 1.7.12 on main's `dependabot-auto-merge.yml` reports
`165:1685: got unexpected character ... while lexing expression`. GitHub's run list shows
only failed `push` runs with zero jobs from main and every branch since the PR 44 merge.

Why LOW and not MEDIUM. The failure was closed: no path armed or merged anything. The disarm
job was dead too, but arming exists only in this workflow, and no Dependabot pull request
was open in that window (the last one, #29, merged on 2026-10-12, before PR 44 merged on
2026-10-15). The cost was a dead mechanism plus a false belief that it ran. That is the
same kind and size as "the probe suite is not run by anything in CI", graded LOW. A gate
that silently never runs, with no wrong outcome reachable, is LOW in this studio's grading.

Pattern. This is not a new pattern. It is a new disabled form of the existing pattern
"probes of workflow steps run the step body and enumerate disabled forms". A file GitHub
cannot parse is the strongest disabled form: every job in it is gone. Step-body probes never
see it, because they never parse the file the way GitHub does. Proposed addition to the
pattern's rule: every workflow file passes the pinned actionlint inside the required probe
check, and the probe step itself is in the not-disabled check.

### Numbers

| Check | Result |
|---|---|
| actionlint 1.7.12 (local), branch, `-shellcheck=` | exit 0 on all 4 workflow files |
| actionlint 1.7.12, main's `dependabot-auto-merge.yml` | exit 1, the expression lexing error above |
| GitHub run list, auto-merge workflow | PR 48: two `pull_request` runs, `skipped` (actor is not Dependabot). Main and earlier branches: `push`, `failure` |
| PR 48 required checks | Build & test, Cipher probes, DCO sign-off, Reference guard, Vulnerability scan: all pass |
| Dependabot probe suite, branch | 45 FIXED, 0 WEAK |
| Same suite, branch probes on main's workflow files | 2 WEAK (both new B-DM3-1 probes), 43 FIXED |
| Release-pipeline suite, local, no Maven | 74 FIXED, 9 WEAK: all 9 are the Maven-dependent probes, which skip as WEAK by design without `CIPHER_PROBE_MAVEN=1`. Not run with Maven: two other builds were running on this machine. CI ran the full suite with Maven on `ef2a161`: green |
| actionlint 1.7.12 checksums | linux amd64, linux arm64, darwin arm64 all equal the release's own `actionlint_1.7.12_checksums.txt`. linux amd64 and darwin arm64 also downloaded and hashed. Release published 2026-03-30 |
| Installer refusals | checksum mismatch: exit 1. Download 404: exit 1. No pin for the platform: exit 1. Nothing installed in each case |
| Condition 7 mutation | step body run on a ci.yml with an expression job name: refused. With the line deleted and the literal name listed and required: armed (see F4) |
| Review probes, `cipher-probe-auto-merge-workflow-syntax-pr48.sh` (internal) | 7 WEAK on `ef2a161` |

### What was verified and holds

1. The fixed workflow is valid. actionlint is clean, and GitHub now runs it on the pull
   request instead of failing on push.
2. The condition 7 check still refuses an expression job name after the rewrite. The marker
   is built as the same three characters. The variants `${{ x }}` and `x${{x}}` are both
   refused.
3. The pin is right, and the installer fails closed on a bad download, a bad checksum and a
   missing platform pin.
4. The two new probes are red on main's file and green on the branch. Deleting only the
   actionlint install step is caught today: actionlint is not on the ubuntu-24.04 image, so
   the actionlint probe reports it missing. Deleting the probe-suite step itself is not
   caught (F1).
5. Nothing in the fix widens what can arm. The marker rewrite matches the same strings as
   before. The new ci.yml step runs in the probe job with a read-only token and adds one
   directory, holding only actionlint, to the PATH of one process. Job names,
   `required-checks.txt`, the path gate and the actor gates are unchanged.

### Rulings on the builder's deviations

- **Shellcheck off in the actionlint probe: accepted. This is not a finding.** I reproduced
  both notes and both are harmless. `ci.yml` line 42 has SC2086 on `set -- $parents`: the
  word split is wanted, and the values are commit hashes. `release.yml` line 575 has SC2295
  on `${jar#$work/}`: `$work` is a `mktemp -d` path under the runner temp directory, with no
  glob characters. The probe checks syntax and expressions. Shell style is not a control.
  There is no follow-up pull request and no register row.
- **The NVD secret in a run script: a finding, F5, LOW. Fix it in this PR.** It is one
  line plus a pom property. The new structural probe is the right place to keep it fixed.
  Opening a separate PR would cost a second review cycle for a one-line correction.

### Findings

#### F1 (LOW, release pipeline). The auto-merge probe suite step can be removed unseen

The not-disabled check from the N12 to N14 findings covers only
`CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`. Three ci.yml mutations leave
`probe_probe_suite_is_not_run_by_ci` FIXED and every required check green:

- delete both new steps;
- `run: true # PATH=... tools/cipher-probe-dependabot.sh`;
- `run: PATH=... tools/cipher-probe-dependabot.sh || true`.

After any of the three, the 45 auto-merge probes stop running in CI. That includes both
B-DM3-1 probes. This is the same weakness as B-DM3-1, one level up.

Second half: `probe_a_workflow_file_fails_actionlint` accepts any actionlint that is first
on the PATH. A stub that prints a different version and exits 0 makes it FIXED.

Fix (fix pass), in `tools/cipher-probe-release-pipeline.sh`:

- `_probe_suite_wired_unconditionally_in` takes the wanted command as an argument.
- `probe_probe_suite_is_not_run_by_ci` stays WEAK unless one unguarded job in one workflow
  holds all three of these `run:` values, string-equal:
  - `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`
  - `tools/install-scanner.sh actionlint "${RUNNER_TEMP}/bin"`
  - `PATH="${RUNNER_TEMP}/bin:${PATH}" tools/cipher-probe-dependabot.sh`
- `probe_suite_probe_accepts_a_disabled_probes_job` and
  `probe_suite_probe_accepts_a_trailing_comment_disable` gain the same mutation cases for the
  two new lines: delete, comment out, trailing comment, `|| true`.

In `probe_a_workflow_file_fails_actionlint`: WEAK unless the first line of
`actionlint -version` equals the version that `tools/install-scanner.sh --print-versions`
prints.

Probes: `probe_dependabot_suite_step_can_be_removed_unseen`,
`probe_actionlint_probe_accepts_an_unpinned_actionlint`.

#### F2 (LOW, supply chain). No probe covers the actionlint checksum refusal

The S10 probe proves that a tampered download is refused for osv-scanner only. It does not
cover grype, and it does not cover the new actionlint branch. Deleting the actionlint
checksum compare leaves the whole suite green. A tampered actionlint could then report every
workflow clean. The installer header also still says "one vulnerability scanner" and "bump
the version and BOTH checksums", with only the osv and grype checksum file names.

Fix (fix pass):

- Add `probe_a_tampered_actionlint_download_installs` to `tools/cipher-probe-dependabot.sh`,
  modelled on S10. Redirect the URL to a local `file://` tar.gz that holds a file named
  `actionlint`. Make the `-version` run check a no-op. The honest checksum must install, and
  a tampered payload with the same recorded checksum must be refused.
- Extend S10 to grype in the same way. It is the same probe, and grype was a gap from before.
- Update the installer header: "one pinned tool", all three checksums, and the
  `actionlint_<version>_checksums.txt` file name.

Probe: `probe_a_tampered_actionlint_download_is_not_probed`.

#### F3 (INFO, false completion). The structural probe flags valid files and never reads `.yaml`

The awk strip pattern accepts only an expression that starts with a letter or an underscore
and holds no brace. Two valid expressions turn it WEAK:

- `${{ !cancelled() }}`
- `${{ format('{0}-x', github.sha) }}`

actionlint passes both. The probe comment and the CHANGELOG say the probe flags only
malformed openers. That overclaims. The structural loop and the actionlint call both read
`*.yml` only, so a broken `.yaml` workflow passes both probes.

Fix (fix pass), in `probe_a_run_block_holds_a_literal_expression_opener`:

- Strip with `gsub(/\$\{\{([^}]|\}[^}])*\}\}/, "", line)`. Grammar is actionlint's job. This
  probe flags only an opener with no closer on the same line.
- Loop over `*.yml` and `*.yaml`, with `nullglob`.
- Call `actionlint -shellcheck=` with no file arguments. It finds every workflow file itself.
- Reword the probe comment and the CHANGELOG line to match: "an opener with no closer on
  the same line".
- Check that the pattern works under mawk on the runner (the CI log shows it).

Probes: `probe_structural_probe_flags_a_valid_expression`,
`probe_a_broken_yaml_workflow_is_not_checked`.

#### F4 (INFO, false completion). The rewritten condition 7 line has no probe

Deleting `case "$jobs" in *"$open"*) refuse ...` leaves the suite green. Run on its own, the
step body without that line arms in one case: `required-checks.txt` and the rules list the
literal expression name. Today GitHub would never report a context with that name, so the
merge would wait forever. That is why this is INFO. But the line was rewritten in this PR,
and a rewritten control needs a probe that breaks when the control is gone.

Fix (fix pass): add `probe_an_expression_job_name_can_arm` to `tools/cipher-probe-dependabot.sh`.
It runs the condition 7 step body against the fake `gh`, with a head ci.yml whose job name
is `${{ github.event.pull_request.title }}`, and with the list and the rules both holding
that literal. It is WEAK if `STOP=1` is not written.

Probe: `probe_the_expression_job_name_refusal_is_not_probed`.

#### F5 (LOW, release pipeline). A secret is interpolated into a run script

`security-scan.yml` line 107 is
`./mvnw -B -Psecurity-scan -DskipTests -Dnvd.api.key=${{ secrets.NVD_API_KEY }} verify`.
GitHub writes the value into the rendered script on disk. It then sits on the Maven
command line, where every process in the job can read it. It is also parsed as shell. The
studio rule is: never on argv. It cannot be reached today, because the secret is not set
and the step skips. Fix it before the key exists.

Fix (fix pass):

- In the step, add `env: NVD_API_KEY: ${{ secrets.NVD_API_KEY }}` and run
  `./mvnw -B -Psecurity-scan -DskipTests verify`.
- In `pom.xml` profile `security-scan`, replace `<nvdApiKey>${nvd.api.key}</nvdApiKey>` with
  `<nvdApiKeyEnvironmentVariable>NVD_API_KEY</nvdApiKeyEnvironmentVariable>`. Confirm that
  this parameter exists in dependency-check-maven 13.0.0 with
  `./mvnw help:describe -Dplugin=org.owasp:dependency-check-maven -Ddetail` (it exists in
  9.2.0).
- Add `probe_a_secret_is_interpolated_into_a_run_script` to
  `tools/cipher-probe-dependabot.sh`, next to the B-DM3-1 probes. It is WEAK if any step's
  `run` value in any workflow (`yq '.jobs[].steps[]? | .run'`) mentions `secrets.`.
- Keep S9 green.

### Fix routing

All five go to the fix pass. None needs a new mechanism. The probe file comes first:
copy its probes into the suites as named above, show them WEAK, then fix. Because these are
LOW and INFO script fixes, the second pass checks that the probes flip and runs the
mutations again. It is not a full adversarial pass.

## Re-verification (2026-10-17)

**Verdict: MERGE WITH FIXES.** B-DM3-1 and F1 to F5 are closed: every pass-1 probe flips,
and every mutation the fix pass lists turns its probe WEAK again. The new surface has three
new findings: one LOW (F6) and two INFO (F7, F8). No HIGH, no MEDIUM. All three are fixed
before merge (no-allowance rule).

Reviewed tree: `42851bb` (`fix/auto-merge-workflow-syntax`, PR 48 head). This pass checks
that the probes flip, repeats the mutations, and attacks what the fixes added. It is not a
full adversarial pass. No Maven run: none of the claims below needs one, and CI ran the
Maven probes on this head.

### Numbers

| Check | Result |
|---|---|
| Pass-1 review probes (`cipher-probe-auto-merge-workflow-syntax-pr48.sh`, internal) | 7 FIXED, 0 WEAK (7 WEAK on `ef2a161`) |
| Auto-merge suite, local | 50 FIXED, 0 WEAK |
| Release suite, local, no Maven | 75 FIXED, 8 WEAK. All 8 return early on the Maven switch (3 on `CIPHER_PROBE_MAVEN`, 5 on `_needs_maven`). Read in the source, not assumed |
| CI on `42851bb`, Cipher probes job | release suite with Maven 83 FIXED, 0 WEAK; actionlint 1.7.12 "verified and installed"; auto-merge suite 50 FIXED, 0 WEAK. All five required checks pass |
| Mutations of the fix pass, repeated here | 11 of 11 turn the named probe WEAK (table below) |
| New probes on main's tree (`b1a090b`) | secret-in-run probe WEAK. Expression-job-name probe FIXED, which is correct (see F4 below) |
| Re-verification probes (`cipher-probe-auto-merge-workflow-syntax-pr48-pass2.sh`, internal) | 3 WEAK on `42851bb` |

### Mutations, repeated

Each was applied to a fresh copy of `42851bb`. The full suite was run, and the copy was then thrown away.

| Mutation | Probe that went WEAK |
|---|---|
| ci.yml: both new steps deleted | `probe_probe_suite_is_not_run_by_ci` |
| ci.yml: `\|\| true` on the auto-merge suite line | `probe_probe_suite_is_not_run_by_ci` |
| ci.yml: `run: true # <cmd>` | `probe_probe_suite_is_not_run_by_ci` |
| N12 probe wants only the first command | `probe_suite_probe_accepts_a_disabled_probes_job`, `probe_suite_probe_accepts_a_trailing_comment_disable` |
| actionlint version check removed | `probe_a_valid_expression_is_flagged_or_an_unpinned_actionlint_passes` |
| actionlint checksum compare deleted | `probe_a_tampered_actionlint_download_installs` |
| grype checksum compare deleted | `probe_scanner_download_unverified` (S10) |
| structural probe back to the old strip pattern | `probe_a_valid_expression_is_flagged_or_an_unpinned_actionlint_passes` |
| both probes back to `*.yml` only | `probe_a_broken_yaml_workflow_is_not_checked` |
| condition 7 refusal line deleted | `probe_an_expression_job_name_can_arm` |
| NVD key back on the Maven command line | `probe_a_secret_is_interpolated_into_a_run_script` |

### Prior findings

- **B-DM3-1: closed.** Branch probes are red on main's files and green on the branch.
- **F1: closed.** The N12 check needs all three run lines, string-equal, in one unguarded job.
  The mutation sets cover each new line. Version-only check of actionlint: verified as
  decided (next section).
- **F2: closed.** The real installer is run on a `file://` payload. The honest payload
  installs and a tampered one is refused, for actionlint and for grype. If the URL rewrite
  ever stops matching, the honest case fails and the probe reports WEAK. So the probe
  fails closed. Installer header updated.
- **F3: closed.** CI's awk: the log does not name it. The ubuntu-24.04 image (version
  20261012.334.1, the one in the log) does not list gawk among its packages. So `awk` there
  is almost certainly the Ubuntu default, mawk, not GNU awk. This does not matter, because
  the behaviour is proved on the runner itself. In the CI log, the valid-expression meta probe is
  FIXED: `!cancelled()` and `format('{0}-x', ...)` were not flagged. The broken-`.yaml` meta
  probe is FIXED too: the unclosed opener was flagged. So the regex works both ways under the
  runner's awk, and it gives the same results under macOS awk 20200816.
  The deviation (actionlint gets the file list instead of no arguments) is accepted: the list
  is `*.yml` and `*.yaml` in `.github/workflows`, and an empty list refuses.
- **F4: closed.** On main's tree, `probe_an_expression_job_name_can_arm` is FIXED, not WEAK.
  That is correct. Main has the refusal line. Its literal opener breaks GitHub's parser, but
  in bash it refuses as intended. F4 was "the line has no probe", not "the refusal is
  missing". The probe is WEAK on main's tree once that line is deleted, and WEAK on the
  branch once it is deleted. That is the property the probe must have.
- **F5: closed.** The step passes `NVD_API_KEY` through `env:` and the run line has no `-D`.
  The pom uses `<nvdApiKeyEnvironmentVariable>NVD_API_KEY</nvdApiKeyEnvironmentVariable>`.
  The parameter exists in dependency-check-maven 13.0.0: I read `META-INF/maven/plugin.xml`
  from the jar on Maven Central (sha1 `792fc57f...` equals Central's `.sha1`). The parameter
  is a `java.lang.String`, described as "the recommended option to pass the API key in CI
  builds". No `nvd.api.key` reference is left in the tree. On main the probe is WEAK; on the
  branch it is FIXED.

### Check of the F1 decision: the only actionlint in CI is the pinned one

The decision holds on the workflow as written.

- The `cipher-probes` job has five steps: checkout, setup-java, the release suite, the
  pinned install, and the auto-merge suite. No other action and no `setup-*` action
  installs a linter. No workflow, and no probe script, writes to `GITHUB_PATH`.
- actionlint is not in the ubuntu-24.04 image's tool list.
- The suite line itself puts `${RUNNER_TEMP}/bin` first on PATH. Even an entry that an
  earlier step added to `GITHUB_PATH` would come after it.
- The earlier release-suite step runs branch code. It could put a file at
  `${RUNNER_TEMP}/bin/actionlint`, but `install -m 0755` replaces that file. If the
  directory cannot be written, the install fails and the job goes red.
- If the install step were moved after the suite, the suite would find no actionlint and
  report WEAK. That is red, so the failure is closed.
- A tampered archive is refused (F2 probe, mutation above).

I found no path by which an unpinned actionlint reaches the probe job. This is not a
finding.

### New findings

#### F6 (LOW, release pipeline). A custom shell or an env switch neutralises a probe step

The not-disabled check refuses `if:` and `continue-on-error:`, and any decoration of the
three run lines. It does not look at the keys that stop a run script from running, or that
turn the suite's own probes off. Each of these eight ci.yml mutations passes actionlint
1.7.12, and each leaves `probe_probe_suite_is_not_run_by_ci` FIXED:

- `shell: true {0}` on any of the three steps. GitHub's custom-shell template runs the
  first word as the command, so it runs `true <script>`, exit 0, and nothing executes.
- `defaults: run: shell: true {0}` on the `cipher-probes` job, or at the top of the workflow.
- `env: BASH_ENV: <file that runs exit 0>` on the job, or at the top of the workflow.
  Non-interactive bash sources `BASH_ENV` before the script, even with `--noprofile --norc`.
  Reproduced locally: a script that fails returns 0.
- `env: AM_PROBE_NESTED: "1"` on the auto-merge suite step. The suite then reports its four
  meta probes FIXED without running them.

Example. Someone adds `shell: true {0}` under "Run the Dependabot auto-merge probe suite". Every
required check stays green, and none of the 50 auto-merge probes runs again. Second example,
two steps: set `AM_PROBE_NESTED: "1"` on that step, then delete the actionlint version check.
The suite still reports 50 FIXED, 0 WEAK. Without the env line, the same deletion shows WEAK.

This is the F1 weakness through a key the check does not read. It is graded LOW like F1. The
same gap existed for the release-suite line before this PR. The F1 fix extended the check to
two more lines, so it is in scope here.

Fix (fix pass), in `tools/cipher-probe-release-pipeline.sh`. No new mechanism: this extends
the refusal list.

- In `_probe_suite_wired_unconditionally_in`, also count as guarded any line of the job
  block that matches `^[[:space:]]*(-[[:space:]]+)?(shell|env|defaults):`. The probes job has
  none of these keys today.
- In `probe_probe_suite_is_not_run_by_ci`, do not accept a workflow file that has a top-level
  `defaults:` or `env:` key. These lines fall before the first job, so the per-job split
  does not see them.
- Refuse `AM_PROBE_NESTED` anywhere under `.github/`.
- Add the eight mutations to `probe_suite_probe_accepts_a_disabled_probes_job`.

Probe: `probe_a_custom_shell_or_env_switch_disables_a_suite_step`.

#### F7 (INFO, false completion). The secret probes see only one spelling

`probe_a_secret_is_interpolated_into_a_run_script` greps for `secrets\.`, and the
release-scan probe (`probe_release_signs_without_a_vulnerability_scan`) does the same.
GitHub expressions also accept `secrets['NAME']`, `toJSON(secrets)`, and
`SECRETS.NAME` (context names are not case-sensitive). actionlint 1.7.12 accepts all three.

Example. Put `-Dnvd.api.key=${{ SECRETS.NVD_API_KEY }}` back on the Maven line in
`security-scan.yml`. The key is back on argv, and the suite says 50 FIXED, 0 WEAK. Put
`LEAK: ${{ SECRETS.GPG_PASSPHRASE }}` in the release scan step's `env:`. The release-scan
probe stays FIXED, but with the lower-case spelling it goes WEAK. Nothing is exposed today,
so this is INFO.

Fix (fix pass): in both places, match the `secrets` context in any spelling, any case,
inside an expression. Tested pattern, case-insensitive:
`grep -qiE '\$\{\{([^}]*[^A-Za-z0-9_])?secrets([^A-Za-z0-9_]|$)'`. It hits all five forms
(`secrets.X`, `secrets.X` with no spaces, bracket, `toJSON(secrets)`, upper case). It
misses `env.MYSECRETS`, `inputs.secrets_dir` and plain text after an expression. It finds
nothing in the current tree.

Probe: `probe_a_secret_reaches_a_run_script_by_another_spelling`.

#### F8 (INFO, false completion). The M7 licence probe goes WEAK at random

`probe_no_licence_file_in_the_repository` is `! git ls-files | grep -qiE ...`, and the
suite sets `pipefail`. `grep -q` exits at the first match, and `LICENSE` sorts early.
`git ls-files` is still writing, so it gets SIGPIPE (exit 141). `pipefail` makes the whole
pipeline fail, and `!` turns that into WEAK.

Example. Run the function 300 times on this tree, which has LICENSE and NOTICE. It reported
WEAK 16 to 18 times (7 in 200 in a first count). This happened twice during this pass, in
two of the mutation runs. The required Cipher probes check can go red with no cause. It
fails closed, so it is INFO. It existed before this PR, but it can redden this PR's required
check, and the fix pass already edits this file.

Fix (fix pass): read the list first, then match:
`local f; f="$(git ls-files)"; ! grep -qiE '^(LICENSE|LICENCE|NOTICE)(\..*)?$' <<<"$f"`.

Probe: `probe_licence_probe_flakes_under_pipefail`.

### Fix routing

All three go to the fix pass. They are script-only corrections and none needs a new
mechanism. The probe file comes first: copy its three probes into the suites
(`probe_a_custom_shell_or_env_switch_disables_a_suite_step` and
`probe_licence_probe_flakes_under_pipefail` into the release suite,
`probe_a_secret_reaches_a_run_script_by_another_spelling` into the auto-merge suite). Show
them WEAK, then fix. Because these are LOW and INFO script fixes, the verifier's numbers
close them: the three probes FIXED, both suites green locally and in CI. No third security
pass is needed.
