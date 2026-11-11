# Security review: release-path refusal and scanner exit code (PR 59, PR 60)

## 2026-11-10, pass 1

Summary. The release-path step of PR 59 does what it says on every case tried against the
real GitHub API, and the scanner fix of PR 60 is correct. PR 59 needs three small fixes; PR 60
can merge as it is, and it must merge first.

**PR 59** (`ci/dependabot-release-path-refusal`, head `cebc005`): **Verdict: MERGE WITH FIXES.**
No HIGH, no MEDIUM. Two LOW and one INFO (AG-AM-2, AG-AM-4, AG-AM-3). Every one is fixed
before merge.

**PR 60** (`ci/scan-exit-code`, head `9284d35`): **Verdict: MERGE.** AG-CI-1 is closed. No new
finding.

Order: PR 60 first. The `Vulnerability scan` check of PR 59 is red only because of AG-CI-1
(the scan step stops on the MEDIUM finding). After PR 60 merges, PR 59 takes main and the
check runs again.

Reviewed trees: `cebc005` and `9284d35`, both on `cb18a0b` (main). No production code in
either diff. Every point of the review brief was run, not read.

### Numbers

| Check | Result |
|---|---|
| CI on `cebc005` (PR 59) | Build & test, DCO, Reference guard, Sample container pass; Vulnerability scan fails (AG-CI-1, fixed by PR 60); Security probes: see the suite lines below |
| CI on `9284d35` (PR 60) | Build & test, DCO, Reference guard, Sample container, Vulnerability scan, Security probes: all pass |
| `tools/cipher-probe-dependabot.sh` on `cebc005`, unchanged | 67 fixed, 0 weak |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` on `cebc005` (Docker up) | 104 fixed, 1 weak on a first run made while six other suites ran beside it (`probe_sources_jar_differs_from_a_test_run`; the probe discards its build output, so the cause is not shown); the same probe run alone: FIXED. Together: 105 fixed, 0 weak. CI on this head: Security probes pass |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` on `9284d35` (Docker up) | 106 fixed, 0 weak (the new AG-CI-1 probe included) |
| Real step body of "Refuse a bump on the release path", real `gh`, real API (read only) | PR 55 (central-publishing 0.12.0): refused by the metadata, and refused by the hunks alone with neutral metadata. PR 58 (group of six, Boot parent 4.1.2): arms |
| Real `gh api --paginate --jq` with an `error()` in the filter | exit 1, so the fake `gh` (`exit $?`) matches the real one on the fail-closed path |
| Mutations of the new step, shipped suite run on each | 6 run, 3 killed (metadata loop off, hunk scan off, patch read made non-fatal), 3 survive (AG-AM-4) |
| Real OSV-Scanner 2.6.0 (pinned, checksum verified) on this tree, real scan step body under `bash -e` | main: step exits 1 before the gate. PR 60: step exits 0, gate exits 0 and lists `MEDIUM GHSA-ghc9-756g-vrcv org.json:json@20251224` (twice: core and starter poms) |
| AG-CI-1 probe `probe_scanner_exit_one_stops_the_scan_step` | FIXED on `9284d35`; WEAK with main's `ci.yml`; WEAK with main's `security-scan.yml`; WEAK with `\|\| true` in place of `\|\| rc=$?` |
| PR 60 scan step, fake scanner exit codes 0 1 2 3 127 128 137 255, both workflows | step exit 0 0 1 1 1 1 1 1: only 0 and 1 pass |
| Severity gate on an empty file, `{}`, `{"results":[]}` | exit 2 each (fails closed); on a HIGH report: exit 1 |
| New probes of this pass, on `cebc005` | 4, all WEAK; all 4 FIXED on a scratch copy with the fixes below applied, and the shipped suite then gives 68 fixed, 0 weak |

### Prior finding confirmed

AG-AM-1 (MEDIUM, register row; PR 55 auto-merged central-publishing 0.12.0 on 2026-10-25).
Closed by this PR. The real step body, run with the real `gh` against PR 55's real files and
real commit metadata, refuses. It also refuses with the metadata replaced by a neutral
dependency, on the hunk alone (`central-publishing.version` on the changed line). The 16 new
shipped probes are FIXED on `cebc005`.

### Findings

| Id | Severity | Class | Probe (review probe file) | Status |
|---|---|---|---|---|
| AG-AM-2 | LOW | release path, parent-managed version | `probe_a_parent_bump_moves_the_main_jar_plugin_unseen` | open, fix below |
| AG-AM-3 | INFO | gate precision (false refusal) | `probe_an_ordinary_bump_next_to_a_release_property_is_refused`, `probe_a_release_property_pointing_at_another_property_passes_the_drift_probe` | open, fix below |
| AG-AM-4 | LOW | probe does not pin the control | `probe_a_release_name_can_be_dropped_with_the_suite_green` | open, fix below |

The review probe file is kept with the internal review notes. The fix pass copies its probes
into `tools/cipher-probe-dependabot.sh` first, shows them WEAK, then fixes.

#### AG-AM-2 (LOW): a Spring Boot parent bump still moves the plugin that builds the main jar

The README now says a bump of "the plugins that sign, publish or build the uploaded bundle"
waits for a maintainer. This PR pins three plugins the Boot parent managed (source, javadoc,
deploy) for that reason. A fourth one builds a file the bundle uploads: `maven-jar-plugin`
writes the main jar of each published module. No tree pom declares it, so its version comes
from the parent. A parent bump names only `spring-boot-starter-parent`: neither the metadata
nor any hunk names the jar plugin, and the bump arms.

Evidence from the published parents: Boot 4.0.0 manages `maven-jar-plugin` 3.4.2 and
`maven-source-plugin` 3.3.1; Boot 4.1.1 manages 3.5.1 and 3.4.0. A Boot minor bump is
patch-or-minor for Dependabot, so it auto-merges. That is the same route this PR closed for
the source plugin.

Repro: the probe runs the real step body with metadata
`org.springframework.boot:spring-boot-starter-parent` and a `-U3` patch of the parent
`<version>` line of the real root pom. Result: `go` (arms).

Fix (build and CI files only):
1. Root `pom.xml`: property `<maven-jar.version>3.5.1</maven-jar.version>` next to the other
   three pins (3.5.1 is what Boot 4.1.2 gives, so the built jar does not change), and a
   `pluginManagement` entry `org.apache.maven.plugins:maven-jar-plugin` with
   `<version>${maven-jar.version}</version>` on the line right after the artifactId.
2. `.github/workflows/dependabot-auto-merge.yml`, step "Refuse a bump on the release path":
   add `maven-jar-plugin` to `release_artifacts` and `maven-jar.version` to
   `release_properties`.
3. `tools/cipher-probe-dependabot.sh`: add `maven-jar-plugin` to `parent_managed` in
   `probe_a_release_plugin_version_escapes_the_hunk_scan`.
4. README and CHANGELOG: name `maven-jar-plugin` in the list.

Rejected alternative: put `spring-boot-starter-parent` itself on the release path. Every
Boot patch would then wait for a maintainer, and the parent would still decide plugins
nobody listed. Pinning the plugins that write an uploaded file keeps the rule exact: those
are the main jar, sources jar, javadoc jar, signatures and the bundle.

#### AG-AM-3 (INFO): three ordinary bumps can never auto-merge

The hunk scan counts a listed property name anywhere in the hunk, its three context lines
included. In the root pom, `license-plugin.version`, `exec-plugin.version` and
`dependency-check.version` sit within three lines of `central-publishing.version` and
`maven-gpg.version`. A bump of `license-maven-plugin`, `exec-maven-plugin` or
`dependency-check-maven` is therefore refused, though nothing on the release path changed.
This fails safe, but the shipped good-case probes use isolated hunks and do not see it.

Repro: for every version line of every tree pom that is not on the release path, the probe
builds the real `git diff -U3` patch of a bump and runs the real step. Refused today:
`pom.xml` lines 117, 118, 119 (the three properties above). Every other version line arms.

Fix:
1. In the step's awk, match `release_properties` only on changed lines (lines that start with
   `+` or `-`), and keep matching `release_artifacts` anywhere in the hunk. A property bump
   always changes the line that carries its name; an inline version bump needs the
   artifactId from the context.
2. Because the property match narrows, extend
   `probe_a_release_plugin_version_escapes_the_hunk_scan`: in every tree pom, the value of a
   listed property must be a literal version, never `${...}`. Today a pom with
   `<maven-gpg.version>${gpg.base}</maven-gpg.version>` passes the drift probe (second probe
   above), and after fix 1 a bump on the `<gpg.base>` line would name nothing listed.

Checked on a scratch copy: with fix 1, all 67 shipped probes stay FIXED and the three bumps arm.

#### AG-AM-4 (LOW): three names can leave the list with every probe green

Six mutations of the new step, the full shipped suite run on each:

| Mutation | Suite result |
|---|---|
| metadata loop switched off | 2 WEAK (killed) |
| hunk scan switched off | 2 WEAK (killed) |
| failed patch read made non-fatal | 1 WEAK (killed) |
| `central-publishing-maven-plugin` removed from `release_artifacts` | 0 WEAK (survives) |
| `maven-wrapper-plugin` removed | 0 WEAK (survives) |
| `maven-wrapper` removed | 0 WEAK (survives) |

The first survivor is the plugin of AG-AM-1. Today its bump is still refused by the property
line, so there is no bypass on this tree. But a later edit can drop the name with CI green,
and the drift probe only checks names that are still in the list.

Fix: a shipped probe `probe_a_release_list_name_was_dropped` in
`tools/cipher-probe-dependabot.sh`, defined with the other release-path probes and registered
with them. It holds the expected lists (the eight names plus `maven-jar-plugin`, the five
properties plus `maven-jar.version`). It runs the real step for each artifact with metadata
`org.example:<name>` and a neutral hunk, and for each property with neutral metadata and a
hunk that changes `<name>` only; each must refuse. The review's meta-probe drops each name
from a copy of the step in turn and requires the shipped probe to go WEAK every time. Checked
on a scratch copy: FIXED with the probe added; each of the 15 drops (nine artifacts, six properties, `maven-jar-plugin` and `maven-jar.version` included) turns it WEAK.

### Attacks tried, no finding

| Attack | Result |
|---|---|
| Group PR of eleven, the listed plugin last | refused |
| Same artifactId, other groupId | refused (the match is on the artifactId, any groupId) |
| Case change (`Maven-GPG-Plugin`) or a U+2010 hyphen in a property | arms; not a finding: Maven coordinates and property names are byte-exact, the upstream release cannot rename our pom's names, and a renamed property in our pom is caught by the drift probe |
| Listed plugin declared with an inline version in a child pom | refused by the hunk; the drift probe walks every tree pom |
| Version four or more lines away from the artifactId | the drift probe goes WEAK (tried on a copy) |
| Parent `pluginManagement` we do not control | AG-AM-2 |
| A second file with `patch: null`, an empty patch, an empty or non-JSON dependency list, an empty dependency name | refused |
| Files API truncation (3000 files, 300 per diff, a patch cut mid-way) | suspected only, not reproduced: GitHub omits `patch` for a diff too large, which refuses; the manifest step caps a PR at 50 files and checks the count; no partial patch could be produced |
| A person pushes after arming | the existing disarm job runs on that push; the arm call carries `--match-head-commit`; a push made with the workflow token starts no check, so a required check never turns green |
| The step runs before arming on every path | yes: arm has no `always()`, so a failed or refused earlier step skips it, and the disarm step runs |
| GitHub runs the step as `bash -e` | every command that can fail is followed by `\|\| refuse`; an unexpected failure ends the step red, arm is skipped |
| Fake `gh` against the real one | same exit status on a `--jq` error (checked); the real step on PR 55 and PR 58 gave the same result as the fakes predict |

### PR 60

Confirmed by the real scanner on this tree, not only by the fake. On main the scan step ends
at exit 1 before the gate. On `9284d35` the step passes, the gate passes, and the gate's
output lists the MEDIUM finding with its id, package and pom. The weekly sweep also writes it
to the job summary. The release path is untouched: the Grype step in `release.yml` already
uses `set +e`, and its below-threshold list goes to the release summary with "Each line needs
a decision in the release notes". So the MEDIUM is listed, not hidden, and the release-time
rule holds. No other `rc=$?` on the line after a command exists in the workflows (the only
other one is the Grype step, inside `set +e`).

### Copies of the AG-CI-1 fix

| Repository, PR | Same change? |
|---|---|
| gdpr-shredding PR 61 (`ede8dc5`) | Yes. Changed lines identical except the sample module name; probe identical. |
| stripe-einvoice PR 61 (`b4c8219`) | Yes. Same lines except the module name; the probe writes to `${PROBE_CAPTURE:-/dev/null}` (that suite's harness), same behaviour. |
| stripe-einvoice-pro PR 8 (`296b0bd`) | No. Different file: the scan is in `tools/release/osv-scan.sh`, which does not run under `-e`, so the defect was latent there. Same line pattern, plus its own probe that runs the script under `bash -e` with a stub installer. Not a copy: it needs its own check, not verifier numbers alone. |

### Not tried

- A live Dependabot run on this repository: no Dependabot PR exists for a listed plugin
  right now. The real API runs used PR 55 and PR 58 after the fact.
- The real `fetch-metadata` action on a synthetic commit message (the step reads its output;
  the action was reviewed in earlier passes and is pinned by sha).
- mawk (the runner's `awk`) locally: the step ran here under BSD awk; CI runs the shipped
  probes under mawk.
- Effective-pom comparison of every plugin bound in `deploy -Prelease` between Boot minors
  beyond the four that write uploaded files.
- stripe-einvoice-pro PR 8 beyond reading its diff.
- Why `probe_sources_jar_differs_from_a_test_run` went WEAK once under load. It sends the
  build output to `/dev/null`, so a failed build and a real byte difference look the same.
  This probe is older than both PRs; a later pass may want it to keep the last lines.

## 2026-11-11, pass 2

Summary. The three pass 1 findings are closed: each probe was WEAK before the fix pass and is
FIXED after it. But the AG-AM-3 fix opened one small gap, and the drift probe has one older
gap. Both are LOW. They go to a fix list; there is no pass 3.

**PR 59** (`ci/dependabot-release-path-refusal`, head `66298ab`): **Verdict: MERGE WITH FIXES.**
No HIGH, no MEDIUM. Two new LOW findings (AG-AM-5, AG-AM-6). Both are fixed before merge.

Reviewed: the three fix commits `f7254a6`, `1a8d1b7`, `66298ab` on top of the pass 1 head.
No production code in the diff. The branch is behind main (PR 60 merged); GitHub reports it
mergeable.

### Numbers

| Check | Result |
|---|---|
| CI on `66298ab` | Build & test, DCO sign-off, Reference guard, Sample container, Vulnerability scan, Security probes: all pass |
| `tools/cipher-probe-dependabot.sh` on `66298ab`, unchanged | 72 fixed, 0 weak (67 before, plus the 5 copied review probes) |
| Pass 1 review probes on `5032e49` (before the fix pass) | 4 weak, 0 fixed |
| Pass 1 review probes on `66298ab` | 0 weak, 4 fixed |
| Effective pom of `agent-guard-core`, before and after | `maven-jar-plugin` 3.5.1 both times: the pin does not change the built jar |
| Real step body of "Refuse a bump on the release path" on `66298ab`, real `gh`, real API (read only) | PR 55, neutral metadata: refused on `central-publishing.version` (hunk only). PR 55, real name: refused. PR 58 (group of six), neutral metadata: arms |
| Mutations of the fixes, shipped suite run on each | 6 run, 5 killed: artifacts matched on changed lines only (1 weak), property loop off (2), property matched in context again (1), literal-value check off (1), jar pin removed from the root pom (2). 1 survives: the changed-line buffer never reset between hunks. That mutant is equivalent: the buffer only grows inside a hunk that has a change, and that hunk already reported the name, so the refuse or arm result cannot change |
| Pass 2 review probes on `66298ab` | 2 weak (AG-AM-5, AG-AM-6) |
| Pass 2 review probes on `5032e49` | AG-AM-5 fixed (the context match still refused it), AG-AM-6 weak (older than the fix pass) |
| Real Maven, both new layouts on a copy, `help:effective-pom -Prelease` | accepted; the three-line property resolves to its trimmed value; the version placed above the artifactId is the one the core module uses |
| Harness check of the drift probe in a copy | unchanged copy: FIXED; a version two lines below the artifactId: WEAK. So "drift probe green" in the new probes is a real result |

### Pass 1 findings

| Id | Severity | How verified | Status |
|---|---|---|---|
| AG-AM-2 | LOW | `probe_a_parent_bump_moves_the_main_jar_plugin_unseen` WEAK on `5032e49`, FIXED on `66298ab`. The effective pom keeps 3.5.1. The plugin is in the step's list, its property is in the property list, and the drift probe now names it as parent-managed. Mutation: removing the pinned version line from the root pom turns the shipped copy of the probe WEAK (row above) | closed |
| AG-AM-3 | INFO | `probe_an_ordinary_bump_next_to_a_release_property_is_refused` and `probe_a_release_property_pointing_at_another_property_passes_the_drift_probe` WEAK on `5032e49`, FIXED on `66298ab`. The real step on PR 55 still refuses on the hunk alone | closed; its fix opened AG-AM-5 |
| AG-AM-4 | LOW | `probe_a_release_name_can_be_dropped_with_the_suite_green` WEAK on `5032e49`, FIXED on `66298ab`: each of the 15 single-name drops turns the shipped `probe_a_release_list_name_was_dropped` WEAK | closed |

### New findings

| Id | Severity | Class | Probe (review probe file, pass 2) | Status |
|---|---|---|---|---|
| AG-AM-5 | LOW | release path, gate precision (fails open) | `probe_a_multiline_release_property_bump_arms` | open, fix below |
| AG-AM-6 | LOW | release path, drift probe layout gap | `probe_a_release_version_before_its_artifactid_escapes_the_drift_probe` | open, fix below |

The pass 2 probes are kept with the internal review notes, beside the pass 1 file. The fix
pass copies both into `tools/cipher-probe-dependabot.sh` first, shows them WEAK, then fixes.

#### AG-AM-5 (LOW): a listed property written on three lines changes with no listed name

The AG-AM-3 fix matches a listed property only on changed lines. The workflow comment gives
the reason: "A property bump always changes the line that carries its name." That is not
always true. Maven accepts this layout and trims the value:

```xml
    <maven-gpg.version>
      3.2.8
    </maven-gpg.version>
```

A bump changes only the middle line. That line names nothing listed, so the hunk scan finds
nothing. Before the fix, the name in the context line refused the bump. The drift probe was
extended to protect this narrowing, but its literal-value check reads one line, so it stays
green.

Failure scenario: a maintainer or a pom formatter writes a listed property on three lines.
Later a bump arrives whose metadata does not name the plugin (the case the hunk scan exists
for). The bump of the signing or publishing plugin arms with every check green.

Repro: on a copy of the tree, rewrite `maven-gpg.version` on three lines and commit. Build
the real `-U3` patch of a bump of the middle line. Run the real step with neutral metadata
(`org.jacoco:jacoco-maven-plugin`): `go`. Run the shipped drift probe on that copy: FIXED.
The same probe on `5032e49` gives `stop`.

Fix (probe and comment only):
1. `tools/cipher-probe-dependabot.sh`, `probe_a_release_plugin_version_escapes_the_hunk_scan`:
   replace the `${` check with a stricter one. In every tree pom, every line that holds the
   opening tag `<name>` of a listed property must match `^\s*<name>[^<$]+</name>\s*$` (open
   tag, literal value and close tag on one line). Any other line with that opening tag is WEAK.
   This also keeps the AG-AM-3 case (`${...}` as value) WEAK.
2. `.github/workflows/dependabot-auto-merge.yml`, comment above the step: say that the drift
   probe requires each listed property on one line, which is why a changed-line match is
   enough.
3. Add `probe_a_multiline_release_property_bump_arms` to the shipped suite.

Checked on a scratch copy with fix 1 applied: the drift probe stays FIXED on the real tree and
goes WEAK on the three-line layout and on the `${gpg.base}` layout.

Rejected alternative: match a property name in the context again when the changed line holds
no tag. It adds a second rule to the step for a layout the tree does not use; the probe
keeps the layout out instead.

#### AG-AM-6 (LOW): a version above its artifactId escapes the drift probe

The drift probe looks for a listed plugin's `<version>` only on the lines after its
`<artifactId>`. Maven reads the children of `<plugin>` in any order. This child-pom entry is
valid:

```xml
      <plugin>
        <version>3.2.8</version>
        <groupId>org.apache.maven.plugins</groupId>
        <configuration>
          <skip>false</skip>
        </configuration>
        <artifactId>maven-gpg-plugin</artifactId>
      </plugin>
```

The probe reads it as "inherits from `pluginManagement`", and the root pin satisfies it. A
bump of the version line has neither the artifactId nor a listed property in its hunk.

Failure scenario: same as AG-AM-5, with a child pom of a published module (the core module
in the repro). The version shown is the one the core module builds with.

Repro: on a copy, insert the entry above into `agent-guard-core/pom.xml` and commit. Build the
real `-U3` patch of `3.2.8` to `3.2.9`. Run the real step with neutral metadata: `go`. Run the
drift probe on the copy: FIXED. Same result on `5032e49`, so this gap is as old as the step.

Fix (probe only): in `probe_a_release_plugin_version_escapes_the_hunk_scan`, read each
innermost `<plugin>` or `<dependency>` element from its open tag to its close tag. If it holds
a listed artifactId, its own `<version>` (any line inside that element, not inside a nested
element) must be either a listed property `${name}` or an inline literal on the line right
after the artifactId. Anything else is "far" and WEAK. A version inside a nested
`<dependencies>` block of the plugin is not the plugin's version. Then add
`probe_a_release_version_before_its_artifactid_escapes_the_drift_probe` to the shipped suite.
This fix was not tried on a scratch copy; the verifier's run must show the new probe FIXED and
the drift probe still FIXED on the real tree.

### Attacks tried, no finding

| Attack | Result |
|---|---|
| Property bump on a changed line, in the root pom and in a child pom | refused |
| Property renamed (old name on the `-` line) | refused: removed lines count as changed |
| `${...}` as value of a listed property | drift probe WEAK (AG-AM-3 fix works) |
| A listed plugin's version moved two or more lines below its artifactId | drift probe WEAK |
| Listed property overridden in a child pom or a profile | refused: the name is on the changed line |
| Group PR touching the root and a child pom (two patches) | each patch starts with `@@`, so the scan resets per hunk; a listed name in either refuses |
| Boot parent bump (the AG-AM-2 route) | arms, and correctly so: the four parent-managed plugins that write uploaded files now come from our own properties |
| A name removed from a list | the shipped per-name probe goes WEAK, for each of the 15 names |
| Two poms in one PR, only an ordinary bump in each | arms (no false refusal across files) |

### Not tried

- Version ranges or `LATEST`/`RELEASE` as the value of a listed property. The literal check
  only refuses `${`; whether Maven 3.9 resolves a range for a build plugin was not tested.
- mawk locally (not installed here). CI runs the shipped suite under the runner's awk and is
  green.
- A live Dependabot run, and the real `fetch-metadata` action, as in pass 1.
- Plugins that change the main jar's bytes without writing a separate upload (compiler,
  resources): out of the rule's scope as pass 1 set it.
- The whole-module release-candidate pass: separate, before the next tag.
