#!/usr/bin/env bash
#
# Cipher probes for the Maven Central release pipeline (branch feat/release-pipeline).
#
# Every probe below asserts a WEAKNESS. Each one PASSES while its finding is open and must
# FLIP TO FAILING once the matching finding from the security review is fixed. A probe
# that starts failing is the signal that the item is closed; delete it in the same PR that
# fixes it.
#
# The first block (M-, L-, I-ids) is the first pass, on 645397d: all FIXED at 30aec6f
# except the one reclassified as not-a-finding; see the note on
# probe_release_job_can_exec_an_unverified_maven_distribution below, which replaces it.
# The second block (N-ids) is the re-verification of 30aec6f: all WEAK there, all FIXED at
# 1da507e.
# The third block (F-ids) is the final verification of 1da507e, after the FSL-1.1-ALv2
# licence switch: all WEAK there.
#
#   tools/cipher-probe-release-pipeline.sh            static probes only (seconds)
#   CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh   + the two build probes
#
# Exit code is 0 once every probe has flipped to FIXED, 1 while any weakness is still
# there (`[ "$pass" -eq 0 ]` on the last line). The header of this file used to claim the
# opposite; the code was always right and the sentence was wrong. This file is evidence,
# not a CI gate: nothing in .github/ runs it.
#
set -uo pipefail
cd "$(dirname "$0")/.."

WF=.github/workflows/release.yml
pass=0; flipped=0

# A probe that shells out to an inner build, a script or any external command writes that
# command's output HERE - `>>"$PROBE_CAPTURE" 2>&1` - and the reporter below prints the last
# 30 lines of it whenever the probe reads WEAK, so a transient runner failure inside an inner
# Maven build is distinguishable from the weakness the probe is looking for.
#
# A probe that cannot run at all (no `zip`, CIPHER_PROBE_MAVEN unset, scanner not installable)
# sets PROBE_SKIP_REASON and returns 0: unverifiable counts as WEAK, and says why on the same
# line.
PROBE_CAPTURE=""
PROBE_SKIP_REASON=""
export PROBE_CAPTURE PROBE_SKIP_REASON

probe() { # probe <name> <"still weak" message>; body returns 0 when the weakness is present
  local name="$1" msg="$2"; shift 2
  # CIPHER_PROBE_ONLY=<regex> runs only the matching probes (development aid; unset in CI).
  if [ -n "${CIPHER_PROBE_ONLY:-}" ] && ! [[ "$name" =~ $CIPHER_PROBE_ONLY ]]; then return 0; fi
  PROBE_CAPTURE="$(mktemp)"
  PROBE_SKIP_REASON=""
  if "$@"; then
    printf 'WEAK    %-52s %s\n' "$name" "$msg"; pass=$((pass + 1))
    if [ -n "$PROBE_SKIP_REASON" ]; then
      printf '        unverifiable: %s\n' "$PROBE_SKIP_REASON"
    fi
    if [ -s "$PROBE_CAPTURE" ]; then
      printf '        --- last 30 lines of this probe%s inner command output ---\n' "'s"
      tail -n 30 "$PROBE_CAPTURE" | sed 's/^/        | /'
      printf '        --- end of inner command output ---\n'
    elif [ -z "$PROBE_SKIP_REASON" ]; then
      printf '        (no inner command output was captured for this probe)\n'
    fi
  else
    printf 'FIXED   %-52s\n' "$name"; flipped=$((flipped + 1))
  fi
  [ -z "${CIPHER_PROBE_KEEP:-}" ] || cp "$PROBE_CAPTURE" "$CIPHER_PROBE_KEEP.$name" 2>/dev/null || true
  rm -f "$PROBE_CAPTURE"
  PROBE_CAPTURE=""
}

# ---------------------------------------------------------------------------
# M4 - the workflow_dispatch version input is validated with a line-oriented grep,
#      so a value containing a newline passes and injects extra lines into
#      $GITHUB_OUTPUT. Extracts the actual "Derive the release version" step body from
#      release.yml and runs it for real against the malicious input, so this probe tests
#      the workflow's own current logic and not a frozen copy of the old snippet.
# ---------------------------------------------------------------------------
probe_multiline_version_accepted() {
  local step out rc
  step=$(awk '
    /- name: Derive the release version/ { infield=0; instep=1 }
    instep && /run: \|/ { inrun=1; next }
    instep && !inrun && /^      - name:/ && !/Derive the release version/ { exit }
    inrun && /^      - name:/ { exit }
    inrun { print }
  ' "$WF")
  [ -n "$step" ] || return 0   # step vanished: cannot prove the fix, count as still weak
  out="$(mktemp)"
  GITHUB_EVENT_NAME=workflow_dispatch \
  INPUT_VERSION="$(printf '0.1.0\nmalicious=1')" \
  GITHUB_OUTPUT="$out" \
  bash -c "$step" >/dev/null 2>&1
  rc=$?
  # Weak: the step exited 0 (accepted the input) and the injected extra line landed in
  # $GITHUB_OUTPUT. Fixed: the step rejected the multiline input (non-zero exit).
  if [ "$rc" -eq 0 ] && grep -q '^malicious=1$' "$out" 2>/dev/null; then
    rm -f "$out"; return 0
  fi
  rm -f "$out"; return 1
}

# ---------------------------------------------------------------------------
# M3 - the release job restores the setup-java maven cache, which covers
#      ~/.m2/wrapper/dists. mvnw execs an existing distribution without ever
#      re-checking distributionSha256Sum, so a poisoned cache entry runs
#      arbitrary Maven in the job that holds the signing key.
# ---------------------------------------------------------------------------
probe_release_job_restores_maven_cache() {
  awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  publish:$/ {f=1} f' "$WF" | grep -q 'cache: maven'
}

# Re-verification of 30aec6f. The probe that used to sit here,
# probe_mvnw_skips_checksum_for_existing_distribution, grepped the vendored `mvnw` for a
# checksum re-check inside its "found existing MAVEN_HOME, exec it" branch. That probe was
# refused: no Maven Wrapper script re-checks an unpacked distribution
# (distributionSha256Sum is only ever compared against the freshly downloaded zip), and the
# only marker that would satisfy the text match - a sidecar checksum file written at install
# time - is writable by exactly the attacker M3 describes, in the same write that plants the
# poisoned distribution. It would have turned the probe green without adding a control.
# Reclassified as NOT A FINDING: the property is not ours to hold.
#
# It is replaced, not dropped, by the probe below, which asserts the operational property
# that does close M3 and that this repository does control: the signing job restores no
# Maven cache, and it removes ~/.m2/wrapper/dists BEFORE the first mvnw invocation, so
# `[ -d "$MAVEN_HOME" ]` is always false there and mvnw always takes the download-and-verify
# path. Weak if the cache comes back, if the removal step disappears, or if it drifts below
# the first mvnw call.
probe_release_job_can_exec_an_unverified_maven_distribution() {
  local job first_mvnw rm_dists
  job=$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  publish:$/ {f=1} f' "$WF")
  printf '%s' "$job" | grep -q 'cache: maven' && return 0          # cache back: weak
  rm_dists=$(printf '%s\n' "$job" | grep -n 'rm -rf ~/\.m2/wrapper/dists' | head -1 | cut -d: -f1)
  [ -n "$rm_dists" ] || return 0                                    # no removal step: weak
  first_mvnw=$(printf '%s\n' "$job" | grep -n '\./mvnw' | head -1 | cut -d: -f1)
  [ -n "$first_mvnw" ] || return 0                                  # no mvnw at all: cannot prove it
  [ "$rm_dists" -lt "$first_mvnw" ] && return 1                     # removed before any mvnw: FIXED
  return 0
}

# ---------------------------------------------------------------------------
# M5 - any ref can release: no environment gate, no check that the tag's commit
#      is an ancestor of main, no requirement that the tag be signed.
# ---------------------------------------------------------------------------
probe_release_job_has_no_environment_gate() { ! grep -q '^\s*environment:' "$WF"; }
probe_release_does_not_check_tag_ancestry()  { ! grep -q 'merge-base' "$WF"; }
probe_release_does_not_verify_tag_signature() { ! grep -qE 'verify-tag|--verify-signatures' "$WF"; }

# ---------------------------------------------------------------------------
# M7 - Apache-2.0 is declared in the POM and there is no licence text anywhere.
# ---------------------------------------------------------------------------
probe_no_licence_file_in_the_repository() {
  ! git ls-files | grep -qiE '^(LICENSE|LICENCE|NOTICE)(\..*)?$'
}

# ---------------------------------------------------------------------------
# L1 - the jars that are signed and uploaded come from the `clean deploy` build,
#      a third build that is never compared against the two the reproducibility
#      script checks.
# ---------------------------------------------------------------------------
probe_published_jars_are_never_checksum_compared() {
  ! grep -qE 'sha256|shasum' "$WF"
}

# ---------------------------------------------------------------------------
# L2 - concurrency is keyed on the ref, so a tag push and a workflow_dispatch for
#      the same version can release at the same time.
# ---------------------------------------------------------------------------
probe_concurrency_group_is_ref_scoped_not_version_scoped() {
  grep -q 'group: release-\${{ github.ref }}' "$WF"
}

# ---------------------------------------------------------------------------
# L3 - checkout leaves the GITHUB_TOKEN in .git/config for every Maven plugin
#      that runs in the release job.
# ---------------------------------------------------------------------------
probe_checkout_persists_credentials() { ! grep -q 'persist-credentials' "$WF"; }

# ---------------------------------------------------------------------------
# L4 - signed jars and .asc files of a FAILED release are uploaded anyway. Scoped to the
#      single step that uploads them: a whole-file grep for both strings anywhere false-
#      positives once the workflow legitimately has an unrelated `if: always()` step
#      (e.g. a `docker compose down` teardown) that has nothing to do with the evidence
#      upload.
# ---------------------------------------------------------------------------
probe_evidence_uploaded_even_when_the_release_failed() {
  awk '
    /^      - name:.*[Rr]elease evidence/ { instep=1; found=0 }
    instep && /if: always\(\)/ { found=1 }
    instep && /\*\.asc/ { has_asc=1 }
    instep && /^      - name:/ && !/[Rr]elease evidence/ { instep=0 }
    END { exit !(found && has_asc) }
  ' "$WF"
}

# ---------------------------------------------------------------------------
# I4 - `-X` makes Maven print env.CENTRAL_TOKEN and env.MAVEN_GPG_PASSPHRASE in
#      clear. The workflow does not use it today; nothing stops it being added.
# ---------------------------------------------------------------------------
probe_nothing_forbids_maven_debug_in_the_release_job() {
  ! grep -qE 'refusing.*(-X|--debug)|forbid.*debug' "$WF"
}

# ---------------------------------------------------------------------------
# M1 - licence gate: a dependency passes when ANY one of its declared licences is
#      on the allowlist, so `Apache-2.0 OR GPL-3.0` slips through. Runs a real build
#      against a synthetic dependency in a throwaway clone, through `verify` so the
#      tools/check-third-party-licences.sh denial pass (M1/M2 fix) actually runs -
#      the plugin's own allowlist stops at `package` and would report FIXED for the
#      wrong reason.
# ---------------------------------------------------------------------------
probe_licence_gate_accepts_a_dual_apache_or_gpl_dependency() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc; work=$(mktemp -d)
  cat > "$work/syn.pom" <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>example.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version><packaging>jar</packaging>
<name>syn-dual</name><licenses>
  <license><name>Apache-2.0</name><url>http://example.invalid</url></license>
  <license><name>GPL-3.0</name><url>http://example.invalid</url></license>
</licenses></project>
EOF
  : > "$work/empty.txt"; (cd "$work" && jar cf syn.jar empty.txt)
  git clone -q --no-hardlinks . "$work/tree" || return 1
  (
    cd "$work/tree" || exit 1
    ./mvnw -B -q org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
      -Dfile="$work/syn.jar" -DpomFile="$work/syn.pom" >/dev/null 2>&1 || exit 1
    perl -0pi -e 's{<dependencies>}{<dependencies>\n    <dependency><groupId>example.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version></dependency>}' \
      agent-guard-core/pom.xml
    ./mvnw -B -pl agent-guard-core -am verify \
      -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true -Denforcer.skip=true >/dev/null 2>&1
  )
  rc=$?
  rm -rf "$work"
  # exit 0 from the build == the GPL-3.0 half was ignored == the weakness is present
  return "$rc"
}

# ===========================================================================
# Re-verification of 30aec6f: probes for the findings the fixes introduced.
# Every one of these asserts a weakness that is present at 30aec6f and must flip
# to FIXED when the matching N-finding from the security review's "Re-verification
# (30aec6f)" pass is closed.
# ===========================================================================

# Runs tools/check-third-party-licences.sh against ONE synthetic dependency line, in a
# throwaway tree, so the repository's own target/ files cannot mask the result.
# Echoes the script's exit code: 0 = the dependency passed the gate.
licence_verdict() { # licence_verdict <notices line>
  local work rc
  work=$(mktemp -d)
  mkdir -p "$work/tools" "$work/mod/target"
  cp tools/check-third-party-licences.sh "$work/tools/"
  printf '\nLists of 1 third-party dependencies.\n%s\n' "$1" > "$work/mod/target/THIRD-PARTY-NOTICES.txt"
  # N1: the script now takes the module build directory and packaging as arguments (it
  # checks one module's own notices, not a tree-wide `find`); jar is the packaging exercised
  # by every synthetic case below.
  "$work/tools/check-third-party-licences.sh" "$work/mod/target" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  return "$rc"
}

# ---------------------------------------------------------------------------
# N2 - the denial pass matches hyphenated SPDX ids and the literal substring "gpl".
#      Real POMs declare licences in prose. "GNU General Public License v3" contains no
#      "gpl" at all, and "Mozilla Public License, Version 2.0" is not the string "mpl-2.0",
#      so both pass the all-of denial pass on their permissive half - the exact M1 hole,
#      respelled. The script's own comment claims it catches "GNU General Public License v3".
# ---------------------------------------------------------------------------
probe_denial_pass_misses_prose_licence_names() {
  licence_verdict '     (Apache-2.0) (GNU General Public License v3) x (c.s:syn:1.0 - no url defined)' &&
  licence_verdict '     (Apache-2.0) (Mozilla Public License, Version 2.0) x (c.s:syn:1.0 - no url defined)'
}

# ---------------------------------------------------------------------------
# N3 - the coordinate the denial pass matches is taken from the FIRST "(g:a:v - " group on
#      the line, and a dependency's own <name> is attacker-controlled text that lands on
#      that line ahead of its real coordinate. A dependency named
#      "evil (ch.qos.logback:logback-core:1.5.6 - http://x)" is read as logback-core, which
#      is on the coordinate allowlist, so every licence it declares is skipped. Second half:
#      a line whose version carries a character outside [\w.-] matches no coordinate at all
#      and is silently skipped rather than failing the build - a fail-open parser.
# ---------------------------------------------------------------------------
probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name() {
  licence_verdict '     (GPL-3.0) evil (ch.qos.logback:logback-core:1.5.6 - http://x) (c.s:evil:1.0 - no url defined)' &&
  licence_verdict '     (GPL-3.0) x (c.s:syn:1.0+build - no url defined)'
}

# ---------------------------------------------------------------------------
# N10 - a licence line carrying an empty "()" token makes the script die on
#       "tok_list[@]: unbound variable" under set -u, abandoning every file and line it had
#       not reached yet. It exits 1, so it fails closed, but on a shell error rather than a
#       verdict, and it stops scanning.
# ---------------------------------------------------------------------------
probe_denial_pass_crashes_on_an_empty_licence_token() {
  local work out
  work=$(mktemp -d); mkdir -p "$work/tools" "$work/mod/target"
  cp tools/check-third-party-licences.sh "$work/tools/"
  printf '\nLists of 1 third-party dependencies.\n     () x (c.s:syn:1.0 - no url defined)\n' \
    > "$work/mod/target/THIRD-PARTY-NOTICES.txt"
  out=$("$work/tools/check-third-party-licences.sh" "$work/mod/target" jar 2>&1)
  rm -rf "$work"
  printf '%s' "$out" | grep -q 'unbound variable'
}

# ---------------------------------------------------------------------------
# N1 - the exec:exec denial pass is inherited by every module, so it runs on
#      agent-guard-parent FIRST, before any module has produced a THIRD-PARTY-NOTICES.txt.
#      The script fails closed when it finds none, so `./mvnw verify` fails on any clean
#      checkout - which is what ci.yml and the release runner do. It only passes in a
#      working tree because the PREVIOUS build's notices files are still on disk when the
#      parent's verify runs (each module is cleaned when its own turn comes), which also
#      means the parent's pass is reading stale evidence.
# ---------------------------------------------------------------------------
probe_verify_fails_on_a_clean_checkout() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc
  work=$(mktemp -d)
  git clone -q --no-hardlinks . "$work/tree" || { rm -rf "$work"; return 1; }
  ( cd "$work/tree" && ./mvnw -B verify \
      -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true >/dev/null 2>&1 )
  rc=$?
  rm -rf "$work"
  [ "$rc" -ne 0 ]   # non-zero on a clean checkout == the weakness is present
}

# ---------------------------------------------------------------------------
# Post-release finding (2026-09-10, run 34419387032) - scripts/verify-reproducible.sh always
# builds with -DskipTests, so its two builds never produce target/surefire-reports/. license-
# maven-plugin's add-third-party execution (addOutputDirectoryAsResourceDir defaults to true,
# includes "**/*.txt") registers outputDirectory (target/) as a live project resource at
# package phase; maven-source-plugin's jar-no-fork execution, bound to the same phase, reads
# project.getResources() at the moment IT runs and archives every target/*.txt it finds into
# the sources jar - THIRD-PARTY-NOTICES.txt deterministically, but also
# target/surefire-reports/*.txt whenever tests actually ran before package, which is never
# byte-identical run to run. A real `clean deploy -Prelease` (what the release job runs) DOES
# run tests, so its sources jars differed from what verify-reproducible.sh had already
# checksummed for the same tree: agent-guard-core-0.1.0-sources.jar and
# agent-guard-spring-boot-starter-0.1.0-sources.jar both failed "Confirm the deployed jars
# match the reproducibility check", while the main jars, javadoc jars and POMs matched.
#
# Behavioural probe: clones HEAD, runs the real scripts/verify-reproducible.sh to get its
# recorded sha256 for each sources jar, then runs a real `clean verify -Prelease
# -Dgpg.skip=true` (tests running, same outputTimestamp) and compares the sources jars it
# produces against those checksums. Weak while either sources jar differs.
# ---------------------------------------------------------------------------
probe_sources_jar_differs_from_a_build_that_actually_ran_tests() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] || { echo "        (skipped: set CIPHER_PROBE_MAVEN=1)" >&2; return 0; }
  local work rc
  work=$(mktemp -d)
  git clone -q --no-hardlinks . "$work/tree" || { rm -rf "$work"; return 1; }
  (
    cd "$work/tree" &&
    ts="$(scripts/git-commit-timestamp.sh)" &&
    REPRODUCIBLE_SHA_FILE="$PWD/repro-sha.txt" scripts/verify-reproducible.sh &&
    ./mvnw -B -q clean verify -Prelease -Dgpg.skip=true -Dproject.build.outputTimestamp="$ts" &&
    for jar in agent-guard-core/target/*-sources.jar agent-guard-spring-boot-starter/target/*-sources.jar; do
      name="$(basename "$jar")" &&
      actual="$(shasum -a 256 "$jar" | cut -d' ' -f1)" &&
      expected="$(awk -v n="$name" '$2==n{print $1}' repro-sha.txt)" &&
      [ -n "$expected" ] && [ "$actual" = "$expected" ] || exit 1
    done
  ) >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  [ "$rc" -ne 0 ]   # a mismatch, a missing jar, or a build failure: weakness present (WEAK)
}

# ---------------------------------------------------------------------------
# N4 - the L5 bundle assertion looks for the bundle in agent-guard-sample/target/. The
#      plugin writes it to the TOP-LEVEL project's target/ (reproduced: a real
#      `deploy -Prelease` on a 0.1.0 checkout produced ./target/central-publishing/
#      central-bundle.zip, 45 files, no agent-guard-sample). The step therefore always
#      fails with "was not created": the bundle is never inspected, and the two steps
#      after it - L1's checksum comparison and L4's evidence upload, both `if: success()` -
#      never run.
# ---------------------------------------------------------------------------
probe_bundle_assertion_points_at_the_wrong_path() {
  grep -q 'agent-guard-sample/target/central-publishing/central-bundle.zip' "$WF"
}

# ---------------------------------------------------------------------------
# N5 - the tag-signature check is skipped, with a warning and exit 0, whenever
#      vars.RELEASE_SIGNING_KEY_ID is unset: a security control whose default is off.
#      Second half: even when it is set, `git verify-tag` only asserts that SOME key in the
#      keyring made a good signature, never that it was that key id (reproduced with two
#      throwaway keys: a tag signed by the second one verifies with exit 0). The binding
#      needs `git verify-tag --raw` and a VALIDSIG match on the full 40-hex fingerprint.
# ---------------------------------------------------------------------------
probe_tag_signature_check_is_optional_and_unbound() {
  local step
  step=$(sed -n '/- name: Verify the tag signature/,/^      - name:/p' "$WF")
  printf '%s' "$step" | grep -q '::warning::' && return 0        # skips when unset: weak
  printf '%s' "$step" | grep -q 'VALIDSIG' || return 0           # no key binding: weak
  return 1
}

# ---------------------------------------------------------------------------
# N6 - the I4 debug guard matches three literal flags. `--errors` (the long form of -e) is
#      not one of them, and neither is -Dorg.slf4j.simpleLogger.defaultLogLevel=debug in
#      MAVEN_OPTS, which turns on the identical DEBUG stream. Reproduced against this
#      repository: both a plain -X run and a MAVEN_OPTS slf4j-debug run print
#      "[DEBUG] env.CENTRAL_TOKEN: <value>" and "[DEBUG] env.MAVEN_GPG_PASSPHRASE: <value>"
#      in clear.
# ---------------------------------------------------------------------------
probe_debug_guard_misses_the_slf4j_log_level() {
  local guard
  guard=$(awk '/- name: Refuse Maven debug output in this job/{i=1} i&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{print}' "$WF")
  [ -n "$guard" ] || return 0
  MAVEN_ARGS='' MAVEN_OPTS='-Dorg.slf4j.simpleLogger.defaultLogLevel=debug' \
    bash -c "$guard" >/dev/null 2>&1 && return 0    # guard passed a debug setting: weak
  MAVEN_ARGS='' MAVEN_OPTS='--errors' bash -c "$guard" >/dev/null 2>&1 && return 0
  return 1
}

# ---------------------------------------------------------------------------
# N6 (run 34389977548, tag v0.1.0): the first version of the guard matched the bare words
#      `simpleLogger` and `defaultLogLevel` unconditionally, so it refused the workflow's
#      OWN job-level MAVEN_OPTS pin (`-Dorg.slf4j.simpleLogger.defaultLogLevel=info`) on
#      every run, before anything was uploaded - the guard's synthetic env cases above
#      never exercised the real job env, so this hole shipped past them. This probe reads
#      the workflow's actual declared MAVEN_ARGS/MAVEN_OPTS out of its own "env:" block
#      (not a hardcoded copy) and runs the real guard step body against exactly that env:
#      weak if the guard refuses its own declared pin.
# ---------------------------------------------------------------------------
probe_debug_guard_refuses_its_own_maven_opts_pin() {
  local guard maven_args maven_opts rc
  guard=$(awk '/- name: Refuse Maven debug output in this job/{i=1} i&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{print}' "$WF")
  [ -n "$guard" ] || return 0
  maven_args=$(awk -F'"' '/^  MAVEN_ARGS:/{print $2; exit}' "$WF")
  maven_opts=$(awk -F'"' '/^  MAVEN_OPTS:/{print $2; exit}' "$WF")
  [ -n "$maven_opts" ] || return 0   # env pin vanished: cannot prove the fix, count as weak
  MAVEN_ARGS="$maven_args" MAVEN_OPTS="$maven_opts" bash -c "$guard" >/dev/null 2>&1
  rc=$?
  [ "$rc" -ne 0 ]   # guard refused the workflow's own declared MAVEN_ARGS/MAVEN_OPTS: weak
}

# ---------------------------------------------------------------------------
# N8 - the ancestry check is `if: github.event_name == 'push'`, so a workflow_dispatch run
#      on any branch skips it entirely and releases whatever is on that ref. Same set of
#      people can do either, so it is not a narrower privilege.
# ---------------------------------------------------------------------------
probe_ancestry_check_skips_the_dispatch_path() {
  sed -n '/- name: Verify the released commit is on main/,/^      - name:/p' "$WF" \
    | grep -q "event_name == 'push'"
}

# ---------------------------------------------------------------------------
# N7 - RETIRED. Verified FIXED (the release runbook's scratch-keyring sanity check now
#      runs in a subshell, so its `trap ... EXIT` fires on any step failure, not only on
#      shell exit). The release runbook that this probe read is maintained privately and
#      is out of scope for this public probe suite; it is no longer checked here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# N11 - I1 from the first pass was never closed: the release profile still passes
#       --pinentry-mode loopback that maven-gpg-plugin 3.2.8 adds by itself whenever a
#       passphrase is supplied, and the comment still credits the flag as "required
#       because there is no tty".
# ---------------------------------------------------------------------------
probe_gpg_arguments_comment_still_credits_the_wrong_actor() {
  grep -q 'required because there is no tty' pom.xml
}

# ---------------------------------------------------------------------------
# N12 - the probe suite is not run by anything: `grep -rl 'cipher-probe' .github/` returns
#       zero files. This is the mechanical reason N6 reached a tagged release. Returns 0
#       (WEAK) unless some workflow under .github/workflows/ invokes this suite
#       unconditionally - a `run:` line naming the script, on a step with no
#       `continue-on-error: true` anywhere in that step.
# ---------------------------------------------------------------------------
probe_probe_suite_is_not_run_by_ci() {
  local wf
  for wf in .github/workflows/*.yml; do
    [ -f "$wf" ] || continue
    if _probe_suite_wired_unconditionally_in "$wf"; then
      return 1   # a workflow runs the suite unconditionally: FIXED
    fi
  done
  return 0   # no such job anywhere: WEAK
}

# N13: strip full-line comments first, same standard as the release guard's own static
# check (.github/workflows/release.yml, `grep -vE '^\s*#'`) - a single `#` used to be enough
# to disable the suite while the probe still reported it FIXED. Then split the file into
# per-JOB blocks (not per-step), because GitHub counts a job skipped by a job-level `if:` as
# satisfying a required status check: a step-scoped check alone cannot see that. A job block
# is the fix only when it invokes the script in a `run:` line AND carries no `if:` and no
# `continue-on-error:` anywhere in that block - job-level or step-level, `true` or any other
# value, since a skipped/soft-failed job is exactly as blind as a deleted one.
#
# N14: a substring/regex match on the `run:` line is still fooled by a trailing comment -
# `run: true # CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` runs `true` and
# reports the probe suite FIXED. Same belt as the MAVEN_OPTS guard elsewhere in this file:
# stop pattern-matching, require the trimmed value of the `run:` line to be string-equal to
# the exact command. No YAML parser - this is still line-oriented - but equality instead of
# substring match refuses any decoration (comment, prefix, substitution) without needing one.
_probe_suite_wired_unconditionally_in() {
  local wf="$1"
  local want='CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh'
  grep -vE '^[[:space:]]*#' "$wf" | awk -v RS='\n  [A-Za-z0-9_.-]+:[[:space:]]*\n' -v want="$want" '
      {
        n = split($0, lines, "\n")
        matched = 0
        guarded = 0
        for (i = 1; i <= n; i++) {
          line = lines[i]
          if (match(line, /^[[:space:]]*(-[[:space:]]+)?run:[[:space:]]*/)) {
            val = substr(line, RLENGTH + 1)
            gsub(/^[[:space:]]+/, "", val)
            gsub(/[[:space:]]+$/, "", val)
            if (val == want) { matched = 1 }
          }
          if (line ~ /^[[:space:]]*(-[[:space:]]+)?(if|continue-on-error):/) { guarded = 1 }
        }
        if (matched && !guarded) { found = 1 }
      }
      END { exit(found ? 0 : 1) }
    '
}

# ---------------------------------------------------------------------------
# N13 - the N12 probe above split ci.yml into per-STEP blocks and only refused
#       `continue-on-error: true` in the same step as the `run:` line. It reported FIXED for
#       a job-level `if: false`, a job-level `continue-on-error: true`, a step-level `if:
#       false`, and the `run:` line commented out with a single `#` - four ways to disable
#       the job while the probe that is supposed to guard it still passes. Applies each
#       mutation to a scratch copy of ci.yml and asserts probe_probe_suite_is_not_run_by_ci
#       reports WEAK (returns 0) for every one. WEAK before the fix above, FIXED after.
# ---------------------------------------------------------------------------
probe_suite_probe_accepts_a_disabled_probes_job() {
  local base d rc overall
  base="$(mktemp -d)"
  mkdir -p "$base/.github/workflows"
  cp .github/workflows/ci.yml "$base/.github/workflows/ci.yml"
  overall=0

  # a: job-level `if: false` on cipher-probes
  d="$base/a"; mkdir -p "$d/.github/workflows"
  sed 's/^  cipher-probes:$/  cipher-probes:\n    if: false/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # b: job-level `continue-on-error: true` on cipher-probes
  d="$base/b"; mkdir -p "$d/.github/workflows"
  sed 's/^  cipher-probes:$/  cipher-probes:\n    continue-on-error: true/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # c: step-level `if: false` on the step running the probe suite
  d="$base/c"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1if: false\n&/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # d: the `run:` line commented out
  d="$base/d"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1# run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  for d in a b c d; do
    ( cd "$base/$d" && probe_probe_suite_is_not_run_by_ci )
    rc=$?
    # rc 1 ("FIXED") on a disabled-job mutation means probe_probe_suite_is_not_run_by_ci was
    # fooled into believing the suite still runs unconditionally: the N13 weakness is present.
    [ "$rc" -eq 0 ] || overall=1
  done

  rm -rf "$base"
  [ "$overall" -ne 0 ]   # a mutation slipped past: weakness present (WEAK)
}

# ---------------------------------------------------------------------------
# N14 - the N13 fix still matched the `run:` line by substring, so a trailing comment after
#       the command (`run: true # CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`)
#       runs `true` and still reads as wired. Also cover the `run: |` multi-line form, where
#       the command appears on a line of the block after another command has already run -
#       that must be refused too, since the `run:` line itself is just `|`. Applies both
#       mutations to a scratch copy of ci.yml and asserts probe_probe_suite_is_not_run_by_ci
#       reports WEAK (returns 0) for both. WEAK before the fix above, FIXED after.
# ---------------------------------------------------------------------------
probe_suite_probe_accepts_a_trailing_comment_disable() {
  local base d rc overall
  base="$(mktemp -d)"
  mkdir -p "$base/.github/workflows"
  cp .github/workflows/ci.yml "$base/.github/workflows/ci.yml"
  overall=0

  # a: the command hidden after a trailing comment on a `run: true` line
  d="$base/a"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1run: true # CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  # b: the command hidden inside a `run: |` multi-line block, after another command
  d="$base/b"; mkdir -p "$d/.github/workflows"
  sed 's/^\([[:space:]]*\)run: CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline\.sh$/\1run: |\n\1  true\n\1  CIPHER_PROBE_MAVEN=1 tools\/cipher-probe-release-pipeline.sh/' \
    "$base/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"

  for d in a b; do
    ( cd "$base/$d" && probe_probe_suite_is_not_run_by_ci )
    rc=$?
    # rc 1 ("FIXED") on a disabled-job mutation means probe_probe_suite_is_not_run_by_ci was
    # fooled into believing the suite still runs unconditionally: the N14 weakness is present.
    [ "$rc" -eq 0 ] || overall=1
  done

  rm -rf "$base"
  [ "$overall" -ne 0 ]   # a mutation slipped past: weakness present (WEAK)
}


# ===========================================================================
# Final verification of 1da507e (F-ids). Everything below asserts a weakness
# introduced or left open by the licence switch and the N-fix pass.
# ===========================================================================

# Sources the helper functions of tools/check-third-party-licences.sh without running its
# argument dispatch (which would `exit 1` on no args and kill the probe run).
_source_licence_lib() {
  local lib
  lib="$(mktemp)"
  sed '/^if \[ "\${1:-}" = "--self-test" \]/,$d' tools/check-third-party-licences.sh >"$lib"
  # shellcheck disable=SC1090
  source "$lib"
  rm -f "$lib"
}

# ---------------------------------------------------------------------------
# F1 - <excludedGroups>com\.housedevinci</excludedGroups> is not anchored. license-maven-plugin
#      wraps a group pattern as "[^:]*(" + pattern + ")[^:]*:[^:]+" and matches it against
#      "groupId:artifactId" with Matcher.matches(), so the pattern is a SUBSTRING test on the
#      groupId: com.housedevinci-evil and xcom.housedevinci are excluded too, and an excluded
#      dependency is checked by neither gate (it never reaches includedLicenses and never
#      appears in THIRD-PARTY-NOTICES.txt for the denial pass to read).
#      Weak while the pattern in pom.xml matches a lookalike groupId under that wrapping.
# ---------------------------------------------------------------------------
probe_excluded_groups_pattern_also_excludes_lookalike_groups() {
  local pat
  pat=$(grep -o '<excludedGroups>[^<]*</excludedGroups>' pom.xml | sed 's/<[^>]*>//g')
  [ -n "$pat" ] || return 1
  perl -e '
    my ($pat, @ga) = @ARGV;
    my $re = qr/^[^:]*($pat)[^:]*:[^:]+$/;
    for my $ga (@ga) { exit 0 if $ga =~ $re; }   # a lookalike matched: still weak
    exit 1;
  ' "$pat" "com.housedevinci-evil:evil-dep" "xcom.housedevinci:evil-dep"
}

# ---------------------------------------------------------------------------
# F2 - N3 respelled through the dependency's URL. parse_notices collects "(...)"" groups with
#      [^()]*, which cannot span a nested pair, so a dependency whose own <url> contains
#      "(ch.qos.logback:logback-core:1.5.6 - x)" makes THAT the last paren group on the line.
#      The real coordinate is dropped, the forged one is on ALLOWED_COORDINATES, and the
#      dependency's GPL-3.0 half is never checked. The plugin's count header still matches,
#      so nothing else catches it.
#      Weak while the script reports a clean notices file for such a line.
# ---------------------------------------------------------------------------
probe_denial_pass_coordinate_can_be_forged_by_the_dependency_url() {
  local d rc
  d="$(mktemp -d)"
  cat >"$d/THIRD-PARTY-NOTICES.txt" <<'EOF'
Lists of 1 third-party dependencies.
     (Apache-2.0) (GPL-3.0) evil-url (example.synth:evil-b:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y))
EOF
  tools/check-third-party-licences.sh "$d" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  [ "$rc" -eq 0 ]   # exit 0 on a GPL-3.0 line: still weak
}

# ---------------------------------------------------------------------------
# F3 - `VALIDSIG <fpr> ...` names the key that MADE the signature. On a key with a signing
#      subkey (git tag -s uses it even when -u names the primary) that is the SUBKEY
#      fingerprint; the PRIMARY fingerprint - the one the release runbook tells the
#      maintainer to put in RELEASE_SIGNING_KEY_ID, via `gpg --fingerprint` - is the LAST field of the same
#      line. Reproduced: with a primary+signing-subkey key the step's grep does not match and
#      the release is refused with "is not signed by <fpr>".
#      Weak while the grep anchors the fingerprint to field 1 instead of the primary-key field.
# ---------------------------------------------------------------------------
probe_tag_signature_binds_the_signing_subkey_not_the_primary_key() {
  sed -n '/- name: Verify the tag signature/,/^      - name:/p' "$WF" \
    | grep -q 'VALIDSIG \${fingerprint} '
}

# ---------------------------------------------------------------------------
# F4 - the deny list carries the bare pattern "mpl" for Mozilla. Normalisation strips
#      punctuation, so "mpl" is a substring of "example", "simplified", "template",
#      "compliance": "Simplified BSD License" and any licence URL on example.com are DENIED.
#      Fail-closed, but it breaks the build on a permissive dependency the allowlist accepts.
#      Weak while a permissive name containing the letters m-p-l is denied.
# ---------------------------------------------------------------------------
probe_denial_list_denies_permissive_names_containing_mpl() {
  ( _source_licence_lib
    is_denied_token "Simplified BSD License" || is_denied_token "https://example.com/LICENSE" )
}

# ---------------------------------------------------------------------------
# F5 - the copyleft patterns are version-pinned where the id is not: "eupl12" misses
#      "EUPL v1.1" and "EUPL-1.1" (copyleft), "sspl10" misses a bare "SSPL" and "SSPL-2.0",
#      and OSL-3.0 / CPAL are absent entirely. Each only matters in the cumulative-dual case
#      the denial pass exists for (permissive half passes includedLicenses, copyleft half
#      must be caught here) - which is exactly N2's scenario.
#      Weak while any of them is allowed.
# ---------------------------------------------------------------------------
probe_denial_list_misses_eupl_1_1_bare_sspl_and_osl() {
  ( _source_licence_lib
    ! is_denied_token "EUPL v1.1" || ! is_denied_token "SSPL" || ! is_denied_token "OSL-3.0" )
}

# ---------------------------------------------------------------------------
# F6 - pom.xml's licence-allowlist comment still reads "Apache-2.0    the licence of this
#      project". Since 1da507e the project is FSL-1.1-ALv2. A stale Apache-2.0 claim about
#      our own code, in the file that is published to Maven Central, is the one place a
#      licensee would look to contradict LICENSE.
#      Weak while the comment survives.
# ---------------------------------------------------------------------------
probe_pom_comment_still_calls_apache_the_licence_of_this_project() {
  grep -q 'the licence of this project' pom.xml
}

# ---------------------------------------------------------------------------
# F7 - CONTRIBUTING.md states no inbound licence terms. Under Apache-2.0 the inbound grant
#      was conventional (ASF SS5); FSL-1.1-ALv2 has no contribution clause at all, and this
#      repository is about to be made public with a paid Pro edition beside it. Without a DCO
#      or an explicit grant, a merged outside PR arrives with no licence to relicense it.
#      Weak while the file says nothing about the licence of a contribution.
# ---------------------------------------------------------------------------
probe_contributing_states_no_inbound_licence_terms() {
  ! grep -qiE 'licen[cs]e|developer certificate of origin|\bDCO\b|copyright' CONTRIBUTING.md
}

# ---------------------------------------------------------------------------
# F8 - RETIRED. Verified FIXED (the release runbook's release-signing-key instructions
#      and Central Portal namespace organisation both now spell the licensor
#      "HouseDevinci", matching LICENSE/NOTICE/the POM). The release runbook that this
#      probe read is maintained privately and is out of scope for this public probe
#      suite; it is no longer checked here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# F9 - SampleEndToEndTest asserts that the 4th tool call in the minute is BUDGET_EXCEEDED,
#      but BudgetLimit windows are epoch-aligned and TUMBLING (windowStart =
#      floorDiv(now, size) * size), so the four calls reset the counter whenever a window
#      boundary falls between them. Observed for real: one ./mvnw -B verify on a clean tree
#      failed at SampleEndToEndTest:155, three re-runs were green. The auto-configuration
#      already offers the seam - agentGuardClock is @ConditionalOnMissingBean(name = ...) -
#      so the test can supply a clock it controls.
#      Weak while the test defines no clock of its own.
# ---------------------------------------------------------------------------
probe_sample_e2e_depends_on_the_wall_clock() {
  local t=agent-guard-sample/src/test/java/com/housedevinci/agentguard/sample/SampleEndToEndTest.java
  [ -f "$t" ] || return 0
  ! grep -q 'agentGuardClock' "$t"
}

# ---------------------------------------------------------------------------
# G1 - F2 respelled FORWARD. F2 closed the case where a URL's nested "(...)" splits the
#      coordinate group; the depth-aware scan fixed that. But the scan still trusts "the
#      LAST top-level group", and a dependency's own <url> is free text that can simply
#      CLOSE its own coordinate group and open a fresh, allowlisted one after it:
#        <url>http://x) (ch.qos.logback:logback-core:1.5.6 - http://y</url>
#      renders as two top-level groups, the last of which is on ALLOWED_COORDINATES, so the
#      dependency is skipped and its GPL-3.0 declaration is never checked. The plugin's own
#      count header still matches (one line in, one line parsed), so the count backstop that
#      catches a silently-dropped line does not fire here either.
#      Weak while the script reports a clean notices file for such a line.
# ---------------------------------------------------------------------------
probe_denial_pass_coordinate_can_be_forged_by_a_trailing_group() {
  local d rc
  d="$(mktemp -d)"
  cat >"$d/THIRD-PARTY-NOTICES.txt" <<'EOF'
Lists of 1 third-party dependencies.
     (GPL-3.0) evil-trailing (example.synth:evil-c:1.0 - http://x) (ch.qos.logback:logback-core:1.5.6 - http://y)
EOF
  tools/check-third-party-licences.sh "$d" jar >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  [ "$rc" -eq 0 ]   # exit 0 on a GPL-3.0 line: still weak
}

# ---------------------------------------------------------------------------
# G2 - ci.yml's `dco` job decides a commit is a merge commit, and therefore exempt from the
#      sign-off requirement, by matching its SUBJECT against "Merge branch"* /
#      "Merge remote-tracking"*. A subject is free text chosen by the committer, so an
#      ORDINARY single-parent commit titled `Merge branch 'x' into y` is exempted from the
#      DCO check with no sign-off at all. Whether a commit is a merge is decided by its
#      parent count (%P), which the committer cannot forge.
#      Weak while the job branches on the subject instead of the parent count.
# ---------------------------------------------------------------------------
probe_dco_check_is_skipped_by_a_forged_merge_subject() {
  local w=.github/workflows/ci.yml
  [ -f "$w" ] || return 0
  grep -q '"Merge branch"\*' "$w"
}

# ---------------------------------------------------------------------------
# G3 - the parent-count exemption that closed G2 is broader than "a real merge". ANY
#      commit with two or more parents is exempt, and a merge commit's tree is not
#      constrained by its parents: an "evil merge" can carry content that exists in NO
#      parent. So an octopus merge (three parents), or a two-parent commit whose second
#      parent is an unrelated branch rather than the base, ships unsigned-off content
#      while the gate reports "all commits are signed off".
#
#      Behavioural probe: extracts the real dco step body from ci.yml and runs it against
#      a synthetic repository containing an octopus merge that adds a file present in none
#      of its three parents. Returns 0 (WEAK) while the gate passes that repository.
# ---------------------------------------------------------------------------
probe_dco_exempts_an_octopus_merge_carrying_unsigned_content() {
  local w=.github/workflows/ci.yml body repo rc
  [ -f "$w" ] || return 0
  body="$(awk '
    /name: Verify every commit in this pull request is signed off/ { instep=1 }
    instep && /run: \|/ { inrun=1; next }
    inrun && /^  [a-z-]+:$/ { exit }
    inrun { sub(/^          /, ""); print }
  ' "$w")"
  [ -n "$body" ] || return 0   # step vanished: cannot prove the fix, count as still weak

  repo="$(mktemp -d)"
  (
    cd "$repo" || exit 1
    git init -q -b main . && git config user.name t && git config user.email t@e.com
    echo v1 > base.txt && git add -A
    git commit -q -m "$(printf 'feat: base\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q -b a && echo a > a.txt && git add -A
    git commit -q -m "$(printf 'feat: a\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main && git checkout -q -b b && echo b > b.txt && git add -A
    git commit -q -m "$(printf 'feat: b\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main
    git merge -q --no-commit --no-ff a b >/dev/null 2>&1 || true
    # content present in NO parent, and no Signed-off-by trailer anywhere
    echo BACKDOOR > evil.txt && git add -A
    git commit -q -m "Merge branches 'a' and 'b'"
  ) >/dev/null 2>&1 || { rm -rf "$repo"; return 0; }

  local base head
  base="$(git -C "$repo" rev-list --max-parents=0 HEAD)"
  head="$(git -C "$repo" rev-parse HEAD)"
  ( cd "$repo" && BASE_SHA="$base" HEAD_SHA="$head" \
      GRANDFATHER_SHA=ddd250c3d0fbdf67fb6cea8d3acb583c3b07de43 \
      bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$repo"
  # exit 0 means the gate accepted an octopus merge carrying unsigned-off content: WEAK.
  [ "$rc" -eq 0 ]
}


# ---------------------------------------------------------------------------
# G4 - the G3 fix reads `auto="$(git merge-tree --write-tree "$1" "$2" 2>/dev/null | head -1)"`.
#      git merge-tree exits 1 when the merge it computes CONFLICTS. It still writes a tree,
#      so head -1 succeeds - but the step runs under `set -euo pipefail`, so pipefail hands
#      the pipeline git's 1, the assignment takes that status, and set -e kills the whole
#      step there: mid-loop, before the sign-off check, before any ::error:: annotation,
#      with 2>/dev/null hiding git's message. A legitimate, fully SIGNED-OFF back-merge
#      that resolved a conflict is rejected with no output at all.
#
#      Behavioural probe: extracts the real dco step body from ci.yml and runs it against a
#      synthetic repository whose back-merge resolved a real conflict and IS signed off.
#      That range is compliant and must pass. Returns 0 (WEAK) while the step exits
#      non-zero.
# ---------------------------------------------------------------------------
probe_dco_step_aborts_silently_on_a_conflicted_back_merge() {
  local w=.github/workflows/ci.yml body repo rc
  [ -f "$w" ] || return 0
  body="$(awk '
    /name: Verify every commit in this pull request is signed off/ { instep=1 }
    instep && /run: \|/ { inrun=1; next }
    inrun && /^  [a-z-]+:$/ { exit }
    inrun { sub(/^          /, ""); print }
  ' "$w")"
  [ -n "$body" ] || return 0   # step vanished: cannot prove the fix, count as still weak

  repo="$(mktemp -d)"
  (
    cd "$repo" || exit 1
    git init -q -b main . && git config user.name t && git config user.email t@e.com
    printf 'line\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: base\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q -b feature && printf 'feature-side\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: f\n\nSigned-off-by: T <t@e.com>')"
    git checkout -q main && printf 'main-side\n' > c.txt && git add -A
    git commit -q -m "$(printf 'feat: base moves on\n\nSigned-off-by: T <t@e.com>')"
    git rev-parse HEAD > .base
    git checkout -q feature
    # both sides edited the same line: the automatic merge conflicts, git merge-tree exits 1
    git merge --no-commit --no-ff main >/dev/null 2>&1 || true
    printf 'resolved\n' > c.txt && git add c.txt
    git commit -q -m "$(printf "Merge branch 'main' into feature\n\nSigned-off-by: T <t@e.com>")"
  ) >/dev/null 2>&1 || { rm -rf "$repo"; return 0; }

  local base head
  base="$(cat "$repo/.base")"
  head="$(git -C "$repo" rev-parse HEAD)"
  ( cd "$repo" && BASE_SHA="$base" HEAD_SHA="$head" \
      GRANDFATHER_SHA=ddd250c3d0fbdf67fb6cea8d3acb583c3b07de43 \
      bash -c "$body" ) >/dev/null 2>&1
  rc=$?
  rm -rf "$repo"
  # every commit in this range carries a Signed-off-by. Non-zero means the step aborted
  # on the conflicted merge-tree instead of checking them: WEAK.
  [ "$rc" -ne 0 ]
}


echo "the security review release-pipeline probes  (WEAK = finding still open)"
echo
probe probe_multiline_version_accepted                       "M4 newline in the version input passes validation"   probe_multiline_version_accepted
probe probe_release_job_restores_maven_cache                 "M3 release job restores the maven/wrapper cache"     probe_release_job_restores_maven_cache
probe probe_release_job_can_exec_unverified_maven_dist       "M3 the signing job can exec an unverified dist"      probe_release_job_can_exec_an_unverified_maven_distribution
probe probe_release_job_has_no_environment_gate              "M5 no environment / reviewer gate"                   probe_release_job_has_no_environment_gate
probe probe_release_does_not_check_tag_ancestry              "M5 a tag on any commit can release"                  probe_release_does_not_check_tag_ancestry
probe probe_release_does_not_verify_tag_signature            "M5 the tag is not required to be signed"             probe_release_does_not_verify_tag_signature
probe probe_no_licence_file_in_the_repository                "M7 Apache-2.0 declared, no LICENSE anywhere"         probe_no_licence_file_in_the_repository
probe probe_published_jars_are_never_checksum_compared       "L1 the deployed jars are never compared"             probe_published_jars_are_never_checksum_compared
probe probe_concurrency_group_is_ref_scoped                  "L2 concurrency keyed on the ref, not the version"    probe_concurrency_group_is_ref_scoped_not_version_scoped
probe probe_checkout_persists_credentials                    "L3 GITHUB_TOKEN left in .git/config"                 probe_checkout_persists_credentials
probe probe_evidence_uploaded_when_release_failed            "L4 signed jars of a failed release are uploaded"     probe_evidence_uploaded_even_when_the_release_failed
probe probe_nothing_forbids_maven_debug                      "I4 nothing stops -X being added to the release"      probe_nothing_forbids_maven_debug_in_the_release_job
probe probe_licence_gate_accepts_dual_apache_or_gpl          "M1 Apache-2.0 OR GPL-3.0 passes the gate"            probe_licence_gate_accepts_a_dual_apache_or_gpl_dependency
echo
probe probe_denial_pass_misses_prose_licence_names           "N2 prose GPL/MPL names pass the denial pass"         probe_denial_pass_misses_prose_licence_names
probe probe_denial_pass_coordinate_can_be_forged             "N3 the dependency <name> forges the coordinate"      probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name
probe probe_denial_pass_crashes_on_empty_licence_token       "N10 empty () token kills the scan under set -u"      probe_denial_pass_crashes_on_an_empty_licence_token
probe probe_verify_fails_on_a_clean_checkout                 "N1 ./mvnw verify fails on a fresh clone"             probe_verify_fails_on_a_clean_checkout
probe probe_sources_jar_differs_from_a_test_run               "post-release: sources jar not reproducible with tests running" probe_sources_jar_differs_from_a_build_that_actually_ran_tests
probe probe_bundle_assertion_points_at_the_wrong_path        "N4 the L5 bundle path is not where it is written"    probe_bundle_assertion_points_at_the_wrong_path
probe probe_tag_signature_check_is_optional_and_unbound      "N5 tag signature check is off by default"            probe_tag_signature_check_is_optional_and_unbound
probe probe_debug_guard_misses_the_slf4j_log_level           "N6 --errors and slf4j debug walk past the guard"     probe_debug_guard_misses_the_slf4j_log_level
probe probe_debug_guard_refuses_its_own_maven_opts_pin       "N6 the guard refuses the workflow's own MAVEN_OPTS"  probe_debug_guard_refuses_its_own_maven_opts_pin
probe probe_ancestry_check_skips_the_dispatch_path           "N8 workflow_dispatch skips the ancestry check"       probe_ancestry_check_skips_the_dispatch_path
probe probe_gpg_arguments_comment_credits_the_wrong_actor    "N11 I1 was never closed"                             probe_gpg_arguments_comment_still_credits_the_wrong_actor
probe probe_probe_suite_is_not_run_by_ci                      "N12 nothing in .github/ runs this suite"             probe_probe_suite_is_not_run_by_ci
probe probe_suite_probe_accepts_a_disabled_probes_job          "N13 the N12 probe misses a disabled probes job"      probe_suite_probe_accepts_a_disabled_probes_job
probe probe_suite_probe_accepts_a_trailing_comment_disable      "N14 a trailing comment still hides a disabled job"   probe_suite_probe_accepts_a_trailing_comment_disable
echo
probe probe_excluded_groups_also_excludes_lookalike_groups   "F1 com.housedevinci-evil is excluded too"            probe_excluded_groups_pattern_also_excludes_lookalike_groups
probe probe_denial_pass_coordinate_forged_by_the_url         "F2 a URL with parens forges the coordinate"          probe_denial_pass_coordinate_can_be_forged_by_the_dependency_url
probe probe_tag_signature_binds_the_subkey_not_the_primary   "F3 VALIDSIG field 1 is the signing subkey"           probe_tag_signature_binds_the_signing_subkey_not_the_primary_key
probe probe_denial_list_denies_simplified_bsd                "F4 bare mpl denies example/simplified"               probe_denial_list_denies_permissive_names_containing_mpl
probe probe_denial_list_misses_eupl_1_1_and_bare_sspl        "F5 EUPL 1.1 / SSPL / OSL-3.0 are allowed"            probe_denial_list_misses_eupl_1_1_bare_sspl_and_osl
probe probe_pom_comment_calls_apache_the_project_licence     "F6 pom.xml still claims Apache-2.0 for us"           probe_pom_comment_still_calls_apache_the_licence_of_this_project
probe probe_contributing_has_no_inbound_licence_terms        "F7 no inbound licence terms for contributions"       probe_contributing_states_no_inbound_licence_terms
probe probe_sample_e2e_depends_on_the_wall_clock             "F9 the sample e2e test has no clock of its own"      probe_sample_e2e_depends_on_the_wall_clock

echo
probe probe_denial_pass_coordinate_forged_by_a_trailing_group "G1 a URL can append an allowlisted coordinate"      probe_denial_pass_coordinate_can_be_forged_by_a_trailing_group
probe probe_dco_check_skipped_by_a_forged_merge_subject      "G2 a forged 'Merge branch' subject skips the DCO"   probe_dco_check_is_skipped_by_a_forged_merge_subject
probe probe_dco_exempts_an_octopus_merge                    "G3 an octopus/evil merge skips the DCO entirely"    probe_dco_exempts_an_octopus_merge_carrying_unsigned_content
probe probe_dco_aborts_on_a_conflicted_merge                "G4 the dco step crashes with no output"             probe_dco_step_aborts_silently_on_a_conflicted_back_merge

# ===========================================================================
# Keyless CVE gate (backported from stripe-einvoice ebbbd33): probes for the OSV-Scanner
# gate in ci.yml and the optional, loudly-skipping OWASP Dependency-Check in
# security-scan.yml. Same rule as every block above.
# ===========================================================================

CI=.github/workflows/ci.yml

# Extracts the body of a `run: |` block for a named step, from a named workflow file.
step_body() { # step_body <workflow> <step name>
  awk -v want="- name: $2" '
    index($0, want) { instep=1; next }
    instep && /run: \|/ { inrun=1; next }
    instep && !inrun && /^      - name:/ { exit }
    inrun && /^      - name:/ { exit }
    # A run block also ends at the next job header (two-space indent): the last step of a job
    # is followed by "  <next-job>:", not by another "- name:". Without this the extracted
    # body ran on into the next job and failed for a reason that has nothing to do with the
    # step under test.
    inrun && /^  [a-z][a-z0-9-]*:/ { exit }
    # the runner hands bash the script with the block indentation removed. A python heredoc body
    # is indentation-sensitive, so the ten spaces of a run block are stripped here too
    inrun { sub(/^ {10}/, ""); print }
  ' "$1"
}

# ---------------------------------------------------------------------------
# S5 - nothing stops a pull request that adds a dependency with a known HIGH or CRITICAL
#      vulnerability. Runs the REAL severity step from ci.yml against a synthetic report
#      carrying one HIGH finding (a CVSS 7.5 vector, computed from the vector exactly as
#      the gate does), rather than asserting that some job name appears in the YAML.
#      Weak while that step exits 0 on a HIGH finding.
# ---------------------------------------------------------------------------
probe_a_high_severity_dependency_passes_the_pull_request_gate() {
  local body work rc
  body="$(step_body "$CI" 'Fail on a known HIGH or CRITICAL vulnerability')"
  [ -n "$body" ] || return 0   # no such step: nothing gates a pull request
  work="$(mktemp -d)"
  cat >"$work/osv.json" <<'REPORT'
{"results":[{"source":{"path":"pom.xml"},"packages":[{
  "package":{"name":"org.example:vulnerable","version":"1.0","ecosystem":"Maven"},
  "vulnerabilities":[{"id":"GHSA-synthetic-high","severity":[
    {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}]}]}]}
REPORT
  RUNNER_TEMP="$work" bash -c "$body" >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  [ "$rc" -eq 0 ]   # the gate accepted a HIGH finding: weak
}

# ---------------------------------------------------------------------------
# S7 - a scanner that could not run is indistinguishable from a clean scan. Three shapes of
#      "no answer" - an empty file, a truncated one, and a syntactically valid report with
#      no result section - each run through the real gate.
#      Weak while any of them exits 0.
# ---------------------------------------------------------------------------
probe_an_unreadable_scan_report_counts_as_clean() {
  local work weak=1
  work="$(mktemp -d)"
  : > "$work/empty.json"
  printf '{"results": [' > "$work/truncated.json"
  printf '{"scanner":"osv","version":"2"}' > "$work/no-results.json"
  # A syntactically perfect report of a scan that looked at nothing. Without --all-packages an
  # OSV report lists only VULNERABLE packages, so a resolution that silently produced nothing
  # renders exactly like a clean tree - the vacuous pass this whole script exists to refuse.
  printf '{"results":[{"source":{"path":"pom.xml"},"packages":[]}]}' > "$work/no-packages.json"
  local f
  for f in empty truncated no-results no-packages; do
    if tools/check-vulnerability-report.py --format osv --report "$work/$f.json" --fail-on high >/dev/null 2>&1; then
      echo "the gate accepted $f.json as a clean scan" >/dev/null
      weak=0
    fi
  done
  rm -rf "$work"
  [ "$weak" -eq 0 ]
}

# ---------------------------------------------------------------------------
# S9 - the weekly deep scan fails the week because no NVD key exists, so the scheduled run
#      is permanently red and the OSV findings beside it go unread; or it skips in silence,
#      which is worse. Runs the real step body with no key and requires BOTH: it does not
#      fail, and it says out loud that it skipped.
#      Weak while it fails, or while it is silent.
# ---------------------------------------------------------------------------
probe_the_weekly_deep_scan_is_red_or_silent_without_a_key() {
  local body work rc out
  body="$(step_body .github/workflows/security-scan.yml 'Say whether this deep scan can run at all')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  : > "$work/out"; : > "$work/summary"
  ( cd "$work" && NVD_API_KEY="" GITHUB_OUTPUT="$work/out" GITHUB_STEP_SUMMARY="$work/summary" \
      bash -c "$body" ) >"$work/log" 2>&1
  rc=$?
  cat "$work/log" >/dev/null 2>/dev/null || true
  out="$(cat "$work/log" "$work/summary" 2>/dev/null)"
  if [ "$rc" -ne 0 ]; then rm -rf "$work"; return 0; fi                    # red for a known reason: weak
  grep -q 'available=false' "$work/out" 2>/dev/null || { rm -rf "$work"; return 0; }
  grep -qi 'skipped' <<<"$out" || { rm -rf "$work"; return 0; }            # silent skip: weak
  rm -rf "$work"
  return 1
}

# ---------------------------------------------------------------------------
# S10 - the pinned scanner binaries are fetched without being verified, so whatever the
#       release page serves on the day is what decides whether a build is safe to trust.
#       Runs the REAL installer against a local file:// URL (a copy of the script with the
#       download location redirected - the production script has no such switch, on purpose)
#       with the right checksum and then with a tampered payload.
#       Weak while a tampered payload installs.
# ---------------------------------------------------------------------------
probe_scanner_downloads_are_installed_without_verification() {
  local work script good_sha rc
  work="$(mktemp -d)"
  printf 'not really a scanner\n' > "$work/payload"
  if command -v sha256sum >/dev/null 2>&1; then good_sha="$(sha256sum "$work/payload" | cut -d" " -f1)"
  else good_sha="$(shasum -a 256 "$work/payload" | cut -d" " -f1)"; fi
  script="$work/install-scanner.sh"
  # Redirect the download to the local payload and make the "does it run" check a no-op:
  # this probe is about the checksum, not about whether a text file is a scanner.
  sed -e "s#url=\"https://github.com/google/osv-scanner/releases/download/[^\"]*\"#url=\"file://$work/payload\"#" \
      -e 's#"\$dest/osv-scanner" --version >/dev/null#true#' \
      tools/install-scanner.sh > "$script"
  chmod +x "$script"
  # 1. the honest case: the recorded checksum matches the payload, so it installs.
  sed -i.bak "s/^OSV_SHA256_linux_amd64=.*/OSV_SHA256_linux_amd64=\"$good_sha\"/;s/^OSV_SHA256_linux_arm64=.*/OSV_SHA256_linux_arm64=\"$good_sha\"/;s/^OSV_SHA256_darwin_arm64=.*/OSV_SHA256_darwin_arm64=\"$good_sha\"/" "$script"
  if ! "$script" osv-scanner "$work/bin" >/dev/null 2>&1; then
    echo "the installer refused a payload matching its own recorded checksum" >/dev/null
    rm -rf "$work"; return 0
  fi
  # 2. the tampered case: same recorded checksum, different bytes on the wire.
  printf 'tampered\n' > "$work/payload"
  "$script" osv-scanner "$work/bin" >/dev/null 2>&1
  rc=$?
  rm -rf "$work"
  [ "$rc" -eq 0 ]   # a tampered payload installed: weak
}

probe probe_high_severity_dep_passes_pr_gate                 "S5 a HIGH-severity dependency passes the PR gate"    probe_a_high_severity_dependency_passes_the_pull_request_gate
probe probe_unreadable_report_counts_as_clean                "S7 an unreadable scan report counts as clean"        probe_an_unreadable_scan_report_counts_as_clean
probe probe_weekly_deep_scan_red_or_silent_without_key        "S9 the weekly deep scan is red or silent without a key" probe_the_weekly_deep_scan_is_red_or_silent_without_a_key
probe probe_scanner_download_unverified                      "S10 a tampered scanner download installs"            probe_scanner_downloads_are_installed_without_verification

# ---------------------------------------------------------------------------
# W1 - the Maven wrapper moved to 3.10.x (Dependabot, PR 17) while central-publishing-maven-plugin
#      0.11.0 cannot build a valid bundle on Maven 3.10: the Portal refused the v0.2.0 bundle
#      ("content that does NOT have a .pom file", maven-metadata-local.xml and
#      _remote.repositories inside it). Upstream: jboss/jboss-parent-pom#584,
#      cuioss/cuioss-parent-pom#1501. No plugin release supports 3.10 yet, so every 0.x plugin
#      is treated as unsupported; revisit this condition when a plugin version documents support.
#      Weak while the wrapper is >= 3.10 and the plugin is a 0.x release (or unreadable).
# ---------------------------------------------------------------------------
# First central-publishing-maven-plugin version whose release notes state Maven 3.10 support.
# Empty = none known: while empty, a wrapper >= 3.10 is WEAK for every plugin version.
CENTRAL_PUBLISHING_FIRST_MAVEN_310_SUPPORT=""

probe_maven_wrapper_is_compatible_with_central_publishing() {
  local props=".mvn/wrapper/maven-wrapper.properties"
  local lines url wv plugin wmaj wmin
  [ -f "$props" ] || return 0                              # missing: unverifiable is weak
  lines="$(tr -d '\r' < "$props" | grep -c '^distributionUrl=' || true)"
  [ "$lines" -eq 1 ] || return 0                           # zero or duplicate: weak
  url="$(tr -d '\r' < "$props" | sed -n 's/^distributionUrl=//p')"
  # the whole URL must be the repo1 distribution with the same version in path and file name
  local re='^https://repo\.maven\.apache\.org/maven2/org/apache/maven/apache-maven/([0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?)/apache-maven-([0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?)-bin\.zip$'
  [[ "$url" =~ $re ]] || return 0                          # any other shape: weak
  [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[3]}" ] || return 0   # path and file name disagree: weak
  wv="${BASH_REMATCH[1]}"
  plugin="$(sed -n 's#.*<central-publishing.version>\([^<]*\)</central-publishing.version>.*#\1#p' pom.xml | head -1)"
  [[ "$plugin" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0  # unreadable or pre-release plugin version: weak
  wmaj="${wv%%.*}"; wmin="${wv#*.}"; wmin="${wmin%%.*}"
  if [ "$wmaj" -gt 3 ] || { [ "$wmaj" -eq 3 ] && [ "$wmin" -ge 10 ]; }; then
    [ -n "$CENTRAL_PUBLISHING_FIRST_MAVEN_310_SUPPORT" ] || return 0
    [ "$(printf '%s\n%s\n' "$CENTRAL_PUBLISHING_FIRST_MAVEN_310_SUPPORT" "$plugin" | sort -V | head -1)" = "$CENTRAL_PUBLISHING_FIRST_MAVEN_310_SUPPORT" ] || return 0
  fi
  return 1
}

probe probe_maven_wrapper_incompatible_with_central_publishing "W1 the Maven wrapper is 3.10+ while central-publishing is a 0.x release" probe_maven_wrapper_is_compatible_with_central_publishing

U=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven
_w1_fixture() { # $1 url line, $2 plugin version
  local d; d=$(mktemp -d); mkdir -p "$d/.mvn/wrapper"
  printf 'distributionUrl=%s\n' "$1" > "$d/.mvn/wrapper/maven-wrapper.properties"
  printf '<properties><central-publishing.version>%s</central-publishing.version></properties>\n' "$2" > "$d/pom.xml"
  echo "$d"; }
# C-30-1: an unreadable or pre-release plugin version counts as "supports 3.10" once the constant is set.
probe_w1_accepts_unparsed_plugin_version() {
  local d rc=1 v
  for v in '${x}' '1.2.0-SNAPSHOT'; do
    d=$(_w1_fixture "$U/3.10.0/apache-maven-3.10.0-bin.zip" "$v")
    ( cd "$d" && CENTRAL_PUBLISHING_FIRST_MAVEN_310_SUPPORT=1.2.0 probe_maven_wrapper_is_compatible_with_central_publishing ) || rc=0
  done; return $rc; }
# C-30-2: the version is read from the last "apache-maven-X-bin.zip" in the URL, not from the path mvnw downloads.
probe_w1_reads_version_from_url_suffix_not_path() {
  local d; d=$(_w1_fixture "$U/3.10.0/apache-maven-3.10.0-bin.zip#/apache-maven-3.9.16-bin.zip" 0.11.0)
  ( cd "$d" && probe_maven_wrapper_is_compatible_with_central_publishing ) && return 1 || return 0; }

probe probe_w1_accepts_unparsed_plugin_version "C-30-1 an unparsed or pre-release plugin version passes the W1 check" probe_w1_accepts_unparsed_plugin_version
probe probe_w1_reads_version_from_url_suffix "C-30-2 the W1 version is read from the URL suffix, not the downloaded path" probe_w1_reads_version_from_url_suffix_not_path


# ===========================================================================
# PR 3 block: the vulnerability scan of the release artifacts before anything is signed
# (design: bundle-scan-before-signing, ruling 2026-09-23, F-1 .. F-9; copied from the
# stripe-einvoice module where the same gate is live, probes included).
#
# Every probe that touches a scanner runs the REAL pinned Grype (tools/install-scanner.sh),
# never a stub: a stub writes the report shape the gate expects, so the one thing that can be
# wrong - the gate and the scanner disagreeing about the document - is the one thing the probe
# cannot see (release run 36048639931 on the sibling module).
# ===========================================================================

SCAN_STEP='Scan the artifacts this release is about to sign'
INSTALL_STEP='Install the pinned Grype and verify its checksum'
SELFTEST_STEP='Self-test the severity gate before it is trusted'
SIGN_STEP='Verify, licence check, sign, upload'
CMP_STEP='Confirm the uploaded bundle matches the reproducibility check'

# The text of one step of the workflow: from its own "- name:" line to the line before the next.
# Matches the name EXACTLY, so a rename or a trailing "(disabled)" is a missing step.
_step_block() { # _step_block <step name>
  awk -v want="      - name: $1" '
    $0 == want { instep=1; print; next }
    instep && /^      - name:/ { exit }
    instep && /^  [a-z][a-z0-9-]*:/ { exit }
    instep { print }
  ' "$WF"
}
_line_of_step() { grep -nxF "      - name: $1" "$WF" | head -1 | cut -d: -f1; }
_uncommented() { grep -vE '^[[:space:]]*#' ; }

# ---------------------------------------------------------------------------
# B-CI-02 / probe 1. The release signs and uploads without anyone having looked for known
#      vulnerabilities in what is being signed. Position is a property of the file and is read
#      there: the scanner is installed before the signing key is imported by setup-java, the
#      gate's self-test and the scan sit after the reproducibility check and before the step
#      that signs, and no secret is named by any of them. The decision the scan feeds is
#      probed by running the gate, below.
#      Weak while any of that is missing.
# ---------------------------------------------------------------------------
probe_release_signs_without_a_vulnerability_scan() {
  local install selftest scan sign repro setup
  install="$(_line_of_step "$INSTALL_STEP")"
  selftest="$(_line_of_step "$SELFTEST_STEP")"
  scan="$(_line_of_step "$SCAN_STEP")"
  sign="$(_line_of_step "$SIGN_STEP")"
  repro="$(_line_of_step 'Reproducibility check (two clean builds, identical jars)')"
  setup="$(grep -n 'uses: actions/setup-java' "$WF" | head -1 | cut -d: -f1)"
  [ -n "$install" ] && [ -n "$selftest" ] && [ -n "$scan" ] && [ -n "$sign" ] && [ -n "$repro" ] && [ -n "$setup" ] || return 0
  [ "$install" -lt "$setup" ] || return 0        # F-3: installability proved before the key is imported
  [ "$repro" -lt "$selftest" ] && [ "$selftest" -lt "$scan" ] && [ "$scan" -lt "$sign" ] || return 0
  # the self-test is the step IMMEDIATELY before the scan (F-3: "immediately before the gate")
  [ "$(awk -v s="$scan" 'NR < s && /^      - name:/ { l=NR } END { print l }' "$WF")" = "$selftest" ] || return 0
  _step_block "$SCAN_STEP" | grep -q 'secrets\.' && return 0     # checklist 8: no secret reaches the scan
  _step_block "$INSTALL_STEP" | grep -q 'secrets\.' && return 0
  _step_block "$SCAN_STEP" | _uncommented | grep -q -- '--fail-on high' || return 0
  return 1
}

# ---------------------------------------------------------------------------
# probe 2. The scan, its installer, its self-test and the bundle comparison are not
#      skippable: no `if:` (the comparison may carry exactly `if: success()`), no
#      continue-on-error, not renamed away, not commented out, no `|| true` on the gate.
#      Weak while any of the four can be skipped.
# ---------------------------------------------------------------------------
probe_scan_step_is_skippable() {
  local name block cmd
  for name in "$INSTALL_STEP|tools/install-scanner.sh grype" \
              "$SELFTEST_STEP|check-vulnerability-report.py --self-test" \
              "$SCAN_STEP|check-vulnerability-report.py" \
              "$CMP_STEP|unzip"; do
    cmd="${name#*|}"; name="${name%%|*}"
    block="$(_step_block "$name")"
    [ -n "$block" ] || return 0                                   # missing or renamed: weak
    _uncommented <<<"$block" | grep -q -- "$cmd" || return 0      # command only in a comment: weak
    _uncommented <<<"$block" | grep -qE '^\s+continue-on-error:' && return 0
    if [ "$name" = "$CMP_STEP" ]; then
      _uncommented <<<"$block" | grep -E '^\s+if:' | grep -vqE '^\s+if: success\(\)\s*$' && return 0
    else
      _uncommented <<<"$block" | grep -qE '^\s+if:' && return 0
    fi
    _uncommented <<<"$block" | grep -qE '\|\|\s*true' && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# A synthetic RELEASE reactor, built exactly the way the signing job builds it: versions:set
# to a version no repository has, an empty local Maven repository, and the real
# scripts/verify-reproducible.sh run over it so that the checksum record the scan step binds to
# is the genuine article. The working tree is copied (not cloned) so that a probe run before
# the commit sees the change it is probing. The local repository holds nothing of our own
# group afterwards, because those builds only `package` - precisely the condition under which
# a bare `dependency:copy-dependencies` fails (F-5; run 35922939487 on the sibling module).
# Tests are skipped in the fixture build (MAVEN_ARGS): they change no jar byte, and the fixture
# is built twice.
#   $1 = clean | vulnerable (core gains org.apache.commons:commons-text:1.9, CVE-2022-42889)
# ---------------------------------------------------------------------------
# The fixtures live on disk under one root so that they survive the command substitutions the
# probes call them through; each is built at most once per suite run.
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT
_scan_fixture_base() { # _scan_fixture_base <clean|vulnerable>; echoes the base dir, building it once
  local kind="$1" base="$FIXTURE_ROOT/$1"
  if [ -f "$base/.built" ]; then printf '%s' "$base"; return 0; fi
  rm -rf "$base"; mkdir -p "$base/tree"
  if ! { git ls-files -z -co --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$base/tree"; } >>"$PROBE_CAPTURE" 2>&1; then
    rm -rf "$base"; return 1
  fi
  if [ "$kind" = vulnerable ] && [ -d "$FIXTURE_ROOT/clean/m2" ]; then
    cp -a "$FIXTURE_ROOT/clean/m2" "$base/m2"      # warm repository, still nothing of our group
  fi
  if ! ( cd "$base/tree" &&
         git init -q . && git -c user.name=probe -c user.email=probe@example.invalid add -A &&
         git -c user.name=probe -c user.email=probe@example.invalid commit -q -m fixture &&
         if [ "$kind" = vulnerable ]; then
           python3 - agent-guard-core/pom.xml <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
dep = ("<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>"
       "<version>1.9</version></dependency>")
assert "<dependencies>" in s
open(p, "w").write(s.replace("<dependencies>", "<dependencies>" + dep, 1))
PY
           git -c user.name=probe -c user.email=probe@example.invalid commit -q -am vulnerable
         fi &&
         export MAVEN_OPTS="-Dmaven.repo.local=$base/m2" MAVEN_ARGS="-B -DskipTests" &&
         ./mvnw -B -q org.codehaus.mojo:versions-maven-plugin:2.21.0:set \
           -Dmaven.repo.local="$base/m2" -DnewVersion=99.99.99-probe \
           -DprocessAllModules=true -DgenerateBackupPoms=false &&
         REPRODUCIBLE_SHA_FILE="$base/record.txt" scripts/verify-reproducible.sh
       ) >>"$PROBE_CAPTURE" 2>&1; then
    rm -rf "$base"; return 1
  fi
  if [ -d "$base/m2/com/housedevinci" ]; then rm -rf "$base"; return 1; fi
  touch "$base/.built"
  printf '%s' "$base"
}

_scan_step_fixture() { # _scan_step_fixture <clean|vulnerable>; echoes a private work dir (tree/, t/ = runner temp)
  local kind="${1:-clean}" base work
  base="$(_scan_fixture_base "$kind")" || return 1
  work="$(mktemp -d)"
  cp -a "$base/tree" "$work/tree"
  mkdir -p "$work/t"
  cp -a "$base/m2" "$work/t/m2repo"
  cp "$base/record.txt" "$work/t/reproducible-sha256.txt"
  # The REAL pinned scanner, installed once into the shared fixture and copied per probe.
  if [ ! -x "$base/realbin/grype" ]; then
    tools/install-scanner.sh grype "$base/realbin" >>"$PROBE_CAPTURE" 2>&1 || { rm -rf "$work"; return 1; }
  fi
  mkdir -p "$work/t/bin"
  cp "$base/realbin/grype" "$work/t/bin/grype"
  printf '%s' "$work"
}

# Runs the real scan step body in a fixture copy and echoes its exit code. The runner
# substitutes ${{ ... }} before bash ever sees it; bash would read ${{ as a bad substitution.
_scan_step_exit() { # _scan_step_exit <work dir>
  local work="$1" body rc ts
  body="$(step_body "$WF" "$SCAN_STEP")"
  [ -n "$body" ] || { echo 127; return; }
  ts="$(cd "$work/tree" && scripts/git-commit-timestamp.sh)"
  body="${body//\$\{\{ runner.temp \}\}/\$RUNNER_TEMP}"
  body="${body//\$\{\{ steps.v.outputs.timestamp \}\}/\$PROBE_RELEASE_TIMESTAMP}"
  ( cd "$work/tree" && RUNNER_TEMP="$work/t" PROBE_RELEASE_TIMESTAMP="$ts" \
      GITHUB_STEP_SUMMARY="$work/summary.md" bash -c "$body" ) >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  echo "$rc"
}

_needs_maven() {
  [ "${CIPHER_PROBE_MAVEN:-0}" = "1" ] && return 1
  PROBE_SKIP_REASON="this probe builds a synthetic release reactor and runs the real pinned grype; set CIPHER_PROBE_MAVEN=1 to run it"
  return 0
}

# ---------------------------------------------------------------------------
# probe 3 (with F-5 and D-SCAN-01/02). The whole scan step body, executed against a synthetic
# release reactor with an EMPTY local repository and the real pinned Grype. Weak while the body
# exits non-zero (it cannot resolve the starter's sibling core module from a reactor that has
# not packaged it, or the scanner cannot run), or while the scan set it produced lacks either
# published jar or any resolved runtime dependency, or while the scanner cataloged fewer
# packages than jars were staged.
# ---------------------------------------------------------------------------
probe_scan_does_not_cover_the_published_jars() {
  _needs_maven && return 0
  local work rc sbom staged covered
  work="$(_scan_step_fixture clean)" || { PROBE_SKIP_REASON="the synthetic release reactor, or the pinned grype, could not be prepared, so the step body was never exercised"; return 0; }
  rc="$(_scan_step_exit "$work")"
  if [ "$rc" -ne 0 ]; then rm -rf "$work"; return 0; fi
  sbom="$(cat "$work/t/grype-sbom.json" 2>/dev/null || true)"
  [ -s "$work/t/scanned-sha256.txt" ] || { rm -rf "$work"; return 0; }
  grep -q 'agent-guard-core-99.99.99-probe.jar' "$work/t/scanned-sha256.txt" || { rm -rf "$work"; return 0; }
  grep -q 'agent-guard-core-99.99.99-probe-sources.jar' "$work/t/scanned-sha256.txt" || { rm -rf "$work"; return 0; }
  grep -q 'agent-guard-spring-boot-starter-99.99.99-probe.jar' "$work/t/scanned-sha256.txt" || { rm -rf "$work"; return 0; }
  grep -q 'slf4j-api' "$work/t/scanned-sha256.txt" || { rm -rf "$work"; return 0; }   # a resolved runtime dependency
  grep -q 'javadoc' "$work/t/scanned-sha256.txt" && { rm -rf "$work"; return 0; }       # F-2: javadoc is not in the scan set
  grep -q 'agent-guard-sample' "$work/t/scanned-sha256.txt" && { rm -rf "$work"; return 0; }
  grep -q 'agent-guard-core-99.99.99-probe.jar' <<<"$sbom" || { rm -rf "$work"; return 0; }
  staged="$(grep -oE 'scanning [0-9]+ jar' "$PROBE_CAPTURE" | tail -1 | grep -oE '[0-9]+')"
  covered="$(grep -oE '[0-9]+ package\(s\) were scanned' "$PROBE_CAPTURE" | tail -1 | grep -oE '^[0-9]+')"
  rm -rf "$work"
  printf '        real pinned scanner: %s package(s) cataloged for %s staged jar(s)\n' "${covered:-none}" "${staged:-none}"
  [ -n "$staged" ] && [ -n "$covered" ] || return 0
  [ "$covered" -ge "$staged" ] || return 0
  return 1
}

# ---------------------------------------------------------------------------
# probe 3, planted-vulnerability half. A resolved runtime dependency with a published CRITICAL
# advisory (commons-text 1.9, CVE-2022-42889) in the published module's graph must turn the
# step red, and the gate must NAME the coordinate. Same step body, same real scanner, a
# fixture that differs from the clean one by one dependency.
# Weak while the step exits 0, or while it fails without naming commons-text.
# ---------------------------------------------------------------------------
probe_scan_passes_a_planted_vulnerable_dependency() {
  _needs_maven && return 0
  local work rc
  work="$(_scan_step_fixture vulnerable)" || { PROBE_SKIP_REASON="the vulnerable synthetic reactor, or the pinned grype, could not be prepared"; return 0; }
  rc="$(_scan_step_exit "$work")"
  rm -rf "$work"
  [ "$rc" -ne 0 ] || return 0
  [ "$rc" -ne 127 ] || return 0                                   # no step: weak
  grep -q 'commons-text' "$PROBE_CAPTURE" || return 0             # red for some other reason: weak
  return 1
}

# ---------------------------------------------------------------------------
# D-SCAN-03. The real pinned grype and the real gate over a scan set holding one jar that
# declares a coordinate with a published CRITICAL advisory. No download: a jar carrying only
# META-INF/maven/.../pom.properties, which is what syft reads. Weak unless the gate names the
# coordinate and refuses. The mutation is inside the probe: the same scanner and gate over an
# EMPTY directory must refuse too (exit 2), so a scan of nothing can never read as clean.
# ---------------------------------------------------------------------------
probe_the_real_scanner_and_gate_miss_a_known_critical() {
  local work bin rc out
  work="$(mktemp -d)"
  if ! tools/install-scanner.sh grype "$work/bin" >>"$PROBE_CAPTURE" 2>&1; then
    rm -rf "$work"; PROBE_SKIP_REASON="the pinned grype could not be installed, so the real scanner was never run"; return 0
  fi
  bin="$work/bin/grype"
  mkdir -p "$work/build/META-INF/maven/org.apache.commons/commons-text" "$work/scan" "$work/empty"
  printf 'groupId=org.apache.commons\nartifactId=commons-text\nversion=1.9\n' \
    > "$work/build/META-INF/maven/org.apache.commons/commons-text/pom.properties"
  ( cd "$work/build" && jar cf "$work/scan/commons-text-1.9.jar" META-INF ) >>"$PROBE_CAPTURE" 2>&1 \
    || { rm -rf "$work"; PROBE_SKIP_REASON="no jar tool to build the vulnerable fixture"; return 0; }
  find "$work/scan" -name '*.jar' -print0 | xargs -0 shasum -a 256 > "$work/staged.sha256"
  if ! "$bin" "dir:$work/scan" -o json="$work/grype.json" -o cyclonedx-json="$work/sbom.json" >>"$PROBE_CAPTURE" 2>&1; then
    rm -rf "$work"; PROBE_SKIP_REASON="the pinned grype could not complete a scan (no vulnerability database?)"; return 0
  fi
  out="$(tools/check-vulnerability-report.py --format grype --report "$work/grype.json" \
          --sbom "$work/sbom.json" --min-artifacts 1 --expect-digests "$work/staged.sha256" \
          --fail-on high 2>&1)"
  rc=$?
  printf '%s\n' "$out" >>"$PROBE_CAPTURE"
  if [ "$rc" -ne 1 ]; then rm -rf "$work"; return 0; fi
  grep -q 'commons-text@1.9' <<<"$out" || { rm -rf "$work"; return 0; }
  "$bin" "dir:$work/empty" -o json="$work/empty-grype.json" -o cyclonedx-json="$work/empty-sbom.json" >>"$PROBE_CAPTURE" 2>&1
  : > "$work/empty.sha256"
  tools/check-vulnerability-report.py --format grype --report "$work/empty-grype.json" \
    --sbom "$work/empty-sbom.json" --min-artifacts 1 --expect-digests "$work/empty.sha256" \
    --fail-on high >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  rm -rf "$work"
  [ "$rc" -eq 2 ] || return 0
  return 1
}

# ---------------------------------------------------------------------------
# probe 4. A report that does not prove a scan happened is refused with exit 2: `{}`, an empty
# file, and a well-formed report whose coverage document lists nothing. Also a report handed
# over with no coverage document at all. Weak while any of them is accepted or answers
# with something other than 2.
# ---------------------------------------------------------------------------
probe_empty_report_passes_the_gate() {
  local work weak=1 rc
  work="$(mktemp -d)"
  printf '{}' > "$work/braces.json"
  : > "$work/empty.json"
  printf '{"matches":[],"source":{"type":"directory","target":"/nonexistent"}}' > "$work/nothing.json"
  printf '{"components":[]}' > "$work/nothing-sbom.json"
  printf '{"components":[]}' > "$work/braces-sbom.json"
  : > "$work/none.sha256"
  local f
  for f in braces empty nothing; do
    tools/check-vulnerability-report.py --format grype --report "$work/$f.json" \
      --sbom "$work/$f-sbom.json" --min-artifacts 1 --expect-digests "$work/none.sha256" \
      --fail-on high >>"$PROBE_CAPTURE" 2>&1
    rc=$?
    if [ "$rc" -ne 2 ]; then echo "$f.json: exit $rc, not 2" >>"$PROBE_CAPTURE"; weak=0; fi
  done
  tools/check-vulnerability-report.py --format grype --report "$work/nothing.json" --fail-on high >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  if [ "$rc" -ne 2 ]; then echo "no coverage document: exit $rc, not 2" >>"$PROBE_CAPTURE"; weak=0; fi
  # The coverage floor: one package cataloged while two jars were staged is a scan that covered
  # less than what is about to be signed. The gate must refuse (exit 2).
  cat >"$work/floor-report.json" <<'J'
{"matches":[],"source":{"type":"directory","target":"/probe/scan"},"descriptor":{"name":"grype","version":"0.118.0"}}
J
  cat >"$work/floor-sbom.json" <<'J'
{"metadata":{"component":{"type":"file","name":"/probe/scan"},"tools":{"components":[{"name":"grype","version":"0.118.0"}]}},
 "components":[{"type":"library","name":"a","version":"1","purl":"pkg:maven/x/a@1"},
               {"type":"file","name":"/probe/scan/a-1.jar","hashes":[{"alg":"SHA-256","content":"aa"}]}]}
J
  printf 'aa  a-1.jar\n' > "$work/floor.sha256"
  tools/check-vulnerability-report.py --format grype --report "$work/floor-report.json" \
    --sbom "$work/floor-sbom.json" --min-artifacts 2 --expect-digests "$work/floor.sha256" \
    --fail-on high >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  if [ "$rc" -ne 2 ]; then echo "fewer packages cataloged than jars staged: exit $rc, not 2" >>"$PROBE_CAPTURE"; weak=0; fi
  rm -rf "$work"
  [ "$weak" -eq 0 ]
}

# ---------------------------------------------------------------------------
# A MEDIUM finding does not fail the release (by decision) but must be written down, so the
# release notes can carry a decision for it. Weak while a MEDIUM leaves no line in the summary
# file, or fails the run.
# ---------------------------------------------------------------------------
probe_a_medium_finding_is_never_written_down() {
  local work rc
  work="$(mktemp -d)"
  cat >"$work/grype.json" <<'REPORT'
{"matches":[{"vulnerability":{"id":"CVE-synthetic-medium","severity":"Medium"},
             "artifact":{"name":"vulnerable","version":"1.0","type":"java-archive"}}],
 "source":{"type":"directory","target":"/probe/scan"},
 "descriptor":{"name":"grype","version":"0.118.0"}}
REPORT
  cat >"$work/sbom.json" <<'SBOM'
{"metadata":{"component":{"type":"file","name":"/probe/scan"},
             "tools":{"components":[{"name":"grype","version":"0.118.0"}]}},
 "components":[{"type":"library","name":"vulnerable","version":"1.0",
                "purl":"pkg:maven/org.example/vulnerable@1.0"},
               {"type":"file","name":"/probe/scan/vulnerable-1.0.jar",
                "hashes":[{"alg":"SHA-256","content":"aa"}]}]}
SBOM
  printf 'aa  vulnerable-1.0.jar\n' > "$work/staged.sha256"
  tools/check-vulnerability-report.py --format grype --report "$work/grype.json" \
    --sbom "$work/sbom.json" --min-artifacts 1 --expect-digests "$work/staged.sha256" \
    --fail-on high --summary-file "$work/below.txt" >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then rm -rf "$work"; return 0; fi
  if [ -s "$work/below.txt" ]; then rm -rf "$work"; return 1; fi
  rm -rf "$work"
  return 0
}

# ---------------------------------------------------------------------------
# D15-01/02 and D15-03. The scan set is bound to the checksum record the reproducibility check
# wrote, not to target/ (a directory the step's own inner build writes to). A published jar
# that is not the recorded build, or a recorded jar absent from the scan set, must be refused.
# Executed against the fixture; weak unless the step body refuses.
# ---------------------------------------------------------------------------
probe_pre_sign_scan_accepts_a_jar_that_is_not_the_recorded_build() {
  _needs_maven && return 0
  local work rc jar
  work="$(_scan_step_fixture clean)" || { PROBE_SKIP_REASON="the synthetic release reactor could not be built"; return 0; }
  jar="$work/tree/agent-guard-core/target/agent-guard-core-99.99.99-probe.jar"
  if [ ! -f "$jar" ]; then rm -rf "$work"; PROBE_SKIP_REASON="the fixture produced no core jar to tamper with"; return 0; fi
  printf 'not the recorded build' >> "$jar"
  rc="$(_scan_step_exit "$work")"
  rm -rf "$work"
  [ "$rc" -eq 0 ]
}

probe_pre_sign_scan_accepts_a_published_jar_missing_from_the_scan_set() {
  _needs_maven && return 0
  local work rc
  work="$(_scan_step_fixture clean)" || { PROBE_SKIP_REASON="the synthetic release reactor could not be built"; return 0; }
  printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" \
    "agent-guard-core-99.99.99-probe-shaded.jar" >> "$work/t/reproducible-sha256.txt"
  rc="$(_scan_step_exit "$work")"
  rm -rf "$work"
  [ "$rc" -eq 0 ]
}

# ---------------------------------------------------------------------------
# F-4. The scanned graph must be the consumer's graph. A published pom whose dependency version
# is a range, LATEST, RELEASE or a SNAPSHOT (also through a property of the same pom) lets a
# consumer resolve an artifact that was never scanned. The step refuses before it builds
# anything. Executed against the fixture with each shape planted in the starter's pom; weak
# when any shape is accepted, or refused for a reason other than the pom check.
# ---------------------------------------------------------------------------
probe_a_version_range_in_a_published_pom_is_accepted() {
  _needs_maven && return 0
  local work rc v weak=1 shape
  work="$(_scan_step_fixture clean)" || { PROBE_SKIP_REASON="the synthetic release reactor could not be built"; return 0; }
  # control: the unmodified fixture passes the pom check, so a refusal below is the pom check's
  for shape in '[1.0,2.0)' '(,3.0]' 'LATEST' 'RELEASE' '1.2.3-SNAPSHOT' '${probe.range}'; do
    rm -rf "$work/tree/.probe-pom"; mkdir -p "$work/tree/.probe-pom"
    cp "$work/tree/agent-guard-spring-boot-starter/pom.xml" "$work/tree/.probe-pom/pom.xml.orig"
    python3 - "$work/tree/agent-guard-spring-boot-starter/pom.xml" "$shape" <<'PY'
import sys
p, v = sys.argv[1], sys.argv[2]
s = open(p).read()
dep = ("<dependency><groupId>org.example</groupId><artifactId>probe-dep</artifactId>"
       "<version>%s</version></dependency>" % v)
s = s.replace("<dependencies>", "<dependencies>" + dep, 1)
if "${probe.range}" in v:
    s = s.replace("<properties>", "<properties><probe.range>[1.0,2.0)</probe.range>", 1) if "<properties>" in s \
        else s.replace("<dependencies>", "<properties><probe.range>[1.0,2.0)</probe.range></properties><dependencies>", 1)
open(p, "w").write(s)
PY
    : > "$PROBE_CAPTURE"
    rc="$(_scan_step_exit "$work")"
    cp "$work/tree/.probe-pom/pom.xml.orig" "$work/tree/agent-guard-spring-boot-starter/pom.xml"
    if [ "$rc" -eq 0 ] || ! grep -q 'floating, unpinned version' "$PROBE_CAPTURE"; then
      echo "shape '$shape': exit $rc, not refused by the pom check" >&2
      weak=0
    fi
  done
  rm -rf "$work"
  [ "$weak" -eq 0 ]
}

# ---------------------------------------------------------------------------
# F-9 aside, RP-5/RP-6. The uploaded bundle is compared entry by entry against the record, poms
# included, and the record itself must contain the poms.
# ---------------------------------------------------------------------------
probe_reproducibility_check_never_records_poms() {
  grep -q '\*\.pom' scripts/verify-reproducible.sh || return 0
  return 1
}

# F-1. The comparison must read the bundle, not the build directory (a sibling of the bundle).
probe_the_comparison_reads_the_build_directory_not_the_bundle() {
  local body
  body="$(step_body "$WF" "$CMP_STEP")"
  [ -n "$body" ] || return 0
  grep -q 'central-bundle.zip' <<<"$body" || return 0
  grep -q 'unzip' <<<"$body" || return 0
  grep -qE '^\s*for jar in agent-guard-core/target' <<<"$body" && return 0
  grep -q 'MISSING FROM BUNDLE' <<<"$body" || return 0
  grep -qE "find \"\\\$work\" .*'\\*\\.pom'" <<<"$body" || return 0
  return 1
}

# Runs the real comparison step body against a synthetic bundle, record and scanned-digest file.
_bundle_comparison_run() { # _bundle_comparison_run <project dir> <output file>
  local body project_dir="$1" out="$2"
  body="$(step_body "$WF" "$CMP_STEP")"
  [ -n "$body" ] || { echo 127 > "$out.rc"; return; }
  body="$(printf '%s' "$body" | sed 's/\${{ runner\.temp }}/$RUNNER_TEMP/g')"
  mkdir -p "$project_dir/.runner-temp"
  cp "$project_dir/reproducible-sha256.txt" "$project_dir/.runner-temp/reproducible-sha256.txt"
  [ -f "$project_dir/scanned-sha256.txt" ] && cp "$project_dir/scanned-sha256.txt" "$project_dir/.runner-temp/scanned-sha256.txt"
  : > "$project_dir/.runner-temp/summary.md"
  ( cd "$project_dir" &&
    RUNNER_TEMP="$project_dir/.runner-temp" GITHUB_STEP_SUMMARY="$project_dir/.runner-temp/summary.md" \
    bash -c "$body" ) >"$out" 2>&1
  echo $? > "$out.rc"
  cat "$project_dir/.runner-temp/summary.md" >> "$out" 2>/dev/null || true
}

# _bundle_case <work dir> <spec>... ; spec = name:recorded:scanned
#   recorded = ok (true digest) | wrong (a different digest) | none (no record line)
#   scanned  = yes | no   (is the digest in scanned-sha256.txt)
_bundle_case() {
  local work="$1" spec name rec sc sha dir; shift
  dir="$work/bundle-src/com/housedevinci/agent-guard-core/0.1.0"
  mkdir -p "$dir" "$work/target/central-publishing"
  : > "$work/reproducible-sha256.txt"; : > "$work/scanned-sha256.txt"
  for spec in "$@"; do
    name="${spec%%:*}"; rec="${spec#*:}"; sc="${rec#*:}"; rec="${rec%%:*}"
    printf 'bytes of %s\n' "$name" > "$dir/$name"
    sha="$(shasum -a 256 "$dir/$name" | cut -d' ' -f1)"
    case "$rec" in
      ok) printf '%s  %s\n' "$sha" "$name" >> "$work/reproducible-sha256.txt" ;;
      wrong) printf '%s  %s\n' "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" "$name" >> "$work/reproducible-sha256.txt" ;;
    esac
    [ "$sc" = yes ] && printf '%s  /scan/%s\n' "$sha" "$name" >> "$work/scanned-sha256.txt"
  done
  ( cd "$work/bundle-src" && zip -q -r "$work/target/central-publishing/central-bundle.zip" . )
}

# ---------------------------------------------------------------------------
# probe 5. A jar in the uploaded bundle whose digest is not in scanned-sha256.txt is a jar that
# was signed without having been scanned. Control: a bundle whose every non-javadoc jar was
# scanned (and whose pom, which jar digests do not cover, was recorded) must pass, or the step is
# simply broken. Weak when the control fails or when the unscanned sources jar passes.
# ---------------------------------------------------------------------------
probe_bundle_may_contain_an_unscanned_jar() {
  command -v zip >>"$PROBE_CAPTURE" 2>&1 || { PROBE_SKIP_REASON="zip is not installed"; return 0; }
  local work out rc weak=1
  work="$(mktemp -d)"
  _bundle_case "$work" 'agent-guard-core-0.1.0.jar:ok:yes' 'agent-guard-core-0.1.0.pom:ok:no'
  _bundle_comparison_run "$work" "$work/control.out"; rc="$(cat "$work/control.out.rc")"
  if [ "$rc" -ne 0 ]; then echo "control bundle refused (exit $rc)" >>"$PROBE_CAPTURE"; cat "$work/control.out" >>"$PROBE_CAPTURE"; rm -rf "$work"; return 0; fi
  rm -rf "$work"; work="$(mktemp -d)"
  _bundle_case "$work" 'agent-guard-core-0.1.0.jar:ok:yes' 'agent-guard-core-0.1.0-sources.jar:ok:no' 'agent-guard-core-0.1.0.pom:ok:no'
  _bundle_comparison_run "$work" "$work/out"; rc="$(cat "$work/out.rc")"
  cat "$work/out" >>"$PROBE_CAPTURE"
  [ "$rc" -eq 0 ] && weak=0
  rm -rf "$work"
  [ "$weak" -eq 0 ]
}

# ---------------------------------------------------------------------------
# probe 6 (F-2). The javadoc exemption is by exact suffix `-javadoc.jar` and nothing else is
# exempt, in both directions: a javadoc jar that differs from the record and was never scanned
# passes (named residue), and `...-javadocX.jar` with a good record but no scan does not.
# Weak when either direction is wrong.
# ---------------------------------------------------------------------------
probe_a_javadoc_jar_fails_the_digest_assertion() {
  command -v zip >>"$PROBE_CAPTURE" 2>&1 || { PROBE_SKIP_REASON="zip is not installed"; return 0; }
  local work rc weak=1
  work="$(mktemp -d)"
  _bundle_case "$work" 'agent-guard-core-0.1.0.jar:ok:yes' 'agent-guard-core-0.1.0-javadoc.jar:wrong:no' 'agent-guard-core-0.1.0.pom:ok:no'
  _bundle_comparison_run "$work" "$work/out"; rc="$(cat "$work/out.rc")"
  if [ "$rc" -ne 0 ]; then echo "javadoc jar refused (exit $rc): the named residue is not honoured" >>"$PROBE_CAPTURE"; cat "$work/out" >>"$PROBE_CAPTURE"; rm -rf "$work"; return 0; fi
  rm -rf "$work"; work="$(mktemp -d)"
  _bundle_case "$work" 'agent-guard-core-0.1.0.jar:ok:yes' 'agent-guard-core-0.1.0-javadocX.jar:ok:no' 'agent-guard-core-0.1.0.pom:ok:no'
  _bundle_comparison_run "$work" "$work/out"; rc="$(cat "$work/out.rc")"
  cat "$work/out" >>"$PROBE_CAPTURE"
  [ "$rc" -eq 0 ] && weak=0
  rm -rf "$work"
  [ "$weak" -eq 0 ]
}

# ---------------------------------------------------------------------------
# F-8 / RP-6. An entry with no recorded checksum must report NO RECORD and let the loop reach the
# entries after it. Weak if the step dies without a NO RECORD line or never reaches the later
# entry (here deliberately mismatching).
# ---------------------------------------------------------------------------
probe_bundle_comparison_dies_on_an_unrecorded_entry() {
  command -v zip >>"$PROBE_CAPTURE" 2>&1 || { PROBE_SKIP_REASON="zip is not installed"; return 0; }
  local work weak=1
  work="$(mktemp -d)"
  _bundle_case "$work" 'agent-guard-core-0.1.0.pom:none:no' 'agent-guard-core-0.1.0.jar:wrong:yes'
  _bundle_comparison_run "$work" "$work/out"
  cat "$work/out" >>"$PROBE_CAPTURE"
  if grep -q 'NO RECORD' "$work/out" && grep -q 'MISMATCH' "$work/out"; then weak=0; fi
  rm -rf "$work"
  [ "$weak" -eq 1 ]
}

# ---------------------------------------------------------------------------
# F-3. The gate's own soundness check (--self-test) runs in a release, in the publish job, as
# the step immediately before the scan. Weak while it does not (probe 1 asserts the adjacency;
# this asserts the command is really executed and exits 0 on the tree as it is).
# ---------------------------------------------------------------------------
probe_the_gate_self_test_never_runs_in_a_release() {
  local body
  body="$(step_body "$WF" "$SELFTEST_STEP")"
  [ -n "$body" ] || return 0
  grep -q 'check-vulnerability-report.py --self-test' <<<"$body" || return 0
  ( bash -c "$body" ) >>"$PROBE_CAPTURE" 2>&1 || return 0
  return 1
}

# The job summary must not kill a step the gate already passed (D18-03 on the sibling module).
probe_summary_block_dies_on_a_missing_coverage_line() {
  local line snippet work rc reached
  line="$(grep -nE "were scanned\|matched by digest" "$WF" | head -1 | cut -d: -f1)"
  [ -n "$line" ] || return 0
  snippet="$(sed -n "${line}p" "$WF")"
  work="$(mktemp -d)"
  printf 'vulnerability gate (grype report, threshold HIGH): 0 finding(s)\n' > "$work/vulnscan-gate.txt"
  RUNNER_TEMP="$work" bash -c "set -euo pipefail
    { echo START; $snippet; echo TAIL-REACHED; } >> \"$work/summary.txt\"" >>"$PROBE_CAPTURE" 2>&1
  rc=$?
  grep -q TAIL-REACHED "$work/summary.txt" 2>/dev/null; reached=$?
  rm -rf "$work"
  [ "$rc" -ne 0 ] && [ "$reached" -ne 0 ]
}

# F-7. The evidence uploads carry the report, the below-threshold list and the binding file.
probe_evidence_uploads_omit_the_scan_files() {
  local ok success failure
  success="$(_step_block 'Upload the release evidence')"
  failure="$(_step_block 'Upload failure diagnostics')"
  for f in grype.json vulnerabilities-below-threshold.txt scanned-sha256.txt; do
    grep -q "$f" <<<"$success" || return 0
    grep -q "$f" <<<"$failure" || return 0
  done
  return 1
}

probe probe_release_signs_without_a_vulnerability_scan       "B-CI-02 nothing scans what the release signs"         probe_release_signs_without_a_vulnerability_scan
probe probe_scan_step_is_skippable                           "B-CI-02 the scan or the comparison can be skipped"    probe_scan_step_is_skippable
probe probe_scan_does_not_cover_the_published_jars           "B-CI-02/F-5 the step body does not run or cover the jars" probe_scan_does_not_cover_the_published_jars
probe probe_scan_passes_a_planted_vulnerable_dependency      "B-CI-02 a planted CRITICAL dependency does not fail the step" probe_scan_passes_a_planted_vulnerable_dependency
probe probe_real_scanner_and_gate_miss_a_known_critical      "D-SCAN-03 a known CRITICAL in a scanned jar is not caught" probe_the_real_scanner_and_gate_miss_a_known_critical
probe probe_empty_report_passes_the_gate                     "an empty or coverage-less Grype report reads as clean" probe_empty_report_passes_the_gate
probe probe_medium_finding_is_never_written_down             "S8 a MEDIUM finding leaves no record"                 probe_a_medium_finding_is_never_written_down
probe probe_pre_sign_scan_accepts_an_unrecorded_jar          "D15-01/02 the scan set is not bound to the recorded build" probe_pre_sign_scan_accepts_a_jar_that_is_not_the_recorded_build
probe probe_pre_sign_scan_accepts_a_missing_published_jar    "D15-03 a recorded jar absent from the scan set passes" probe_pre_sign_scan_accepts_a_published_jar_missing_from_the_scan_set
probe probe_version_range_in_a_published_pom_is_accepted     "F-4 a floating dependency version in a published pom passes" probe_a_version_range_in_a_published_pom_is_accepted
probe probe_reproducibility_check_never_records_poms         "RP-5 the reproducibility record has no poms"          probe_reproducibility_check_never_records_poms
probe probe_comparison_reads_build_dir_not_the_bundle        "F-1 the comparison reads target/, not the bundle"      probe_the_comparison_reads_the_build_directory_not_the_bundle
probe probe_bundle_may_contain_an_unscanned_jar              "B-CI-02 a bundle jar absent from scanned-sha256.txt passes" probe_bundle_may_contain_an_unscanned_jar
probe probe_javadoc_exemption_is_not_exact                   "F-2 the javadoc exemption is wrong in one direction"   probe_a_javadoc_jar_fails_the_digest_assertion
probe probe_bundle_comparison_dies_on_an_unrecorded_entry    "F-8 an unrecorded entry kills the comparison silently" probe_bundle_comparison_dies_on_an_unrecorded_entry
probe probe_gate_self_test_never_runs_in_a_release           "F-3 the gate self-test does not run in a release"      probe_the_gate_self_test_never_runs_in_a_release
probe probe_summary_block_dies_on_a_missing_coverage_line    "D18-03 the job summary can kill a step the gate passed" probe_summary_block_dies_on_a_missing_coverage_line
probe probe_evidence_uploads_omit_the_scan_files             "F-7 the evidence uploads omit the scan files"          probe_evidence_uploads_omit_the_scan_files

# --- end of the PR 3 block -----------------------------------------------------------------


# ---------------------------------------------------------------------------
# The reference guard (internal-name and machine-path leak check, checklist item 10), copied
# from the reference implementation. Each probe is weak while the property is missing.
# ---------------------------------------------------------------------------
RG=tools/check-private-references.sh

probe_reference_guard_is_not_its_own_job() {
  grep -q '^  reference-guard:$' "$CI" || return 0
  local job
  job="$(awk 'f && /^  [a-z][a-z-]*:$/ {exit} /^  reference-guard:$/ {f=1} f' "$CI")"
  grep -q 'name: Reference guard$' <<<"$job" || return 0
  grep -q 'check-private-references.sh --tree' <<<"$job" || return 0
  grep -q 'check-private-references.sh --self-test' <<<"$job" || return 0
  return 1
}

probe_reference_guard_pattern_is_not_defined_exactly_once() {
  [ -f "$RG" ] || return 0
  [ "$(grep -c '^pattern=' "$RG")" -eq 1 ] || return 0
  # no second copy of the pattern in any workflow
  grep -rqE "docs\[/\]plans" .github/ 2>/dev/null && return 0
  return 1
}

probe_reference_guard_pattern_matches_its_own_source() {
  [ -f "$RG" ] || return 0
  local pat
  pat="$(sed -n "s/^pattern='\(.*\)'\$/\1/p" "$RG")"
  [ -n "$pat" ] || return 0
  grep -qE "$pat" "$RG" && return 0
  return 1
}

probe_reference_guard_tree_scan_is_not_text_forced() {
  [ -f "$RG" ] || return 0
  grep -q 'git grep -n --text -E' "$RG" || return 0
  return 1
}

probe_reference_guard_has_a_path_or_marker_exemption() {
  [ -f "$RG" ] || return 0
  grep -qE ':\(exclude\)|:![a-zA-Z./*]|--exclude|grep -v ' "$RG" && return 0
  return 1
}

probe_reference_guard_misses_a_machine_path_family() {
  [ -f "$RG" ] || return 0
  local pat
  pat="$(sed -n "s/^pattern='\(.*\)'\$/\1/p" "$RG")"
  [ -n "$pat" ] || return 0
  local s
  for s in "/User""s/x/y" "/hom""e/runner/x" "/roo""t/x" 'C:\User''s\x'; do
    printf '%s\n' "$s" | grep -qE "$pat" || return 0
  done
  return 1
}

probe_reference_guard_calls_a_scanner_error_clean() {
  [ -f "$RG" ] || return 0
  local work out1 out2 rc1=0 rc2=0
  work="$(mktemp -d)"
  mkdir -p "$work/nongit" "$work/mod/target"
  printf 'x\n' > "$work/mod/target/broken.jar"
  CHECK_PRIVATE_REFERENCES_ROOT="$work/nongit" bash "$RG" --tree >/dev/null 2>&1 || rc1=$?
  ( cd "$work" && bash "$OLDPWD/$RG" --jars mod >/dev/null 2>&1 ) || rc2=$?
  rm -rf "$work"
  [ "$rc1" -eq 1 ] && [ "$rc2" -eq 1 ] && return 1
  return 0
}

probe_reference_guard_self_test_is_red() {
  [ -f "$RG" ] || return 0
  bash "$RG" --self-test >/dev/null 2>&1 && return 1
  return 0
}

probe_jar_guard_is_not_run_on_the_jars() {
  [ -f "$RG" ] || return 0
  grep -q 'for jar in "\$module"/target/\*\.jar' "$RG" || return 0
  grep -q 'check-private-references.sh --jars agent-guard-core agent-guard-spring-boot-starter' "$CI" || return 0
  grep -q 'check-private-references.sh --jars agent-guard-core agent-guard-spring-boot-starter' "$WF" || return 0
  return 1
}

probe probe_reference_guard_is_not_its_own_job             "the guard is not a check of its own"                 probe_reference_guard_is_not_its_own_job
probe probe_reference_guard_pattern_defined_wrongly       "the guard pattern is not defined exactly once"       probe_reference_guard_pattern_is_not_defined_exactly_once
probe probe_reference_guard_pattern_matches_own_source    "the guard pattern matches its own source"            probe_reference_guard_pattern_matches_its_own_source
probe probe_reference_guard_tree_scan_not_text            "the tree scan is not git grep --text"                probe_reference_guard_tree_scan_is_not_text_forced
probe probe_reference_guard_has_an_exemption              "the guard has a path or marker exemption"            probe_reference_guard_has_a_path_or_marker_exemption
probe probe_reference_guard_misses_a_path_family          "the guard misses one of the four machine path families"  probe_reference_guard_misses_a_machine_path_family
probe probe_reference_guard_calls_a_scanner_error_clean   "a scanner error is read as clean"                    probe_reference_guard_calls_a_scanner_error_clean
probe probe_reference_guard_self_test_is_red              "the guard's own self-test is not green"              probe_reference_guard_self_test_is_red
probe probe_jar_guard_not_run_on_the_jars                 "the jar scan is not run on built and released jars"  probe_jar_guard_is_not_run_on_the_jars

echo
echo "still weak: $pass    fixed: $flipped"
[ "$pass" -eq 0 ]
