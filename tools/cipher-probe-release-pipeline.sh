#!/usr/bin/env bash
#
# Cipher probes for the Maven Central release pipeline (branch feat/release-pipeline).
#
# Every probe below asserts a WEAKNESS that is present at 645397d. Each one PASSES today
# and must FLIP TO FAILING once the matching finding in
# docs/SECURITY-REVIEW-feat-release-pipeline.md is fixed. A probe that starts failing is
# the signal that the item is closed; delete it in the same PR that fixes it.
#
#   tools/cipher-probe-release-pipeline.sh            static probes only (seconds)
#   CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh   + the licence-gate probe
#
# Exit code is 0 while the weaknesses are still there, 1 once every probe has flipped.
# That inversion is deliberate: this file is evidence, not a CI gate.
#
set -uo pipefail
cd "$(dirname "$0")/.."

WF=.github/workflows/release.yml
pass=0; flipped=0

probe() { # probe <name> <"still weak" message>; body returns 0 when the weakness is present
  local name="$1" msg="$2"; shift 2
  if "$@"; then
    printf 'WEAK    %-52s %s\n' "$name" "$msg"; pass=$((pass + 1))
  else
    printf 'FIXED   %-52s\n' "$name"; flipped=$((flipped + 1))
  fi
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
probe_mvnw_skips_checksum_for_an_existing_distribution() {
  grep -q 'if \[ -d "\$MAVEN_HOME" \]; then' mvnw &&
    ! grep -q 'sha256sum -c' <(sed -n '/if \[ -d "\$MAVEN_HOME" \]/,/^fi/p' mvnw)
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
<groupId>the security review.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version><packaging>jar</packaging>
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
    perl -0pi -e 's{<dependencies>}{<dependencies>\n    <dependency><groupId>the security review.synthetic</groupId><artifactId>syn-dual</artifactId><version>1.0</version></dependency>}' \
      agent-guard-core/pom.xml
    ./mvnw -B -pl agent-guard-core -am verify \
      -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true -Denforcer.skip=true >/dev/null 2>&1
  )
  rc=$?
  rm -rf "$work"
  # exit 0 from the build == the GPL-3.0 half was ignored == the weakness is present
  return "$rc"
}

echo "the security review release-pipeline probes  (WEAK = finding still open)"
echo
probe probe_multiline_version_accepted                       "M4 newline in the version input passes validation"   probe_multiline_version_accepted
probe probe_release_job_restores_maven_cache                 "M3 release job restores the maven/wrapper cache"     probe_release_job_restores_maven_cache
probe probe_mvnw_skips_checksum_for_existing_distribution    "M3 mvnw execs a cached distribution unverified"      probe_mvnw_skips_checksum_for_an_existing_distribution
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
echo "still weak: $pass    fixed: $flipped"
[ "$pass" -eq 0 ]
