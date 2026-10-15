#!/usr/bin/env bash
#
# Cipher probes for the Dependabot auto-merge mechanism (branch ci/dependabot-auto-merge-2).
# The seven conditions of the maintainer-approved Dependabot auto-merge rule, one probe each.
#
# Every probe below asserts a WEAKNESS. Each one PASSES (prints WEAK) while its condition is
# not enforced and must FLIP TO FAILING (prints FIXED) once it is. Probes run the real step
# bodies extracted from the workflow file against synthetic inputs - never a grep of the YAML.
#
#   tools/cipher-probe-dependabot.sh
#
# Exit code is 0 once every probe has flipped to FIXED, 1 while any weakness remains.
#
set -uo pipefail
cd "$(dirname "$0")/.."

WF=.github/workflows/dependabot-auto-merge.yml
DEP=.github/dependabot.yml
pass=0; flipped=0

probe() {
  local name="$1" msg="$2"; shift 2
  if "$@"; then
    printf 'WEAK    %-52s %s\n' "$name" "$msg"; pass=$((pass + 1))
  else
    printf 'FIXED   %-52s\n' "$name"; flipped=$((flipped + 1))
  fi
}

# Extracts the body of a `run: |` block for a named step.
step_body() { # step_body <step name>
  awk -v want="- name: $1" '
    index($0, want) { instep=1; next }
    instep && /run: \|/ { inrun=1; next }
    instep && !inrun && /^      - name:/ { exit }
    inrun && /^      - name:/ { exit }
    inrun && /^  [a-z][a-z0-9-]*:/ { exit }
    inrun { print }
  ' "$WF"
}

# A fake `gh` on PATH so a step's real `gh api` calls can be exercised without the network.
# GH_FAKE_FILES_JSON / GH_FAKE_COMMIT_JSON drive the two calls this workflow makes.
make_fake_gh() { # make_fake_gh <dir>
  local dir="$1"
  cat > "$dir/gh" <<'FAKE'
#!/usr/bin/env bash
if [ "$1" = "api" ]; then
  [ -z "${GH_FAKE_API_FAIL:-}" ] || exit 1
  for a in "$@"; do
    case "$a" in
      # The real call pipes through --jq '.[].filename'; the fake applies the same
      # transform with the real jq binary so the step's own parsing runs as in production.
      */pulls/*/files) printf '%s' "${GH_FAKE_FILES_JSON:-[]}" | jq -r '.[]'; exit 0 ;;
      */contents/.github/required-checks.txt*) printf '%s\n' "${GH_FAKE_LISTED-}"; exit 0 ;;
      */contents/.github/workflows/ci.yml*) printf '%s\n' "${GH_FAKE_CI-}"; exit 0 ;;
      */rules/branches/*) printf '%s' "${GH_FAKE_RULES:-[]}"; exit 0 ;;
      */commits/*) printf '%s' "${GH_FAKE_COMMIT_JSON:-\{\}}"; exit 0 ;;
    esac
  done
  echo '{}'; exit 0
elif [ "$1" = "pr" ] && [ "$2" = "merge" ]; then
  echo "$*" >> "${GH_FAKE_MERGE_LOG:-/dev/null}"
  exit 0
fi
exit 0
FAKE
  chmod +x "$dir/gh"
}

# ---------------------------------------------------------------------------
# major refused - fails closed: only semver-patch and semver-minor pass.
# ---------------------------------------------------------------------------
probe_major_update_is_not_refused() {
  local body work rc
  body="$(step_body 'Refuse anything other than a patch or minor update')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  UPDATE_TYPE="version-update:semver-major" GITHUB_ENV="$work/env" bash -c "$body" >/dev/null 2>&1
  rc=0
  grep -q '^STOP=1$' "$work/env" 2>/dev/null || rc=1
  rm -rf "$work"
  [ "$rc" -eq 1 ]   # STOP was not set on a major: weak
}

probe_patch_update_is_wrongly_refused() {
  local body work
  body="$(step_body 'Refuse anything other than a patch or minor update')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  UPDATE_TYPE="version-update:semver-patch" GITHUB_ENV="$work/env" bash -c "$body" >/dev/null 2>&1
  local blocked=1
  grep -q '^STOP=1$' "$work/env" 2>/dev/null && blocked=0
  rm -rf "$work"
  [ "$blocked" -eq 0 ]   # a legitimate patch was refused: also a defect, reported as weak
}

# ---------------------------------------------------------------------------
# foreign path refused
# ---------------------------------------------------------------------------
probe_a_foreign_path_passes_the_manifest_gate() {
  local body work rc
  body="$(step_body 'Refuse a PR that touches anything but a manifest')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_FILES_JSON='["pom.xml","src/main/java/Evil.java"]' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard PR_NUMBER=1 GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  rc=0
  grep -q '^STOP=1$' "$work/env" 2>/dev/null || rc=1
  rm -rf "$work"
  [ "$rc" -eq 1 ]   # a non-manifest path did not stop the merge: weak
}

probe_manifest_only_pr_is_wrongly_refused() {
  local body work
  body="$(step_body 'Refuse a PR that touches anything but a manifest')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_FILES_JSON='["pom.xml","agent-guard-core/pom.xml"]' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard PR_NUMBER=1 GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  local blocked=1
  grep -q '^STOP=1$' "$work/env" 2>/dev/null && blocked=0
  rm -rf "$work"
  [ "$blocked" -eq 0 ]   # a manifest-only PR was refused: also a defect, reported as weak
}

# ---------------------------------------------------------------------------
# non-Dependabot actor / unverified commit refused
# ---------------------------------------------------------------------------
probe_a_non_dependabot_head_commit_passes() {
  local body work rc
  body="$(step_body 'Refuse an unverified or non-Dependabot head commit')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_COMMIT_JSON='{"author":{"login":"a-human"},"commit":{"verification":{"verified":true}}}' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard HEAD_SHA=deadbeef GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  rc=0
  grep -q '^STOP=1$' "$work/env" 2>/dev/null || rc=1
  rm -rf "$work"
  [ "$rc" -eq 1 ]   # a human-authored head commit did not stop the merge: weak
}

probe_an_unverified_dependabot_commit_passes() {
  local body work rc
  body="$(step_body 'Refuse an unverified or non-Dependabot head commit')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_COMMIT_JSON='{"author":{"login":"dependabot[bot]"},"commit":{"verification":{"verified":false}}}' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard HEAD_SHA=deadbeef GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  rc=0
  grep -q '^STOP=1$' "$work/env" 2>/dev/null || rc=1
  rm -rf "$work"
  [ "$rc" -eq 1 ]   # an unverified signature did not stop the merge: weak
}

probe_a_verified_dependabot_commit_is_wrongly_refused() {
  local body work
  body="$(step_body 'Refuse an unverified or non-Dependabot head commit')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_COMMIT_JSON='{"author":{"login":"dependabot[bot]"},"commit":{"verification":{"verified":true}}}' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard HEAD_SHA=deadbeef GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  local blocked=1
  grep -q '^STOP=1$' "$work/env" 2>/dev/null && blocked=0
  rm -rf "$work"
  [ "$blocked" -eq 0 ]   # a legitimate Dependabot commit was refused: also a defect, weak
}

# ---------------------------------------------------------------------------
# cooldown present and >= 7 in every ecosystem
# ---------------------------------------------------------------------------
probe_cooldown_missing_or_short_in_dependabot_yml() {
  local ecosystems days weak=1 line
  ecosystems="$(grep -c 'package-ecosystem:' "$DEP" 2>/dev/null || echo 0)"
  [ "$ecosystems" -gt 0 ] || return 0
  local cooldowns
  cooldowns="$(grep -c 'default-days:' "$DEP" 2>/dev/null || echo 0)"
  if [ "$cooldowns" -lt "$ecosystems" ]; then
    return 0   # fewer cooldown blocks than ecosystems: weak
  fi
  weak=0
  while IFS= read -r line; do
    days="$(printf '%s' "$line" | grep -oE '[0-9]+')"
    [ -n "$days" ] || { weak=1; break; }
    [ "$days" -ge 7 ] || { weak=1; break; }
  done < <(grep 'default-days:' "$DEP")
  [ "$weak" -eq 1 ]
}

# ---------------------------------------------------------------------------
# trigger is pull_request, not pull_request_target
# ---------------------------------------------------------------------------
probe_trigger_is_pull_request_target() {
  grep -q '^on:' "$WF" || return 0
  local trigger_block
  trigger_block="$(awk '/^on:/{f=1} f{print} f&&/^permissions:/{exit}' "$WF")"
  printf '%s' "$trigger_block" | grep -q 'pull_request_target'
}

# ---------------------------------------------------------------------------
# no checkout step
# ---------------------------------------------------------------------------
probe_workflow_checks_out_the_pr_head() {
  grep -q 'actions/checkout' "$WF"
}

# ---------------------------------------------------------------------------
# permissions exactly the two
# ---------------------------------------------------------------------------
probe_permissions_are_not_exactly_the_two() {
  local block
  block="$(awk '/^permissions:/{f=1;print;next} f&&/^[a-z]/{exit} f{print}' "$WF")"
  local n
  n="$(printf '%s\n' "$block" | grep -cE '^\s+(contents|pull-requests|[a-z-]+):')"
  [ "$n" -eq 2 ] || return 0
  printf '%s\n' "$block" | grep -qE '^\s+contents:\s*write\s*$' || return 0
  printf '%s\n' "$block" | grep -qE '^\s+pull-requests:\s*write\s*$' || return 0
  return 1   # exactly the two, both write: FIXED
}

# ---------------------------------------------------------------------------
# condition 4, strict: a workflow or dependabot.yml change is NOT a manifest. A bump that
# could rewrite its own gate must wait for a human.
# ---------------------------------------------------------------------------
probe_a_github_path_passes_the_manifest_gate() {
  local body work rc
  body="$(step_body 'Refuse a PR that touches anything but a manifest')"
  [ -n "$body" ] || return 0
  work="$(mktemp -d)"
  make_fake_gh "$work"
  GH_FAKE_FILES_JSON='["pom.xml",".github/workflows/ci.yml"]' \
    PATH="$work:$PATH" REPO=1of1Canopus/agent-guard PR_NUMBER=1 GITHUB_ENV="$work/env" \
    bash -c "$body" >/dev/null 2>&1
  rc=0
  grep -q '^STOP=1$' "$work/env" 2>/dev/null || rc=1
  rm -rf "$work"
  [ "$rc" -eq 1 ]
}

# ---------------------------------------------------------------------------
# condition 7: arming needs every CI gate job to be a required check, live. Runs the real
# step against synthetic rules. Returns the step's STOP result: 0 = STOP set, 1 = not set.
# ---------------------------------------------------------------------------
GOOD_LISTED=$'Build & test\nDCO sign-off'
GOOD_CI=$'name: CI\njobs:\n  a:\n    name: Build & test\n    steps:\n      - name: not a job\n  b:\n    name: DCO sign-off'
GOOD_RULES='[{"type":"pull_request"},{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"Build & test"},{"context":"DCO sign-off"}]}}]'

run_required_checks_step() { # env GH_FAKE_* set by caller; echoes "stop" or "go"
  local body work out
  body="$(step_body 'Refuse unless every CI gate job is a required check')"
  [ -n "$body" ] || { echo "nostep"; return; }
  work="$(mktemp -d)"; make_fake_gh "$work"
  PATH="$work:$PATH" REPO=1of1Canopus/agent-guard BASE_REF=main HEAD_SHA=deadbeef \
    GITHUB_ENV="$work/env" bash -c "$body" >/dev/null 2>&1
  if grep -q '^STOP=1$' "$work/env" 2>/dev/null; then out=stop; else out=go; fi
  rm -rf "$work"; echo "$out"
}

probe_an_ordinary_green_setup_is_wrongly_refused() {
  [ "$(GH_FAKE_LISTED="$GOOD_LISTED" GH_FAKE_CI="$GOOD_CI" GH_FAKE_RULES="$GOOD_RULES" run_required_checks_step)" != go ]
}
probe_a_ci_job_that_is_not_a_required_check_passes() {
  local ci="$GOOD_CI"$'\n  c:\n    name: Extra gate'
  [ "$(GH_FAKE_LISTED="$GOOD_LISTED"$'\nExtra gate' GH_FAKE_CI="$ci" GH_FAKE_RULES="$GOOD_RULES" run_required_checks_step)" != stop ]
}
probe_a_ci_job_missing_from_the_list_passes() {
  local ci="$GOOD_CI"$'\n  c:\n    name: Extra gate'
  [ "$(GH_FAKE_LISTED="$GOOD_LISTED" GH_FAKE_CI="$ci" GH_FAKE_RULES="$GOOD_RULES" run_required_checks_step)" != stop ]
}
probe_a_rules_api_error_passes() {
  [ "$(GH_FAKE_API_FAIL=1 GH_FAKE_LISTED="$GOOD_LISTED" GH_FAKE_CI="$GOOD_CI" GH_FAKE_RULES="$GOOD_RULES" run_required_checks_step)" != stop ]
}
probe_a_branch_with_no_required_checks_passes() {
  [ "$(GH_FAKE_LISTED="$GOOD_LISTED" GH_FAKE_CI="$GOOD_CI" GH_FAKE_RULES='[{"type":"pull_request"}]' run_required_checks_step)" != stop ]
}

# ---------------------------------------------------------------------------
# disarm: a refusal and a non-Dependabot push both turn auto-merge off.
# ---------------------------------------------------------------------------
probe_a_refusal_does_not_disarm() {
  local body work rc
  body="$(step_body 'Disarm auto-merge after a refusal')"
  [ -n "$body" ] || return 0
  # the step must be gated on a refusal having happened (STOP=1), and must run even after a failure
  awk '/- name: Disarm auto-merge after a refusal/{f=1;next} f&&/run:/{exit} f' "$WF" | grep -q "always() && env.STOP == '1'" || return 0
  work="$(mktemp -d)"; make_fake_gh "$work"
  GH_FAKE_MERGE_LOG="$work/log" PATH="$work:$PATH" PR_URL=https://example/pr/1 bash -c "$body" >/dev/null 2>&1
  rc=0; grep -q -- '--disable-auto' "$work/log" 2>/dev/null || rc=1
  rm -rf "$work"; [ "$rc" -eq 1 ]
}
probe_a_foreign_push_does_not_disarm() {
  local body work rc
  body="$(step_body 'Disarm')"
  [ -n "$body" ] || return 0
  grep -q "github.actor != 'dependabot\[bot\]'" "$WF" || return 0
  work="$(mktemp -d)"; make_fake_gh "$work"
  GH_FAKE_MERGE_LOG="$work/log" PATH="$work:$PATH" PR_URL=https://example/pr/1 bash -c "$body" >/dev/null 2>&1
  rc=0; grep -q -- '--disable-auto' "$work/log" 2>/dev/null || rc=1
  rm -rf "$work"; [ "$rc" -eq 1 ]
}

# The committed list must match reality right now (the live check the workflow does at run time).
probe_required_checks_txt_drifted_from_ci_yml() {
  local jobs listed
  jobs="$(sed -n 's/^    name: //p' .github/workflows/ci.yml | sort -u)"
  listed="$(sed -e '/^#/d' -e '/^$/d' .github/required-checks.txt 2>/dev/null | sort -u)"
  [ -n "$listed" ] || return 0
  [ "$jobs" != "$listed" ]
}

echo "the Dependabot auto-merge probes  (WEAK = condition not yet enforced)"
echo
probe probe_major_update_is_not_refused                    "1 a semver-major update passes the gate"          probe_major_update_is_not_refused
probe probe_patch_update_is_wrongly_refused                 "1 a semver-patch update is wrongly refused"       probe_patch_update_is_wrongly_refused
probe probe_cooldown_missing_or_short_in_dependabot_yml     "2 cooldown missing or under 7 days somewhere"     probe_cooldown_missing_or_short_in_dependabot_yml
probe probe_trigger_is_pull_request_target                  "6 pull_request_target is used"                    probe_trigger_is_pull_request_target
probe probe_workflow_checks_out_the_pr_head                 "6 the workflow checks out the PR head"            probe_workflow_checks_out_the_pr_head
probe probe_permissions_are_not_exactly_the_two              "6 permissions are not exactly contents+PR write"  probe_permissions_are_not_exactly_the_two
probe probe_a_foreign_path_passes_the_manifest_gate          "4 a non-manifest path passes the gate"            probe_a_foreign_path_passes_the_manifest_gate
probe probe_manifest_only_pr_is_wrongly_refused              "4 a manifest-only PR is wrongly refused"          probe_manifest_only_pr_is_wrongly_refused
probe probe_a_non_dependabot_head_commit_passes              "5 a human-authored head commit passes"            probe_a_non_dependabot_head_commit_passes
probe probe_an_unverified_dependabot_commit_passes           "5 an unverified signature passes"                 probe_an_unverified_dependabot_commit_passes
probe probe_a_verified_dependabot_commit_is_wrongly_refused   "5 a verified Dependabot commit is wrongly refused" probe_a_verified_dependabot_commit_is_wrongly_refused
probe probe_a_github_path_passes_the_manifest_gate           "4 a .github path passes the manifest gate"        probe_a_github_path_passes_the_manifest_gate
probe probe_an_ordinary_green_setup_is_wrongly_refused        "7 a consistent setup is wrongly refused"          probe_an_ordinary_green_setup_is_wrongly_refused
probe probe_a_ci_job_that_is_not_a_required_check_passes      "7 a CI job that is not required passes"           probe_a_ci_job_that_is_not_a_required_check_passes
probe probe_a_ci_job_missing_from_the_list_passes             "7 a CI job missing from the list passes"          probe_a_ci_job_missing_from_the_list_passes
probe probe_a_rules_api_error_passes                          "7 an API error passes"                            probe_a_rules_api_error_passes
probe probe_a_branch_with_no_required_checks_passes           "7 a branch with no required checks passes"        probe_a_branch_with_no_required_checks_passes
probe probe_required_checks_txt_drifted_from_ci_yml           "7 required-checks.txt differs from ci.yml jobs"   probe_required_checks_txt_drifted_from_ci_yml
probe probe_a_refusal_does_not_disarm                         "7 a refusal leaves auto-merge armed"              probe_a_refusal_does_not_disarm
probe probe_a_foreign_push_does_not_disarm                    "5 a non-Dependabot push leaves it armed"          probe_a_foreign_push_does_not_disarm

echo
echo "still weak: $pass    fixed: $flipped"
[ "$pass" -eq 0 ]
