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


# ---------------------------------------------------------------------------
# non-Dependabot actor / unverified commit refused
# ---------------------------------------------------------------------------



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

# ---------------------------------------------------------------------------
# condition 7: arming needs every CI gate job to be a required check, live. Runs the real
# step against synthetic rules. Returns the step's STOP result: 0 = STOP set, 1 = not set.
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# disarm: a refusal and a non-Dependabot push both turn auto-merge off.
# ---------------------------------------------------------------------------

# The committed list must match reality right now (the live check the workflow does at run time).

# ===========================================================================
# Review probes, PR 44 (DM2-01 .. DM2-07). They run step bodies by job id and exact step name
# against a fake gh that applies the real --jq expression with real jq.
# ===========================================================================
# body of the `run: |` block of the step whose name is EXACTLY $2, inside job $1
step() { awk -v job="  $1:" -v want="      - name: $2" '
  $0 == job { injob=1; next }
  injob && /^  [a-zA-Z0-9_-]+:/ { exit }
  injob && $0 == want { instep=1; next }
  instep && !inrun && /^      - name:/ { exit }
  instep && /^        run: \|/ { inrun=1; next }
  inrun && /^      - name:/ { exit }
  inrun && /^ {0,9}[^ ]/ && !/^ *$/ { if ($0 !~ /^          /) exit }
  inrun { print }' "$WF"; }
# the `if:` line of that step, verbatim
step_if() { awk -v job="  $1:" -v want="      - name: $2" '
  $0 == job { injob=1; next }  injob && /^  [a-zA-Z0-9_-]+:/ { exit }
  injob && $0 == want { instep=1; next }
  instep && /^      - name:/ { exit }
  instep && /^        if: / { sub(/^        if: /, ""); print; exit }' "$WF"; }

FAKE_DIR="$(mktemp -d)"; trap 'rm -rf "$FAKE_DIR"' EXIT
cat > "$FAKE_DIR/gh" <<'FAKE'
#!/usr/bin/env bash
# Fixtures: FK_FILES FK_PULL FK_COMMIT FK_RULES FK_LISTED FK_CI_BASE FK_CI_HEAD FK_REPO
# FK_API_FAIL=1 fails every api call; FK_ARMED=1|0 auto-merge state; FK_MERGE_FAIL=1.
log="${FK_LOG:-/dev/null}"; echo "gh $*" >> "$log"
jqx=""; ep=""; args=("$@")
for ((i=0;i<${#args[@]};i++)); do case "${args[$i]}" in
  --jq|-q) jqx="${args[$((i+1))]}";; esac; done
out() { if [ -n "$jqx" ]; then printf '%s' "$1" | jq -r "$jqx"; else printf '%s\n' "$1"; fi; }
if [ "$1" = api ]; then
  [ -z "${FK_API_FAIL:-}" ] || { echo "HTTP 502" >&2; exit 1; }
  for a in "$@"; do case "$a" in repos/*) ep="$a";; esac; done
  case "$ep" in
    */pulls/*/files*) out "${FK_FILES:-[]}" ;;
    */pulls/*)        out "${FK_PULL:-{\}}" ;;
    */commits/*)      out "${FK_COMMIT:-{\}}" ;;
    */rules/branches/*) out "${FK_RULES:-[]}" ;;
    */contents/.github/required-checks.txt*) printf '%s\n' "${FK_LISTED-}" ;;
    */contents/.github/workflows/ci.yml\?ref=main) printf '%s\n' "${FK_CI_BASE-}" ;;
    */contents/.github/workflows/ci.yml*) printf '%s\n' "${FK_CI_HEAD-}" ;;
    repos/*/*) out "${FK_REPO:-{\}}" ;;
    *) echo '{}' ;;
  esac; exit 0
fi
if [ "$1" = pr ] && [ "$2" = view ]; then
  [ -z "${FK_API_FAIL:-}" ] || exit 1
  if [ "${FK_ARMED:-0}" = 1 ]; then out '{"autoMergeRequest":{"mergeMethod":"MERGE"}}'; else out '{"autoMergeRequest":null}'; fi; exit 0
fi
if [ "$1" = pr ] && [ "$2" = merge ]; then
  [ -z "${FK_MERGE_FAIL:-}" ] || { echo "GraphQL: Resource not accessible by integration" >&2; exit 1; }
  exit 0
fi
exit 0
FAKE
chmod +x "$FAKE_DIR/gh"

# run_step <job> <step name> : runs it with the fake gh and the caller's env; prints
# "stop" if STOP=1 was written, else "go"; exit status of the body in $RC
run_step() { local b w; b="$(step "$1" "$2")"; [ -n "$b" ] || { echo nostep; RC=99; return; }
  w="$(mktemp -d)"; : > "$w/env"
  PATH="$FAKE_DIR:$PATH" GITHUB_ENV="$w/env" REPO="${REPO:-1of1Canopus/agent-guard}" \
    PR_NUMBER="${PR_NUMBER:-7}" BASE_REF="${BASE_REF:-main}" HEAD_SHA="${HEAD_SHA:-aaaa}" \
    PR_URL="${PR_URL:-https://github.com/1of1Canopus/agent-guard/pull/7}" bash -c "$b" >/dev/null 2>&1
  RC=$?; if grep -q '^STOP=1$' "$w/env"; then echo stop; else echo go; fi; rm -rf "$w"; }

J=auto-merge
GUARD='Refuse a re-run, a fork or a moved head'
PATHS='Refuse a PR that touches anything but a manifest'
COMMIT='Refuse an unverified or non-Dependabot head commit'
GATES='Refuse unless every CI gate job is a required check'
SETTING='Refuse while the repository does not allow auto-merge'
ARM='Enable auto-merge'
DISARM='Disarm auto-merge after a refusal'
FJ=disarm-on-foreign-push
FDISARM='Disarm'

# ---- DM2-01 (MEDIUM) arming is not bound to the event head ------------------------------
good_guard_env() { ACTOR='dependabot[bot]' TRIGGERING_ACTOR='dependabot[bot]' PR_AUTHOR='dependabot[bot]' \
  HEAD_REPO=1of1Canopus/agent-guard HEAD_REF=dependabot/maven/x FK_PULL='{"head":{"sha":"aaaa"}}' "$@"; }
probe_a_rerun_by_a_person_can_arm() {
  [ "$(good_guard_env env TRIGGERING_ACTOR=a-person bash -c "$(declare -f run_step step); FAKE_DIR=$FAKE_DIR WF=$WF; run_step $J '$GUARD'")" != stop ]; }
probe_a_moved_head_can_arm() {
  [ "$(good_guard_env env FK_PULL='{"head":{"sha":"bbbb"}}' bash -c "$(declare -f run_step step); FAKE_DIR=$FAKE_DIR WF=$WF; run_step $J '$GUARD'")" != stop ]; }
probe_a_fork_pr_is_not_refused() {
  [ "$(good_guard_env env HEAD_REPO=someone/agent-guard bash -c "$(declare -f run_step step); FAKE_DIR=$FAKE_DIR WF=$WF; run_step $J '$GUARD'")" != stop ]; }
probe_a_genuine_dependabot_run_is_wrongly_refused() {
  [ "$(good_guard_env bash -c "$(declare -f run_step step); FAKE_DIR=$FAKE_DIR WF=$WF; run_step $J '$GUARD'")" != go ]; }
probe_arm_is_not_bound_to_the_event_head() {
  local l; l="$(mktemp)"; FK_LOG="$l" HEAD_SHA=aaaa run_step $J "$ARM" >/dev/null
  ! grep -qE -- '--match-head-commit[ =]aaaa' "$l"; local r=$?; rm -f "$l"; return $r; }
probe_two_runs_on_one_pr_are_not_serialised() {
  ! awk '/^concurrency:/{f=1;next} f&&/^[a-z]/{exit} f' "$WF" | grep -qE 'group: .*github\.event\.pull_request\.number'; }

# ---- DM2-02 (LOW) a run that cannot decide, or a failed disarm, leaves it armed -----------
probe_an_api_error_in_the_path_gate_leaves_it_armed() {
  [ "$(FK_API_FAIL=1 run_step $J "$PATHS")" != stop ]; }
probe_an_api_error_in_the_commit_gate_leaves_it_armed() {
  [ "$(FK_API_FAIL=1 run_step $J "$COMMIT")" != stop ]; }
probe_the_disarm_step_skips_when_a_step_errored() {
  [ "$(step_if $J "$DISARM")" != "always() && steps.arm.outcome != 'success'" ]; }
probe_a_failed_disarm_is_green() {
  FK_ARMED=1 FK_MERGE_FAIL=1 run_step $J "$DISARM" >/dev/null; [ "$RC" -eq 0 ]; }
probe_a_failed_foreign_push_disarm_is_green() {
  FK_ARMED=1 FK_MERGE_FAIL=1 run_step $FJ "$FDISARM" >/dev/null; [ "$RC" -eq 0 ]; }
probe_a_disarm_with_nothing_armed_goes_red() {   # guard against over-fixing
  FK_ARMED=0 run_step $FJ "$FDISARM" >/dev/null; [ "$RC" -ne 0 ]; }

# ---- DM2-03 (LOW) condition 7 job discovery ------------------------------------------------
CI_OK=$'name: CI\njobs:\n  a:\n    name: Build & test\n    runs-on: x\n  b:\n    name: DCO sign-off\n    runs-on: x'
L_OK=$'Build & test\nDCO sign-off'
R_PIN='[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"Build & test","integration_id":15368},{"context":"DCO sign-off","integration_id":15368}]}}]'
R_NAME='[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"Build & test"},{"context":"DCO sign-off"}]}}]'
probe_a_ci_job_without_a_name_is_not_checked() {
  local ci="$CI_OK"$'\n  extra:\n    runs-on: x'
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$ci" FK_CI_HEAD="$ci" FK_RULES="$R_PIN" run_step $J "$GATES")" != stop ]; }
probe_a_job_only_on_the_base_ci_is_not_checked() {
  local base="$CI_OK"$'\n  c:\n    name: New gate\n    runs-on: x'
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$base" FK_CI_HEAD="$CI_OK" FK_RULES="$R_PIN" run_step $J "$GATES")" != stop ]; }
probe_a_second_pr_workflow_escapes_the_drift_probe() {
  [ -z "${AM_PROBE_NESTED:-}" ] || return 1   # no recursion: the nested run skips the meta probes   # mutation of the shipped drift probe
  local d; d="$(mktemp -d)"; mkdir -p "$d/tools"; cp -R .github "$d/"; cp tools/cipher-probe-dependabot.sh "$d/tools/"
  printf 'name: Extra\non:\n  pull_request:\njobs:\n  x:\n    name: Sneaky gate\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n' > "$d/.github/workflows/extra.yml"
  local o; o="$(AM_PROBE_NESTED=1 bash "$d/tools/cipher-probe-dependabot.sh")"; grep -qE '^FIXED +probe_required_checks_txt_drifted_from_ci_yml' <<<"$o"; local r=$?; rm -rf "$d"; return $r; }
probe_an_app_pinned_setup_is_wrongly_refused() {   # good case for DM2-03 and DM2-05
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$CI_OK" FK_CI_HEAD="$CI_OK" FK_RULES="$R_PIN" run_step $J "$GATES")" != go ]; }

# ---- DM2-04 (LOW) path gate reads only .filename and no count --------------------------------
probe_a_rename_into_a_pom_passes() {
  [ "$(FK_FILES='[{"filename":"pom.xml","status":"modified"},{"filename":"x/pom.xml","previous_filename":".github/workflows/ci.yml","status":"renamed"}]' \
       FK_PULL='{"changed_files":2,"head":{"sha":"aaaa"}}' run_step $J "$PATHS")" != stop ]; }
probe_a_truncated_file_list_passes() {
  [ "$(FK_FILES='[{"filename":"pom.xml","status":"modified"}]' FK_PULL='{"changed_files":3001,"head":{"sha":"aaaa"}}' run_step $J "$PATHS")" != stop ]; }
probe_a_pom_only_pr_is_wrongly_refused() {   # good case
  [ "$(FK_FILES='[{"filename":"pom.xml","status":"modified"},{"filename":"agent-guard-core/pom.xml","status":"modified"}]' \
       FK_PULL='{"changed_files":2,"head":{"sha":"aaaa"}}' run_step $J "$PATHS")" != go ]; }

# ---- DM2-05 (LOW) required contexts are name-only --------------------------------------------
probe_a_name_only_required_check_passes() {
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$CI_OK" FK_CI_HEAD="$CI_OK" FK_RULES="$R_NAME" run_step $J "$GATES")" != stop ]; }

# ---- DM2-06 (LOW) "Allow auto-merge" off is not an off switch ---------------------------------
probe_auto_merge_off_still_proceeds() {
  [ "$(FK_REPO='{"allow_auto_merge":false}' run_step $J "$SETTING")" != stop ]; }
probe_auto_merge_on_is_wrongly_refused() {
  [ "$(FK_REPO='{"allow_auto_merge":true}' run_step $J "$SETTING")" != go ]; }

# ---- DM2-07 (INFO) shipped probes that survive the mutation they claim to cover -----------------
mut_survives() { # <perl expr> <shipped probe name>
  local d; d="$(mktemp -d)"; mkdir -p "$d/tools"; cp -R .github "$d/"; cp tools/cipher-probe-dependabot.sh "$d/tools/"
  perl -0pi -e "$1" "$d/$WF"
  local o; o="$(AM_PROBE_NESTED=1 bash "$d/tools/cipher-probe-dependabot.sh")"; grep -qE "^FIXED +$2( |\$)" <<<"$o"; local r=$?; rm -rf "$d"; return $r; }
probe_shipped_probes_survive_mutations() {
  [ -z "${AM_PROBE_NESTED:-}" ] || return 1
  mut_survives "s/(\n  disarm-on-foreign-push:\n.*?\n    if: )/\${1}false \&\& /s" probe_a_foreign_push_does_not_disarm && return 0
  mut_survives 's/(\n  disarm-on-foreign-push:\n.*?run: \|\n).*\z/${1}          true\n/s' probe_a_foreign_push_does_not_disarm && return 0
  mut_survives "s/(- name: Disarm auto-merge after a refusal\n        if: [^\n]*)/\${1} \&\& false/" probe_a_refusal_does_not_disarm && return 0
  return 1; }



# ---------------------------------------------------------------------------
# Conditions 4, 5, 7 and the disarm steps, on the shared fake gh (run_step).
# ---------------------------------------------------------------------------
PODS='[{"filename":"pom.xml","status":"modified"},{"filename":"X","status":"modified"}]'
probe_a_foreign_path_passes_the_manifest_gate() {
  [ "$(FK_FILES="${PODS/X/src\/main\/java\/Evil.java}" FK_PULL='{"changed_files":2}' run_step $J "$PATHS")" != stop ]; }
probe_a_github_path_passes_the_manifest_gate() {
  [ "$(FK_FILES="${PODS/X/.github\/workflows\/ci.yml}" FK_PULL='{"changed_files":2}' run_step $J "$PATHS")" != stop ]; }
probe_manifest_only_pr_is_wrongly_refused() {
  [ "$(FK_FILES="${PODS/X/agent-guard-core\/pom.xml}" FK_PULL='{"changed_files":2}' run_step $J "$PATHS")" != go ]; }
probe_a_non_dependabot_head_commit_passes() {
  [ "$(FK_COMMIT='{"author":{"login":"a-human"},"commit":{"verification":{"verified":true}}}' run_step $J "$COMMIT")" != stop ]; }
probe_an_unverified_dependabot_commit_passes() {
  [ "$(FK_COMMIT='{"author":{"login":"dependabot[bot]"},"commit":{"verification":{"verified":false}}}' run_step $J "$COMMIT")" != stop ]; }
probe_a_verified_dependabot_commit_is_wrongly_refused() {
  [ "$(FK_COMMIT='{"author":{"login":"dependabot[bot]"},"commit":{"verification":{"verified":true}}}' run_step $J "$COMMIT")" != go ]; }
probe_an_ordinary_green_setup_is_wrongly_refused() {
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$CI_OK" FK_CI_HEAD="$CI_OK" FK_RULES="$R_PIN" run_step $J "$GATES")" != go ]; }
probe_a_ci_job_that_is_not_a_required_check_passes() {
  local ci="$CI_OK"$'\n  c:\n    name: Extra gate'
  [ "$(FK_LISTED="$L_OK"$'\nExtra gate' FK_CI_BASE="$ci" FK_CI_HEAD="$ci" FK_RULES="$R_PIN" run_step $J "$GATES")" != stop ]; }
probe_a_ci_job_missing_from_the_list_passes() {
  local ci="$CI_OK"$'\n  c:\n    name: Extra gate'
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$ci" FK_CI_HEAD="$ci" FK_RULES="$R_PIN" run_step $J "$GATES")" != stop ]; }
probe_a_rules_api_error_passes() {
  [ "$(FK_API_FAIL=1 FK_LISTED="$L_OK" FK_CI_BASE="$CI_OK" FK_CI_HEAD="$CI_OK" FK_RULES="$R_PIN" run_step $J "$GATES")" != stop ]; }
probe_a_branch_with_no_required_checks_passes() {
  [ "$(FK_LISTED="$L_OK" FK_CI_BASE="$CI_OK" FK_CI_HEAD="$CI_OK" FK_RULES='[{"type":"pull_request"}]' run_step $J "$GATES")" != stop ]; }

# Every workflow that runs on pull_request (except this one) must have its jobs in
# required-checks.txt. Same yq expression as the workflow's condition 7 step.
probe_required_checks_txt_drifted_from_ci_yml() {
  command -v yq >/dev/null 2>&1 || return 0   # unverifiable counts as weak
  local jobs="" f listed
  for f in .github/workflows/*.yml; do
    [ "$f" = "$WF" ] && continue
    if [ "$(yq '.on | (tag == "!!map" and has("pull_request")) or (tag == "!!seq" and contains(["pull_request"])) or (. == "pull_request")' "$f")" = true ]; then
      jobs+="$(yq -r '.jobs | to_entries | .[] | (.value.name // .key)' "$f")"$'\n'
    fi
  done
  jobs="$(printf '%s' "$jobs" | sed '/^$/d' | sort -u)"
  listed="$(sed -e '/^#/d' -e '/^$/d' .github/required-checks.txt 2>/dev/null | sort -u)"
  [ -n "$listed" ] && [ -n "$jobs" ] || return 0
  [ "$jobs" != "$listed" ]
}

# Disarm steps: whole-line if: assertions, and the body is run by job id and exact step name.
job_if() { awk -v job="  $1:" '$0 == job { injob=1; next } injob && /^  [a-zA-Z0-9_-]+:/ { exit } injob && /^    if: / { sub(/^    if: /, ""); print; exit }' "$WF"; }
probe_a_refusal_does_not_disarm() {
  [ "$(step_if $J "$DISARM")" != "always() && steps.arm.outcome != 'success'" ] && return 0
  local l; l="$(mktemp)"; FK_ARMED=1 FK_LOG="$l" run_step $J "$DISARM" >/dev/null
  ! grep -q -- '--disable-auto' "$l"; local r=$?; rm -f "$l"; return $r; }
probe_a_foreign_push_does_not_disarm() {
  [ "$(job_if $FJ)" != "github.actor != 'dependabot[bot]' && startsWith(github.head_ref, 'dependabot/')" ] && return 0
  local l; l="$(mktemp)"; FK_ARMED=1 FK_LOG="$l" run_step $FJ "$FDISARM" >/dev/null
  ! grep -q -- '--disable-auto' "$l"; local r=$?; rm -f "$l"; return $r; }

echo "the Dependabot auto-merge probes  (WEAK = condition not yet enforced)"
echo
probe probe_major_update_is_not_refused                    "1 a semver-major update passes the gate"          probe_major_update_is_not_refused
probe probe_patch_update_is_wrongly_refused                 "1 a semver-patch update is wrongly refused"       probe_patch_update_is_wrongly_refused
probe probe_cooldown_missing_or_short_in_dependabot_yml     "2 cooldown missing or under 7 days somewhere"     probe_cooldown_missing_or_short_in_dependabot_yml
probe probe_trigger_is_pull_request_target                  "6 pull_request_target is used"                    probe_trigger_is_pull_request_target
probe probe_workflow_checks_out_the_pr_head                 "6 the workflow checks out the PR head"            probe_workflow_checks_out_the_pr_head
probe probe_permissions_are_not_exactly_the_two              "6 permissions are not exactly contents+PR write"  probe_permissions_are_not_exactly_the_two

probe probe_a_rerun_by_a_person_can_arm                 "DM2-01 a person's re-run arms"                    probe_a_rerun_by_a_person_can_arm
probe probe_a_moved_head_can_arm                        "DM2-01 a head moved after the event arms"         probe_a_moved_head_can_arm
probe probe_a_fork_pr_is_not_refused                    "DM2-01 a fork head repo is not refused"           probe_a_fork_pr_is_not_refused
probe probe_a_genuine_dependabot_run_is_wrongly_refused "DM2-01 good case refused"                         probe_a_genuine_dependabot_run_is_wrongly_refused
probe probe_arm_is_not_bound_to_the_event_head          "DM2-01 arm without --match-head-commit"           probe_arm_is_not_bound_to_the_event_head
probe probe_two_runs_on_one_pr_are_not_serialised       "DM2-01 no per-PR concurrency group"               probe_two_runs_on_one_pr_are_not_serialised
probe probe_an_api_error_in_the_path_gate_leaves_it_armed   "DM2-02 API error: no STOP, no disarm"         probe_an_api_error_in_the_path_gate_leaves_it_armed
probe probe_an_api_error_in_the_commit_gate_leaves_it_armed "DM2-02 API error: no STOP, no disarm"         probe_an_api_error_in_the_commit_gate_leaves_it_armed
probe probe_the_disarm_step_skips_when_a_step_errored   "DM2-02 disarm only on STOP=1"                     probe_the_disarm_step_skips_when_a_step_errored
probe probe_a_failed_disarm_is_green                    "DM2-02 failed disarm exits 0"                     probe_a_failed_disarm_is_green
probe probe_a_failed_foreign_push_disarm_is_green       "DM2-02 failed foreign-push disarm exits 0"        probe_a_failed_foreign_push_disarm_is_green
probe probe_a_disarm_with_nothing_armed_goes_red        "DM2-02 good case red"                             probe_a_disarm_with_nothing_armed_goes_red
probe probe_a_ci_job_without_a_name_is_not_checked      "DM2-03 nameless job invisible"                    probe_a_ci_job_without_a_name_is_not_checked
probe probe_a_job_only_on_the_base_ci_is_not_checked    "DM2-03 base ci.yml never read"                    probe_a_job_only_on_the_base_ci_is_not_checked
probe probe_a_second_pr_workflow_escapes_the_drift_probe "DM2-03 drift probe reads ci.yml only"            probe_a_second_pr_workflow_escapes_the_drift_probe
probe probe_an_app_pinned_setup_is_wrongly_refused      "DM2-03/05 good case refused"                      probe_an_app_pinned_setup_is_wrongly_refused
probe probe_a_rename_into_a_pom_passes                  "DM2-04 rename into pom.xml passes"                probe_a_rename_into_a_pom_passes
probe probe_a_truncated_file_list_passes                "DM2-04 file count never compared"                 probe_a_truncated_file_list_passes
probe probe_a_pom_only_pr_is_wrongly_refused            "DM2-04 good case refused"                         probe_a_pom_only_pr_is_wrongly_refused
probe probe_a_name_only_required_check_passes           "DM2-05 context without integration_id passes"     probe_a_name_only_required_check_passes
probe probe_auto_merge_off_still_proceeds               "DM2-06 setting off does not stop the run"         probe_auto_merge_off_still_proceeds
probe probe_auto_merge_on_is_wrongly_refused            "DM2-06 good case refused"                         probe_auto_merge_on_is_wrongly_refused
probe probe_shipped_probes_survive_mutations            "DM2-07 shipped probes survive mutations"          probe_shipped_probes_survive_mutations

probe probe_a_foreign_path_passes_the_manifest_gate           "4 a non-manifest path passes the gate"            probe_a_foreign_path_passes_the_manifest_gate
probe probe_manifest_only_pr_is_wrongly_refused              "4 a manifest-only PR is wrongly refused"          probe_manifest_only_pr_is_wrongly_refused
probe probe_a_github_path_passes_the_manifest_gate           "4 a .github path passes the manifest gate"        probe_a_github_path_passes_the_manifest_gate
probe probe_a_non_dependabot_head_commit_passes              "5 a human-authored head commit passes"            probe_a_non_dependabot_head_commit_passes
probe probe_an_unverified_dependabot_commit_passes           "5 an unverified signature passes"                 probe_an_unverified_dependabot_commit_passes
probe probe_a_verified_dependabot_commit_is_wrongly_refused  "5 a verified Dependabot commit is wrongly refused" probe_a_verified_dependabot_commit_is_wrongly_refused
probe probe_an_ordinary_green_setup_is_wrongly_refused        "7 a consistent setup is wrongly refused"          probe_an_ordinary_green_setup_is_wrongly_refused
probe probe_a_ci_job_that_is_not_a_required_check_passes      "7 a CI job that is not required passes"           probe_a_ci_job_that_is_not_a_required_check_passes
probe probe_a_ci_job_missing_from_the_list_passes             "7 a CI job missing from the list passes"          probe_a_ci_job_missing_from_the_list_passes
probe probe_a_rules_api_error_passes                          "7 an API error passes"                            probe_a_rules_api_error_passes
probe probe_a_branch_with_no_required_checks_passes           "7 a branch with no required checks passes"        probe_a_branch_with_no_required_checks_passes
probe probe_required_checks_txt_drifted_from_ci_yml           "7 required-checks.txt differs from PR workflows"  probe_required_checks_txt_drifted_from_ci_yml
probe probe_a_refusal_does_not_disarm                         "7 a refusal leaves auto-merge armed"              probe_a_refusal_does_not_disarm
probe probe_a_foreign_push_does_not_disarm                    "5 a non-Dependabot push leaves it armed"          probe_a_foreign_push_does_not_disarm

echo
echo "still weak: $pass    fixed: $flipped"
[ "$pass" -eq 0 ]
