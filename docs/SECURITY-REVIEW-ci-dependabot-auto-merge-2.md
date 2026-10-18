# Security review - branch `ci/dependabot-auto-merge-2` (PR #44)

## 2026-10-15 - first pass, head `014cc54`

Scope: the Dependabot auto-merge workflow, its two new pieces (condition 7, the gate-list
check; the strict pom-only path rule), the new job that disarms after a non-Dependabot push,
and the probe suite `tools/cipher-probe-dependabot.sh`. No production code changes.

**Verdict: MERGE WITH FIXES.** No HIGH. 1 MEDIUM, 5 LOW, 1 INFO (DM2-01 .. DM2-07). Every
one is fixed before merge.

Read this first. The branch builds the seven-condition rule as written, plus a disarm job.
It does not build the arming-guard design approved at the 2026-09-21 design review (round 2,
"approved with changes"). Five of the seven findings below are controls that design already
had: run provenance and the live head (DM2-01), fail-closed disarm (DM2-02), the
`changed_files` count (DM2-04), the app pin (DM2-05), and the `--auto` direct-merge path
(DM2-06). Each one is reproduced here on this head; none is listed on the design's word.

### Numbers

| What | Result |
|---|---|
| CI on head `014cc54` (Build & test, DCO, Reference guard, Vulnerability scan, Security probes) | all 5 pass |
| Build & test, core module | 98 run, 0 failures, 0 errors, 1 skipped (`CipherProbeFinalSpringAiTest`, one method; not touched by this branch) |
| Release-pipeline probe suite (CI) | 74 fixed, 0 weak |
| Shipped Dependabot probe suite, re-run here unchanged | 20 fixed, 0 weak |
| Mutations run against the shipped suite | 8 run, 5 killed, 3 survive (DM2-07) |
| Probes of this pass, on this head | 23 probes: 20 weak (the defects), 3 good-case probes pass |
| Live repository reads (read-only) | ruleset 22670337: 5 required contexts, none with `integration_id`; `allow_auto_merge: false` |

### What holds

Verified, not read:

- The trigger is `pull_request`; there is no `pull_request_target` and no checkout. Every
  value from the event reaches a shell through `env:` and is quoted. No step builds a shell
  command from a pull request string.
- `dependabot/fetch-metadata` is pinned to `25dd0e34f4fe68f24cc83900b1fe3fe149efef98`. The
  tag `v3.1.0` resolves to that commit today.
- Permissions are exactly `contents: write` and `pull-requests: write`. That is what
  `enablePullRequestAutoMerge` and the direct merge need.
- A major or unknown update type is refused. A `.github/` path, a `tools/` path and a source
  path are each refused. A human-authored or unverified head commit is refused.
- `required-checks.txt` is read from the base branch, never from the pull request. A stale
  list cannot open the gate: a name that the ruleset spells differently, or a job renamed in
  `ci.yml`, makes the two sets differ and the step refuses. An API error refuses.
- Both ecosystems in `dependabot.yml` keep a 7-day cooldown.
- "Allow auto-merge" off: while CI is still running on the pull request, `gh pr merge --auto`
  fails and the job goes red. That part is loud. But see DM2-06: once the pull request is
  already mergeable, `gh` does not arm anything, it merges at once, and the setting is not
  consulted.

### Findings

**DM2-01 - MEDIUM - arming is not bound to the head the run was raised for.**
Reopens B-DM-03 from the first review of this mechanism.
Repro (steps run against a fake `gh`, plus the documented re-run rules):
1. Dependabot opens the pull request at commit A. The run arms auto-merge.
2. A person pushes commit B onto the Dependabot branch. Any pom-only change passes the
   path gate (a new plugin repository, a different artifact). The disarm job disarms.
3. The person clicks "Re-run jobs" on the run from step 1. A re-run keeps `github.actor`
   as `dependabot[bot]` and keeps the old event payload, so `HEAD_SHA` is still A.
   `fetch-metadata` checks the first commit of the pull request only, so it passes. The
   commit gate checks A, so it passes. The path gate reads the live file list (pom only), so
   it passes.
4. `gh pr merge --auto --merge "$PR_URL"` carries no head sha. It acts on the live head B.
   With CI green on B, `gh` merges B at once (see DM2-06).
The same result comes without a re-run when the disarm job (one step) finishes before the
slower arming job, because nothing serialises the two runs.
The commit fields cannot fix this on their own: a commit made through the contents API with
a Dependabot author has the same `author.login`, `committer.login = web-flow` and
`verified: true` as a real Dependabot commit. Provenance has to come from the run.
Fix (Dependabot auto-merge workflow):
- New first step, before `fetch-metadata`, named exactly `Refuse a re-run, a fork or a moved
  head`, same `refuse()` pattern as the condition 7 step. Env: `ACTOR: ${{ github.actor }}`,
  `TRIGGERING_ACTOR: ${{ github.triggering_actor }}`,
  `PR_AUTHOR: ${{ github.event.pull_request.user.login }}`,
  `HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}`,
  `HEAD_REF: ${{ github.head_ref }}`, `REPO`, `PR_NUMBER`, `HEAD_SHA`. Refuse unless
  `ACTOR`, `TRIGGERING_ACTOR` and `PR_AUTHOR` are all `dependabot[bot]`, `HEAD_REPO` equals
  `REPO`, `HEAD_REF` starts with `dependabot/`, and the live
  `gh api "repos/${REPO}/pulls/${PR_NUMBER}" --jq .head.sha` equals `HEAD_SHA` (an API error
  refuses). Every later step, `fetch-metadata` included, keeps `if: env.STOP != '1'`.
- Arm step: `gh pr merge --auto --merge --match-head-commit "$HEAD_SHA" "$PR_URL"`.
- Workflow level: `concurrency: { group: dependabot-auto-merge-${{ github.event.pull_request.number }}, cancel-in-progress: true }`.
- Header: a person can no longer re-run this job successfully. Recovery is
  `@dependabot rebase` or a merge by hand.
Probes: `probe_a_rerun_by_a_person_can_arm`, `probe_a_moved_head_can_arm`,
`probe_a_fork_pr_is_not_refused`, `probe_arm_is_not_bound_to_the_event_head`,
`probe_two_runs_on_one_pr_are_not_serialised`; good case
`probe_a_genuine_dependabot_run_is_wrongly_refused`.

**DM2-02 - LOW - a run that cannot decide leaves auto-merge armed, and a failed disarm is green.**
Reopens G-06 of the design review.
Repro: (a) the path gate and the commit gate run under `set -e`. With the API failing
(fake `gh` exits 1), each step exits 1 and writes no `STOP=1`. The disarm step runs only on
`always() && env.STOP == '1'`, so it is skipped, and an auto-merge armed by an earlier run
stays armed. The same holds when `fetch-metadata` fails or when the arm call itself fails.
(b) Both disarm bodies end in `|| true`. With auto-merge armed and the disarm call failing,
each body exits 0: the job is green and the pull request is still armed.
Fix:
- Give the arm step `id: arm`. Disarm step `if: always() && steps.arm.outcome != 'success'`.
- Path gate and commit gate: every `gh` call ends in `|| refuse "<what failed>"`, like the
  condition 7 step. No step relies on `set -e` to reach a refusal.
- Both disarm bodies (the refusal step and the `disarm-on-foreign-push` job) become:
  read `gh pr view "$PR_URL" --json autoMergeRequest --jq '.autoMergeRequest != null'`
  (error: `::error::`, exit 1). If `true`, run `gh pr merge --disable-auto "$PR_URL"`
  (error: exit 1), read again, and exit 1 with `::error::` if still armed. `false` before
  the call is "nothing armed" and exits 0. No `|| true`.
Probes: `probe_an_api_error_in_the_path_gate_leaves_it_armed`,
`probe_an_api_error_in_the_commit_gate_leaves_it_armed`,
`probe_the_disarm_step_skips_when_a_step_errored` (structural: the `if:` line must be exactly
the one above), `probe_a_failed_disarm_is_green`, `probe_a_failed_foreign_push_disarm_is_green`;
good case `probe_a_disarm_with_nothing_armed_goes_red`.

**DM2-03 - LOW - condition 7 does not see every gate job.**
Repro: the step finds jobs with `sed -n 's/^    name: //p'`.
(a) A job with no `name:` has the job id as its check name. It is invisible: a `ci.yml` with
an extra unnamed job, not listed and not required, arms.
(b) `ci.yml` is read at the head sha only. The checks of a pull request run from the merge
ref, which carries the base branch's `ci.yml`. A job that exists on `main` but not on an
older Dependabot head is never compared: a new, unrequired gate job on `main` arms.
(c) The shipped drift probe reads `ci.yml` only. A second workflow with a `pull_request`
trigger and a gate job escapes it (mutation: add one, the probe stays FIXED).
Fix: in the condition 7 step, read `ci.yml` at `?ref=${BASE_REF}` and at `?ref=${HEAD_SHA}`,
list jobs in each with `yq -r '.jobs | to_entries | .[] | (.value.name // .key)'` (yq is on
the GitHub ubuntu runner), take the union, refuse on any yq error and on any name containing
`${{`. In `tools/cipher-probe-dependabot.sh`, the drift probe uses the same yq expression
over every `.github/workflows/*.yml` whose `on:` includes `pull_request`, except
`dependabot-auto-merge.yml`.
Probes: `probe_a_ci_job_without_a_name_is_not_checked`,
`probe_a_job_only_on_the_base_ci_is_not_checked`,
`probe_a_second_pr_workflow_escapes_the_drift_probe`; good case
`probe_an_app_pinned_setup_is_wrongly_refused`.

**DM2-04 - LOW - the path gate reads only the new file name, and never checks the count.**
Repro: the gate takes `.[].filename`. A rename from `.github/workflows/ci.yml` to
`x/pom.xml` reports `filename: x/pom.xml` and passes; the deleted path is in
`previous_filename`, which is never read. The file list API also stops at 3000 files, and
the gate never compares its list with the pull request's `changed_files`.
Fix: `--jq '.[] | [.status, .filename, (.previous_filename // "")] | @tsv'`. Refuse unless
every entry has status `modified`, an empty previous name, and a `pom.xml` or `*/pom.xml`
name. Read `changed_files` from the live pull request read (the same call as DM2-01) and
refuse unless it equals the number of entries and is at most 50.
Probes: `probe_a_rename_into_a_pom_passes`, `probe_a_truncated_file_list_passes`; good case
`probe_a_pom_only_pr_is_wrongly_refused`.

**DM2-05 - LOW - the required checks are name-only, and condition 7 accepts that.**
Reopens G-07 of the design review.
Repro: live rules API on `main`: the five contexts carry no `integration_id`. A required
context without one is satisfied by a commit status from any source, so a token with
`statuses: write` can post `Build & test` (and the four others) as green on any commit.
Chain on this branch: a person pushes onto an armed Dependabot branch with `[skip ci]` in
the commit message. No `pull_request` workflow runs, so neither CI nor the disarm job runs,
and auto-merge stays armed. Five hand-posted statuses then complete the merge. Condition 7
passes this ruleset (step run on the live rules shape: it arms).
Fix: condition 7 counts a context as required only if its rule entry has
`integration_id == 15368` (GitHub Actions):
`.parameters.required_status_checks[] | select(.integration_id == 15368) | .context`.
A listed context that is name-only is then "not a required check" and refuses. The
maintainer pins the five contexts to GitHub Actions in ruleset 22670337. Until then nothing
arms: that is the secure default, not a defect. The shipped good-case fixture gains the
`integration_id`.
Probe: `probe_a_name_only_required_check_passes`.

**DM2-06 - LOW - "Allow auto-merge" is not an off switch, and the CHANGELOG says it is.**
Repro: `gh` 2.102.0, `pkg/cmd/pr/merge/merge.go`:
`autoMerge: opts.AutoMergeEnable && !isImmediatelyMergeable(pr.MergeStateStatus)`, true for
`CLEAN`, `HAS_HOOKS` and `UNSTABLE`. In those states `--auto` calls `mergePullRequest`
directly, which does not consult the repository setting. So with the setting off (as today)
a run that finds the pull request already green merges it (the DM2-01 re-run is one such
run). The CHANGELOG line "Needs the repository setting 'Allow auto-merge' to be on" is
therefore not true, and the header "every refusal is a notice and exit 0" does not cover the
red arm failure.
Fix: new step, after the DM2-01 step, named exactly `Refuse while the repository does not
allow auto-merge`: `v="$(gh api "repos/${REPO}" --jq .allow_auto_merge)" || refuse ...`;
refuse with a notice naming the setting unless `v` is `true`. The setting is then the real
switch. Header: state that `--auto` merges at once when the pull request is already
mergeable and arms otherwise, both with `--match-head-commit`, and that an unexpected arm
error is red on purpose. CHANGELOG: "The repository setting 'Allow auto-merge' is the on/off
switch; while it is off, the workflow refuses with a notice."
Probes: `probe_auto_merge_off_still_proceeds`; good case `probe_auto_merge_on_is_wrongly_refused`.

**DM2-07 - INFO - three mutations survive the shipped probes.**
Repro (each in a temporary copy of the tree, shipped suite run unchanged):
- `disarm-on-foreign-push` job `if:` prefixed with `false &&`: `probe_a_foreign_push_does_not_disarm` stays FIXED.
- that job's run body replaced with `true`: same probe stays FIXED. `step_body 'Disarm'`
  matches the first step whose name starts with `Disarm`, which is the refusal step of the
  other job.
- refusal disarm `if:` suffixed with `&& false`: `probe_a_refusal_does_not_disarm` stays
  FIXED (substring grep).
Fix in `tools/cipher-probe-dependabot.sh`: `step_body` takes a job id and matches the step
name exactly; structural `if:` assertions compare the whole line; add
`probe_shipped_probes_survive_mutations` (the three mutations above) to the suite.

### Probe file

The probes of this pass (23, named above) run from the repository root against a fake `gh`
that applies the real `--jq` expression with real jq. They extract step bodies by job and
exact step name; a prescribed step that does not exist reads WEAK. The fix pass copies them
into `tools/cipher-probe-dependabot.sh` before it touches the workflow, and shows each one
RED, then GREEN, in the pull request body. The DM2-03 good case needs `yq` locally.

### Tried and not reproduced

- A required gate job that is skipped counts as green (design G-03). Not reachable on this
  tree: the only gate job with an `if:` is `DCO sign-off`, and its condition is true on every
  pull request; a Dependabot pull request cannot change `ci.yml`. Whoever adds an `if:` to a
  gate job reopens this.
- Base retarget of an armed pull request (design G-02): needs a live armed pull request; not
  attempted on the public repository.
- A fork pull request updated by the fork's own Dependabot gets `github.actor ==
  dependabot[bot]` and passes every step body on this head; it is stopped only by the
  read-only token GitHub gives fork runs. Folded into DM2-01's `HEAD_REPO` check.
- The write token on a Dependabot-triggered `pull_request` run is documented, never
  observed here. The first live run must show the arm call succeed with the default token.

### Fix order

DM2-01 and DM2-06 (new steps, step order: provenance, setting, `fetch-metadata`, the four
conditions, arm, disarm), then DM2-02, DM2-04, DM2-03, DM2-05, DM2-07. Maintainer, after
merge: pin the five contexts to GitHub Actions, then turn "Allow auto-merge" on.

## 2026-10-15 - second pass, head `ff1bd6d`

Scope: the fix commits `5fdaa7a` (probes first) and `ff1bd6d` (workflow, CHANGELOG,
`required-checks.txt`), plus two new angles: the `allow_auto_merge` read through the
default token, and the concurrency group.

**Verdict: MERGE.** DM2-01 to DM2-07 are closed. Each one was closed by its probe turning
green on this head and by a mutation of its control turning it red again. The two new angles
gave no finding.

### Numbers

| What | Result |
|---|---|
| CI on `ff1bd6d` | all 5 gates pass |
| Build & test | 206 + 98 + 3 run, 0 failures; 1 skipped (`CipherProbeFinalSpringAiTest`, as on main) |
| Release-pipeline probe suite (CI) | 74 fixed, 0 weak |
| Dependabot probe suite (CI and here, yq v4.47.1, checksum checked) | 43 fixed, 0 weak |
| The 23 probes of pass 1, re-run here | 23 fixed, 0 weak |
| Mutations of the new controls | 15 run; 13 caught by the probe named for them; 2 caught by the next layer (below) |

### Closure, finding by finding

| Id | Probe green on `ff1bd6d` | Mutation that turns it red |
|---|---|---|
| DM2-01 | `probe_a_rerun_by_a_person_can_arm`, `probe_a_moved_head_can_arm`, `probe_a_fork_pr_is_not_refused`, `probe_arm_is_not_bound_to_the_event_head`, `probe_two_runs_on_one_pr_are_not_serialised`, good case | triggering-actor check removed; live-head check removed; `--match-head-commit` removed; `concurrency:` removed |
| DM2-02 | `probe_an_api_error_in_the_*_gate_leaves_it_armed`, `probe_the_disarm_step_skips_when_a_step_errored`, `probe_a_failed_disarm_is_green`, `probe_a_failed_foreign_push_disarm_is_green`, good case | disarm `if:` back to `env.STOP == '1'` |
| DM2-03 | `probe_a_ci_job_without_a_name_is_not_checked`, `probe_a_job_only_on_the_base_ci_is_not_checked`, `probe_a_second_pr_workflow_escapes_the_drift_probe`, good case | union reduced to the head `ci.yml` |
| DM2-04 | `probe_a_rename_into_a_pom_passes`, `probe_a_truncated_file_list_passes`, good case | status and previous-name checks removed; count and cap checks removed |
| DM2-05 | `probe_a_name_only_required_check_passes` | `select(.integration_id == 15368)` removed |
| DM2-06 | `probe_auto_merge_off_still_proceeds`, good case | setting check removed |
| DM2-07 | `probe_shipped_probes_survive_mutations` (shipped) | foreign-push job `if:` prefixed `false &&`; its whole body replaced with `true`; refusal disarm `if:` suffixed `&& false` |

Two mutations did not turn the probe named for them red, and that is correct.
(1) Removing the `--disable-auto` call from the foreign-push disarm: the re-read finds it
still armed and the step goes red; `probe_a_foreign_push_does_not_disarm` catches it.
(2) Making the disarm call `|| true`: the same re-read goes red. In both cases the
behaviour stays correct, because the second check catches what the first one lost.

### New angle (a): `allow_auto_merge` through the default token

The REST reference for "Get a repository" says: "To view merge-related settings, you must
have the contents:read and contents:write permissions." This workflow's token has
`contents: write`, so the field is returned. If GitHub ever omits it, `jq` prints `null`,
and the step refuses with a notice (run here with a fake `gh` that prints `null`: `STOP=1`
written). Either way it fails safe. Not observed with the real token yet: the first live
Dependabot run must show the notice while the setting is off (it is off today).

### New angle (b): can a cancelled run leave auto-merge armed?

The group is per pull request with `cancel-in-progress: true`, so the newer event always
wins, and that newer run decides again from scratch:
- A person pushes twice. The second disarm run cancels the first, then disarms.
- A Dependabot run is cancelled after arming by a person's push. The disarm run that
  cancelled it disarms. A Dependabot run cancelled before arming has armed nothing. Its
  refusal disarm step runs on cancel anyway, because `always()` runs on cancellation.
- A person re-runs an old Dependabot run, and that cancels a disarm run. The re-run is
  refused by the provenance step (`triggering_actor`), and its disarm step disarms.
- A newer Dependabot push cancels a disarm run. Dependabot pushes replace the branch, so
  the person's commit is gone, and the newer run checks the new head on its own merits.
The one way to leave a person's commit armed is for a person with write access to cancel
the disarm run by hand (`gh run cancel`). The approved design names this as accepted:
against a write collaborator the disarm is defence in depth, and the control is the
ruleset on the new head (required checks pinned to GitHub Actions; DM2-05). Not a finding.

### Before auto-merge can do anything (maintainer, after merge)

1. Pin the five required checks of ruleset 22670337 to GitHub Actions. Until then every
   Dependabot run refuses at condition 7.
2. Then turn "Allow auto-merge" on. Until then every run refuses with a notice.
