# Security review - `ci/dependabot-auto-merge`

## Pass 1, 2026-09-21 - head `69d26bd` (stacked on `ci/keyless-cve-gate`)

One mechanism review. The contract is the seven-condition rule approved on 2026-09-21; the
branch was attacked as a hostile Dependabot-shaped pull request and as a hostile
collaborator. The sibling module's copy (head `ad8094f`) was diffed against this one: the
workflow and `dependabot.yml` are byte-identical, and the probe script differs only in the
repository slug and one module name in a fixture. Everything below applies to both.

**Verdict: NOT MERGEABLE** - one HIGH (1 HIGH, 3 MEDIUM, 1 LOW, 3 INFO).

Probe script: `cipher-probe-dependabot-automerge-round1.sh` in this module's internal
probes folder. All five of its probes read WEAK on this head, on both repositories.

### What holds

Verified, not read: the trigger is `pull_request` and there is no `pull_request_target`
anywhere; there is no checkout of any ref; permissions are exactly `contents: write` and
`pull-requests: write`; `dependabot/fetch-metadata` is pinned to
`25dd0e34f4fe68f24cc83900b1fe3fe149efef98`, which is the commit tag `v3.1.0` resolves to
today and the newest release; a `version-update:semver-major` is refused and a patch is not;
an unknown or empty update type is refused (fail closed); a pull request that touches a path
outside the manifest allowlist is refused, including the "bumps a pom and adds a file under
`tools/`" shape; a head commit whose author is not `dependabot[bot]`, or whose signature is
not verified, is refused; both ecosystems in `dependabot.yml` carry a 7-day cooldown. A pull
request from a fork cannot reach the merge step: `pull_request` hands a read-only token to
fork runs whatever the `permissions:` block says, and `github.actor` cannot be made to read
`dependabot[bot]` by a forker. Seven of the eleven shipped probes run the real step bodies
against synthetic inputs; the other four are structural assertions about the workflow file
(trigger, checkout, permissions, cooldown), which is the only way those can be asserted.

`gh pr merge --auto --merge` with the default token does **not** bypass the ruleset: native
auto-merge waits for the checks the ruleset requires. That is exactly why the first finding
is HIGH.

### Findings

**B-DM-01 - HIGH - auto-merge can complete with the CVE gate red.**
Repro: `gh api repos/<owner>/<repo>/rulesets` shows main requires `Build & test`,
`DCO sign-off` and `Cipher probes` (and `Reference guard` on the sibling module).
`Vulnerability scan` is not required, and on the sibling module `Release dry run` is not
either. Native auto-merge waits only for required checks, so a Dependabot bump that pulls in
a HIGH or CRITICAL advisory arms auto-merge, the vulnerability job goes red, and the pull
request merges anyway with nobody reading it. Condition 3 of the contract is not met, and
the mechanism is precisely the one that removes the human who would have noticed. Probe
`probe_required_checks_omit_a_ci_gate_job`.
This is a **DESIGN STOP**. The property that must hold: *auto-merge is never armed unless
every gate job defined in the repository's CI workflows is, at that moment, a required
status check on the target branch*. Paths it must cover: the arming step, a new pull request,
a re-run, and a ruleset changed after arming. Do not prescribe the mechanism in a fix list;
the builder writes a one-page design and it is reviewed before any code. Adding the contexts
to the ruleset by hand is necessary but is not the fix: nothing then stops them being
removed again.

**B-DM-02 - MEDIUM - condition 5 is bypassed by a committer-spoofed head commit.**
Repro: the step accepts on `.author.login == "dependabot[bot]"` and
`.commit.verification.verified == true`. GitHub resolves a commit's *author* from the
author email, which the creator chooses freely, and a commit created through the repository
contents API is signed with GitHub's web-flow key, so `verified` is `true`. A collaborator
can push onto a Dependabot branch a commit that reads as authored by `dependabot[bot]` and
verified, while the committer is the collaborator. Probe
`probe_a_committer_spoofed_head_commit_passes` runs the real step body against exactly that
shape and it does not stop.
Fix: in the step "Refuse an unverified or non-Dependabot head commit", also require
`.committer.login == "dependabot[bot]"` and `.commit.verification.reason == "valid"`, and
refuse when either is absent. Probe must flip on
`probe_a_committer_spoofed_head_commit_passes`.

**B-DM-03 - MEDIUM - condition 5 validates a head the checks never ran on.**
Repro: `HEAD_SHA` comes from `github.event.pull_request.head.sha`, frozen in the event
payload. `github.actor` keeps its original value on a re-run, so a collaborator who pushes
onto the branch (the `synchronize` run is skipped by the actor gate, see B-DM-04) and then
re-runs the original `opened` run gets condition 4 re-evaluated against the live file list
but condition 5 re-evaluated against the stale Dependabot commit, after which the arming
step arms auto-merge on the live head. Probe
`probe_condition_five_validates_a_stale_head`.
Fix: read the head sha from the live API in the same step
(`gh api repos/$REPO/pulls/$PR_NUMBER --jq .head.sha`) and validate that, never the payload
value; do the same for the arming step's target.

**B-DM-04 - MEDIUM - a refusal never disarms an auto-merge that is already armed.**
Repro: condition 5 of the contract says "a human push onto a Dependabot branch disables
auto-merge". Nothing disables anything. The job-level `if: github.actor ==
'dependabot[bot]'` makes the whole job *skip* on the `synchronize` event a human push
raises, and no refusal path anywhere calls `gh pr merge --disable-auto`. With
`required_approving_review_count: 0` and `require_last_push_approval: false` on main, the
auto-merge armed at `opened` stays armed and completes on its own. Probe
`probe_a_refusal_never_disarms_an_armed_auto_merge`.
Fix: this is the same mechanism as B-DM-01 and goes to the builder with it, not to a fix
pass. The property: *every refusal path, and every event on a Dependabot branch whose actor
is not `dependabot[bot]`, actively disarms auto-merge*. That means the job must run on those
events rather than being skipped by the actor gate, with the actor check moved into a step
that disarms rather than a job-level `if` that skips.

**B-DM-05 - LOW - a failed arming turns every Dependabot pull request red, today.**
Repro: `allow_auto_merge` is `false` on both repositories right now. `gh pr merge --auto`
errors when the repository does not allow auto-merge, and the arming step runs under
`set -euo pipefail`, so the job fails. The workflow's own header states "every refusal is a
`::notice::` and exit 0". Probe `probe_a_failing_arm_turns_every_dependabot_pr_red` runs the
real step body with a failing `gh` and the step exits non-zero.
**What happens the day `allow_auto_merge` is switched on**: nothing else changes. Every
condition above is evaluated the same way; the arming call starts succeeding, and from that
moment B-DM-01 is live - a Dependabot pull request merges itself on three green checks with
the CVE gate not among them. Do not switch the flag on before B-DM-01 is closed.
Fix: handle a failing arm explicitly - emit a `::notice::` naming `allow_auto_merge` and
exit 0 - so the red is not mistaken for a scan failure and nobody learns to ignore it.

**B-DM-06 - INFO - two contract conditions have no probe.**
Condition 7 names "non-Dependabot actor refused" and "red check never merges" as probes that
must exist. Neither does: the job-level actor gate is asserted by nothing, and nothing
asserts anything about required checks. Eleven probes cover conditions 1, 2, 4, 5 and 6.
Fix: fold into the B-DM-01 and B-DM-04 designs; both conditions become testable once the
mechanism owns them instead of delegating to a job-level `if` and to GitHub.

**B-DM-07 - INFO - the cooldown premise does not hold for security updates.**
Dependabot's cooldown applies to version updates; security updates are opened without
waiting for it. Condition 1 lets a patch or minor security update auto-merge, so for exactly
the class of update most likely to be rushed or poisoned upstream, condition 2 protects
nothing. This is a decision to record, not necessarily to change - stating it in the
workflow header is the minimum.

**B-DM-08 - INFO - an auto-merged pull request may rewrite the gate that let it in.**
`.github/workflows/*.yml` is in the manifest allowlist, by contract, because the
github-actions ecosystem edits workflows. It follows that an auto-merged action bump can
modify `ci.yml` and `dependabot-auto-merge.yml` themselves. Accepted residual; write it in
the workflow header so the next reader does not have to rediscover it.

### The sibling module's copy

Head `ad8094f`. `dependabot-auto-merge.yml` and `.github/dependabot.yml` are byte-identical
to this branch. `tools/cipher-probe-dependabot.sh` differs in five lines: the repository slug
in five fixtures and one module name in a file-list fixture. Both probe suites run 11 probes,
0 weak. Every finding above applies unchanged, with the ids read as `C-DM-*`; B-DM-01 is
worse there, because two gate jobs are missing from the ruleset rather than one.
