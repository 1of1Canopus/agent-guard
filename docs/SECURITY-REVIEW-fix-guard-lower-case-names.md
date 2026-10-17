# Security review: the document names in the reference guard become case-insensitive (PR 50)

## 2026-10-17, pass 1

**Verdict: MERGE WITH FIXES.** No HIGH, no MEDIUM. One LOW and two INFO findings, all fixed
before merge (no-allowance rule). This PR merges second, after PR 49 (file names); B-NG-27 can
only be closed on the branch that carries both.

Reviewed tree: `c45c4aa` (`fix/guard-lower-case-names`, PR 50 head), probe commit `006e415`.
Scope: the `pattern=` line of `tools/check-private-references.sh`, its header paragraph, the new
self-test cases, the new suite probe, and the edited definition-count probe. The two sibling
repositories carry the same change; they get the verifier's numbers and a diff only.

Method: as in the PR 49 review. Every attack ran against the real script, on BSD grep 2.6.0
(macOS) and GNU grep 3.11 (Debian container). The combined state was built for the review by
applying this PR's pattern line and self-test rows onto the PR 49 script, in a scratch folder
(no branch, no merge commit).

### Numbers

| Check | Result |
|---|---|
| CI on `c45c4aa` (run 39030588819) | all five checks green; Build & test ran this PR's `--jars` on this PR's own build: every built jar clean |
| `--self-test`, BSD and GNU, this PR alone | exit 0, 73 OK |
| `--self-test`, BSD and GNU, combined with PR 49 | exit 0, 115 OK (after the `red` rows become `red:content`, see decision 2) |
| `--tree` on `c45c4aa` | tree clean |
| Suite probe on `006e415` / on `c45c4aa` | B-NG-12 probe WEAK / FIXED; fixed 75 to 76 |
| Builder mutations L1 to L10, rerun | 10 of 10 red, each by the case named in the PR body |
| Reviewer mutations | 8 run (each document name rewritten to match lower case only); 5 survive (B-NG-26) |
| `--tree`, combined guard, on the three `main` trees (agent-guard `b1a090b`, gdpr-shredding `801d651`, stripe-einvoice `65d74a2`) | clean on all three |
| `--jars` on the 12 published jars (core and starter, main and sources, of the three modules) | the same 4 hits with `main`, PR 49, PR 50 and the combined guard (old hits in the published gdpr-shredding 0.2.0 sources jar, the unqualified JDK class; fixed in source since) |
| New probes this pass | 4, all WEAK on `c45c4aa` (internal probe file `cipher-probe-guard-lower-case-names-pr50.sh`) |

### Findings

| Id | Severity | Class | Probe | Fix in |
|---|---|---|---|---|
| B-NG-25 | LOW | boundary validation | `probe_lower_case_review_or_release_file_name_passes` | this PR |
| B-NG-26 | INFO | false completion | `probe_self_test_misses_an_upper_case_regression` | this PR |
| B-NG-27 | INFO | false completion | `probe_lower_case_private_file_name_passes`, `probe_slug_rescan_has_no_killing_case` | this PR, after `main` (with PR 49) is merged in |

#### B-NG-25 (LOW): the file-name forms of the review word and the release word pass in lower case

The builder kept the bare review word and the bare release word upper case only. The reason is
right: in lower case both are plain English. Measured again on today's `main` trees: 8 lines
(agent-guard 1, gdpr-shredding 4, stripe-einvoice 3), all plain English, one of them in the
published gdpr-shredding core jar (`schema-postgresql.sql`, "security-review findings"). The
builder's 11 counted older trees.

But the narrowing also lets through the file-name forms. The upper-case bare words refuse any
extension; the new lower-case rule covers only `<word>.md` for the release word and nothing for
the review word. The moved-private documents include review documents and the release runbook.

Example: after both PRs, a tracked file `securit[y]-review.md` at the root passes both scans
(exit 0), and so do `docs/[R]eleasing.txt` and `docs/sub/Securit[y]-Review-pr12.md`. Their
upper-case twins are refused.

Measured fix: replace the release alternative `[Rr]...[Gg][.][Mm][Dd]` with
`[Rr][Ee][Ll][Ee][Aa][Ss][Ii][Nn][Gg][.]`, and add
`[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy][-][Rr][Ee][Vv][Ii][Ee][Ww][.-]` (the word followed by a dot
or a hyphen, the way a file name continues; plain English continues with a space). With that
pattern: 0 new hits in content and names of the three `main` trees, the same 4 jar hits on the
12 published jars, self-test 115 OK on BSD and GNU (combined state), and the three examples
above refused. Keep the bare upper-case words. Self-test rows: the three examples, red, plus a
green row "releasing a version. A security-review probe ran." Mutations: drop each new
alternative, a row goes red.

Row wording: amend B-NG-12 to say what is built: document names and the plans folder in any
case; the review and release words in any case when they continue as a file name (followed by
`.` or `-`), upper case only as bare words.

#### B-NG-26 (INFO): the upper-case document names are no longer pinned by the self-test

The new rows are lower and mixed case. Only the open-items document is also pinned in upper
case (by the older rows). So rewriting one of the five others to match lower case only, for
example `[Ss][Tt][Aa][Tt][Uu][Ss][.][Mm][Dd]` to `statu[s][.]md`, leaves the self-test green:
the upper-case original, the form every real reference uses, would pass. Survivors: status,
spec, licensing, shared conventions, agents. (Questions, plans folder and release runbook are
killed by existing rows.)

Fix (fix pass): for each of the eight names, three rows built in a loop: the original upper
form, all lower, one mixed form. Mutation: the probe above goes FIXED when all five rewrites
turn the self-test red.

#### B-NG-27 (INFO): the merged branch must prove the two changes meet

This PR touches content matching only. With PR 49, the same pattern also runs on file names,
and the slug of an admitted review document is scanned again. Two facts measured on the
combined state: (1) the name scan refuses `notes/question[s].md`, but no self-test row says so;
(2) deleting the slug re-scan leaves the self-test green. With PR 49's pattern no lower-case
slug can hit, so the re-scan had no possible case there. With this PR's pattern it can:
`docs/SECURITY[-]REVIEW-statu[s].md.md` is refused only by the re-scan.

Fix (fix pass, after `main` with PR 49 is merged into this branch, by a merge commit, never a
force-push):
1. Change this PR's eleven `red` rows and its green row to the PR 49 form, `red:content`
   (without it the combined self-test fails 11 rows: the reason word "red" is never printed).
2. Add `_name_case "name-lower-case-private-document" red:name 100644 "notes/question""s.md"`.
3. Add `_name_case "name-review-doc-slug-carries-a-document-name" red:name 100644
   "docs/SECURITY""-REVIEW-statu""s.md.md"`. Mutation: delete the slug re-scan, this row goes
   red.
4. Add `_zip_case "jar-member-mixed-case-private-document" red:name case.jar
   "META-INF/Agent""s.md" "clean"`.

### The three builder decisions in the brief

1. **Narrowing of B-NG-12.** Safe for plain English, not safe for file names. What passes today
   is B-NG-25. Amend the build (two alternatives, measured at zero false hits) and then amend the
   row's wording to the exact boundary. Neither change alone is enough.
2. **Merge order.** PR 49 first, this PR second. This branch then merges `main` in and carries
   the four changes of B-NG-27. The extra test asked for in the brief is item 2 (a lower-case
   private document as a file name); items 3 and 4 are needed too.
3. **Build-2 jars from the build-1 runs.** Accepted. This PR changes no input of any jar: its
   diff is `CHANGELOG.md` and two scripts under `tools/`, and no published jar holds a changelog,
   a `tools/` file or a workflow (listing checked). The CI Build & test job on `c45c4aa` also ran
   this PR's guard on this PR's own fresh jars, with GNU grep, and they were clean. The review's
   own run of four guard versions on the 12 published jars gave identical hits. The B-NG-25
   pattern change is the same kind of change, so the same evidence holds for it; no local
   rebuild is needed.

### Fix list for this PR

| Finding | Who | Change | Proof |
|---|---|---|---|
| B-NG-25 | fix pass | two alternatives on the `pattern=` line; header paragraph and CHANGELOG say the boundary | three red rows, one green row; probe FIXED |
| B-NG-26 | fix pass | three letter-case rows per document name | five rewrites go red |
| B-NG-27 | fix pass | merge `main`; reason words; three new rows | probe FIXED; slug mutation red |

The probe file `cipher-probe-guard-lower-case-names-pr50.sh` goes into the suite first (WEAK).
Pass 2 checks each probe FIXED on the merged head and measures the new alternatives again.
