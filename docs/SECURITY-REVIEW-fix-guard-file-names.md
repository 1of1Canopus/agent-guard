# Security review: the reference guard also scans file names (PR 49)

## 2026-10-17, pass 1

**Verdict: MERGE WITH FIXES.** No HIGH, no MEDIUM. Four LOW and two INFO findings. Every one is
fixed before merge (no-allowance rule), except B-NG-22: that gap sits in older code on `main`,
not in this diff, and it is the same mechanism as B-NG-14 (members the content scan cannot
read), so it is fixed in the B-NG-14 pull request, before the module's next tag.

Reviewed tree: `aadcb19` (`fix/guard-file-names`, PR 49 head), probe commit `2d7e513`. Scope:
`tools/check-private-references.sh` (name scan of the tree and of jars, the admitted review
shape, the locale rule, the listing checks, escaped output), the new suite probes, and the three
renamed CI step names. The two sibling repositories carry the same script; they get the
verifier's numbers and a diff only.

Method: every attack ran against the real script (`--tree`, `--jars` or `--self-test`, real exit
code). macOS: BSD grep 2.6.0, git 2.53, Info-ZIP unzip 6.00 (Apple build), bash 3.2. Linux: a
Debian container with GNU grep 3.11, git 2.47 and Debian unzip 6.00. Jars were built with
Python's `zipfile`. Results are the same on both unless stated. No Maven run: the brief did not
need one, and the CI run on the head is green.

### Numbers

| Check | Result |
|---|---|
| CI on `aadcb19` (run 39026686220) | all five checks green; Build & test ran `--jars` on its own build: every built jar clean |
| `--self-test`, BSD grep (macOS) | exit 0, 103 OK |
| `--self-test`, GNU grep (Linux) | exit 0, 103 OK |
| `--self-test` with a grep that says it is ugrep, or an unknown grep | refuses to run, exit 1 |
| `--tree` on `aadcb19` | tree clean (content and names) |
| Suite probes on `2d7e513` (probe commit) | the six new probes WEAK |
| Suite probes on `aadcb19` | the six new probes FIXED; fixed 81, still weak 8 (the 8 need `CIPHER_PROBE_MAVEN=1`; the same 8 on `main`) |
| Builder mutations M1 to M20, rerun by the review | 20 of 20 red, each by the case the design names |
| Reviewer mutations | 4 run, 4 survive (B-NG-24, and the slug re-scan, see the PR 50 review) |
| Admitted review-document names on the three `main` trees | 6, 11 and 13; every one of the admitted shape |
| One-to-one measurement on the 12 published jars (bytes and files listed vs extracted) | equal on all 12; differs on every attack jar of B-NG-19 to B-NG-21 |
| New probes this pass | 6, all WEAK on `aadcb19` (internal probe file `cipher-probe-guard-file-names-pr49.sh`) |

### Builder mutations, rerun

Each mutation was applied to a copy of the script, the self-test was run, and the copy was
thrown away.

| # | mutation | self-test | case that went red |
|---|---|---|---|
| M1 | no `scan_tree_names` call | red (17 FAIL) | name-moved-private-document-at-root, and every other tree name case |
| M2 | shape without `^` | red | name-review-doc-in-a-sub-folder |
| M3 | shape without `$` | red | name-review-doc-trailing-suffix |
| M4 | slug class `[A-Za-z0-9.-]+` | red | name-review-doc-upper-case-slug |
| M5 | pathspec exclude of review documents on the content `git grep` | red | review-doc-content-still-scanned |
| M6 | `git ls-files` without `-z` | red (25 FAIL) | name-newline-in-a-private-name, clean cases too |
| M7 | no control-byte refusal on the raw stream | red | name-tab-in-a-path, both newline cases |
| M8 | no symlink and gitlink refusal | red | name-symlink, name-gitlink |
| M9 | jar names from `find` on the extracted tree | red (11 FAIL) | jar-member-parent-segment, jar-member-absolute-path, every name case |
| M10 | review shape applied to jar members | red | jar-member-review-doc-name |
| M11 | no `..` and leading `/` refusal | red | jar-member-parent-segment, jar-member-absolute-path (wrong reason) |
| M12 | no jar file-name check | red | jar-file-name |
| M13 | a listing failure returns success | red | listing-of-a-missing-jar |
| M14 | no `^` refusal | red | jar-member-caret, newline and tab members (wrong reason) |
| M15 | no count comparison | red | listing-count-mismatch |
| M16 | no exact-duplicate check | red | jar-duplicate-member |
| M17 | no case-fold duplicate check | red | jar-case-fold-duplicate-member |
| M18 | no `export LC_ALL=C` | red | both non-UTF-8 byte cases, and the export-order check |
| M19 | refused paths printed raw | red | name-newline-workflow-command (N6) |
| M20 | listing read through a pipe, exit code of the last command | red | listing-of-a-missing-jar, non-git directory |

### Attacks that held

* Path separators: a path that only looks like the admitted shape is refused:
  `docs/SECURITY[-]REVIEW-a.md/x.txt` (a directory with the shape's name), a sub folder, the
  root, an upper-case slug, a `.md.bak` suffix. Git never stores a `..` segment in the index.
* The admitted shape cannot be widened by a file in `docs/`. The shape is one fixed line in the
  script, not data. A symlink or a gitlink at an admitted name is refused for its mode. The text
  of every admitted file is still scanned.
* Moved-private review documents have names of the admitted shape. Measured: four of the seven
  internal ones carry 13 to 149 content hits, so a copy is refused by its text. The other three
  have no hit; they are reviews of the same kind the public `docs/` folder now holds by the
  current public-text rule. Not a finding: the name rule cannot tell them apart, and their
  content leaks nothing the rule protects.
* Non-ASCII bytes: `x/<0xC3 0xA9><name 1>.md` and `x/<0xFF><name 1>.md` are refused in the C
  locale, on both greps. Apple's unzip prints a non-ASCII member name as `?`, so the member is
  "listed, not extracted" and refused (fail closed); Debian's unzip prints the raw bytes and
  the name is scanned. An NFC/NFD pair and a Kelvin-sign pair collide on the macOS disk; they
  are refused there for the same reason, and on Linux they do not collide.
* Look-alike letters (long s, dotless i, Kelvin sign in a document name) pass both scans. The
  design refused them for this PR. They have no register row yet; this pass adds B-NG-28 so the
  later rule is tracked.
* Long names: a 4,012-byte tree path is refused (`name`); a 1,212-byte jar member is refused on
  Linux (`name`) and fails closed on macOS (`cannot list`); a 60,000-byte member fails closed on
  both. GNU grep has no line limit; no truncation was seen.
* A jar member named with a newline, a tab, a DEL byte or a literal `^`: refused (`control
  byte`, or "listed, not extracted" for DEL on macOS).
* `.gitattributes`: the name scan reads the index and never consults attributes; the content
  scan keeps `--text` (self-test case and its negative control).
* `--text` everywhere (checklist line 10): `grep -a` on every name list and on jar content,
  `git grep --text` on the tree.
* A newline in a tree path with dirty content: the name is refused and printed escaped, and
  `git grep` quotes the path in the content output, so no line starts with `::`.
* Self-non-matching: the self-test check passes with this pattern and with the PR 50 pattern on
  top; the `review_doc_shape` line is clean too.

### Findings

| Id | Severity | Class | Probe | Fix in |
|---|---|---|---|---|
| B-NG-19 | LOW | copy/leak paths | `probe_jar_member_normalised_path_hides_content` | this PR |
| B-NG-20 | LOW | copy/leak paths | `probe_jar_symlink_member_target_passes` | this PR |
| B-NG-21 | LOW | copy/leak paths | `probe_jar_directory_entry_data_passes` | this PR |
| B-NG-22 | LOW | copy/leak paths | `probe_nested_archive_with_a_prefix_passes` | B-NG-14 PR (older code) |
| B-NG-23 | INFO | boundary validation | `probe_content_hit_replays_a_carriage_return_command` | this PR |
| B-NG-24 | INFO | false completion | `probe_self_test_misses_three_name_checks` | this PR |

#### B-NG-19 (LOW): a member path that unzip normalises hides the content of another member

B-NG-10 refuses two members with the same name, or the same name after case folding. Unzip
also rewrites `./`, `//` and `/./` before it writes a file. So `./a.txt` and `a.txt` are two
different names in the listing, but one file on disk. The second member overwrites the first.

Example: a jar with `./a.txt` holding a line that names the private open-items document, then
`a.txt` holding "clean". The guard says "every built jar is clean" (exit 0) on macOS and Linux.
`unzip -p x.jar ./a.txt` prints the dirty line: the bytes are published. Same with `b//a.txt`
and `b/a.txt`, and with `b/./a.txt` and `b/a.txt`.

Fix (the builder of this mechanism, not the fix pass): two changes in `scan_jars` /
`check_jar_listing`.
1. Refuse an empty or `.` segment in a member name with reason `dot segment`: a name that is
   `.`, starts with `./`, contains `/./` or `//`, or ends with `/.`.
2. After extraction and before the content scan, check that extraction was one to one: the
   number of regular files under the extraction folder equals the number of non-directory
   members in the `-Z1` list, and the sum of their sizes equals the "bytes uncompressed" figure
   of the `-Zt` line already parsed by `jar_counts_match`. A difference refuses with reason
   `listing mismatch`. This closes the class, not only the three spellings: any rewrite or disk
   collision unzip makes loses a file or bytes. Measured on the 12 published jars of the three
   modules: equal on every one, so no false refusal.
Self-test rows: the three pairs above, `red:dot segment`; one pair that only the count check
catches (for example an NFC/NFD pair run on macOS is not portable, so use the B-NG-20 symlink
jar, or call the check as a function on a synthetic folder, like `jar_counts_match`),
`red:listing mismatch`. Mutations: delete each check, the matching row goes green.

#### B-NG-20 (LOW): a symlink member's stored target is never scanned

A zip entry can carry the Unix mode of a symlink. Its data is the target path. Unzip creates a
symlink, and the recursive `grep -r` does not follow symlinks it meets inside the folder. The
`-f` test in the nested-archive loop does follow it, so a target that exists passes that test.

Example (Linux, GNU grep): a jar with `a.txt` "clean" and a symlink member `link` whose stored
target is `[/]root[/].bashrc`. The guard exits 0. `unzip -p x.jar link` prints the machine path.
On macOS the same with a target under `[/]Users[/]Shared`. A target that does not exist is
refused today ("listed, not extracted"), by accident.

Fix (same hand): refuse any symlink under the extraction folder after extraction, reason
`symlink` (the tree side already refuses mode 120000 with that word). The one-to-one check of
B-NG-19 also catches it (the link is not a regular file), but the reason word must be
`symlink`. Self-test row: a symlink member whose target is a file the self-test creates under
its scratch folder, `red:symlink`. Mutation: delete the check, the row goes green.

#### B-NG-21 (LOW): data inside a directory entry is never scanned

A member whose name ends in `/` is a directory for unzip. Unzip creates the folder and drops
the entry's bytes. The name is scanned; the data is not.

Example: a jar with `a.txt` "clean" and a directory entry `d/` that stores a line naming the
private open-items document. The guard exits 0. `unzip -p x.jar d/` prints the line.

Fix (same hand): the one-to-one check of B-NG-19 catches it, because the "bytes uncompressed"
total counts the dropped bytes (measured: 23 listed, 6 extracted). No second listing is
needed. Self-test row: the jar above, `red:listing mismatch`.

#### B-NG-22 (LOW): a nested zip that does not start with the zip magic passes as text

B-NG-6 refuses a member whose first four bytes are `PK\x03\x04`. Unzip and `java.util.zip`
read a zip from its end (the central directory), so a zip with any prefix is still a zip. A
Spring Boot executable jar with a launch script in front is the common real case.

Example: a member `lib/x.bin` made of one zero byte and then a small zip whose member names the
private open-items document twenty times, compressed. The guard exits 0 on both systems.
`unzip -l lib/x.bin` lists the inner member.

This code is on `main` (PR 43), not in this diff. Fix: in the B-NG-14 pull request, which
already exists to refuse members the content scan cannot read (gzip). Property to hold there:
no member that an archive tool can open as an archive passes as text, whatever its first
bytes. Paths to cover: a zip with a prefix, a zip whose only signature is the end record, a
nested jar, gzip. That PR writes its design page first (new detection rule), and it merges
before the module's next tag. This PR does not wait for it.

#### B-NG-23 (INFO): a content hit is replayed raw, and a carriage return can start a runner command

B-NG-13 made refused NAMES print escaped. Content hits are still printed raw: the `git grep`
lines on the tree side and the `grep -rna` lines on the jar side. A content line cannot hold a
newline, but it can hold a carriage return. The Actions runner reads job output with
`StreamReader.ReadLine` (checked in the runner's `ProcessInvoker.cs`), and that call ends a
line at a carriage return too.

Example: a tracked `doc.md` with the line `see <open-items document>\r::warning::spoofed`.
The guard refuses it, and its output holds the raw `\r` followed by `::warning::`. Split the way
the runner splits it, one output line starts with `::warning::`. The same on the jar side.
Not run on a hosted runner: the split is the documented behaviour of that call.

Fix (fix pass): print every content-hit line through `escape_bytes`, on the tree side and on
the jar side. Self-test row: the line above, assert that after splitting the output on CR and
LF no line starts with `::`. Mutation: print the hit lines raw, the row goes green.

#### B-NG-24 (INFO): three checks of this PR have no self-test case

Each of these deletions leaves the self-test green (all 103 OK), on BSD grep:
1. The control-byte refusal of the jar's own file name (`case "$base" in *[[:cntrl:]]*`).
2. The "listed, not extracted" refusal in the nested-archive loop.
3. The backslash alternative of the `dot segment` refusal.

Fix (fix pass): one red case each, with its reason word. A jar file whose name holds a newline
(`red:control byte`); a member `a\b.txt` (`red:dot segment`). For item 2, either a case that
reaches it on macOS and Linux, or, once the B-NG-19 one-to-one check is in, drop the branch
if that check makes it unreachable, and say so in the header. A fourth survivor, the slug
re-scan of the admitted shape, cannot have a case with this PR's pattern (no lower-case slug
can hit it); it gets one in PR 50 after the merge (B-NG-27).

### The three builder decisions in the brief

1. B-NG-12 narrowed: judged in the PR 50 review.
2. Merge order: this PR first, then PR 50 merges `main` in and adds the cases listed in its
   review (B-NG-27). Reason: this PR builds the name scan; the interaction can only be proved
   on the branch that carries both, and that is the second one.
3. Build-2 jars: judged in the PR 50 review.

### Fix list for this PR

| Finding | Who | Change | Proof |
|---|---|---|---|
| B-NG-19 | builder of the mechanism | refuse empty and `.` segments; one-to-one check after extraction (files and bytes) | three pair rows, one mismatch row; two mutations |
| B-NG-20 | builder of the mechanism | refuse a symlink in the extraction folder, reason `symlink` | symlink row; mutation |
| B-NG-21 | builder of the mechanism | covered by the one-to-one byte check | directory-data row |
| B-NG-23 | fix pass | escape every content-hit line | CR row; mutation |
| B-NG-24 | fix pass | three red rows (or a stated removal for item 2) | the three deletions go red |
| B-NG-22 | B-NG-14 PR | archive detection by content, design page first | its own probe flips there |

The probe file `cipher-probe-guard-file-names-pr49.sh` goes into the suite first (WEAK), as for
the earlier groups. Pass 2 checks each probe FIXED (B-NG-22 stays WEAK until its own PR) and
attacks the new checks.

## Pass 2 (2026-10-17)

**Verdict: MERGE WITH FIXES.** No HIGH, no MEDIUM. The five fixed findings (B-NG-19, 20, 21, 23,
24) are confirmed: each probe flips to FIXED on BSD and GNU grep, and the eight builder
mutations go red by the case the PR body names. The attack on the new one-to-one check finds
three new findings: one LOW in older jar code (B-NG-29, routed with B-NG-22 to the B-NG-14
pull request as a design stop), and two INFO in this diff (B-NG-30, B-NG-31). Both INFO items
are fixed in this PR before merge. B-NG-22 and B-NG-28 stay deferred as agreed.

Reviewed tree: `b3349e3` (`fix/guard-file-names`, PR 49 head; `main` at `b714620` merged in).
Fix commits `f1d299e` (probes) and `4f52d97` (fix). macOS: BSD grep 2.6.0, Apple unzip 6.00.
Linux: a Debian trixie container with GNU grep 3.11 and Debian unzip 6.00. Every attack ran
against the real script with its real exit code. No Maven run (not needed by the brief).

### Numbers

| Check | Result |
|---|---|
| `--self-test`, BSD grep | exit 0, 115 OK |
| `--self-test`, GNU grep | exit 0, 115 OK |
| `--tree` on `b3349e3` | clean (content and names) |
| Pass 1 probes on `b3349e3` | 5 FIXED (B-NG-19, 20, 21, 23, 24); B-NG-22 WEAK as planned |
| Builder mutations N1 to N8, rerun by the review, both greps | 8 of 8 red, each by the named case (N1: 3 FAIL) |
| Reviewer mutations | 2 run: byte half removed is red; file-count half removed survives (B-NG-31) |
| Attack jars | 30 built: 20 refused for the right reason on both systems; 2 Unicode-path jars refused on Debian and green on macOS (the field is ignored there and the content is clean); 4 clean controls green; 4 pass with text outside member data (B-NG-29) |
| Copies: gdpr-shredding #39 `1f4cd01`, stripe-einvoice #34 `a4f52c1` | `diff` against this head: one line each, the runner-path line (`h=...`), nothing else |
| New probes this pass | 3, all WEAK on `b3349e3` (same internal probe file) |

### Prior findings

| id | probe | result |
|---|---|---|
| B-NG-19 | `probe_jar_member_normalised_path_hides_content` | FIXED, both greps; mutation N1 red (3 rows) |
| B-NG-20 | `probe_jar_symlink_member_target_passes` | FIXED; N3 red |
| B-NG-21 | `probe_jar_directory_entry_data_passes` | FIXED; N2 red |
| B-NG-23 | `probe_content_hit_replays_a_carriage_return_command` | FIXED; N4 and N5 red. The remainder (hit line that starts with `::`) is B-NG-30 |
| B-NG-24 | `probe_self_test_misses_three_name_checks` | FIXED; N6, N7, N8 red |
| B-NG-22 | `probe_nested_archive_with_a_prefix_passes` | WEAK, deferred to the B-NG-14 PR as agreed |

### Attacks on the new check that held

Same result on both systems unless stated.

* Size lies in the central directory (the zip index at the end of the file). Uncompressed size
  raised or lowered in the central directory and the local header, or in the central
  directory only: refused, `listing mismatch`. unzip inflates the real stream and ignores the
  stated size, so the byte total no longer matches.
* Two lies that balance (one member under-stated, another over-stated by the same amount),
  deflated and stored: the byte total matches, but every real byte is extracted and the hit
  is found (`content`). A lie alone hides nothing. With a fold it does: see B-NG-31.
* Zip64 (`force_zip64`) and data descriptors (sizes after the data, local header sizes zero):
  clean jars stay green, dirty jars are refused by content. The `unzip -Zt` line parses on
  both unzip builds; the guard exports `LC_ALL=C` first and Info-ZIP prints no locale-dependent
  digits. An archive comment does not add a line to `-Zt`.
* Empty member with a dirty name: refused, `name`. Two empty members only: green, correct.
* Directory on one side, file on the other: `d/` then `d`, `d` then `d/`, `d` then `d/x.txt`:
  unzip exits non-zero, refused, `cannot list`. A directory mode on a name without `/`,
  carrying data: unzip writes a regular file, the hit is found.
* Duplicate names with equal sizes and different content: refused, `duplicate member`, before
  any extraction.
* Symlink to a directory under the home folder: refused, `symlink`. Symlink then a member
  written through it (`l` then `l/x.txt`): unzip defers the link and exits non-zero, refused;
  nothing was written outside the extraction folder.
* Hard-link-like entries: Info-ZIP has no hard links. FIFO and character-device modes are
  written as regular files and scanned.
* The Info-ZIP Unicode path field (a second, UTF-8 name inside the entry). Apple's unzip
  ignores it for both the list and the extraction. Debian's unzip uses it for both: a clean
  stored name with a dirty Unicode name is refused (`name`), a `../` or `./` Unicode name is
  refused (`dot segment`). The list and the disk agree on each build.
* Encrypted flag: unzip cannot extract without a password, refused.
* Prefix bytes before the first entry: unzip warns and exits 1, refused.
* Escaping: a hit holding `\r::warning::`, `\x1b[2K` and `\` prints as `\x0D::warning::`,
  `\x1B[2K` and `\x5C`. A hit line cannot hold `\n`. The escape runs on output only; the scan
  runs first on the raw bytes, so escaping cannot hide a hit. The escaped form is never
  scanned again; the script's own text stays clean under `--tree`.

### Findings

| id | severity | class | probe | fixed in |
|---|---|---|---|---|
| B-NG-29 | LOW | copy/leak paths | `probe_jar_bytes_outside_member_data_pass` | B-NG-14 PR (older code), design stop |
| B-NG-30 | INFO | boundary validation | `probe_tree_hit_path_starts_a_runner_command` | this PR |
| B-NG-31 | INFO | false completion | `probe_self_test_misses_the_file_count_half` | this PR |

#### B-NG-29 (LOW): bytes outside every member's data are never scanned

The content scan reads only the extracted files. A jar can hold text in four places that
unzip never writes to disk: the archive comment, a member comment, an extra field (a typed
binary block inside an entry header), and a gap before the central directory. Each passes the
guard, exit 0, on both systems and on `main` (the jar content scan is older than PR 49).
`unzip -z`, `zipinfo -v` and `strings` show the text.

Example: a jar with one clean `a.txt` and an archive comment `see <private document name>`
prints "every built jar is clean". `unzip -z x.jar` prints the comment.

Why LOW: Maven's jar plugin writes none of these places, so an accidental leak needs an odd
build step; but the bytes ship in the published artifact. A raw `grep -a` of the jar is not
the fix: compressed data gives random matches of the short agent-name alternatives.

DESIGN STOP. Property: every byte of the jar file is either member data that the content scan
reads, or zip structure that the guard has parsed and found free of text (no archive comment,
no member comment, only known extra fields, no gap: the parsed structure accounts for the
file size). Paths it must cover: archive comment, member comments, extra fields in local and
central headers, gaps between entries and before the central directory, trailing bytes. Same
mechanism as B-NG-14 and B-NG-22 (bytes the content scan cannot read), so one design page in
the B-NG-14 PR covers all three. Before the module's next tag.

#### B-NG-30 (INFO): a tree hit line starts with the file path, so a path can start a runner command

B-NG-23 escaped the bytes inside a hit, but a tree hit line is `path:line:text`, and the path
comes first. A tracked file named `::stop-commands::tok` (or ` ::warning::spoofed`, leading
blank) with a hit prints a line that starts with `::`. The Actions runner reads that line as a
workflow command. `stop-commands` hides every later annotation of the job; `add-mask` can mask
the evidence in the log. The job still fails on the exit code, so nothing passes.

Example: the line `::stop-commands::tok:1:see <private document name>` reaches the log
unchanged after the guard's own `::error::` line (reproduced to the output bytes, not run on a
hosted runner).

Fix (fix pass, same place as B-NG-23): in `scan_tree_content` and in `scan_jars`, after
`escape_lines`, put a fixed prefix that is not blank and not `:` before every hit line (for
example `hit: `), so no line made of data can start with `::` even after the runner trims
blanks. Self-test row: a tree file named `::warning::<x>` with a hit; assert that, split on CR
and LF, every line that starts with blanks then `::` is the guard's own
`::error::check-private-references:` line. Mutation: drop the prefix, the row goes red. Apply
to the two copies.

#### B-NG-31 (INFO): the file-count half of the one-to-one check has no self-test row

`extracted_matches_listing` compares the file count and the byte total. Removing the file-count
half keeps the self-test green (115 OK) on both greps. That half is load-bearing: with the
name rule mutated away (N1), a jar with a dirty `./a.txt`, a clean `a.txt`, and the central
directory size of `./a.txt` set to 0 has equal bytes (6 listed, 6 extracted) and unequal files
(2 listed, 1 extracted). Only the file-count half refuses it. With both removed, the jar
prints "every built jar is clean".

Example: `if [ "$have_bytes" != "$want_bytes" ]; then` instead of the two-part test; self-test
115 OK, no row red.

Fix (fix pass): one self-test row that calls `extracted_matches_listing` on a synthetic folder,
as the "listed, not extracted" row does: a list of two members, one file on disk, and a `-Zt`
line whose byte figure equals that one file. Expected red, `listing mismatch`. Mutation: drop
the file half, the row goes red. Apply to the two copies.

### Fix list for this PR

| id | who | change | proof |
|---|---|---|---|
| B-NG-30 | fix pass | fixed non-blank prefix on every content-hit line, tree and jar | self-test row; mutation; probe FIXED |
| B-NG-31 | fix pass | self-test row on `extracted_matches_listing` with equal bytes, unequal files | row; mutation; probe FIXED |
| B-NG-29 | B-NG-14 PR | design page first (property and paths above) | its probe flips there |

The probes go into the suite before the code changes. Both changes also go to the two copies,
identical except the runner-path line. A third pass is not needed for these two: the verifier
reports the self-test count, the two probes FIXED on both greps, and the two mutations red.
