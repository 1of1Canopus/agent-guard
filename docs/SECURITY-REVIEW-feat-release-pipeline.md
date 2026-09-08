# SECURITY-REVIEW — branch `feat/release-pipeline` (Maven Central release pipeline)

Reviewer: `cipher` (adversarial pass, per `AGENTS.md` "Cipher — security review on EVERY PR").
Date: 2026-09-08. Scope: PR #9, HEAD `645397d`, three commits by Thor — `pom.xml` (release profile, metadata,
licence gate), `.github/workflows/release.yml`, `scripts/git-commit-timestamp.sh`,
`scripts/verify-reproducible.sh`, `agent-guard-sample/pom.xml`, `docs/RELEASING.md`, `CHANGELOG.md`,
`QUESTIONS.md` #21–#26, `STATUS.md`.
Read first: `QUESTIONS.md` #21–#26, `docs/RELEASING.md`, `STATUS.md`, `docs/SECURITY-REVIEW-feat-agent-guard-core.md`.
Dollar's standing rulings honoured here: the licence gate stays in the default build (#22), `oss@housedevinci.com`
is Souhaile's to create (#21), `META-INF` notices embedding is deferred (#26).

**Nothing in production code or in the workflow was edited.** The only files added by this review are
`docs/SECURITY-REVIEW-feat-release-pipeline.md` and `tools/cipher-probe-release-pipeline.sh`.

## Method

Every claim below was produced by running something, not by reading YAML. The release profile was executed end to
end against a throwaway 1-day GPG key in an ephemeral `GNUPGHOME` and a scratch `settings.xml` carrying deliberately
fake Central credentials, under `-X`, in a clone outside the repository; the resulting 15 999-line debug log, the
`central-bundle.zip`, the published POMs and the jars were then searched for the fake values. The licence gate was
attacked with four synthetic dependencies installed into the local repository. The reproducibility script was run
for real. The action pins were checked against the GitHub tag API. The Central Portal and `actions/setup-java`
sources were read at the version actually pinned.

Probes: `tools/cipher-probe-release-pipeline.sh` (13 probes, all **WEAK** at `645397d`, script exit 1). Each probe
asserts a weakness and must flip to `FIXED` when its finding is closed. The heavy licence probe runs under
`CIPHER_PROBE_MAVEN=1`.

---

## Verdict

**MERGE WITH FIXES.** No HIGH. The design is right where it matters most: the pipeline stops at `USER_MANAGED`
(verified on the wire, not in the pom), the sample never reaches the bundle, the build is byte-reproducible, the
passphrase never touches a command line, the signing key lives in an ephemeral keyring, and `permissions` is
`contents: read`. The problems are in the gates around it — a licence gate that does not do what its own comment
claims, a signing job that restores a mutable Maven distribution cache, an input validator that is line-oriented
where it needed to be string-oriented, a release that any tag on any commit can start, a runbook that puts the
private key on the macOS clipboard, and an Apache-2.0 library with no licence text in it.

Under the no-allowance rule every item below is fixed before this branch merges.

| Severity | Count | Ids |
|---|---|---|
| HIGH | 0 | — |
| MEDIUM | 7 | M1 dual-licence bypass · M2 `excludedLicenses` is the wrong fix and destroys evidence · M3 signing job restores an unverified Maven distribution cache · M4 newline in the `version` input injects into `$GITHUB_OUTPUT` · M5 any tag on any commit releases, no gate · M6 `RELEASING.md` leaks the private key twice · M7 Apache-2.0 declared, no LICENSE anywhere |
| LOW | 7 | L1–L7 |
| INFO | 11 | I1–I11, of which I2, I3, I5–I11 are verified-good and close with no change |

Release gates that are not code (must be true before `v0.1.0` is tagged, not before this PR merges): `oss@housedevinci.com`
exists and forwards (#21); the repository is public (L7); the `release` environment exists with Souhaile as required
reviewer (M5).

---

## MEDIUM

### M1 — The licence allowlist passes a dependency on its permissive half, so `Apache-2.0 OR GPL-3.0` ships

**Where:** `pom.xml`, `license-maven-plugin` execution `third-party-notices`, `<includedLicenses>`.

**Repro (reproduced, not inferred).** Four synthetic artifacts were installed into the local repository, each with
nothing but a POM declaring licences, then added one at a time to `agent-guard-core` and built with
`./mvnw -B -pl agent-guard-core -am package -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true`:

| synthetic dependency | declared licences | build |
|---|---|---|
| `syn-gpl` | `GPL-3.0` | **fails** — "There are 1 forbidden licenses used" |
| `syn-dual` | `Apache-2.0`, `GPL-3.0` | **BUILD SUCCESS** |
| `syn-pd` | `Public Domain Dedication and License (PDDL) 1.0` | fails |
| `syn-sub` | `Apache-2.0-with-a-nasty-rider` | fails |

`THIRD-PARTY-NOTICES.txt` after the `syn-dual` build:

```
     (Apache-2.0) (GPL-3.0) syn-dual (cipher.synthetic:syn-dual:1.0 - no url defined)
```

Probe: `probe_licence_gate_accepts_dual_apache_or_gpl` (WEAK).

**Impact.** The comment in `pom.xml` states "Everything else, GPL/LGPL/AGPL/MPL/CDDL/SSPL included, fails". That is
false for any dependency that declares a permissive licence *alongside* a copyleft one. Thor recorded the behaviour
honestly in QUESTIONS #22 and correctly noted it is the right answer for a genuinely dual-licensed artifact
(`logback` is `EPL-2.0 OR LGPL-2.1`, `jakarta.annotation-api` is `EPL-2.0 OR GPL-2.0-with-classpath-exception`).
It is the wrong answer for an artifact whose POM lists two licences that are **cumulative** rather than
alternative, and for a transitive dependency added by a future Dependabot bump that nobody reads. The published
artifact is permanent; a licence mistake in it cannot be withdrawn.

**Exact fix.** Do not touch `<includedLicenses>` — it is correct as an any-of *permission* check. Add a second,
all-of *denial* pass over the generated notices file, as a script, wired into the same `verify` the release runs:

1. New file `tools/check-third-party-licences.sh`. It reads every
   `*/target/THIRD-PARTY-NOTICES.txt` produced by the `third-party-notices` execution, and for each dependency
   line extracts every `(...)` licence token. It exits non-zero, naming the dependency and the token, if any token
   matches a denied set — at minimum `GPL-1.0 GPL-2.0 GPL-3.0 LGPL-2.0 LGPL-2.1 LGPL-3.0 AGPL-1.0 AGPL-3.0
   SSPL-1.0 CDDL-1.0 CDDL-1.1 MPL-1.1 MPL-2.0 CPOL EUPL-1.2 BUSL-1.1 Elastic-2.0 CC-BY-NC` and any token whose
   normalised form contains `GPL` without a `classpath-exception` qualifier.
2. Add the two known-good exceptions as an explicit, commented allowlist of *coordinates* (not licences):
   `ch.qos.logback:logback-classic`, `ch.qos.logback:logback-core`, `jakarta.annotation:jakarta.annotation-api`.
   An exception is a coordinate a human wrote down, never a pattern.
3. Wire it with `exec-maven-plugin` `exec` at `verify` in the root `pom.xml`, in the default build (Dollar's #22
   ruling), immediately after the `license-maven-plugin` execution.
4. Test: extend `tools/cipher-probe-release-pipeline.sh`'s
   `probe_licence_gate_accepts_a_dual_apache_or_gpl_dependency` — it must flip to `FIXED`.

### M2 — `excludedLicenses` is not the fix: it makes the build pass *and* deletes the evidence

**Repro.** The obvious remedy for M1 is to add a blocklist beside the allowlist. It was tried:

```xml
<includedLicenses>Apache-2.0|MIT|BSD|EPL-2.0|Public Domain</includedLicenses>
<excludedLicenses>GPL-3.0|GPL-2.0|LGPL-2.1|LGPL-3.0|AGPL-3.0|SSPL-1.0|MPL-2.0|CDDL-1.0</excludedLicenses>
```

With that in place the `syn-dual` build still succeeds — and `THIRD-PARTY-NOTICES.txt` now reads:

```
     (Apache-2.0) syn-dual (cipher.synthetic:syn-dual:1.0 - no url defined)
```

The `GPL-3.0` declaration has been **removed from the notices file that ships as release evidence**. The gate got no
stronger and the audit trail got weaker.

**Impact.** Whoever fixes M1 will reach for `excludedLicenses` first. Recorded here so they do not.

**Exact fix.** Never add `<excludedLicenses>` to this execution. Put the denial pass outside the plugin, as in M1.
Add the anti-pattern as a comment on the `third-party-notices` execution in `pom.xml` so it is not re-attempted.

### M3 — The job that holds the signing key restores an unverified Maven distribution from a mutable cache

**Where:** `.github/workflows/release.yml`, job `publish`, `actions/setup-java` step, `cache: maven`.

**Repro.** Two facts, both read at the pinned versions:

* `actions/setup-java@dd06d9c` (v6.0.0), `src/cache.ts`: the `maven` package manager caches
  `~/.m2/repository` **and**, as `additionalCaches`, `~/.m2/wrapper/dists`.
* `mvnw` in this repository, at the top of the download path:

  ```sh
  if [ -d "$MAVEN_HOME" ]; then
    verbose "found existing MAVEN_HOME at $MAVEN_HOME"
    exec_maven "$@"
  fi
  ```

  `distributionSha256Sum` (`5af3b743…89ce`) is checked at line 226, on the downloaded zip only. A distribution that
  is already unpacked in `~/.m2/wrapper/dists` is executed with no integrity check whatsoever. Confirmed locally:
  `./mvnw -v` reports `Maven home: ~/.m2/wrapper/dists/apache-maven-3.9.16/56ba1f9f`.

Probes: `probe_release_job_restores_maven_cache`, `probe_mvnw_skips_checksum_for_existing_distribution` (both WEAK).

**Impact.** Anyone who can cause a cache entry to be written on a ref the release run can read — in practice, push
access to `main`, since GitHub scopes caches to the writing branch plus the default branch — can plant an altered
`apache-maven-3.9.16` or a trojaned jar in `~/.m2/repository`. The release job then runs that code while holding
the imported GPG private key and `CENTRAL_TOKEN`, and signs whatever comes out. The whole point of this pipeline is
that the bytes on Maven Central correspond to the reviewed source; a mutable cache in the signing job removes that
guarantee, and the human Publish step cannot detect it because the bundle looks correct.

**Exact fix.**
1. Remove `cache: maven` from the `publish` job's `setup-java` step, with a comment saying why (a release build
   must not restore state it did not verify). Keep it in `ci.yml` and in `sample-smoke`, which sign nothing.
2. Add `-Dmaven.repo.local="$RUNNER_TEMP/m2repo"` to both Maven invocations in the `publish` job so the local
   repository is empty at the start of the release.
3. Add `-C` (`--strict-checksums`) to the `deploy` invocation. If it fails on a real dependency, that failure is
   itself a finding to investigate, not a flag to drop.
4. Test: `probe_release_job_restores_maven_cache` flips to `FIXED`.

### M4 — A newline in the `workflow_dispatch` `version` input passes validation and injects into `$GITHUB_OUTPUT`

**Where:** `.github/workflows/release.yml`, step `Derive the release version`.

**Repro** (the workflow's own snippet, replayed verbatim):

```
$ v=$(printf '0.1.0\nmalicious=1')
$ printf '%s' "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' && echo ACCEPTED
ACCEPTED
$ case "$v" in *-SNAPSHOT) echo rejected;; *) echo "snapshot-check passed";; esac
snapshot-check passed
$ printf 'version=%s\n' "$v"     # what lands in $GITHUB_OUTPUT
version=0.1.0
malicious=1
```

Probe: `probe_multiline_version_accepted` (WEAK).

**Impact.** `grep -E` is line-oriented: the anchors `^` and `$` bind to a line, not to the string. The
`workflow_dispatch` UI textbox is single-line, but `gh workflow run -f version=$'…'` and the REST
`POST /actions/workflows/{id}/dispatches` endpoint accept arbitrary strings including newlines. The result is a
`$GITHUB_OUTPUT` file-command injection: the caller sets any step output of their choosing, including `timestamp`
(which is interpolated straight into the Maven command line as `-Dproject.build.outputTimestamp=…`, breaking the
reproducibility guarantee silently) and a second `version=` line that wins over the first. The `-SNAPSHOT` refusal
is bypassed the same way, since `case` matches the whole string and a trailing line can carry anything.
Exploitation needs write access; the point of a validator is that it holds anyway.

**Exact fix.** Replace the two checks with a single whole-string test that cannot see lines:

```bash
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "::error::'$version' is not a semver release version"; exit 1
fi
```

(bash `=~` anchors to the whole string and `.` never matches a newline, so `0.1.0\nmalicious=1` is rejected; the
step already runs under `bash` via `set -euo pipefail`, add `shell: bash` explicitly). Keep the `-SNAPSHOT` `case`
as a second belt. Test: `probe_multiline_version_accepted` flips to `FIXED`.

### M5 — Any tag on any commit starts a release; no environment gate, no ancestry check, no signature requirement

**Where:** `.github/workflows/release.yml`, `on.push.tags: v*`, and the absence of `environment:`.

**Repro.** `gh api repos/1of1Canopus/agent-guard/environments` → `{"total_count":0,"environments":[]}`. Branch
protection and rulesets return HTTP 403 ("Upgrade to GitHub Pro or make this repository public"), so today there is
no tag protection either. The workflow contains no `merge-base`, no `git verify-tag`, no `environment:`.
Probes: `probe_release_job_has_no_environment_gate`, `probe_release_does_not_check_tag_ancestry`,
`probe_release_does_not_verify_tag_signature` (all WEAK).

**Impact.** `git push origin v9.9.9` on a commit that lives only on a scratch branch, was never reviewed and is not
an ancestor of `main`, produces a signed, validated bundle under `com.housedevinci` sitting on the Portal. The
`autoPublish=false` design means a human must still press Publish, and that is the control that saves this — but it
is the *only* control, and the thing the human is shown is a component list, not a diff. The signing key has by then
already been applied to unreviewed bytes.

**Exact fix.**
1. Add to the `publish` job:
   ```yaml
   environment: release
   ```
   and create the `release` environment with Souhaile as a required reviewer. Move all four secrets from repository
   secrets to environment secrets so they are unreachable from any other workflow. **This requires the repository to
   be public** (see L7) or a paid plan; it is a gate on the first release, not on this merge.
2. Add a step before the build, on the tag path:
   ```bash
   git fetch --no-tags --depth=100 origin main
   git merge-base --is-ancestor "$GITHUB_SHA" origin/main \
     || { echo "::error::$GITHUB_SHA is not on main"; exit 1; }
   ```
   with `fetch-depth: 0` on the checkout.
3. Require the tag to be annotated and signed: `git verify-tag "$GITHUB_REF_NAME"`, after importing Souhaile's
   public key. Document the key id in `docs/RELEASING.md`.
4. Test: the three M5 probes flip to `FIXED`.

### M6 — `docs/RELEASING.md` leaks the private key twice: to the macOS clipboard, and to a temp directory that is never removed

**Where:** `docs/RELEASING.md`, Part 1 step 4.

**Step as written:**

```bash
gpg --armor --export-secret-keys <KEY_ID> | pbcopy
```

and, as the "sanity check":

```bash
export GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME"
gpg --armor --export-secret-keys <KEY_ID> | gpg --batch --import
gpg --list-secret-keys
unset GNUPGHOME
```

**Impact.** Two separate exposures of the release signing key, in the document Souhaile is told to follow literally.

* `pbcopy` puts the armoured secret key on the macOS general pasteboard. The pasteboard is readable by every process
  running as the user with no prompt, is captured by clipboard-history utilities, and — with Handoff/Universal
  Clipboard on, which is the default — is transmitted to every other Apple device signed into the same iCloud
  account. It persists until something else is copied.
* `unset GNUPGHOME` does not delete the directory. `mktemp -d` leaves a full `private-keys-v1.d` copy of the secret
  key under `$TMPDIR` (`/var/folders/…` on macOS), where it survives the session and is not covered by any cleanup
  the document mentions. The key is passphrase-protected, which lowers the severity; it is not zero, because
  `GPG_PASSPHRASE` is a separate secret that a laptop compromise may also reach.

**Exact fix.** Replace both blocks in `docs/RELEASING.md`:

```bash
# Set the secret straight from gpg to GitHub. The key never touches the clipboard,
# the shell history, or the filesystem.
gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard
gh secret set GPG_PASSPHRASE --repo 1of1Canopus/agent-guard   # prompts, reads from the tty, no history
```

and for the sanity check:

```bash
GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME" && export GNUPGHOME
trap 'gpgconf --kill all 2>/dev/null; rm -rf "$GNUPGHOME"; unset GNUPGHOME' EXIT
gpg --armor --export-secret-keys <KEY_ID> | gpg --batch --import
gpg --list-secret-keys
```

Add a sentence stating that the armoured key must never be written to a file, a clipboard, or a shell argument, and
that `gh secret set` is the only sanctioned path. If Souhaile prefers the web UI, say explicitly: select the block
in the terminal, paste into the secret box, then copy something harmless to clear the pasteboard.

### M7 — Apache-2.0 is declared in the POM and there is no licence text in the repository or in the jars

**Repro.** `git ls-files | grep -iE 'LICENSE|LICENCE|NOTICE'` → nothing.
`gh repo view --json licenseInfo` → `"licenseInfo": null`.
`unzip -l` of the two jars in the produced `central-bundle.zip`: `META-INF/MANIFEST.MF`,
`META-INF/maven/**`, spring metadata, `schema-postgresql.sql`, classes. No `LICENSE`, no `NOTICE`.
Probe: `probe_no_licence_file_in_the_repository` (WEAK).

**Impact.** The POM grants Apache-2.0 and this PR is what makes that grant permanent on Maven Central. Apache-2.0
§4(a) requires a copy of the licence to accompany distributed copies; §4(d) requires the `NOTICE` file to be
propagated if one exists. A regulated buyer's OSS-compliance review will open the jar, find no licence text, and
raise it. It is free to fix now and impossible to fix in `0.1.0` once published.

**Exact fix.**
1. Add `LICENSE` at the repository root — the verbatim Apache-2.0 text, unmodified.
2. Add `NOTICE` with the single line `Agent Guard\nCopyright 2026 House Devinci`.
3. In the root `pom.xml`, add a `maven-remote-resources`-free variant: a `<resources>` entry on `agent-guard-core`
   and `agent-guard-spring-boot-starter` copying `${maven.multiModuleProjectDirectory}/LICENSE` and `NOTICE` into
   `META-INF/`. This is *not* the deferred #26 item — #26 is about `THIRD-PARTY-NOTICES.txt`, which stays deferred;
   this is the project's own licence, which has no open question attached.
4. Test: `probe_no_licence_file_in_the_repository` flips to `FIXED`.

---

## LOW

### L1 — The reproducibility check does not attest the bytes that are actually published
The `publish` job builds three times: twice inside `scripts/verify-reproducible.sh`, then once more in
`./mvnw -B clean deploy -Prelease`. The jars that are signed and uploaded come from the third build and are never
compared with the two that were proved identical. The check proves the tree is deterministic; it does not prove the
release artifact is one of the two verified outputs. Probe: `probe_published_jars_are_never_checksum_compared` (WEAK).
**Fix:** make `verify-reproducible.sh` write `target/reproducible-sha256.txt`, and add a step after `deploy` that
recomputes SHA-256 for `agent-guard-{core,spring-boot-starter}/target/*.jar` and fails on any mismatch. Print the
table into `$GITHUB_STEP_SUMMARY` so the human pressing Publish sees it.

### L2 — Two releases of the same version can run at once
`concurrency: group: release-${{ github.ref }}`. A `workflow_dispatch` on `main` with `version: 0.1.0` and a push of
tag `v0.1.0` have different refs, so both run, both build, both sign, and both upload a deployment named
`agent-guard 0.1.0`. Probe: `probe_concurrency_group_is_ref_scoped` (WEAK).
**Fix:** `group: release-${{ inputs.version || github.ref_name }}`, keeping `cancel-in-progress: false`.

### L3 — `actions/checkout` leaves the `GITHUB_TOKEN` in `.git/config`
Default `persist-credentials: true`. Every Maven plugin, annotation processor and test that runs in the release job
can read the token from the checkout. `contents: read` limits the damage, but the release job is exactly the one
that should carry nothing it does not use, and it never talks to git after checkout.
Probe: `probe_checkout_persists_credentials` (WEAK). **Fix:** `persist-credentials: false` on both checkout steps
(add `fetch-depth: 0` on the `publish` one for M5's ancestry check, then re-add credentials only if that fetch needs
them — for a public repo it does not).

### L4 — Signed jars of a *failed* release are published as a workflow artifact
`Upload the release evidence` runs `if: always()` and includes `*.asc`. Signing happens at `verify`, the upload to
the Portal happens after; a run that fails at upload still produces a downloadable artifact containing
`agent-guard-core-0.1.0.jar` with a valid signature for a version that was never published and may never be.
Probe: `probe_evidence_uploaded_when_release_failed` (WEAK).
**Fix:** split the step — on failure upload only `**/target/THIRD-PARTY-NOTICES.txt` and the surefire reports; upload
the jars and `.asc` only `if: success()`. Name the failed artifact `release-<version>-FAILED`.

### L5 — `agent-guard-sample`'s `skipPublishing` does not do what the comment claims, and the arrangement is fragile
`agent-guard-sample/pom.xml` calls `skipPublishing` "belt and braces" against `excludeArtifacts`. The `-X` log shows
otherwise: on the sample module the plugin logs `(f) skipPublishing = true`, then
`Skipping Central Staging Publishing as no staged artifacts were found`, then
`Created bundle successfully …/central-bundle.zip` and `Going to upload …`. The sample is the **last** module in the
reactor, so it is the module that assembles and uploads the whole deployment. The sample is kept out of the bundle
by `excludeArtifacts` alone (verified: 54 files, three coordinates, no `agent-guard-sample`); `skipPublishing`
contributes nothing, and a future plugin version that honoured it at the aggregate step would make the release
silently upload nothing while reporting success.
**Fix:** remove `<skipPublishing>` from `agent-guard-sample/pom.xml` and correct the comment to say that
`excludeArtifacts` is the mechanism. Add a step after `deploy` asserting the bundle exists and contains exactly the
three expected coordinates and no `agent-guard-sample` (`unzip -l target/central-publishing/central-bundle.zip`),
so a silent no-op upload fails the run.

### L6 — No `SECURITY.md`, and the address the POM publishes does not exist
QUESTIONS #21 recommends putting `oss@housedevinci.com` in `SECURITY.md`; there is no `SECURITY.md`, only
`SECURITY-NOTES.md` (internal notes, not a disclosure policy). The POM ships `oss@housedevinci.com` to
repo1.maven.org permanently as the only contact.
**Fix:** add `SECURITY.md` with the address, a supported-versions table and a 90-day disclosure window, before
`v0.1.0`. Dollar's ruling stands that creating the mailbox is Souhaile's; the file is Thor's.

### L7 — The repository is private, and the published POM points at it
`gh repo view` → `"visibility": "PRIVATE"`. The POM's `url`, `scm` and `issueManagement` all resolve to
`https://github.com/1of1Canopus/agent-guard`, which 404s for everyone who is not a collaborator. Publishing 0.1.0
from a private repository ships permanent dead links in the POM, makes the Apache-2.0 grant unverifiable, and keeps
GitHub Environments and tag rulesets (M5) unavailable on the free plan.
**Fix:** the repository must be public before the first release. Add it to `docs/RELEASING.md` Part 2 step 1 as a
precondition with the other freeze checks.

---

## INFO

### I1 — `gpgArguments` duplicates a flag the plugin already passes
`pom.xml` sets `<gpgArguments><arg>--pinentry-mode</arg><arg>loopback</arg></gpgArguments>`. The actual command
line, from the `-X` log, is
`gpg --pinentry-mode loopback --batch --pinentry-mode loopback --passphrase-fd 0 --armor --detach-sign …`:
maven-gpg-plugin 3.2.8 adds it itself whenever a passphrase is supplied. Harmless, but the comment claims the flag
is "required because there is no tty", which credits the wrong actor. **Fix:** delete the `<gpgArguments>` block and
keep the comment, or keep the block and correct the comment to say it is belt-and-braces.

### I2 — Verified good: the passphrase never reaches a command line
From the `-X` log, every signing invocation is
`… '--passphrase-fd' '0' '--armor' '--detach-sign' …` — the passphrase is written to gpg's stdin, never to argv, so
it is not visible in `ps`, in the runner's process listing, or in a crash dump of the command line. No change.

### I3 — Verified good: the signing key is imported into an ephemeral `GNUPGHOME`
`actions/setup-java@dd06d9c` `src/gpg.ts`: `importKey` creates `mkdtemp($RUNNER_TEMP/setup-java-gpg-…)`, `chmod 0700`,
writes the armoured key with `flag: 'wx', mode: 0o600`, imports it, and `fs.rmSync`s the armoured file in a `finally`.
`src/cleanup-java.ts` removes the whole home in the post step. `src/auth.ts` writes `~/.m2/settings.xml` containing
only `${env.CENTRAL_USERNAME}` / `${env.CENTRAL_TOKEN}` and a `gpg.passphraseEnvName` property — never a value.
The runner's own `~/.gnupg` is never touched. No change.

### I4 — `-X` would dump both secrets in clear; nothing forbids adding it
The rehearsal was run with `-X` on purpose. Maven's debug dump prints the process environment:

```
[DEBUG] env.CENTRAL_TOKEN: CIPHERTOKEN-DEADBEEF-9911
[DEBUG] env.CENTRAL_USERNAME: CIPHERUSER-DEADBEEF-9911
[DEBUG] env.MAVEN_GPG_PASSPHRASE: CIPHERPASS-DEADBEEF-9911
```

25 occurrences of the fake markers across the 15 999-line log, all from that dump and from the Portal request's
`userId=` query parameter. The workflow does **not** use `-X`, and GitHub's automatic masking would render registered
secrets as `***` — but masking is exact-string and is the only remaining defence, so the day someone adds `-X` or
`-e` to debug a failing release the passphrase is one transformation away from the log.
Probe: `probe_nothing_forbids_maven_debug` (WEAK).
**Fix:** add a guard step to the `publish` job that greps the workflow's own Maven lines and fails on `-X`,
`--debug` or `-e`, or simply set `MAVEN_ARGS: -B` and a comment. Grepping `target/` and the produced bundle for the
three markers after the run found **nothing**: no secret is written to disk, into a jar, into a POM, or into the
bundle.

### I5 — Not a finding: `Public Domain` is not matching loosely
Thor flagged that `Public Domain` might over-match. Tested and closed with no change: matching is exact against the
canonical name after `licenseMerges`, not substring and not regex. `"Public Domain Dedication and License (PDDL)
1.0"` fails the gate, and so does `"Apache-2.0-with-a-nasty-rider"`. The only strings that reach `Public Domain` are
the four listed in the merge (`Public Domain`, `Public Domain, per Creative Commons CC0`, `CC0-1.0`, `CC0`).

### I6 — Verified good: `autoPublish=false` / `waitUntil=validated` are in effect on the wire
Not read from the effective POM but from the request the plugin actually made:

```
POST /api/v1/publisher/upload?name=agent-guard%200.1.0&publishingType=USER_MANAGED&userId=…
```

`USER_MANAGED` is the Portal's encoding of "stage, validate, wait for a human". The run then stopped on the fake
token with `Invalid request. Status: 401`.

### I7 — Verified good: the bundle contains exactly what it should
`unzip -l target/central-publishing/central-bundle.zip` → 54 files under exactly
`com/housedevinci/agent-guard-parent/0.1.0/`, `…/agent-guard-core/0.1.0/`, `…/agent-guard-spring-boot-starter/0.1.0/`,
each with `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar` as applicable plus `.asc`, `.md5`, `.sha1`, `.sha256`,
`.sha512`. No `agent-guard-sample`, no `.env`, no test resources, no `docker-compose`, no `settings.xml`, no
`.git`. Jar contents are classes, `META-INF/MANIFEST.MF`, `META-INF/maven/**`, `schema-postgresql.sql` and the
Spring metadata files — nothing else. The manifests carry no username and no build path.

### I8 — Verified good: reproducible, and the timestamp comes from the commit
`scripts/verify-reproducible.sh` run for real: 6 of 6 jars byte-identical across two clean builds,
**including both javadoc jars**, at `timestamp: 2026-09-08T13:26:32Z`. `scripts/git-commit-timestamp.sh` is
`TZ=UTC0 git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd` — the committer date of HEAD, not wall
clock. The `-D` override is honoured: every entry in the produced jars is stamped `09-08-2026 13:26`. The QUESTIONS
#24 javadoc exemption is currently unused, as Thor states. See L1 for what this does *not* prove.

### I9 — Verified good: pins, permissions, triggers
All three action pins match their tags via the GitHub tag API:
`actions/checkout` v7.0.1 → `3d3c42e5…`, `actions/setup-java` v6.0.0 → `dd06d9cb…`,
`actions/upload-artifact` v7.0.1 → `043fb46d…`, each an annotated-tag-free `commit` object equal to the pinned SHA.
`permissions: contents: read` at workflow level, applying to both jobs; `id-token` correctly not requested (the
plugin uses the Central user token, not OIDC). No `pull_request_target` in any of the three workflows. The Maven
wrapper carries `distributionSha256Sum` (which M3 explains is bypassable via the cache, not absent).

### I10 — Verified good: the keyserver step is current
central.sonatype.org's GPG requirements page, read 2026-09-08, names exactly three supported keyservers:
`keyserver.ubuntu.com`, `keys.openpgp.org`, `pgp.mit.edu`. `docs/RELEASING.md` uses `keyserver.ubuntu.com` and
explains the `keys.openpgp.org` user-id stripping correctly (QUESTIONS #23). The publish-portal-maven page still
documents plugin 0.9.0 with defaults `autoPublish=false` and `waitUntil=validated`, which is what the POM sets
explicitly. No change.

### I11 — POM metadata: correct, and no personal data beyond the role address
`url`, `scm.connection`, `scm.developerConnection`, `scm.url` and `issueManagement.url` all point at
`1of1Canopus/agent-guard`, which `gh repo view` confirms is the real repository (see L7 for its visibility). The
`child.*.inherit.append.path="false"` attributes work: the published `agent-guard-core-0.1.0.pom` inherits the
repository URL rather than `…/agent-guard-core`. `<licenses>` is a single correct Apache-2.0 block with
`<distribution>repo</distribution>` (see M7 for the missing text). The only personal data is the display name
"Souhaile (Canopus)" and `Europe/Paris`; the email is the role address. QUESTIONS #21 stands as Dollar ruled.

---

## What could not be verified without real credentials

Named here rather than left implied, because a skipped check is never a passing one.

1. **Central Portal validation itself.** The upload was driven to a real `POST /api/v1/publisher/upload` and stopped
   at HTTP 401 on the fake token. Whether the Portal accepts this bundle — signature check against the keyserver,
   POM completeness, javadoc/sources presence, namespace ownership — is unknown until a real token runs it.
2. **The signature Central will actually verify.** Signing was rehearsed with a throwaway 1-day RSA-3072 key in an
   ephemeral `GNUPGHOME`, deleted afterwards; it never touched the repository, CI, or a keyserver. Whether
   Souhaile's real key is on `keyserver.ubuntu.com`, and whether its user id survives there, is unverified.
3. **GitHub's secret masking on this repository.** I could not run the workflow, so the claim in I4 that
   `secrets.*` values would appear as `***` rests on documented behaviour, not on an observed run log.
4. **Cache-poisoning end to end (M3).** The two halves — setup-java caching `~/.m2/wrapper/dists`, and `mvnw`
   skipping the checksum for an unpacked distribution — were each verified directly. Planting a poisoned cache entry
   on `main` and observing the release job execute it was not attempted, and will not be.
5. **`environment: release` (M5).** Environments cannot be created on this repository while it is private on the
   free plan (`environments` → `total_count: 0`; rulesets → HTTP 403). The fix is prescribed but cannot be tested
   until L7 is done.
6. **Whether `oss@housedevinci.com` resolves.** No mail was sent. Dollar's ruling puts the mailbox on Souhaile.

---

## Fix list for Thor, in order

1. **M7** — `LICENSE` + `NOTICE` at the root, copied into `META-INF/` of both published jars.
2. **M1 + M2** — `tools/check-third-party-licences.sh`, all-of denial pass, wired at `verify`; do **not** add
   `excludedLicenses`; comment the anti-pattern in `pom.xml`.
3. **M3** — drop `cache: maven` from the `publish` job, `-Dmaven.repo.local="$RUNNER_TEMP/m2repo"`, `-C` on deploy.
4. **M4** — whole-string bash `=~` validation of `version`, `shell: bash` on the step.
5. **M5** — `environment: release`, `merge-base --is-ancestor` against `main`, `git verify-tag`.
6. **M6** — rewrite `docs/RELEASING.md` Part 1 step 4: `gh secret set` from a pipe, `trap` on the scratch keyring.
7. **L1** — `reproducible-sha256.txt` from the script, compared after `deploy`, printed to the step summary.
8. **L2** — version-scoped concurrency group.
9. **L3** — `persist-credentials: false` on both checkouts.
10. **L4** — split the evidence upload; jars and `.asc` only on success.
11. **L5** — remove `skipPublishing` from the sample, fix the comment, assert the bundle's contents after deploy.
12. **L6** — `SECURITY.md`.
13. **L7** — repository public before `v0.1.0` (Souhaile).
14. **I1** — drop the duplicated `gpgArguments`, or correct its comment.
15. **I4** — guard step refusing `-X` / `--debug` / `-e` in the release Maven line.

Every fix must flip its probe in `tools/cipher-probe-release-pipeline.sh`. When the script prints
`still weak: 0` and exits 0 — the inverted exit code is deliberate — the branch is ready for a re-verification pass.
