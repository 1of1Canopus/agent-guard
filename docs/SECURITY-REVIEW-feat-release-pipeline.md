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

---

## Re-verification (30aec6f)

Reviewer: `cipher`. Date: 2026-09-08. Scope: PR #9 at HEAD `30aec6f`, five commits by Isis on top of `41c3755`
(the first review). Read first: `STATUS.md` run 13, `QUESTIONS.md` #27, `docs/RELEASING.md`, `SECURITY.md`,
`tools/check-third-party-licences.sh`, `.github/workflows/release.yml`, `CHANGELOG.md`.

**Nothing in production code, in `pom.xml` or in the workflow was edited by this pass.** The only files this pass
changes are this document and `tools/cipher-probe-release-pipeline.sh` (my own probes).

### Verdict: **MERGE WITH FIXES**

No HIGH. Twelve of the first pass's fifteen fix-list items are closed and hold under attack. The fixes themselves
introduced eight new findings, four MEDIUM, four LOW, plus three INFO — one of which is that the first pass's I1
was never closed at all. Under the no-allowance rule none of them merges as-is. One of them, **N1**, is on its own
a merge blocker independent of severity: **this branch does not build from a clean checkout.**

| Severity | Count | Ids |
|---|---|---|
| HIGH | 0 | — |
| MEDIUM | 4 | N1 `verify` fails on a fresh clone · N2 the denial pass misses prose licence names · N3 the denial pass's coordinate is forgeable by the dependency's own name · N4 the bundle assertion points at a path the plugin never writes |
| LOW | 4 | N5 tag-signature check is off by default and unbound to the key id · N6 the `-X` guard misses two equivalent debug switches · N7 `RELEASING.md`'s scratch-keyring trap does not fire on a failing step · N8 `workflow_dispatch` skips the ancestry check |
| INFO | 3 | N9 the `classpath-exception` / `cpe` carve-out is a licence-name pattern · N10 the denial pass crashes on an empty `()` token · N11 I1 was never closed · N12 `RELEASING.md` still documents `skipPublishing` |

### Numbers

| Run | Result |
|---|---|
| `./mvnw -B clean verify -Prelease -Dgpg.skip=true` (working tree) | **220 tests** (core 161, starter 58, sample 1), 0 failures, **1 skip**, BUILD SUCCESS in **58.3s** |
| `./mvnw -B verify -DskipTests` **on a fresh `git clone`** | **BUILD FAILURE** — `exec:exec (check-third-party-licences) @ agent-guard-parent`: "no THIRD-PARTY-NOTICES.txt found under */target/" (**N1**) |
| `scripts/verify-reproducible.sh` | **6/6 jars byte-identical** across two clean builds, javadoc jars included, timestamp `2026-09-08T18:55:27Z`; checksum file written |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | **13 FIXED / 10 WEAK**, exit 1. All 13 first-pass probes flipped; the 10 WEAK are the new N-findings |
| `deploy -Prelease` on a `versions:set 0.1.0` clone, fake token | bundle built (**45 files**, no `agent-guard-sample`), upload stopped at the Portal's 401 |
| Docker | up; no test skipped for want of it. The one skip is the pre-existing Spring AI context test |

### The first pass, item by item

Verified in code **and** by attack, not by reading the diff.

| Id | State | How it was verified |
|---|---|---|
| M1 | closed, **incompletely** | `probe_licence_gate_accepts_dual_apache_or_gpl` flips: a real `verify` build against a synthetic `Apache-2.0` + `GPL-3.0` dependency now fails. But the denial pass only catches that spelling — see **N2**, **N3** |
| M2 | closed | No `<excludedLicenses>` anywhere; the anti-pattern is commented on the `third-party-notices` execution and in the script header |
| M3 | closed | `cache: maven` gone from `publish`, `rm -rf ~/.m2/wrapper/dists` before the first `mvnw`, `-Dmaven.repo.local="$RUNNER_TEMP/m2repo"` on both invocations, `-C` on deploy. New probe asserts the removal step precedes the first `mvnw` line |
| M4 | closed, holds | The real step body was extracted from the workflow and run against 12 inputs: `0.1.0\nmalicious=1` **rejected**, leading `v` rejected, `vv0.1.0` rejected, `1.0.0-SNAPSHOT` rejected on both paths, trailing space rejected, Arabic-Indic digits `١.٢.٣` rejected (bash `=~` `[0-9]` does not match them in a UTF-8 locale — checked directly). `1.0.0-snapshot` and `01.02.03` are accepted; neither is a Maven snapshot and neither is a finding |
| M5 (environment) | closed in code | `environment: release` present. Creating it with a reviewer is a release gate, below |
| M5 (ancestry) | closed for the tag path | Simulated on a scratch repository: tag on main's merge commit **accepted**, tag on a `--no-ff` branch tip **accepted**, tag on the squashed commit on main **accepted**, tag on the pre-squash branch tip **refused**, `origin/main` missing **refused** (fails closed). Not applied to `workflow_dispatch` — **N8** |
| M5 (signature) | **not closed** | Off unless a repository variable is set, and unbound to that key when it is — **N5** |
| M6 | closed, one residual | `pbcopy` is gone; `gh secret set` from a pipe is the only path; the pasteboard reasoning is written out. The `trap` claim is wrong — **N7** |
| M7 | closed | `LICENSE` at the root is the verbatim Apache-2.0 text (md5 `3b83ef96387f14655fc854ddc3c6bd57`); `NOTICE` is the two lines. `unzip -l` of the jars **inside the real bundle**: `META-INF/LICENSE` + `META-INF/NOTICE` in `agent-guard-core-0.1.0.jar`, `-sources.jar`, and both starter equivalents. Javadoc jars carry neither; not a finding |
| L1 | closed | `verify-reproducible.sh` writes `<sha256>  <name>` per jar, outside `target/` when `REPRODUCIBLE_SHA_FILE` is set, and the post-deploy step compares and prints a step-summary table. Run for real: 6/6 identical. It is reachable only if N4 is fixed first — the step before it always fails today |
| L2 | closed | `group: release-${{ inputs.version \|\| github.ref_name }}` |
| L3 | closed | `persist-credentials: false` on both checkouts, `fetch-depth: 0` on the publish one (which is what makes `origin/main` resolvable for the ancestry check) |
| L4 | closed | Evidence upload is `if: success()`; a separate `if: failure()` step uploads only notices and surefire reports as `release-<v>-FAILED` |
| L5 | **not closed** | `skipPublishing` is gone from the sample and the comment is corrected. The assertion step that was supposed to replace it never runs — **N4** |
| L6 | closed | `SECURITY.md` exists: address, supported-versions table, 90-day window, scope. It names `security@housedevinci.com` while the POM names `oss@housedevinci.com`: **two mailboxes**, both on the release gate |
| L7 | correctly deferred | Documented as a release gate in `RELEASING.md` Part 2 step 1 and in `STATUS.md`. Souhaile's |
| I1 | **not closed** | `pom.xml` still passes `--pinentry-mode loopback` and still says it is "required because there is no tty" — **N11** |
| I4 | closed, incompletely | The guard step exists and refuses `-X`, `--debug`, `-e` in `MAVEN_ARGS`/`MAVEN_OPTS` and on the two Maven command lines. Two equivalent switches walk past it — **N6** |

### Ruling on QUESTIONS.md #27 — Isis is right

`probe_mvnw_skips_checksum_for_existing_distribution` is **reclassified as not-a-finding** and has been removed.

The reasoning stands on its own terms. The probe was a text match on vendored Apache Software Foundation code
asserting a property no Maven Wrapper has and none is going to grow: `distributionSha256Sum` is compared against
the downloaded zip and nothing re-checks an already-unpacked distribution. The only change that would have turned
the probe green — a sidecar checksum written at install time — is writable by precisely the attacker M3 describes,
in the same write that plants the poisoned distribution. That is a marker against accidental corruption sold as a
defence against a hostile cache, and flipping a probe with it is the same failure mode as weakening the probe,
one level removed. Isis was right to refuse it and right to flag it rather than quietly leave the script at exit 1.

Two corrections to how it was closed, neither a criticism of the decision:

1. **A reclassified probe is deleted or replaced, never left WEAK.** A probe file whose exit code cannot reach 0 on
   a clean branch stops being evidence and starts being noise, and `RELEASING.md` Part 2 step 1 tells Souhaile to
   run this script and expect exit 0. That was my rule to enforce and I am enforcing it here rather than asking
   Isis to.
2. **The coverage should not go with it.** M3's real control is operational, so the probe should be too. It is
   replaced by `probe_release_job_can_exec_an_unverified_maven_distribution`, which is WEAK if `cache: maven`
   returns to the `publish` job, if the `rm -rf ~/.m2/wrapper/dists` step disappears, or if it drifts below the
   first `./mvnw` line in that job. It is FIXED at `30aec6f`.

The script now exits 0 on a branch with no open findings. It exits 1 today because of N1–N11, which is the correct
signal.

---

## MEDIUM

### N1 — `./mvnw verify` fails on a clean checkout: the licence denial pass runs on the parent before any notices exist

**Where:** `pom.xml`, `exec-maven-plugin` execution `check-third-party-licences` (root `<build><plugins>`, phase
`verify`), and `tools/check-third-party-licences.sh`'s fail-closed "no THIRD-PARTY-NOTICES.txt found" branch.

**Repro (executed).**

```
$ git clone --no-hardlinks <repo> fresh && cd fresh
$ ./mvnw -B verify -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true
[INFO] --- exec:3.6.3:exec (check-third-party-licences) @ agent-guard-parent ---
check-third-party-licences: no THIRD-PARTY-NOTICES.txt found under */target/ (did third-party-notices run first?)
[ERROR] Failed to execute goal ... (check-third-party-licences) on project agent-guard-parent:
        Command execution failed. Process exited with an error: 1
[INFO] BUILD FAILURE
```

Probe: `probe_verify_fails_on_a_clean_checkout` (WEAK, `CIPHER_PROBE_MAVEN=1`).

**Impact.** The execution is declared in the root `<build>`, so it is inherited by every module, and Maven runs the
parent's whole lifecycle first. At `agent-guard-parent:verify` no module has produced a `THIRD-PARTY-NOTICES.txt`
yet — `add-third-party` writes nothing for a `pom`-packaging module — so the script's fail-closed branch fires and
the build stops. `ci.yml` runs `./mvnw -B clean verify` on a fresh runner checkout: **CI is red on every build of
this branch.** The release job survives only by accident, because `verify-reproducible.sh` runs two `clean package`
builds before `clean deploy`, leaving notices files on disk for the parent's `verify` to find — which is the second
half of the problem: **when it passes on the parent, it passes by validating the previous build's notices files.**
Each module's `target/` is cleaned when its own turn in the reactor comes, so the parent's check systematically
reads stale evidence, and it is the last module's run that does the real work.

**Exact fix.** Make each module check its own module, and keep every jar module fail-closed:

1. Add `<arguments><argument>${project.build.directory}</argument><argument>${project.packaging}</argument></arguments>`
   to the `check-third-party-licences` execution in `pom.xml`.
2. In `tools/check-third-party-licences.sh`, take those two arguments; scan
   `<build directory>/THIRD-PARTY-NOTICES.txt` only. If the file is missing: exit 1 as today, **unless** the
   packaging is `pom`, in which case print one line saying the module declares no shipped dependencies and exit 0.
   Do not widen this to any other packaging and do not fall back to a tree-wide `find`.
3. Test, both of which must hold: `probe_verify_fails_on_a_clean_checkout` flips to FIXED (a fresh clone builds
   green), and deleting `agent-guard-core/target/THIRD-PARTY-NOTICES.txt` between `package` and `verify` still
   fails the build.

### N2 — The denial pass matches SPDX ids and the literal substring "gpl", so prose licence names pass on their permissive half

**Where:** `tools/check-third-party-licences.sh`, `DENIED_TOKENS` and `is_denied_token`.

**Repro (executed, one synthetic dependency line at a time, script exit code shown).**

| licence tokens declared alongside `Apache-2.0` | script |
|---|---|
| `GPL-3.0` | exit 1 — denied |
| `GPLv3` | exit 1 — denied |
| **`GNU General Public License v3`** | **exit 0 — clean** |
| **`Mozilla Public License, Version 2.0`** | **exit 0 — clean** |
| **`MPL 2.0`** | **exit 0 — clean** |
| **`Common Development and Distribution License (CDDL) v1.0`** | **exit 0 — clean** |
| **`Server Side Public License, v 1`** | **exit 0 — clean** |
| **`European Union Public Licence 1.2`** | **exit 0 — clean** |
| **`Business Source License 1.1`** | **exit 0 — clean** |
| **`Creative Commons Attribution-NonCommercial 4.0`** | **exit 0 — clean** |

Probe: `probe_denial_pass_misses_prose_licence_names` (WEAK).

**Impact.** This is M1, respelled. `is_denied_token` denies a token only if its lowercased form *contains* `gpl` or
is *exactly equal* to one of eighteen hyphenated SPDX ids. The tokens that actually reach it are POM-declared
`<name>` values after `licenseMerges`, and real POMs write prose: `h2database` declares "MPL 2.0" and "EPL 1.0";
GNU-licensed artifacts routinely write "GNU General Public License, version 2", which contains no `gpl` at all. The
script's own comment claims it "catches spellings such as … 'GNU General Public License v3'". It does not — that is
the first case I tried and it passed. A dual-declared dependency using any of these spellings clears the plugin's
allowlist on `Apache-2.0` and clears the denial pass because its copyleft half is unrecognised, which is exactly the
combination M1 exists to stop, and the result is permanent on Maven Central.

**Exact fix.** Match on a normalised form, not on the raw token, and cover the words as well as the ids.

1. Normalise before matching: lowercase, strip everything that is not `[a-z0-9]` (so `GPL-3.0`, `GPL 3.0`, `gplv3`
   and `GPL_3` all become `gpl3`).
2. Deny on **word patterns** as well as ids, at minimum: `generalpubliclicense` (covers GPL, LGPL and AGPL prose in
   one), `lessergeneralpublic`, `affero`, `mozillapubliclicense`, `commondevelopmentanddistribution`,
   `serversidepublic`, `businesssourcelicense`, `europeanunionpublic`, `noncommercial`, `elastic2`, `cpol`, plus
   the existing normalised ids.
3. Keep the denial *positive*: anything the pass does not recognise is not thereby allowed — that is the plugin's
   `<includedLicenses>` job, and it is the reason the two passes exist. Do not add "unknown = deny" here.
4. Test: `probe_denial_pass_misses_prose_licence_names` flips to FIXED. Every row in the table above must exit 1.

### N3 — The coordinate the denial pass matches is taken from text the dependency controls

**Where:** `tools/check-third-party-licences.sh`, the `perl -ne` extractor and `is_allowed_coordinate`.

**Repro (executed).**

```
# a dependency whose POM <name> is "evil (ch.qos.logback:logback-core:1.5.6 - http://x)"
(GPL-3.0) evil (ch.qos.logback:logback-core:1.5.6 - http://x) (c.s:evil:1.0 - no url defined)
  -> check-third-party-licences: clean          (exit 0)

# a dependency whose version carries a character outside [\w.-]
(GPL-3.0) x (c.s:syn:1.0+build - no url defined)
  -> check-third-party-licences: clean          (exit 0)
```

Probe: `probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name` (WEAK).

**Impact.** Two fail-open paths in one parser.

* The regex takes the **first** `(group:artifact:version - ` group on the line with a non-greedy `.*?`, and the
  dependency's own `<name>` is printed on that line *before* its real coordinate. A dependency named so that it
  contains an allowlisted coordinate in that shape is read as `ch.qos.logback:logback-core`, matches
  `ALLOWED_COORDINATES`, and every licence it declares is skipped without being looked at. The name is written by
  whoever published the dependency. The coordinate allowlist is the one part of this script the design leans on —
  "an exception is a coordinate a human wrote down" — and it is being read out of attacker-supplied text.
* A line the regex does not match at all is skipped in silence. `[\w.\-]` excludes `+`, `~` and `!`, all legal in a
  Maven version, so a dependency can be invisible to the gate by versioning itself `1.0+build`.

**Exact fix.**

1. Anchor the coordinate to the **end** of the line, not the first match: the notices format is
   `(<licences>) <name> (<groupId>:<artifactId>:<version> - <url>)`, so match the **last** parenthesised group on
   the line and take the coordinate from it. Widen the version character class to `[^\s:()]+`.
2. Count the lines. A line inside the dependency list that yields no coordinate must **fail** the build with
   "unparseable dependency line", not be skipped. Compare the parsed count against the plugin's own
   "Lists of N third-party dependencies." header and fail on a mismatch.
3. Test: `probe_denial_pass_coordinate_can_be_forged_by_the_dependency_name` flips to FIXED — both lines above must
   exit 1.

### N4 — The bundle assertion looks for the bundle in a directory the plugin never writes, so it always fails and the two steps after it never run

**Where:** `.github/workflows/release.yml`, step `Confirm the bundle contains exactly the three published
coordinates`, `bundle="agent-guard-sample/target/central-publishing/central-bundle.zip"`.

**Repro (executed, not inferred).** A clone with `versions:set -DnewVersion=0.1.0`, then
`./mvnw -s <scratch settings> deploy -Prelease -Dgpg.skip=true`, run to the Portal's 401 on a fake token:

```
$ find . -name central-bundle.zip
./target/central-publishing/central-bundle.zip
$ [ -f agent-guard-sample/target/central-publishing/central-bundle.zip ] && echo MATCH || echo MISMATCH
MISMATCH
$ unzip -l target/central-publishing/central-bundle.zip | tail -2
  1433398   45 files
$ unzip -l target/central-publishing/central-bundle.zip | grep -c agent-guard-sample
0
```

Probe: `probe_bundle_assertion_points_at_the_wrong_path` (WEAK).

**Impact.** `central-publishing-maven-plugin` assembles the aggregate bundle in the **top-level** project's build
directory, not in the last module's. L5's reasoning about the sample being the module that performs the upload is
right; the path it produced is wrong, and my own I7 in the first pass records the correct one
(`target/central-publishing/central-bundle.zip`). Consequences, in order:

1. The step fails with `::error::agent-guard-sample/target/… was not created` on **every** release run, after the
   upload has already happened. The run is red while a validated deployment sits on the Portal.
2. The assertion never inspects anything, so the control L5 asked for — the sample is not in the bundle, the three
   coordinates are — does not exist.
3. `Confirm the deployed jars match the reproducibility check` (L1) and `Upload the release evidence` (L4) are both
   `if: success()`. Neither ever runs. The human pressing Publish is shown no checksum table, which was L1's whole
   point.

**Exact fix.** Set `bundle="target/central-publishing/central-bundle.zip"`. Do not glob for it: a `find`-based
lookup would silently pass on a stale bundle from an earlier module. Keep the step `if: success()` and keep the
three-coordinate and no-sample assertions as written. Test:
`probe_bundle_assertion_points_at_the_wrong_path` flips to FIXED.

---

## LOW

### N5 — The tag-signature check is off unless a variable is set, and does not bind the signature to that key

**Where:** `.github/workflows/release.yml`, step `Verify the tag signature`.

**Repro.** The step reads:

```bash
if [ -z "${RELEASE_SIGNING_KEY_ID:-}" ]; then
  echo "::warning::RELEASE_SIGNING_KEY_ID is not configured; tag signature not verified. …"
  exit 0
fi
gpg --keyserver keyserver.ubuntu.com --recv-keys "$RELEASE_SIGNING_KEY_ID"
git verify-tag "$GITHUB_REF_NAME"
```

and, on the binding, executed with two throwaway keys in one keyring — `RELEASE` and `ATTACKER` — on a tag signed
by `ATTACKER`:

```
$ git verify-tag v0.1.0; echo $?
gpg: Good signature from "Cipher ATTACKER <a@example.invalid>"
0
$ git verify-tag --raw v0.1.0 | grep VALIDSIG
[GNUPG:] VALIDSIG 5F26203CCC9EF9199778D8A4E00D210DC53C5682 …
```

Probe: `probe_tag_signature_check_is_optional_and_unbound` (WEAK).

**Impact.** Two things, both of which my own spec-review rule forbids: *the secure mode is the default; never
prescribe a control as "optional, when set"*.

* Unset variable → warning → `exit 0`. The control's default state is off, and the signal that it is off is a
  `::warning::` in a log nobody reads on a run that goes green. `RELEASING.md` states this is deliberate so the
  `workflow_dispatch` rehearsal is not blocked — but the step is already `if: github.event_name == 'push'`, so it
  never runs on that path at all. The exemption buys nothing and costs the control.
* `git verify-tag` asserts that *some* key in the keyring produced a good signature, never that it was the
  configured one. On a fresh runner the keyring holds whatever `--recv-keys` returned, and nothing constrains
  `RELEASE_SIGNING_KEY_ID` to a full fingerprint — a short key id on `keyserver.ubuntu.com`, where anyone may
  upload, can return more than one key.

**Exact fix.**
1. Delete the skip branch. Unset `RELEASE_SIGNING_KEY_ID` on a tag push is `::error::` and `exit 1`. It is a
   release gate already on Souhaile's list; make the workflow enforce it instead of narrating it.
2. Require a fingerprint: `[[ "$RELEASE_SIGNING_KEY_ID" =~ ^[0-9A-Fa-f]{40}$ ]]` or fail.
3. Bind the signature to it:
   ```bash
   git verify-tag --raw "$GITHUB_REF_NAME" 2>&1 \
     | grep -q "^\[GNUPG:\] VALIDSIG ${RELEASE_SIGNING_KEY_ID^^} " \
     || { echo "::error::$GITHUB_REF_NAME is not signed by $RELEASE_SIGNING_KEY_ID"; exit 1; }
   ```
4. Update `docs/RELEASING.md` Part 1 step 6 accordingly: full fingerprint, and the variable is required, not
   optional. Test: `probe_tag_signature_check_is_optional_and_unbound` flips to FIXED.

### N6 — The `-X` guard misses `--errors` and the slf4j log level, which dump the same secrets

**Where:** `.github/workflows/release.yml`, step `Refuse Maven debug output in this job`.

**Repro (executed against this repository, with marker values in the environment).**

```
$ MAVEN_OPTS='-Dorg.slf4j.simpleLogger.defaultLogLevel=debug' ./mvnw -B -o -pl agent-guard-core process-resources
[DEBUG] env.CENTRAL_TOKEN: CIPHERTOKEN-REVERIFY-7731
[DEBUG] env.MAVEN_GPG_PASSPHRASE: CIPHERPASS-REVERIFY-7731
$ ./mvnw -B -o -X -pl agent-guard-core process-resources     # the flag the guard does block
[DEBUG] env.CENTRAL_TOKEN: CIPHERTOKEN-REVERIFY-7731
[DEBUG] env.MAVEN_GPG_PASSPHRASE: CIPHERPASS-REVERIFY-7731
```

and the guard step's own body, extracted from the workflow and run:

| `MAVEN_OPTS` | guard |
|---|---|
| `-X`, `--debug`, `-e` | refused |
| **`--errors`** | **passes** |
| **`-Dorg.slf4j.simpleLogger.defaultLogLevel=debug`** | **passes** |
| **`-Dorg.slf4j.simpleLogger.log.org.apache.maven=debug`** | **passes** |

Probe: `probe_debug_guard_misses_the_slf4j_log_level` (WEAK).

**Impact.** The guard matches three literal flags. Maven's debug output is not gated on those flags — it is gated
on the log level, which `MAVEN_OPTS` can set directly, and `-e` has a long form the guard does not know. The
identical clear-text dump of `CENTRAL_TOKEN` and `MAVEN_GPG_PASSPHRASE` comes out either way. GitHub's masking is
still there and these values are registered secrets, so this is the same defence-in-depth loss I4 described, not a
new class of exposure — but a guard that names three spellings of a thing it does not actually gate on invites the
belief that the job is safe from it.

**Exact fix.** In the same step, extend both the environment check and the two static command-line checks to
also refuse `--errors` and any occurrence of `simpleLogger`, `defaultLogLevel` or `maven.debug` in `MAVEN_ARGS` /
`MAVEN_OPTS`. Then close the hole rather than only naming it: set `MAVEN_ARGS: -B` at job level and assert that
`MAVEN_OPTS` in this job is exactly the `-Dmaven.repo.local=…` the reproducibility step needs. Test:
`probe_debug_guard_misses_the_slf4j_log_level` flips to FIXED.

### N7 — `RELEASING.md`'s scratch-keyring `trap` does not fire on a failing step, and the document says it does

**Where:** `docs/RELEASING.md`, Part 1 step 4, the sanity-check block, and the sentence under it.

**Repro (executed, the block exactly as written, pasted into a shell).**

```
scratch keyring: /var/folders/…/tmp.r4k7piQVKS
--- after the failing step, still inside the same shell ---
  directory STILL EXISTS: /var/folders/…/tmp.r4k7piQVKS
  GNUPGHOME is still exported: /var/folders/…/tmp.r4k7piQVKS
--- after the shell exited ---
  cleaned up on shell exit
```

Probe: `probe_releasing_scratch_keyring_trap_does_not_fire_on_failure` (WEAK).

**Impact.** M6's real leaks — `pbcopy` and a scratch keyring with no cleanup at all — are closed, and this is the
residue. `trap … EXIT` set at the top level of the shell Souhaile is told to paste into fires when **that shell**
exits, i.e. when he closes the terminal tab, not when a step in the block fails. The document says "cleaned up
automatically, key included, even if a step above it fails", which is the one case it does not cover. Until the tab
closes, a directory under `$TMPDIR` holds `private-keys-v1.d` for the release key, and `GNUPGHOME` stays exported,
so every later `gpg` command in that session — including `gpg --send-keys` in step 3 — silently operates on the
throwaway keyring instead of his own.

**Exact fix.** Put the block in a subshell so the trap has a scope that ends with the check, and drop the now
inaccurate sentence:

```bash
(
  GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME" && export GNUPGHOME
  trap 'gpgconf --kill all 2>/dev/null; rm -rf "$GNUPGHOME"' EXIT
  gpg --armor --export-secret-keys <KEY_ID> | gpg --batch --import
  gpg --list-secret-keys                    # the key must appear
)
```

Say what is true: the subshell exits at the closing parenthesis, on success or on failure, and the trap removes the
keyring then; `GNUPGHOME` never leaks into the outer shell. Test:
`probe_releasing_scratch_keyring_trap_does_not_fire_on_failure` flips to FIXED.

### N8 — `workflow_dispatch` skips the ancestry check entirely

**Where:** `.github/workflows/release.yml`, step `Verify the released commit is on main`,
`if: github.event_name == 'push'`.

**Repro.** Static, and the step's comment states it: "Only meaningful on the tag-push path; `workflow_dispatch`
releases whatever is checked out on its own ref, which is already gated by who can trigger a `workflow_dispatch`
run." Probe: `probe_ancestry_check_skips_the_dispatch_path` (WEAK).

**Impact.** The people who can start a `workflow_dispatch` run are the people who can push a tag — the same set
M5 was written about, so the trigger is not a narrower privilege. **Actions → Release → Run workflow** on a scratch
branch builds, signs and uploads a bundle from a commit that is not on `main`, with the ancestry check skipped by
construction. The `release` environment's reviewer gate does block it before the job starts, once that environment
exists, and that is why this is LOW rather than MEDIUM — but the reviewer is shown a ref name, not a diff, and the
check is free to run on this path.

**Exact fix.** Drop the `if:` and run the check on both paths — on a dispatch, `$GITHUB_SHA` is the tip of the ref
that was chosen, which is exactly what is about to be released. Keep the `git fetch` and the failure message as
they are. If a rehearsal from a branch is genuinely wanted, make it an explicit `workflow_dispatch` input
(`allow_off_main: false` by default) that is refused unless it is set, rather than a silent skip. Test:
`probe_ancestry_check_skips_the_dispatch_path` flips to FIXED.

---

## INFO

### N9 — The `classpath-exception` / `cpe` carve-out is a licence-name pattern, which the script's own design forbids
`is_denied_token` allows any token containing `gpl` if it also contains `classpath-exception`, `classpath exception`
or `cpe`. Executed: `GPL-3.0-with-classpath-exception` passes, and so does `GPL-3.0 see cpe notice` — `cpe` is a
three-character substring. The script's stated principle is "an exception is a coordinate a human wrote down, never
a licence-token pattern", and this is a licence-token pattern. It is also dead weight: the only artifact in the
tree that needs it, `jakarta.annotation:jakarta.annotation-api`, is already in `ALLOWED_COORDINATES` and never
reaches the token check. It can therefore only ever admit something new that no human has looked at. That
prescription was mine in the first pass and it was wrong. **Fix:** delete the qualifier carve-out; every `gpl`
token is denied, and a genuine classpath-exception dependency is admitted the same way logback is — by a coordinate
a human wrote down.

### N10 — The denial pass dies on an empty `()` licence token
Executed: a dependency line carrying `()` produces `check-third-party-licences.sh: line 114: tok_list[@]: unbound
variable` and exit 1. It fails closed, which is the right direction, but on a shell error rather than a verdict, and
`set -u` ends the script there, so every file and line it had not yet reached goes unscanned. Reachable only from a
notices file, whose content comes from third-party POMs. Probe:
`probe_denial_pass_crashes_on_an_empty_licence_token` (WEAK). **Fix:** `IFS='|' read -ra tok_list <<<"$tokens" ||
true` and iterate `"${tok_list[@]:-}"`; treat a dependency whose token list is empty as an unparseable line under
N3's counting rule.

### N11 — I1 was never closed
`pom.xml`'s `maven-gpg-plugin` block still carries `<gpgArguments><arg>--pinentry-mode</arg><arg>loopback</arg>`
and the comment above it still reads "loopback pinentry is required because there is no tty". The plugin passes
that flag itself whenever a passphrase is supplied — the first pass read it off the real command line:
`gpg --pinentry-mode loopback --batch --pinentry-mode loopback --passphrase-fd 0 …`. Harmless, and it is on the
fix list as item 14 of 15, closed in neither the commits nor `CHANGELOG.md`. Probe:
`probe_gpg_arguments_comment_still_credits_the_wrong_actor` (WEAK). **Fix:** as prescribed the first time — delete
the block, or keep it and say it is belt-and-braces. Under the no-allowance rule an INFO is not a "later".

### N12 — `RELEASING.md` still documents `skipPublishing`
The "How the pieces fit" table's `agent-guard-sample/pom.xml` row still lists `skipPublishing` among the properties
that keep the sample unpublished. L5 removed it, and the pom's own comment now explains at length why it was
removed. Doc-only; no probe. **Fix:** drop it from the table row.

---

## Fix list for Isis, in order

1. **N1** — module-scoped licence check (`${project.build.directory}` + `${project.packaging}` as arguments); a
   fresh clone must build green and a jar module with no notices file must still fail.
2. **N4** — `bundle="target/central-publishing/central-bundle.zip"`.
3. **N2** — normalise-then-match, and deny on word patterns as well as SPDX ids.
4. **N3** — anchor the coordinate to the last group on the line, widen the version class, fail on any unparseable
   dependency line.
5. **N5** — no skip branch, require a 40-hex fingerprint, bind with `git verify-tag --raw` + `VALIDSIG`; update
   `RELEASING.md` Part 1 step 6.
6. **N8** — run the ancestry check on both trigger paths.
7. **N6** — guard `--errors`, `simpleLogger`, `defaultLogLevel`, `maven.debug`; pin `MAVEN_ARGS: -B`.
8. **N7** — subshell around the `RELEASING.md` scratch-keyring block; correct the sentence.
9. **N9** — delete the `classpath-exception` / `cpe` carve-out.
10. **N10** — survive an empty licence token.
11. **N11** — close I1 (`gpgArguments`).
12. **N12** — drop `skipPublishing` from the `RELEASING.md` table.

Every one has a probe in `tools/cipher-probe-release-pipeline.sh` except N12. When the script prints
`still weak: 0` and exits 0, this branch is ready for the next re-verification pass.

---

## Release gates — Souhaile's checklist, in order

None of these blocks the merge of PR #9. All of them must be true before `v0.1.0` is tagged, and the first two
before the third is even possible.

- [ ] **1. Make `1of1Canopus/agent-guard` public.** Everything below depends on it: GitHub Environments and tag
      rulesets do not exist on a private repository on the free plan (`gh api …/environments` →
      `total_count: 0`; rulesets → HTTP 403), and the POM's `url`, `scm` and `issueManagement` all point at a
      repository that 404s for everyone else, permanently, once 0.1.0 is on Maven Central. (L7)
- [ ] **2. Two mailboxes exist and forward.** `oss@housedevinci.com` — the address published in the POM's
      `<developers>` block, permanent on repo1.maven.org (QUESTIONS #21). `security@housedevinci.com` — the address
      in `SECURITY.md`, the only channel a vulnerability report has. Remove the placeholder warning at the top of
      `SECURITY.md` once both are confirmed. (L6)
- [ ] **3. The four secrets, set from a pipe, never from the clipboard.** `CENTRAL_USERNAME`, `CENTRAL_TOKEN`,
      `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`. Follow `docs/RELEASING.md` Part 1 step 4 literally:
      `gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard`.
      The armoured key must not touch a file, the pasteboard, or a shell argument. (M6; and see N7 — do not run the
      sanity-check block until it has been wrapped in a subshell)
- [ ] **4. Create the `release` environment with yourself as a required reviewer, and move all four secrets into
      it.** Repository → Settings → Environments → New environment → exactly `release`. The workflow already
      declares `environment: release`; until this exists GitHub creates it implicitly with **no protection rules**,
      so the line is a placeholder, not a gate. Environment secrets keep the signing key unreachable from any other
      workflow. (M5)
- [ ] **5. Set the `RELEASE_SIGNING_KEY_ID` repository *variable*** (Settings → Secrets and variables → Actions →
      **Variables**, not Secrets — it is a key id, not a secret) to the **full 40-character fingerprint** of the key
      you sign release tags with, and confirm that key is on `keyserver.ubuntu.com`. Tag with `git tag -s`, never
      `-a`. (M5, N5)
- [ ] **6. Tag the commit as it exists on `main`.** The workflow refuses a tag whose commit is not an ancestor of
      `origin/main` — verified on a scratch repository: a tag on a merge commit or on a squashed commit on `main`
      passes, a tag on the pre-squash branch tip is refused. If PRs are squash-merged, tag after the merge, on
      `main`, not on the PR branch head.
- [ ] **7. Press Publish yourself, the first time and every time.** `autoPublish=false` /
      `publishingType=USER_MANAGED` is the last control in the chain and the only one that is a human. Before
      pressing it, read the component list: exactly `agent-guard-parent`, `agent-guard-core`,
      `agent-guard-spring-boot-starter`, each with `.pom`, `.jar`, `-sources.jar`, `-javadoc.jar` and an `.asc`
      for each — **and no `agent-guard-sample`**. Also read the checksum table in the job summary, which is what
      L1 exists to put in front of you: it should appear once N4 is fixed. If anything is wrong: **Drop**. A
      version that reaches Maven Central can never be changed or removed.

## What could not be verified without real credentials or a public repository

Named rather than implied. A skipped check is never a passing one.

1. **The workflow has still never run.** Everything it does was executed locally instead, including the deploy,
   which reached `POST /api/v1/publisher/upload` and stopped at the Portal's 401 on a fake token. N4 in particular
   is a bug that only a real run would have surfaced, and there has been no real run.
2. **Central Portal validation of this bundle** — signature check against the keyserver, POM completeness,
   namespace ownership — unknown until a real token runs it.
3. **`environment: release`** cannot be created while the repository is private on the free plan, so the M5
   reviewer gate is declared but untested.
4. **GitHub's secret masking on this repository** rests on documented behaviour; no run log exists to confirm it.
5. **Cache poisoning end to end (M3)** was not attempted and will not be. The fix is verified by construction: no
   cache is restored, and `~/.m2/wrapper/dists` is removed before the first `mvnw` invocation.
6. **Whether either mailbox resolves.** No mail was sent.

---

# Final verification (78c808e)

Cipher, 2026-09-08/09. Branch `feat/release-pipeline`, PR #9, HEAD `78c808e`. Third pass.
Scope: confirm N1–N12 closed, attack the surfaces the N-fixes introduced, and audit the
FSL-1.1-ALv2 switch.

The pass started on `1da507e` ("build(licence): switch the core to FSL-1.1-ALv2") and was
re-run on `78c808e` ("build(licence): spell the licensor HouseDevinci everywhere", Dollar,
one commit on top: `Housedevinci` → `HouseDevinci` in `LICENSE` and `NOTICE`,
`House Devinci` → `HouseDevinci` in the POM `<organization>` and the developer's
`<organization>`; 4 changed lines, nothing else). Every number below is from `78c808e`.
The only finding the extra commit moved is F8, which it created.

## Verdict

**MERGE WITH FIXES** — 1 MEDIUM, 6 LOW, 2 INFO. Nothing HIGH. Every one of N1–N12 is
genuinely closed and I could not reopen any of them by their original route; the MEDIUM
below is N3 respelled through a field the N3 fix did not consider, found by attacking the
new parser rather than by re-running the old probe.

Under Souhaile's no-allowance rule (2026-09-07) F1–F9 are all fixed before merge. None of
them is a reason to redesign anything: F2 is one parser function, F1 and F3 are one regex
each, F4/F5 are entries in a list, F9 is a test fixture, F6/F7/F8 are text.

| id | sev | one line |
|---|---|---|
| F1 | LOW | `<excludedGroups>com\.housedevinci</excludedGroups>` is a substring test: `com.housedevinci-evil` and `xcom.housedevinci` are excluded from **both** licence gates |
| F2 | MEDIUM | the last-paren-group coordinate can still be forged — not from the dependency `<name>` (N3, closed) but from its `<url>` |
| F3 | LOW | the `VALIDSIG` match binds the **signing subkey**, not the primary key `RELEASING.md` tells Souhaile to configure; the first real release is refused |
| F4 | LOW | the deny pattern `mpl` matches "si**mpl**ified" and "exa**mpl**e": `Simplified BSD License` is denied |
| F5 | LOW | `eupl12`/`sspl10` are version-pinned: `EUPL v1.1`, bare `SSPL`, `OSL-3.0`, `CPAL` all pass the denial pass |
| F6 | INFO | `pom.xml` still comments "Apache-2.0 — the licence of this project" |
| F7 | LOW | `CONTRIBUTING.md` states no inbound licence terms; FSL has no contribution clause and the repo is about to be public |
| F8 | INFO | `78c808e` says "everywhere", but `docs/RELEASING.md` still names the signing key's real name `House Devinci` and the Portal organisation `Housedevinci` |
| F9 | LOW | `SampleEndToEndTest` is wall-clock dependent — the budget window is epoch-aligned and tumbling, so the four calls can straddle a boundary and the `BUDGET_EXCEEDED` assertion fails. Seen for real in this pass |

## Numbers

All measured on this machine, Docker up, `git config core.hooksPath .githooks` set, JDK
Temurin 21.0.10, HEAD `78c808e`. Nothing skipped.

| run | result | time |
|---|---|---|
| fresh `git clone` of `feat/release-pipeline` into the scratchpad, `./mvnw -B verify` | **BUILD SUCCESS**, exit 0 | 46.6 s (Maven), 48.1 s wall |
| repo `./mvnw -B verify`, run 1 | **BUILD FAILURE**, exit 1 — `SampleEndToEndTest:155`, see **F9** | 40.9 s |
| repo `./mvnw -B verify`, runs 2, 3, 4 | **BUILD SUCCESS**, exit 0, three times | 35.1 s / 33.5 s / 33.8 s |
| repo `./mvnw -B clean verify -Prelease -Dgpg.skip=true` | **BUILD SUCCESS**, exit 0 | 46.7 s |
| `scripts/verify-reproducible.sh` | 6/6 artifacts byte-identical across two clean builds, exit 0 | 27.7 s |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` | **23/23 N-and-earlier probes FIXED**, 9 new F-probes WEAK, exit 1 (32 probes total) | 30.0 s |

Tests, identical in every green run, plain and release: core **161** passed / 0 failed /
0 errors / 0 skipped; starter **58** passed / 0 failed / 0 errors / **1 skipped**
(`CipherProbeJedisPinningTest`, excluded by `agentguard.surefire.exclude` as before); sample
**1** passed. Reproducibility, build 1 vs build 2: all six artifacts `same` — e.g.
`agent-guard-core-0.1.0-SNAPSHOT.jar`
`2a37890950fbc6e80532268e0b4d22b0576c14037c397fd93b2e147efdaee7ac`.

The four builds at `1da507e`, before Dollar's spelling commit, were green as well
(fresh clone 47.1 s, repo verify 34.3 s, release profile 48.4 s, reproducible 26.8 s); the
numbers above supersede them.

## N1–N12: confirmed closed

Each by its own probe flipping and, where the probe is static, by an independent repro.

| id | how I confirmed it, beyond the probe |
|---|---|
| N1 | a genuinely fresh `git clone` into the scratchpad, never built before: `./mvnw -B verify` green in 47 s. The parent module now prints `check-third-party-licences: pom module, no THIRD-PARTY-NOTICES.txt`, each jar module checks its own `target/`. |
| N2 | `--self-test` runs 20 deny cases and 7 allow cases, all correct. I re-ran the whole N2 repro table plus eight phrasings that were not in it (`GPL v2 or later`, `LGPL-2.1+`, `AGPLv3`, `EUPL 1.2`, `SSPL-1.0`, `CC BY-NC-SA 4.0`, an empty token, a URL-only token): the first six are denied, the empty token denies nothing and does not crash. Two gaps and one false positive remain — F4, F5. |
| N3 | the dependency-`<name>` forgery is dead: `(Apache-2.0) (GPL-3.0) evil (ch.qos.logback:logback-core:1.5.6 - http://x) (cipher.synth:evil-a:1.0 - no url defined)` now parses as `cipher.synth:evil-a` and is DENIED. The same idea moved into the `<url>` still works — **F2**. |
| N4 | reproduced the real thing rather than trusting the note: `versions:set -DnewVersion=0.1.0` then `./mvnw -B -s <scratch settings> clean deploy -Prelease` with a fake Central token. The bundle was written to **`<top-level>/target/central-publishing/central-bundle.zip`** — the exact path the workflow asserts — and contains `agent-guard-parent`, `agent-guard-core`, `agent-guard-spring-boot-starter` (`.pom`, `.jar`, `-sources.jar`, `-javadoc.jar`) and **no `agent-guard-sample`**. The run then stopped at the Portal's `401`. Note for the record: on a `-SNAPSHOT` version the plugin takes the snapshot-deploy path and no bundle is assembled at all, so this only reproduces on a release version — which is what the workflow always sets. |
| N5 | the step now fails closed when `RELEASE_SIGNING_KEY_ID` is unset, rejects a short id or an email, and greps `VALIDSIG <fpr>`. The binding is real but bound to the wrong field — **F3**. |
| N6 | `MAVEN_OPTS` is pinned at workflow level and the guard asserts equality, not just absence of a flag. I tested the obvious escape: `JAVA_TOOL_OPTIONS=-Dorg.slf4j.simpleLogger.defaultLogLevel=debug` **does** turn on `[DEBUG]` (666 lines) when `MAVEN_OPTS` is unset, and **does not** when the workflow's pin is present — `JAVA_TOOL_OPTIONS` is prepended and `MAVEN_OPTS` appended, so the later `-D` wins. The pin is what closes it; the guard alone would not have. See the note below on `.mvn/maven.config`. |
| N7 | the sanity block is inside `( … )` in `RELEASING.md`; the trap fires on the subshell. |
| N8 | the ancestry step is unconditional. Reproduced on a scratch repository: a tag on a scratch branch is REJECTED, a tag on the tip of `main` PASSES, and with `origin/main` absent `git merge-base` errors and the step exits 1 — fail closed. `$GITHUB_SHA` is always a commit sha on both triggers, so there is no "branch name instead of a sha" case to exploit; `actions/checkout` with `fetch-depth: 0` fetches `+refs/heads/*:refs/remotes/origin/*`, so `origin/main` exists. |
| N9 | `ALLOWED_COORDINATES` holds three coordinates and there is no licence-token carve-out anywhere in the script. |
| N10 | `is_denied_token ""` returns not-denied and the scan survives it under `set -u`. |
| N11 | the stale `pom.xml` phrasing is gone. |
| N12 | `skipPublishing` no longer appears in `RELEASING.md`. |

## MEDIUM

### F2 — The coordinate the denial pass trusts can still be forged, now from the dependency's URL

`tools/check-third-party-licences.sh`, `parse_notices`. N3 moved the coordinate from the
first paren group to the **last** one, on the reasoning that "the notices format always
places the real coordinate last". It does — but the group scanner is
`while ($rest =~ /\(([^()]*)\)/g)`, and `[^()]*` cannot span a nested pair. A dependency's
project `<url>` is free text on the same line, *inside* the coordinate group, and it may
contain parentheses. When it does, the outer group never matches and the scanner returns the
**inner** one instead — which the dependency's author chose.

**Repro** (`tools/check-third-party-licences.sh <dir> jar` on a synthetic notices file):

```
Lists of 1 third-party dependencies.
     (Apache-2.0) (GPL-3.0) evil-url (cipher.synth:evil-b:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y))
```

`parse_notices` emits `OK  ch.qos.logback:logback-core:1.5.6  Apache-2.0|GPL-3.0`. That
coordinate is on `ALLOWED_COORDINATES`, so the line is skipped, licences unchecked, and the
script exits **0**. Run side by side with the N3 line in the same file, the N3 line is denied
and this one is not. The `Lists of N` count check is no backstop: the line parses cleanly, so
`parsed_count` still matches.

**Impact.** The same class as N3: a dependency that declares two **cumulative** licences (a
permissive one to pass `<includedLicenses>`, a copyleft one that this pass exists to catch)
and sets its own `<url>` to `http://x/(ch.qos.logback:logback-core:1.5.6 - y)` passes both
gates, and `THIRD-PARTY-NOTICES.txt` ships as release evidence with a GPL-3.0 declaration
nobody was told about. Both fields are controlled by whoever publishes the dependency.

**Fix (Isis).** Do not tokenise with `[^()]*`. Scan the line tracking paren **depth** and
collect the top-level groups; take the last top-level group and validate its `g:a:v` shape
exactly as now. Under a depth-aware scan the line above yields the top-level group
`cipher.synth:evil-b:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y)` and the real
coordinate `cipher.synth:evil-b`, which is denied. Also require the line to end with `)`
after the last top-level group; anything else is `UNPARSEABLE` and fails closed, as today.
While you are there: a URL containing a balanced pair, e.g.
`https://en.wikipedia.org/wiki/Foo_(bar)`, is today reported UNPARSEABLE **and** trips the
count check — fail-closed but a false build break on a legitimate dependency; the depth-aware
scan fixes that in the same edit. Extend `--self-test` with both lines (forged URL must be
denied, Wikipedia-style URL must parse) so the table covers the parser and not only
`is_denied_token`.
Probe: `probe_denial_pass_coordinate_forged_by_the_url` (WEAK).

## LOW

### F1 — `excludedGroups` is a substring test, and an excluded dependency is checked by neither gate

`pom.xml`, `third-party-notices` execution:
`<excludedGroups>com\.housedevinci</excludedGroups>`. license-maven-plugin 2.7.1 wraps a
group pattern (`ArtifactFilters.toGaPattern`, verified in the plugin's own bytecode) as
`[^:]*(<pattern>)[^:]*:[^:]+` and matches it against `groupId:artifactId` with
`Matcher.matches()`. The `[^:]*` on both sides make the configured pattern a **substring**
test on the groupId.

**Repro**, three real builds against a fresh clone with a synthetic dependency added to
`agent-guard-core`, each declaring `GNU General Public License, version 3`, served from a
scratch file repository:

| dependency groupId | `./mvnw -B verify` |
|---|---|
| `com.housedevinci-evil` | **BUILD SUCCESS** — never scanned |
| `xcom.housedevinci` | **BUILD SUCCESS** — never scanned |
| `com.plainly.evil` (control) | **BUILD FAILURE**, `License: 'GNU General Public License, version 3' used by 1 dependencies` |

**Impact.** An excluded artifact is not a third party at all: it never reaches
`<includedLicenses>` **and** it is never written to `THIRD-PARTY-NOTICES.txt`, so the denial
pass cannot see it either. Both gates are bypassed at once, silently, and the notices file
that ships as release evidence does not mention the dependency. Nothing in the tree matches
today, so this is a hole waiting for a dependency, not a live leak — hence LOW, not MEDIUM.

**Fix (Isis).** Anchor the pattern so it can only match our own groupId and its subgroups,
given the wrapping the plugin applies:
`<excludedGroups>^com\.housedevinci(\.[^:]*)?(?=:)</excludedGroups>`. The leading `^` forces
the plugin's own `[^:]*` prefix to match empty; the lookahead forces its `[^:]*` suffix to
match empty. Verify with the same three synthetic dependencies: the first two must now fail
the build, `com.housedevinci:agent-guard-core` must still be excluded (a plain
`./mvnw -B verify` staying green is that check).
Probe: `probe_excluded_groups_also_excludes_lookalike_groups` (WEAK).

### F3 — The tag-signature check binds the signing subkey; `RELEASING.md` tells Souhaile to configure the primary

`.github/workflows/release.yml`, "Verify the tag signature":

```
grep -q "^\[GNUPG:\] VALIDSIG ${fingerprint} " /tmp/verify-tag.out
```

GnuPG's `VALIDSIG` status line is
`VALIDSIG <fpr-of-the-key-that-signed> … <primary-key-fpr>`. When the key has a signing
subkey — which `git tag -s` uses **even when `-u` names the primary** — field 1 is the
subkey and the primary fingerprint is the last field.

**Repro**, two throwaway keys, `git tag -s -u <primary fingerprint>` in each case:

| key shape | `VALIDSIG` line | workflow grep, `RELEASE_SIGNING_KEY_ID` = primary fpr |
|---|---|---|
| primary `[SC]`, no signing subkey | `VALIDSIG B797…85DF … B797…85DF` | matches — release proceeds |
| primary `[C]` + subkey `[S]` | `VALIDSIG 893C…D8D4 … 836A…214E` | **no match** — `::error::v0.1.0 is not signed by 836A…214E` |

**Impact.** Fail-closed, so this is not a bypass — but `docs/RELEASING.md` line 201 hands
Souhaile the command that produces the **primary** fingerprint
(`gpg --fingerprint <KEY_ID> | awk '/Key fingerprint/…'`), and the checklist repeats "full
40-character fingerprint". If his release key has a signing subkey, every release is refused
with a message that says the tag is not signed by his own key. The workaround someone would
reach for under time pressure — putting the *subkey* fingerprint in the variable — pins the
wrong thing: the control is supposed to bind the identity, and a subkey is rotated and
revoked independently of it.

**Fix (Isis).** Match the primary-key fingerprint, the last field, which is correct for both
key shapes (proved above — for a primary-signed tag the last field is the primary too):

```
grep -qE "^\[GNUPG:\] VALIDSIG [0-9A-F]{40} .* ${fingerprint}$" /tmp/verify-tag.out
```

Keep the 40-hex validation of the variable. Add one sentence to `docs/RELEASING.md` Part 1
step 6 and to the release checklist: the value is the **primary** key fingerprint, and the
check verifies the signature chains to it whether the primary or a signing subkey made it.
Probe: `probe_tag_signature_binds_the_subkey_not_the_primary` (WEAK).

### F4 — The deny pattern `mpl` matches "simplified" and "example"

`tools/check-third-party-licences.sh`, `DENIED_PATTERNS`. Normalisation strips everything
outside `[a-z0-9]`, then every pattern is a substring test. `mpl` is a substring of
`si**mpl**ified`, `exa**mpl**e`, `te**mpl**ate`, `co**mpl**iance`.

**Repro** (`is_denied_token`, sourced directly):

| token | result | should be |
|---|---|---|
| `Simplified BSD License` | **DENIED** | allowed |
| `BSD 2-Clause Simplified License` | **DENIED** | allowed |
| `https://example.com/licence.txt` | **DENIED** | allowed |
| `The Apache Software License (example)` | **DENIED** | allowed |

**Impact.** Fail-closed, so no licence leaks — but "Simplified BSD License" is a real,
common spelling in real POMs, and the allowlist accepts it while the denial pass rejects it.
The failure mode is a red build on a permissive dependency with a message that says the
dependency is copyleft, which is the kind of false alarm that gets a gate weakened.

**Fix (Isis).** Drop the bare `mpl` pattern. `mpl11`, `mpl20` are already there; add `mpl10`
and keep the prose pattern `mozillapubliclicense`. Add all four rows above to `--self-test`'s
`allow_cases`.
Probe: `probe_denial_list_denies_simplified_bsd` (WEAK).

### F5 — Version-pinned copyleft patterns miss the neighbouring versions

Same list. `eupl12` misses `EUPL v1.1` and `EUPL-1.1`; `sspl10` misses a bare `SSPL` and
`SSPL-2.0`; OSL-3.0 (Open Software License, strong copyleft) and CPAL are absent entirely.
Verified with `is_denied_token`: `EUPL v1.1` → allowed, `SSPL` → allowed, `OSL-3.0` →
allowed, `Common Public Attribution License` → allowed.

**Impact.** Narrow, because the plugin's allowlist rejects any of these on its own. It only
matters in the exact case this pass exists for: a dependency declaring a permissive licence
**and** one of these cumulatively. That is N2's scenario with a different id, so the same
reasoning that made N2 a finding makes this one.

**Fix (Isis).** Replace `eupl12` with `eupl`, `sspl10` with `sspl` (neither string occurs in
a permissive licence name), and add `osl30`, `opensoftwarelicense`, `cpal`. Add each spelling
to `--self-test`'s `deny_cases`.
Probe: `probe_denial_list_misses_eupl_1_1_and_bare_sspl` (WEAK).

### F7 — `CONTRIBUTING.md` states no inbound licence terms, and the repository is about to be public

`CONTRIBUTING.md` is three lines about Conventional Commits and points at
`15/specs/SHARED-CONVENTIONS.md` / `14/AGENTS.md`, paths that exist only on this machine. It
says nothing about the licence of a contribution. Under Apache-2.0 the inbound grant was
conventional (ASF §5, which the starter POM's own comment still refers to); FSL-1.1-ALv2 has
no contribution clause at all.

**Impact.** Release gate 1 makes this repository public, and a Pro edition sits beside the
free core. A merged outside PR would arrive with no express grant, which is precisely the
thing that later prevents relicensing — including the automatic Apache-2.0 conversion the
FSL promises two years out, which we can only grant for code we have the rights to.

**Fix (Isis).** Before the repository goes public: add an inbound section to
`CONTRIBUTING.md` — a DCO sign-off requirement (`git commit -s`, `Developer Certificate of
Origin 1.1` quoted or linked) plus one sentence that contributions are licensed to
HouseDevinci under the same terms as the project and may be relicensed under the Grant of
Future License. Replace the internal lane paths with the repository's own conventions.
Souhaile decides between DCO and a CLA; DCO is the lighter of the two and is what a
source-available project of this size normally ships.
Probe: `probe_contributing_has_no_inbound_licence_terms` (WEAK).

### F9 — `SampleEndToEndTest` depends on where its four calls fall inside a wall-clock minute

`./mvnw -B verify` on this working tree, at `78c808e`, went **BUILD FAILURE**:

```
[ERROR] SampleEndToEndTest.read_allowed_write_parked_approve_once_budget_of_three_audit_chain:155
Expecting value to be true but was false
```

Line 155 is `assertThat(fourth.isError()).isTrue()` — the fourth tool call inside the minute
is supposed to come back `BUDGET_EXCEEDED` / `AG-BUDGET-001`. It came back successful. The
same command re-run three times immediately afterwards was green three times (35.1 s,
33.5 s, 33.8 s), and the release-profile run in the same batch was green.

**Mechanism, proved deterministically at the domain level.** `BudgetLimit` windows are
*tumbling and epoch-aligned*, not sliding — `windowStart` is
`floorDiv(now.toEpochMilli(), size) * size`, and the store key ends in that window start.
Two instants 200 ms apart therefore land in different windows whenever an epoch-minute
boundary falls between them, and the counter starts again from zero:

```
calls 1-3 key: agentguard:budget:PRINCIPAL:TOOL_CALLS:agent:1788901740
call 4    key: agentguard:budget:PRINCIPAL:TOOL_CALLS:agent:1788901800
same window? false
```

(`new BudgetLimit(PRINCIPAL, TOOL_CALLS, Duration.ofMinutes(1), 3)`,
`t1 = 2026-09-08T21:09:59.900Z`, `t2 = t1 + 200 ms`, run against
`agent-guard-core/target/classes`.) That is correct, intended behaviour for the product —
tumbling windows are what `BudgetLimit`'s own javadoc promises. It is the *test* that
assumes its four calls share one window, which the test does nothing to guarantee. The test
body takes about 2 s, so the boundary falls inside it a few percent of the time; the failing
run was one of two Maven builds competing for this machine, which stretches it.

**Reproduction attempt, and what it did not achieve — stated plainly.** I patched a scratch
clone (never the repository) with a `@TestConfiguration` supplying `agentGuardClock` as
`Clock.offset(systemUTC(), …)`, computed so the next window boundary lands a chosen number
of milliseconds after the bean is built, and swept leads of 500, 1500, 2500, 3500, 4500 and
20000 ms. All six runs passed. The offset is fixed when the context starts, and Testcontainers'
PostgreSQL start plus context refresh eats several seconds before the first tool call, so
every chosen boundary had already gone by the time the calls happened — the sweep did not
put the boundary where it needed to be. So: the failure is **observed, not forced**. The
mechanism above is proved; the end-to-end forcing is not. I am not softening the finding on
that basis — a test that failed once on a clean tree and passes on re-run is a flaky test
whatever the mechanism — but the distinction belongs on the record.

**Impact.** `ci.yml` and the `sample-smoke` job go red at random, on a schedule nobody
controls, including on the tag push that starts a release. A red release run is not
dangerous — nothing is published — but a test that is known to fail for no reason is exactly
the test whose next real failure gets waved through.

**Fix (Isis).** The seam already exists:
`AgentGuardAutoConfiguration.agentGuardClock()` is
`@ConditionalOnMissingBean(name = "agentGuardClock")`. Give `SampleEndToEndTest` a nested
`@TestConfiguration` that supplies a clock the test controls — a `MutableClock`-style
`Clock` pinned to a fixed instant well inside a window, advanced explicitly by the test
between phases where elapsed time is part of the scenario. Then the assertion tests the
budget rule instead of the machine's speed, and the same fixture makes the
window-rollover case testable on purpose, which is worth having on its own. Do not paper
over it with a retry, a wider budget, or a `sleep`: they hide the rollover instead of
covering it.
Probe: `probe_sample_e2e_depends_on_the_wall_clock` (WEAK).

## INFO

### F6 — `pom.xml` still calls Apache-2.0 "the licence of this project"

`pom.xml`, inside the `<includedLicenses>` comment:

```
Apache-2.0    the licence of this project; permissive, patent grant.
```

Since `1da507e` the project is FSL-1.1-ALv2. This is the only stale Apache-2.0 claim about
**our own** code anywhere outside the historical review records — and it lives in the file
that is published to Maven Central, where it is exactly the sentence a licensee would quote
back to contradict `LICENSE`. Everywhere else is correct: `CHANGELOG.md` and `STATUS.md`
describe the switch, `docs/index.md` says "fair source", the starter POM's Apache-2.0
mention is explicitly marked "used before the licence switch", and `QUESTIONS.md` #22 is
about dependency licences.

**Fix (Isis).** Reword to what the line actually means, e.g. `Apache-2.0    the most common
permissive licence among our dependencies; patent grant.`
Probe: `probe_pom_comment_calls_apache_the_project_licence` (WEAK).

### F8 — "everywhere" missed two lines, and one of them is the release signing key

`78c808e`'s subject is "spell the licensor HouseDevinci everywhere". `LICENSE`, `NOTICE` and
`pom.xml` are correct. `docs/RELEASING.md` still carries two other spellings:

- **line 71**, in the key-generation block: `#   real name:  House Devinci`. That string
  becomes the UID of the key that signs every release tag and every `.asc` on Maven Central.
  A licensee comparing the signature's identity with the copyright holder named in `LICENSE`
  sees two different names. Cosmetic today; permanent once a signature is on repo1.
- **line 31**: `organisation "Housedevinci", status Verified` — the Central Portal namespace
  record. If that is genuinely how the organisation is registered with Sonatype, leave the
  line and say so in a comment; if it is just the old spelling copied along, correct it.

**Fix (Isis).** Line 71 to `HouseDevinci`. Line 31: correct it, or annotate it as the
literal value Sonatype holds. Then `grep -rn 'House Devinci\|Housedevinci'` over the tree,
excluding `.git/`, `target/` and this review file, must return nothing.
Probe: `probe_licensor_spelling_disagrees_in_releasing_md` (WEAK).

## The FSL-1.1-ALv2 switch: audited, and correct apart from F6, F7 and F8

- **`LICENSE` is byte-equal to the upstream template except the two fields.** Fetched
  `https://raw.githubusercontent.com/getsentry/fsl.software/main/FSL-1.1-ALv2.template.md`
  and diffed: **one hunk, one line** — `Copyright ${year} ${licensor name}` →
  `Copyright 2026 HouseDevinci`. 105 lines, 3744 bytes, no other change, no reflowing, the
  Grant of Future License intact.
- **`NOTICE`** (294 bytes) names the licence, points at `LICENSE`, and states the two-year
  Apache-2.0 conversion. Consistent with `LICENSE`.
- **POM `<licenses>`** — one block, `Functional Source License, Version 1.1, ALv2 Future
  License`, `https://fsl.software/FSL-1.1-ALv2.template.md`, `distribution=repo`, comment
  "Converts to Apache-2.0 two years after each version's release". Correct and singular.
- **Both files are in both published jars.** Extracted `META-INF/LICENSE` and
  `META-INF/NOTICE` from `agent-guard-core` and `agent-guard-spring-boot-starter` (main jars)
  and diffed against the repository files: **identical**, both modules. Also present in the
  `-sources.jar`s. The `<licenses>` block is inherited rather than repeated in each module
  POM; the parent POM carrying it is in the Central bundle, which is how Central resolves it.
- **No "open source" claim for our own code, anywhere.** `grep -rniE 'open.?source'` over the
  whole tree excluding `target/` and `.git/`: **zero hits**.
- **No stale Apache-2.0 claim for our own code** outside the historical review records —
  except F6.

## Attacks that did not land

Recorded because a checked-and-clean surface is worth as much as a finding.

- **N3 by the dependency `<name>`** — closed, verified with the original repro line.
- **A name containing a full fake coordinate followed by the real one** — the real one wins.
- **`workflow_dispatch` with a branch name instead of a sha** — not reachable: `$GITHUB_SHA`
  is a commit sha on both triggers. Ancestry verified on a scratch repository, including the
  missing-`origin/main` case, which fails closed.
- **`JAVA_TOOL_OPTIONS` against the `MAVEN_OPTS` pin** — it loses: `JAVA_TOOL_OPTIONS` is
  prepended to the JVM arguments and `MAVEN_OPTS` appended, so the workflow's
  `defaultLogLevel=info` is the last `-D` and wins. Confirmed both ways (666 `[DEBUG]` lines
  without the pin, none with it).
- **The empty licence token and the URL-only licence token** — the first denies nothing and
  does not crash the scan; the second is a false positive, folded into F4.
- **The bundle assertion** — reproduced end to end with a real `deploy -Prelease` on a
  release version; the asserted path is the written path, and the sample is absent.
- **Two notes, neither a finding.** (1) `.mvn/maven.config` carrying `-X` is not covered by
  the debug guard, which scans `MAVEN_ARGS`/`MAVEN_OPTS` and two named `run:` blocks; it is a
  reviewed repository file and the fix would be one more line in the same loop — mentioned
  so it is on the record, not raised. (2) On this Maven version `-X` does **not** print the
  process environment: I set a marker variable, ran with `-X`, got 666 `[DEBUG]` lines and
  zero occurrences of the value. The I4/N6 guard is still worth having (stack traces,
  future Maven versions), but its stated premise is stronger than what I could reproduce.

## Fix list for Isis, in order

1. **F2** — depth-aware paren scan in `parse_notices`; last **top-level** group; line must end
   with `)`; two new `--self-test` parser rows. `probe_denial_pass_coordinate_forged_by_the_url`
   must flip.
2. **F1** — anchor `<excludedGroups>` to `^com\.housedevinci(\.[^:]*)?(?=:)`; re-run the three
   synthetic-dependency builds.
3. **F3** — bind the `VALIDSIG` match to the primary-key field; one clarifying sentence in
   `docs/RELEASING.md` and in the checklist.
4. **F4** — drop bare `mpl`, add `mpl10`, add the four false-positive rows to `allow_cases`.
5. **F5** — `eupl`, `sspl`, `osl30`, `opensoftwarelicense`, `cpal`; add them to `deny_cases`.
6. **F6** — reword the `pom.xml` comment.
7. **F7** — inbound licence terms in `CONTRIBUTING.md`, and drop the internal lane paths.
8. **F8** — the two remaining licensor spellings in `docs/RELEASING.md`.
9. **F9** — a test-controlled `agentGuardClock` in `SampleEndToEndTest`.

Then re-run, and put the numbers in `STATUS.md`: fresh-clone `./mvnw -B verify`, repo
`verify`, `-Prelease -Dgpg.skip=true`, `scripts/verify-reproducible.sh`, and
`CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` at **32/32 FIXED, exit 0**.

## Release gates — Souhaile’s checklist, in order (updated at 78c808e)

Unchanged in substance from the previous pass; F3 and F7 add to it. None of it blocks the
merge of PR #9. All of it must be true before `v0.1.0` is tagged.

- [ ] **1. Make `1of1Canopus/agent-guard` public.** Everything below depends on it:
      Environments and tag rulesets do not exist on a private repository on the free plan
      (`gh api …/environments` → `total_count: 0`, rulesets → 403), and the POM's `url`,
      `scm` and `issueManagement` point at a repository that would 404 for everyone else,
      permanently, once 0.1.0 is on Maven Central. (L7)
      **New at this pass:** before it goes public, F7 — `CONTRIBUTING.md` must state the
      inbound licence terms for contributions. FSL has no contribution clause; without a DCO
      or a grant, a merged outside PR is code we cannot relicense, including into the
      Apache-2.0 conversion the FSL itself promises.
- [ ] **2. Two mailboxes exist and forward.** `oss@housedevinci.com` — published in the POM's
      `<developers>` block, permanent on repo1.maven.org (QUESTIONS #21).
      `security@housedevinci.com` — the address in `SECURITY.md`, the only channel a
      vulnerability report has. Remove the placeholder warning at the top of `SECURITY.md`
      once both are confirmed. Neither was tested: no mail was sent. (L6)
- [ ] **3. The four secrets, set from a pipe, never from the clipboard.** `CENTRAL_USERNAME`,
      `CENTRAL_TOKEN`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`. Follow `docs/RELEASING.md`
      Part 1 step 4 literally:
      `gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard`.
      The armoured key must not touch a file, the pasteboard, or a shell argument. The
      sanity-check block is now inside a subshell, so its `trap` really does clean up on a
      failing step (N7). (M6, N7)
- [ ] **4. Create the `release` environment with yourself as a required reviewer, and move
      all four secrets into it.** Settings → Environments → New environment → exactly
      `release`. `release.yml` already declares `environment: release`; until the environment
      exists GitHub creates it implicitly **with no protection rules**, so the line is a
      placeholder and not a gate. Environment secrets are what keep the signing key
      unreachable from any other workflow. (M5)
- [ ] **5. Set the `RELEASE_SIGNING_KEY_ID` repository *variable*** (Settings → Secrets and
      variables → Actions → **Variables**, not Secrets — it is a key id, not a secret) to the
      **full 40-character fingerprint of the primary key**, and confirm that key is on
      `keyserver.ubuntu.com`. The workflow now refuses to run without it and refuses a short
      id or an email (N5). **New at this pass (F3):** if your key signs with a subkey, the
      check as written at `1da507e` will refuse your tag — do not work around it by putting
      the subkey fingerprint in the variable; the F3 fix makes the primary fingerprint the
      right value in both cases. Tag with `git tag -s`, never `-a`.
- [ ] **6. Tag the commit as it exists on `main`.** The workflow refuses a tag whose commit is
      not an ancestor of `origin/main`, on both triggers — re-verified on a scratch
      repository at this pass. If PRs are squash-merged, tag after the merge, on `main`,
      never on the PR branch head. (M5, N8)
- [ ] **7. Press Publish yourself, the first time and every time.** `autoPublish=false` /
      `publishingType=USER_MANAGED` is the last control in the chain and the only one that is
      a human. Before pressing it, read the component list: exactly `agent-guard-parent`,
      `agent-guard-core`, `agent-guard-spring-boot-starter`, each with `.pom`, `.jar`,
      `-sources.jar`, `-javadoc.jar` and an `.asc` for each — **and no `agent-guard-sample`**
      (that shape is now confirmed against a real bundle, N4). Also read the checksum table in
      the job summary, which is what L1 exists to put in front of you. If anything is wrong:
      **Drop**. A version that reaches Maven Central can never be changed or removed.

## What could not be verified without real credentials or a public repository

Named, not implied. A skipped check is never a passing one. Unchanged from the previous pass
except where noted.

1. **The workflow has still never run.** Everything it does was executed locally, including a
   `deploy -Prelease` that reached the Portal and stopped at `401` on a fake token. N4's fix
   is now proved against a real bundle; the steps *after* the upload (the L1 checksum table,
   the L4 evidence upload) have still only been read, never executed by Actions.
2. **Central Portal validation of the bundle** — keyserver signature check, POM completeness
   including the licence block inherited from the parent, namespace ownership — unknown until
   a real token runs it.
3. **`environment: release`** cannot be created while the repository is private on the free
   plan, so the M5 reviewer gate is declared and untested.
4. **GitHub's secret masking** rests on documented behaviour; no run log exists.
5. **Cache poisoning end to end (M3)** was not attempted and will not be. Verified by
   construction: no cache is restored and `~/.m2/wrapper/dists` is removed before the first
   `mvnw` invocation.
6. **Whether either mailbox resolves.** No mail was sent.
7. **F3 against Souhaile's actual release key.** Reproduced with two synthetic keys covering
   both shapes. Which shape his key has, I do not know and did not look for.

---

## Clean-verdict pass (`fad6659`, 2026-09-09) — MERGE WITH FIXES

Fresh clone of `feat/release-pipeline` at `fad6659` into a scratch directory, built and
attacked from scratch. Docker was up; no test was skipped for want of it.

### Numbers

| Gate | Command | Result |
|---|---|---|
| Full verify (fresh clone) | `./mvnw -B verify` | **BUILD SUCCESS**, exit 0, 53.4 s |
| Tests | core / starter / sample | **220 run, 0 failures, 0 errors, 1 skipped** (161 / 58 / 1) |
| Release profile | `./mvnw -B -Prelease -DskipTests -Dgpg.skip=true install` | **BUILD SUCCESS**, exit 0, 7.6 s; 6 publishable jars + 1 sample |
| Reproducibility | `scripts/verify-reproducible.sh` | exit 0, **6/6 artifacts byte-identical** across two clean builds (both javadoc jars matched too, though they are reported-not-enforced) |
| Probes | `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` | **32 FIXED, 2 WEAK** (the two new findings below), exit non-zero |

The one skipped test is `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on`,
an `Assumptions.assumeTrue(ClassUtils.isPresent(...))` on the Spring AI tool
autoconfiguration jar, which is not a dependency of this module. Pre-existing, outside this
branch's scope, and it names its own run instruction in the skip message. Recorded, not
counted as passing.

### F1–F9 — all nine confirmed closed

Each verified in the code and by its probe flipping to FIXED, then attacked again:

- **F1** `excludedGroups` is `^com\.housedevinci(\.[^:]*)?(?=:)`. Anchored at `^`, the
  subgroup requires a literal `.`, and the `(?=:)` lookahead forces the coordinate
  separator. `com.housedevinci-evil` and `xcom.housedevinci` are both scanned; only the real
  group is excluded. Closed.
- **F2** Depth-aware scan verified against a 10-case matrix: a legitimate
  `.../wiki/Foo_(bar)` URL parses cleanly; a coordinate forged inside the `<name>` or inside
  the URL resolves to the real coordinate; an extra `)`, an extra `(`, a `)` before any `(`,
  and trailing text after the last group all fall to `UNPARSEABLE` (fail closed); a
  200-deep paren bomb parses without hanging. Closed **as written** — but see G1, which is
  the same forgery pointed the other way.
- **F3** `VALIDSIG` last-field match attacked with six forged status lines. Both legitimate
  shapes match (subkey signs with primary last; primary signs itself). All six attacks are
  rejected: primary in a middle field, primary as the *suffix* of a longer trailing token
  (`FFFF<fp>`), primary as its *prefix* (`<fp>FFFF`), a trailing space after it, an
  unanchored line, and an `ERRSIG` line ending in the fingerprint. The mandatory-and-bound
  shape is correct. Closed.
- **F4/F5** Deny-table corrections confirmed by the script's own `--self-test`. Closed.
- **F6** pom comment. **F7** DCO + inbound grant in `CONTRIBUTING.md` with a `dco` CI job.
  **F8** licensor spelling. **F9** `MutableClock` seam. All closed.

### Attacks run on the new surfaces

- **Grandfather exemption (#29) — sound.** Built a throwaway repo and ran the job's script
  verbatim. A new commit **cannot** be made an ancestor of `ddd250c` (ancestry is fixed by
  that commit's own parent DAG; forging it needs a SHA-1 collision). A **rebase** of the
  branch gives every commit a new SHA, none of which is an ancestor, so all of them are
  checked — fail closed. **After merge** the exemption is unreachable: a later PR's
  `base..head` range never contains a commit that is already on `main`, and an unsigned new
  commit on such a branch is caught. The check is scoped to `pull_request` only and to the
  PR range only. All three claims in the job's comment hold.
- **DCO action pins and permissions — clean.** All three actions (`checkout`, `setup-java`,
  `upload-artifact`) are pinned to full 40-character commit SHAs with a version comment, and
  the same SHA is used for a given action everywhere in all three workflows. Every workflow
  carries a top-level `permissions: contents: read`; the `dco` job restates it at job level.
  Least privilege, no `id-token`, no `packages`.

### Findings — both must be closed before merge (no-allowance rule)

**G1 — MEDIUM — a dependency's `<url>` can append an allowlisted coordinate and skip the licence gate.**
`tools/check-third-party-licences.sh`, `parse_notices`. F2 closed the case where a URL's
*nested* parens split the coordinate group. The scan still trusts "the **last** top-level
group", and the URL is free text that can simply close its own group and open a fresh one
after it. A dependency POM with

```xml
<url>http://x) (ch.qos.logback:logback-core:1.5.6 - http://y</url>
```

renders the notices line

```
(GPL-3.0) evil (com.evil:evil:1.0 - http://x) (ch.qos.logback:logback-core:1.5.6 - http://y)
```

whose last top-level group is on `ALLOWED_COORDINATES`, so `is_allowed_coordinate` returns
true, `continue` fires, and the `GPL-3.0` token is never tested. Reproduced end to end
against the real script: **exit 0, "clean"**, on a GPL-3.0 dependency. The count backstop
does not fire — one line declared, one line parsed. This is N3/F2's exact threat class
forged *forward* instead of *backward*.

*Repro:* `probe_denial_pass_coordinate_forged_by_a_trailing_group` (added to
`tools/cipher-probe-release-pipeline.sh`, WEAK on current code).

*Fix:* the coordinate cannot be recovered by position when the line is attacker-shaped, so
stop trying. In `parse_notices`, after `@parens` is built, count the top-level groups that
match the coordinate shape and require **exactly one**:

```perl
my $coord_re = qr/^\s*([\w.\-]+):([\w.\-]+):([\w.+\-]+)\s*-\s*.*$/;
my $coord_like = grep { $_ =~ $coord_re } @parens;
if (@parens && $trailing_ok && $coord_like == 1) {
  my $last = $parens[-1];
  if ($last =~ $coord_re) { ... }
}
```

Two coordinate-shaped groups on one line is genuine ambiguity and must fall to
`UNPARSEABLE`, which the caller already fails the build on. Verified: this rejects the
trailing-group forgery **and** the `<name>` forgery, still accepts a legitimate nested-paren
URL and a legitimate parenthesised project name (`Apache Commons (Core)`), and produces
**zero regressions** on the real corpus — 7/7 and 87/87 dependency lines still parse `OK`,
0 `UNPARSEABLE`.

**G2 — LOW — a forged "Merge branch" subject skips the DCO check entirely.**
`.github/workflows/ci.yml`, `dco` job. Merge commits are exempted by matching the commit
**subject**:

```sh
case "$subject" in
  "Merge branch"*|"Merge remote-tracking"*) continue ;;
esac
```

A subject is free text chosen by the committer. An ordinary **single-parent** commit titled
`Merge branch 'evil' into feat`, carrying no `Signed-off-by` trailer, passes the job.
Reproduced: `parents=<one sha>`, no sign-off, job reports `OK all signed off`. The exemption
is legitimate (GitHub's "Update branch" merges carry no trailer) but the test is the wrong
one — whether a commit is a merge is decided by its parent count, which cannot be forged.

*Repro:* `probe_dco_check_skipped_by_a_forged_merge_subject` (added, WEAK on current code).

*Fix:* branch on `%P` instead of `%s`:

```sh
case "$(git log -1 --format='%P' "$sha")" in
  *' '*) continue ;;   # two or more parents: a real merge commit
esac
```

Verified: this catches the forged-subject commit and still skips a real two-parent merge
commit. The `subject` variable is still wanted for the error message.

### Rulings

**#28 — ACCEPT, no change.** The answer is correct and I could not fault it. `excludedGroups`
is a single filter over a single dependency set in `license-maven-plugin` 2.7.1, so
"excluded from the gate but kept in the listing" is genuinely not expressible in this
execution shape. It is also moot here: the only excluded group is `com.housedevinci`, which
is not a third party, so its absence from a *third*-party notices file is correct rather
than a gap. The stated escape hatch for any future real third party — a human-reviewed
entry in `ALLOWED_COORDINATES`, which keeps the dependency and its licences in the file — is
the right one. Closed.

**#29 — ACCEPT the exemption as written, and PRESCRIBE the follow-up removal (Dollar's end
state (a)).** The mechanism is sound and I proved all three of its claims above. Of the two
acceptable end states, **(b) is not available**: expressing the rule as "commits already on
`main` are exempt" would not exempt PR #9's own nine commits, because they are not on `main`
until #9 merges — the very PR that needs the exemption is the one that shape cannot serve.
The pinned-SHA form is therefore the only one that works now, and it is provably
self-limiting. So: keep it for this PR, and open a follow-up that **deletes** the
`GRANDFATHER_SHA` env var and the `git cat-file` / `merge-base --is-ancestor` block once #9
is on `main`, at which point it is demonstrably dead code rather than an argument the next
reader has to re-derive. Not a blocker for merge; it is a blocker for leaving the file tidy.

### Verdict

**MERGE WITH FIXES.** No HIGH. The release pipeline builds, tests, reproduces and gates
correctly, F1–F9 are genuinely closed, and #28/#29 are answered soundly. Two findings are
open — **G1** (MEDIUM) and **G2** (LOW) — both with a proven, regression-tested fix above.
Under the no-allowance rule the probe script must reach `still weak: 0` before this merges.
Back to Isis.

### Release gate — state for Souhaile as of 2026-09-09

Done, verified today:

- Sonatype namespace `com.housedevinci` verified.
- Mail aliases `oss@` and `security@` exist.
- Sonatype Central Portal token created, **expires 2027-09-09**.
- GPG release key: **Ed25519, `[SC]` primary-signing** (no separate signing subkey),
  expires **2029-05**; fingerprint held by Souhaile. Note this is the "primary signs
  itself" shape, which is the second legitimate `VALIDSIG` case F3 covers — the first and
  last fields of the status line are the same fingerprint, and the check matches.

Remaining, in order:

1. Close **G1** and **G2**; probe script back to `still weak: 0`.
2. Merge PR #9.
3. Add the four secrets from a pipe (never a shell argument, never a file left on disk).
4. Set repository variable `RELEASE_SIGNING_KEY_ID` to the **full 40-character primary
   fingerprint** — the workflow rejects a short key id or an email.
5. Flip the repository to public.
6. Create the `release` environment with Souhaile as the required reviewer (this is the M5
   gate; it cannot exist while the repo is private on the free plan).
7. Tag on `main`.
8. Publish click at the Central Portal — the bundle waits there; nothing in the workflow can
   publish on its own.

---

## Final confirmation pass (`cae839e`) — 2026-09-09

Fresh clone of the branch into a scratch directory, full build, release profile,
reproducibility across two independent clones, and the probe suite. Then G1 and G2
re-attacked with two new inputs each, as instructed.

### Numbers

| What | Result |
| --- | --- |
| Fresh clone, `./mvnw -B verify` | **BUILD SUCCESS**, 46.1 s, 4 modules |
| Tests | **220 run, 0 failures, 0 errors, 1 skipped** (core 161, starter 58 + 1 skipped, sample 1) |
| Skipped test | `CipherProbeFinalSpringAiTest`, one `assumeTrue` case — a deliberate assumption, not a failure |
| Testcontainers | real containers, digest-pinned: `postgres:16-alpine@sha256:57c72f…`, `redis:7-alpine@sha256:6ab0b6…` |
| JaCoCo (core) | **90.93 %** line (7738 covered / 772 missed), gate `0.80` — met |
| Third-party notices | clean on all three jar modules; parent `pom` module correctly declares none |
| Release profile (`-Prelease`) | **BUILD SUCCESS**, 15.7 s; sources + javadoc + 9 `.asc` signatures, all **Good signature** |
| Sample module | not signed, not installed, not deployed — `maven.deploy.skip`/`install.skip`/`source.skip`/`javadoc.skip`/`gpg.skip` all true |
| Reproducibility | **6 / 6 artifacts byte-identical** across two independent clones at different absolute paths (core + starter jar/sources/javadoc) |
| `CIPHER_PROBE_MAVEN=1` probe suite, at `cae839e` as received | `still weak: 0    fixed: 34`, exit 0 |
| Same suite, with the new G3 probe added by this pass | `still weak: 1    fixed: 34`, exit 1 |
| `check-third-party-licences.sh --self-test` | all cases correct, including the three G1 rows |

### G1 (MEDIUM, forward coordinate forgery) — CONFIRMED FIXED

`probe_denial_pass_coordinate_forged_by_a_trailing_group` reports **FIXED**. The
"exactly one coordinate-shaped top-level group, else `UNPARSEABLE`" rule is the right
shape: it stops trying to recover a coordinate by position once the line is
attacker-shaped.

Six further attacks, all against the real script, all **fail closed**, and the one
legitimate case is accepted with no false positive:

| # | Line shape | Result |
| --- | --- | --- |
| A1 | coordinate-shaped group nested inside the GPL dep's own URL: `(cipher.synth:evil-d:1.0 - http://x/(ch.qos.logback:logback-core:1.5.6 - y))` | **DENIED** on `GPL-3.0` against the *real* coordinate `evil-d` — the nested allowlisted coordinate is never reached |
| A2 | outer group not coordinate-shaped, allowlisted coordinate nested inside the URL | **DENIED**, `UNPARSEABLE` |
| A3 | the literal shape asked for, `http://x/(a:b:1.0 - y)` | **DENIED** on `GPL-3.0` against `evil-e` |
| B1 | legitimate permissive dep whose URL holds a balanced pair (`…/wiki/Foo_(bar)`) | **ACCEPTED** — no false positive |
| B2 | same, but GPL | **DENIED** |
| C1 | unbalanced `)` injected through the dependency `<name>` | **DENIED**, `UNPARSEABLE` (depth never returns to 0) |
| D1 | allowlisted coordinate forged *backwards*, into the licence run ahead of the real one | **DENIED** — greedy licence-run match leaves the real coordinate as the only top-level one, and the forged group is read as a licence token |
| E1 | coordinate-shaped group at depth 3 (double nesting) | **DENIED** |

The depth-aware scan collects only depth-1 groups, so a nested coordinate is content of
its parent group, never a candidate. And because the notices format always writes the
real `g:a:v` at the *start* of the coordinate group, and the attacker controls only the
`<url>` that follows it, the captured `g:a:v` cannot be forged from inside. G1 is closed.

### G2 (LOW, forged merge subject) — CONFIRMED FIXED, and it opens G3

`probe_dco_check_is_skipped_by_a_forged_merge_subject` reports **FIXED**. Control test:
a single-parent commit with the subject `Merge branch 'x' into y` and no trailer is now
**caught** (exit 1). The finding as written is closed — parent count is not forgeable the
way a subject is.

But both attacks I was asked to run against the *new* surface succeed.

### G3 — NEW, LOW — a multi-parent commit is exempt regardless of what it carries

**Repro** (real git, `git 2.53.0`; the dco step body extracted verbatim from `ci.yml`
at `cae839e` and run over a synthetic range):

1. **Octopus merge, three parents.** `git merge --no-commit --no-ff a b`, then add
   `evil.txt` before committing, subject `Merge branches 'a' and 'b'`, **no sign-off**.
2. **Two-parent commit that is not a merge of main.** `git commit-tree -p <octopus>
   -p <unrelated orphan>` with `evil2.txt` added, subject
   `chore: routine dependency refresh`, **no sign-off**.

Gate output over the range containing both: `all commits … are signed off`, **exit 0**.

Verified the payloads are genuine *evil merges*, not inherited content:

```
is evil.txt  in ANY parent of the octopus?    a8911e2 ABSENT  ebefd37 ABSENT  80c486a ABSENT
is evil2.txt in ANY parent of the fake merge? ed2dba9 ABSENT  02abbbf ABSENT
```

A merge commit's tree is not constrained by its parents. `git rev-list BASE..HEAD` does
still walk into both parents, so the *branch* commits are checked — what escapes is the
merge commit's own delta, which is authored content that exists nowhere else. The gate
reports a green it has not earned, which is the same class of false green G2 was.

**Severity LOW.** The impact is provenance and inbound-licence hygiene, not code
execution or secret disclosure: the delta still shows in the PR's own diff and a human
still merges. But it is a bypass of a gate this PR introduces, and the no-allowance rule
admits no LOW waivers.

**Prescribed fix** (`.github/workflows/ci.yml`, the `dco` job, replacing the `%P`
case block). Exempt a merge only when it is a *trivial back-merge of the base branch* —
exactly two parents, second parent an ancestor of `BASE_SHA`, and the commit's tree
identical to the tree git itself computes for that merge:

```bash
parents="$(git log -1 --format='%P' "$sha")"
set -- $parents
if [ "$#" -ge 2 ]; then
  exempt=0
  if [ "$#" -eq 2 ] && git merge-base --is-ancestor "$2" "$BASE_SHA" 2>/dev/null; then
    auto="$(git merge-tree --write-tree "$1" "$2" 2>/dev/null | head -1)"
    own="$(git rev-parse "$sha^{tree}")"
    [ -n "$auto" ] && [ "$auto" = "$own" ] && exempt=1
  fi
  [ "$exempt" -eq 1 ] && continue
fi
```

An octopus, a two-parent commit whose second parent is not from the base, and a merge
carrying a conflict-resolution or evil-merge delta all fall through to the sign-off
requirement — correctly, because a resolution *is* authored content. `git merge-tree
--write-tree` needs git ≥ 2.38; `ubuntu-latest` is well past it.

I tested this candidate before prescribing it. Four cases, all correct:

| Case | Required | Result |
| --- | --- | --- |
| Octopus + fake two-parent merge (above) | fail | **exit 1**, both named |
| Genuine clean back-merge of `main`, no sign-off | pass | **exit 0** |
| G2's forged-subject single-parent control | fail | **exit 1** |
| The real PR #9 range, 34 commits, 0 merges | pass | **exit 0** — no regression |

Probe added: `probe_dco_exempts_an_octopus_merge_carrying_unsigned_content` in
`tools/cipher-probe-release-pipeline.sh`. It is behavioural, not a grep: it extracts the
dco step body from `ci.yml` and runs it against a freshly built octopus repository, so it
will flip to FIXED against whatever the fix actually is rather than against a spelling.

### Verdict

**MERGE WITH FIXES.** No HIGH, no MEDIUM. G1 and G2 are genuinely closed and I could not
break either with eight further attacks. The pipeline builds, tests, signs and reproduces
byte-for-byte. One LOW is open — **G3** — with a proven, regression-tested fix and a
behavioural probe. Under the no-allowance rule the probe suite must read
`still weak: 0` before this merges. Back to Isis; it is a ten-line change to one job.

### Release gate — the order for Souhaile, once G3 is closed

Nothing below can start until the probe suite reads `still weak: 0` again.

1. **Merge PR #9** into `main`.
2. **Add the four repository secrets**, each straight from a pipe — never a shell
   argument, never a file left on disk, never the clipboard. From `docs/RELEASING.md`:
   `gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard`,
   then `gh secret set GPG_PASSPHRASE --repo 1of1Canopus/agent-guard` (prompts, reads the
   tty, stays out of shell history), and the same prompted form for `CENTRAL_USERNAME`
   and `CENTRAL_TOKEN` — the username and password halves of the Sonatype Central user
   token, which is shown once.
3. **Set the repository variable `RELEASE_SIGNING_KEY_ID`** to the **full 40-character
   primary fingerprint**. Not a short key id, not an email — the workflow matches the
   last field of `git verify-tag --raw`'s `VALIDSIG` line, which is always the primary's
   fingerprint even when a subkey made the signature.
4. **Flip the repository to public.**
5. **Create the `release` environment** with yourself as the required reviewer. This is
   the M5 gate; it cannot exist while the repo is private on the free plan, which is why
   it comes after step 4.
6. **Run the follow-up PR that removes the grandfather exemption** — delete
   `GRANDFATHER_SHA` and its `git cat-file` / `merge-base --is-ancestor` block from the
   `dco` job. Once #9 is on `main` that block is dead code (QUESTIONS.md #29 / #33).
7. **Tag `v0.1.0` on `main`, signed**: `git tag -s v0.1.0` (signed, not `-a`) — the
   workflow requires a signature bound to the fingerprint from step 3.
8. **Run the release workflow.**
9. **Press Publish on the Sonatype Central Portal.** The bundle waits there; nothing in
   the workflow can publish on its own.

## Final verdict pass (`5cac151`) — 2026-09-09 — MERGE WITH FIXES

Isis applied the G3 fix I prescribed, exactly as prescribed. G3 is closed. Testing the fix
against a case I did not put in my own four — a back-merge whose automatic merge
**conflicts** — showed that the prescription I wrote has a defect of its own: the step
does not fall through to the sign-off requirement as the fix's comment claims, it aborts.
That is my error, carried faithfully into the implementation. It is recorded below as
**G4 (LOW)** and it blocks the merge under the no-allowance rule.

### Numbers — fresh clone of `feat/release-pipeline` at `5cac151`, nothing reused

| What | Result |
| --- | --- |
| Fresh clone, `./mvnw -B clean verify` | **BUILD SUCCESS**, 56.9 s |
| Tests | **220 run, 0 failures, 0 errors, 1 skipped** (161 core / 58 starter / 1 sample) |
| The one skip | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` — `Assumptions.assumeTrue` on the optional `spring-ai-autoconfigure-model-tool` jar. Known, pre-existing, not a Docker skip. |
| `CipherProbe*` suites re-run unchanged | **28 classes, 117 test methods**, all green |
| JaCoCo (core) | **line 1552/1713 = 90.60 %**, branch 461/590 = 78.14 % — gate 80 % met, "All coverage checks have been met" |
| Docker | up; Testcontainers PostgreSQL and Redis started, **no test skipped for a missing daemon** |
| Release profile, `./mvnw -B -Prelease -Dgpg.skip=true clean verify` | **BUILD SUCCESS**, 220 tests, 6 artifacts produced (2 main, 2 sources, 2 javadoc) |
| `scripts/verify-reproducible.sh` (two clean builds, same clone) | **6 of 6 byte-identical, exit 0** — including both javadoc jars this run, which are reported but not enforced |
| Reproducibility timestamp | `2026-09-09T13:23:56Z`, the committer date of `5cac151` |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | **`still weak: 0    fixed: 35`, exit 0** — reproduced independently, matches Isis's report |

The six SHA-256 values from this run do not match the committed `reproducible-sha256.txt`,
and that is correct, not a finding: the file was written at `cae839e`, and every jar is
stamped with `-Dproject.build.outputTimestamp` = the committer date of `HEAD`, which moved
when `5cac151` was made. Nothing in the build or the workflows reads the committed file;
the release job regenerates it into `$RUNNER_TEMP` and compares *that* against the jars it
actually deploys (L1). The committed copy is a sample, and it will be stale again the
moment G4 is fixed.

### G3 — closed. Verified by the probe and by five cases against the committed step body

The probe flips: `probe_dco_exempts_an_octopus_merge` reads **FIXED**, suite
`still weak: 0    fixed: 35`.

I did not trust the probe alone. I extracted the `dco` step body from the committed
`.github/workflows/ci.yml` with the same awk the probe uses (44 lines) and ran it against
six synthetic repositories. `EXEMPT` means the merge was waved through; `CHECKED` means it
fell through to the sign-off requirement and was named in a `::error::` annotation.

| # | Case | Required | Observed |
| --- | --- | --- | --- |
| 1 | Octopus merge, three parents, adds `evil.txt` present in no parent, no sign-off | CHECKED | **exit 1**, merge named in `::error::` |
| 2 | Two parents, second an unrelated branch and **not** an ancestor of `BASE_SHA`, no sign-off | CHECKED | **exit 1**, both the merge and the rogue commit named |
| 3 | Genuine trivial back-merge of the base, no sign-off on the merge commit | EXEMPT | **exit 0**, "all commits … are signed off" |
| 4a | Real PR range, ordinary single-parent commits, all signed off | pass | **exit 0** |
| 4b | Same range plus one ordinary unsigned commit | CHECKED | **exit 1**, that commit named |
| 5 | Back-merge, second parent **is** an ancestor of `BASE_SHA`, but the tree adds `smuggled.txt` (conflict-resolution smuggling) | CHECKED | **exit 1**, merge named in `::error::` |

Case 5 is the one Dollar asked for and it is the load-bearing one. The merge's own tree is
`6df8506…`; `git merge-tree --write-tree` of its two parents is `6c3943a…`. They differ, so
`exempt` stays 0 and the commit is required to carry a sign-off. The smuggling attempt is
caught.

The exemption is sound in the general case, not only in these six. A merge is waved through
only when its tree is exactly the tree git itself computes from its two parents, so it can
contribute no byte that is not already derivable from them. Its first parent is inside
`BASE_SHA..HEAD_SHA` and is therefore checked on its own turn in the same loop; its second
parent is an ancestor of `BASE_SHA` and is therefore already on the base branch, already
reviewed, already merged. There is no third place for content to come from.

I also confirmed that `set -e` does not abort the loop on the non-exempt path: cases 1, 2
and 5 all printed their `::error::` annotations, which only happens if execution reached
the `grep` after the `if` block. The failing `[ "$exempt" -eq 1 ] && continue` is the
command *preceding* the final `&&`, so errexit ignores it. That was worth proving rather
than assuming.

### G4 (LOW) — the dco step aborts silently when the automatic merge conflicts

**Where.** `.github/workflows/ci.yml`, `dco` job, step "Verify every commit in this pull
request is signed off", the line added by `5cac151`:

```sh
auto="$(git merge-tree --write-tree "$1" "$2" 2>/dev/null | head -1)"
```

**What goes wrong.** `git merge-tree --write-tree` exits **1** when the merge it computes
has a conflict. It still writes a tree, so `head -1` succeeds — but the step runs under
`set -euo pipefail`, and with `pipefail` the pipeline's status is git's `1`, not `head`'s
`0`. The status of a command that is only an assignment is the status of its command
substitution, so `auto=…` returns 1, and `set -e` kills the whole step **there** —
mid-loop, before the sign-off check, before any `::error::` annotation, and without
examining a single remaining commit in the range. `2>/dev/null` hides git's message; the
step produces **no output at all**.

**Repro.** A back-merge of the base where both sides edited the same line and the
committer resolved it — the most ordinary merge conflict there is:

```
main:     c.txt = "line" → "main-side"
feature:  c.txt = "line" → "feature-side"
feature:  git merge --no-ff main; resolve c.txt = "resolved"; git commit -s
```

Run the committed step body over `BASE_SHA..HEAD_SHA`:

```
+ auto=c8df1656aa01e89fba185d98139cde0fe162f318
final rc: 1
```

`bash -x` stops on that assignment. Observed with the merge commit **signed off** and with
it unsigned; both give `rc=1` and empty output. Reproduced against the committed
`ci.yml`, not against a copy.

**Impact.** No bypass — this fails closed, and the job stays red. Two things are wrong
anyway. A legitimate, fully signed-off back-merge that resolved a conflict is rejected
with **zero diagnostics**, which on this branch is not a hypothetical: `main` moves,
branches back-merge, conflicts get resolved. And a security gate that can go red with no
message is the precursor to someone deciding the gate is broken and taking it out. The
fix's own comment claims a conflict-resolution merge "falls through to the sign-off
requirement"; it does not, it crashes. That claim is mine, from the previous pass, and it
is wrong. Severity **LOW**: correctness and operability of a control, not a bypass. Under
the no-allowance rule it is fixed before merge.

**Fix (for Isis).** File `.github/workflows/ci.yml`, `dco` job, same step. Replace the one
line above with the explicit form, so the failure is non-fatal *and* a conflicted tree is
never even considered a candidate:

```sh
              auto=""
              if merged="$(git merge-tree --write-tree "$1" "$2" 2>/dev/null)"; then
                auto="$(printf '%s\n' "$merged" | head -1)"
              fi
              own="$(git rev-parse "$sha^{tree}")"
              [ -n "$auto" ] && [ "$auto" = "$own" ] && exempt=1
```

A command substitution used as an `if` condition is exempt from errexit, so a conflicting
merge now leaves `auto` empty, `[ -n "$auto" ]` fails, `exempt` stays 0, and the commit
falls through to the sign-off requirement — which is the behaviour the comment already
describes and the correct one, because a conflict resolution *is* authored content and
must be signed for. The one-line `… | head -1 || true)"` variant is equally correct but
leaves a conflicted tree oid in `auto`; prefer the explicit form.

Amend the block comment above it: strike the claim that a conflict-resolution merge falls
through today and state that `git merge-tree` exits non-zero on conflict, which is why the
`if` is there. `Cipher-Finding: G4`.

**Probe to add**, in `tools/cipher-probe-release-pipeline.sh`, alongside the G3 probe and
in the same behavioural style — extract the step body from `ci.yml`, run it, do not grep
for a spelling:

```
probe_dco_step_aborts_silently_on_a_conflicted_back_merge
```

Build the repo above with the merge commit **signed off**, run the extracted step body
over `BASE_SHA..HEAD_SHA`, and return 0 (WEAK) while the step exits non-zero. It must exit
0 after the fix — a signed-off conflict-resolved back-merge is a legitimate PR. Register it
as `probe_dco_aborts_on_a_conflicted_merge  "G4 the dco step crashes with no output"`.
The suite must then read `still weak: 0    fixed: 36`.

### Attacks on the new surface that did not land

- Forging the exemption by choosing parents. Impossible: the tree must equal
  `git merge-tree`'s deterministic output for those two parents, so the merge adds nothing.
- A first parent outside the checked range. Either it is inside `BASE_SHA..HEAD_SHA` and
  gets its own turn in the loop, or it is reachable from `BASE_SHA` and is already on the
  base branch. No third case.
- `git merge-base --is-ancestor` returning 128 on a bad or missing object — treated as
  "not an ancestor", so not exempt. Fails closed.
- `set -- $parents` word-splitting on attacker input — parents are hex object names; no
  glob or IFS character can appear. The step uses no other positional parameters.
- A four-or-more-parent octopus, and a two-parent merge whose second parent is a
  *descendant* of `BASE_SHA` rather than an ancestor: both non-exempt, both checked.
- `git merge-tree --write-tree` needs git ≥ 2.38 and `ubuntu-latest` is well past it; on an
  older git the invocation would fail, which is the same silent abort as G4 and is closed
  by the same fix.

### Verdict

**MERGE WITH FIXES.** No HIGH, no MEDIUM. G1, G2 and G3 are all confirmed closed, and G3
is closed properly — the exemption is now narrow enough that an exempted merge cannot carry
a byte its parents do not already have, which I verified with six cases including the
conflict-resolution smuggling one. The pipeline builds from a fresh clone, tests green with
one documented assumption skip, holds 90.60 % line coverage, builds under the release
profile, and reproduces six of six artifacts byte-for-byte.

One LOW is open: **G4**, a silent `set -e` abort in the very line that closed G3, found by
testing my own prescription against a case my own four did not cover. It is a five-line
change to one step plus one probe. The suite must read `still weak: 0    fixed: 36` before
this merges. Back to Isis.

The nine-step release-gate checklist for Souhaile is unchanged from the previous pass and
is not repeated here; it starts the moment G4 is closed and the suite is clean.

## Final verdict (3a0cb46): MERGE

2026-09-09. Confirmation pass on `feat/release-pipeline` at `3a0cb46`, PR #9,
`1of1Canopus/agent-guard`. Isis applied the five-line G4 fix I prescribed at `9b82d5e`
verbatim and corrected the block comment that was wrong. G4 is closed. Every finding
opened on this branch — M1–M7, L1–L7, I1–I4, N1–N11, F1–F9, G1–G4 — is closed. No HIGH,
no MEDIUM, no LOW, no INFO is open. Under the no-allowance rule this merges.

### Numbers — fresh clone of `feat/release-pipeline` at `3a0cb46`, nothing reused

| What | Result |
| --- | --- |
| Fresh clone, `git config core.hooksPath .githooks`, `./mvnw -B clean verify` | **BUILD SUCCESS**, 49.6 s |
| Tests | **220 run, 0 failures, 0 errors, 1 skipped** (161 core / 58 starter / 1 sample) |
| The one skip | `CipherProbeFinalSpringAiTest.real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on` — `Assumptions.assumeTrue` on the optional `spring-ai-autoconfigure-model-tool` jar. Known, pre-existing, not a Docker skip. |
| `CipherProbe*` suites re-run unchanged | **26 classes, 102 methods** in `clean verify`, all green |
| The 27th `CipherProbe*` class | `CipherProbeJedisPinningTest` is excluded from the default run by `agent-guard-core/pom.xml` (`agentguard.surefire.exclude`) because it deliberately hangs twice for 10 s. Run on demand as documented: `./mvnw -Ppinning-probe -pl agent-guard-core test -Dtest=CipherProbeJedisPinningTest` → **2 run, 0 failures, BUILD SUCCESS**. Nothing skipped anywhere: **27 classes / 104 methods green in total.** (The previous pass's "28 classes, 117 methods" counted the 28 `CipherProbe*.java` files, one of which — `CipherProbeJedisPinningMain.java` — is a child-JVM main, not a test class. A counting error in my own note, not a code change.) |
| JaCoCo (core) | **line 1551/1712 = 90.60 %**, branch 461/590 = 78.14 % — gate 80 % met, "All coverage checks have been met" |
| Docker | up; Testcontainers PostgreSQL and Redis started, **no test skipped for a missing daemon** |
| Release profile, `./mvnw -B -Prelease -Dgpg.skip=true clean verify` | **BUILD SUCCESS**, 53.7 s, 220 tests, 6 artifacts (2 main, 2 sources, 2 javadoc) |
| `scripts/verify-reproducible.sh` (two clean builds, same clone) | **6 of 6 byte-identical, exit 0**; e.g. `agent-guard-core-0.1.0-SNAPSHOT.jar` = `37ab9ebd0e3f863d39398d5a7f2eca354148dac29feffd1199d6d080e996f8e7`, starter jar = `1c2bd0d5ac845524b5e3024fddbe9d5b64f05dd3de4cfe9ec7d3a52cf239338b`. Both javadoc jars matched too this run; they are reported, not enforced. |
| Reproducibility timestamp | `2026-09-09T17:00:46Z`, the committer date of `3a0cb46` |
| `tools/cipher-probe-release-pipeline.sh` (`CIPHER_PROBE_MAVEN=1`) | **`still weak: 0    fixed: 36`, exit 0** — reproduced independently, matches Isis's report |
| CI on `3a0cb46` | **both jobs pass**: `Build & test` 2m15s, `DCO sign-off` 6s. PR #9 still draft, `MERGEABLE`. |

The stale-`reproducible-sha256.txt` note from the previous pass is resolved and was never a
real exposure: the file is listed in `.gitignore` (line 6) and `git log --all` for that path
is empty — it has never been tracked. What I saw before was an untracked build leftover in a
dirty working copy. The fresh clone contains no such file, and the release job writes its own
into `$RUNNER_TEMP` (`release.yml:251`) and compares *that* against the jars it deploys (L1).

### G4 — closed. Verified by the probe, by a control experiment, and by eight cases

The probe flips: `probe_dco_aborts_on_a_conflicted_merge` reads **FIXED**, suite
`still weak: 0    fixed: 36`, exit 0.

I did not trust the probe alone. I extracted the `dco` step body from the committed
`.github/workflows/ci.yml` in the fresh clone with the same awk the probe uses (54 lines)
and ran it against eight synthetic repositories. `EXEMPT` means the merge was waved through;
`CHECKED` means it fell through to the sign-off requirement.

| # | Case | Required | Observed |
| --- | --- | --- | --- |
| 1 | Octopus merge, three parents, adds `evil.txt` present in no parent, no sign-off | CHECKED | **exit 1**, merge named in `::error::` |
| 2 | Two parents, second an unrelated branch, **not** an ancestor of `BASE_SHA`, no sign-off | CHECKED | **exit 1**, both the merge and the rogue commit named |
| 3 | Genuine trivial back-merge of the base, no sign-off on the merge commit | EXEMPT | **exit 0**, "all commits … are signed off" |
| 4a | Real PR range, ordinary single-parent commits, all signed off | pass | **exit 0** |
| 4b | Same range plus one ordinary unsigned commit | CHECKED | **exit 1**, that commit named |
| 5 | Back-merge, second parent **is** an ancestor of `BASE_SHA`, tree smuggles `smuggled.txt` | CHECKED | **exit 1**, merge named in `::error::` |
| **G4a** | **Conflicted back-merge, conflict resolved, merge commit signed off** | **CHECKED and PASS** | **exit 0**, `all commits in … are signed off` — the whole range was examined |
| **G4b** | **The same conflicted back-merge, merge commit unsigned** | **CHECKED and FAIL** | **exit 1**, `::error::commit a100101d… ("Merge branch 'main' into feature") has no 'Signed-off-by:' trailer`, then `::error::1 commit(s) missing a DCO sign-off` |

The six G3 cases are byte-for-byte the verdicts of the previous pass. Unchanged.

G4a is the load-bearing one, and it is on the conflicted path for real, not by construction:
`git merge-tree --write-tree HEAD^1 HEAD^2` on that repository **exits 1** and emits 7 lines /
272 bytes of conflict detail, against 1 line / 40 bytes and exit 0 on the clean merge in case 3.
So the guard is exercised.

**Control experiment.** The same signed-off conflicted repository, run against the *pre-fix*
step body taken from `git show 5cac151:.github/workflows/ci.yml`:

```
exit=1  output bytes=0
```

Post-fix, the identical input gives `exit=0` and the summary line. The harness discriminates
between the broken and the fixed step; G4 is closed by the change, not by the test's phrasing.

`set -e` no longer aborts the loop on any path: cases 1, 2, 4b, 5 and G4b all printed their
`::error::` annotations, and cases 3, 4a and G4a all reached the closing summary line, which
only prints after the whole range is walked.

### Attacks on the new surface that did not land

- **`merged` unbound under `set -u`.** `if merged="$(…)"` performs the assignment whatever the
  substitution's status, so `merged` is always set; it is read only inside the `if`-true branch.
  Executed directly: `set -euo pipefail; auto=""; if merged="$(false)"; then …; fi` survives with
  `auto` empty. Fails closed.
- **`printf | head -1` re-introducing the same `set -e`/`pipefail` abort by SIGPIPE.** Real
  hazard in the abstract — I reproduced `rc=141` by piping 100 000 lines into `head -1` under
  `set -euo pipefail` — but unreachable here. The pipeline runs only when `git merge-tree`
  exited **0**, and on exit 0 `--write-tree` prints exactly one 40-byte line (measured above).
  40 bytes fit in the pipe buffer, `printf` completes before `head` exits, no EPIPE. The
  `head -1` is now defensive only. Not a finding; recorded so the next person does not have to
  re-derive it.
- **`git merge-tree` unavailable (git < 2.38), which the previous pass flagged as the same
  silent abort.** Closed by the same fix, and verified rather than assumed: with a `PATH` shim
  that makes `git merge-tree` exit 129, case 3's trivial back-merge is no longer exempted — it
  is CHECKED, exits 1, and names the commit in an `::error::`. Old git degrades to strict, with
  output. Fails closed.
- **`git merge-tree` exiting 0 with empty output.** `auto` stays empty, `[ -n "$auto" ]` fails,
  not exempt, checked. Fails closed.
- **Forging the exemption by choosing parents**, **a first parent outside the checked range**,
  **`--is-ancestor` returning 128**, **word-splitting on `$parents`**, **a four-parent octopus**,
  **a second parent that is a descendant rather than an ancestor of `BASE_SHA`** — all re-checked
  against the current body, all still closed exactly as recorded in the previous pass.
- **The block comment.** Isis corrected it. It now states that `git merge-tree` exits non-zero on
  conflict and that this is why the `if` is there, and no longer claims a conflict-resolution
  merge already fell through. The comment matches the code.

### Verdict

**MERGE.** No HIGH, no MEDIUM, no LOW, no INFO open. G4 — the last one, and my own error from
the previous pass — is closed by a five-line change I prescribed and Isis applied verbatim, and
it is closed for the right reason: a conflict resolution is authored content, so it now falls
through to the sign-off requirement with a visible annotation instead of aborting the step in
silence. The DCO gate is correct on all eight cases I can construct. The pipeline builds from a
fresh clone, tests green with one documented assumption skip and nothing skipped for Docker,
holds 90.60 % line coverage, builds under the release profile, and reproduces six of six
artifacts byte-for-byte. The probe suite reads `still weak: 0    fixed: 36`, exit 0. CI is green
on both jobs.

I do not merge and I do not undraft. PR #9 is ready for Souhaile.

### The nine steps for Souhaile, in this exact order

1. **Merge PR #9 into `main`.** Nothing below works until this is on `main`.
2. **Add the four repository secrets, each straight from a pipe** — never a shell argument,
   never a file left on disk, never the clipboard:
   `gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard`,
   then `gh secret set GPG_PASSPHRASE --repo 1of1Canopus/agent-guard` (it prompts, reads the
   terminal, and stays out of shell history), and the same prompted form for `CENTRAL_USERNAME`
   and `CENTRAL_TOKEN` — the two halves of the Sonatype Central user token, which is shown once
   and never again.
3. **Set the repository variable `RELEASE_SIGNING_KEY_ID` to the full 40-character primary
   fingerprint.** Not a short key id, not an email address. The workflow matches the last field
   of `git verify-tag --raw`'s `VALIDSIG` line, and that field is always the primary key's
   fingerprint even when a subkey made the signature.
4. **Flip the repository to public.**
5. **Create the `release` environment with yourself as the required reviewer.** This is the
   human gate on the job that holds the signing key. It cannot exist while the repository is
   private on the free plan, which is why it comes after step 4.
6. **Run the follow-up PR that removes the grandfather exemption** — delete `GRANDFATHER_SHA`
   and its `git cat-file` / `merge-base --is-ancestor` block from the `dco` job. Once #9 is on
   `main` that block is dead code (QUESTIONS.md #29 / #33).
7. **Tag `v0.1.0` on `main`, signed:** `git tag -s v0.1.0`. Signed, not `-a` — the workflow
   requires a signature bound to the fingerprint from step 3 and will refuse an unsigned tag.
8. **Run the release workflow.** It builds, verifies reproducibility, signs, and uploads the
   bundle to the Sonatype Central Portal.
9. **Press Publish on the Sonatype Central Portal.** The bundle waits there. Nothing in the
   workflow can publish on its own, by design — this last step is a person, on purpose.

---

## Re-verification pass — 2026-09-10 — branch `fix/release-debug-guard` (PR #13, `39435f1`)

Scope: the one-commit fix for N6's recurrence in the first real release run
(34389977548, tag `v0.1.0`), which failed at `Refuse Maven debug output in this job`
because `debug_pattern` matched the bare words `simpleLogger`/`defaultLogLevel` and the
workflow pins `MAVEN_OPTS=-Dorg.slf4j.simpleLogger.defaultLogLevel=info` for itself.

### Numbers

| Run | Result |
| --- | --- |
| `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` | 37 fixed, 0 weak, exit 0 |
| `tools/cipher-probe-release-pipeline.sh` (no Maven) | 35 fixed, 2 **skipped and counted weak**, exit 1 |
| Guard body run against the workflow's own declared env | exit 0 |
| Guard body, 15 adversarial env cases | 15/15 refused |

The two probes that need `CIPHER_PROBE_MAVEN=1` are reported WEAK when skipped and the
suite exits 1. That is the correct behaviour: a skipped probe is not a passing probe.
Isis's "37/37 exit 0" is only true with `CIPHER_PROBE_MAVEN=1` set.

### N6 confirmed closed

`debug_pattern` is now
`(^|[[:space:]])(-X|--debug|-e|--errors)([[:space:]]|$)|defaultLogLevel=(debug|trace)|maven\.debug`.
I extracted the step body from the yml and ran it directly, not through the probe:

- `MAVEN_ARGS=-B`, `MAVEN_OPTS=-Dorg.slf4j.simpleLogger.defaultLogLevel=info` (the workflow's
  own declared values, parsed from lines 52-53) → **exit 0**. The production failure is gone.
- Refused, exit 1, all of: `-X`, `--debug`, `-e`, `--errors` in `MAVEN_ARGS`;
  `defaultLogLevel=DEBUG`, `=trace`, `=TrAcE` (the `grep -Ei` covers case);
  `-Dmaven.debug=true`.
- Refused by the exact-pin belt, exit 1, all of: the pin with a **trailing space**; the pin
  with a second flag **appended**; a flag **prepended** to the pin; `MAVEN_OPTS` empty;
  `MAVEN_OPTS` set to whitespace; the pin plus an unrelated per-logger property.

The belt (`MAVEN_OPTS` must be string-equal to the pin) is what makes the narrowed pattern
safe: every `MAVEN_OPTS` mutation is caught by equality even when the pattern does not
match it. `MAVEN_ARGS` has no equivalent pin and is covered by the pattern only.

No residue of the old pattern anywhere: every remaining `simpleLogger`/`defaultLogLevel`
occurrence in `.github/`, `tools/` and `docs/` is either the pin itself, the exact-pin belt
comparison, or prose in a comment. The guard's static check over the two named `run:` blocks
uses the same narrowed variable and passes against the current file.

### N12 — LOW — the probe suite is not run by anything

`grep -rl 'cipher-probe' .github/` returns **zero files**. `tools/cipher-probe-release-pipeline.sh`
is invoked only by hand. This is the mechanical reason N6 reached a tagged release: the suite
that would have caught it was never executed by CI on the branch that broke it, and the fix
for that is a workflow job, not a habit.

QUESTIONS.md #34 states the right rule — every guard probe must include the workflow's own
declared env — but a rule whose only enforcement is that the next agent remembers it is not
a control. It has already failed once here, in exactly this file.

Repro: `cd modules/B-agent-guard && grep -rn 'cipher-probe' .github/ ; echo "exit=$?"` → no
output, exit 1.

Fix (Isis): add a job to `.github/workflows/ci.yml` that runs
`CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh` on every push and pull request,
with no `continue-on-error` and no `if:` that can skip it. The script already exits 1 when any
probe is weak, so no change to the script is needed. Add
`probe_probe_suite_is_not_run_by_ci` asserting that some workflow under `.github/workflows/`
invokes the suite unconditionally.

### Reproduction attempts that closed with no code change

- **Per-logger slf4j level walks past the pattern.** `MAVEN_ARGS="-B
  -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.MavenCli=debug"` and
  `...log.org.apache.maven=trace` both pass the guard (exit 0). I then tried to demonstrate
  the leak this guard exists to prevent and could not: on Apache Maven 3.9.16 (this repo's
  wrapper), with a canary environment variable set, **`-X` itself does not print the process
  environment** — 0 canary hits across 185 lines with `help:evaluate` and 232 lines with a
  real `validate`, with and without the `MAVEN_OPTS` pin. Since the baseline leak is not
  reproducible on the pinned Maven, a bypass of the guard that would enable it is
  **suspected, not a finding**. Not a code change. Re-open if the wrapper moves to a Maven
  version whose `-X` does dump `env.*`.
- **Maven invocations outside the guard's static check.** The `Reproducibility check` step
  (its own `MAVEN_OPTS`), `scripts/verify-reproducible.sh`, and the `mvnw` call at line 415
  are not covered by the two-step static check. Not a finding: line 415 is in the separate
  `sample-smoke` job and the guard is job-scoped by design and says so, and the only step in
  `publish` that holds `CENTRAL_USERNAME`/`CENTRAL_TOKEN`/`MAVEN_GPG_PASSPHRASE` is
  `Verify, licence check, sign, upload`, which the static check does cover. Debug output in a
  step with no secret in its environment leaks no secret.
- **Same-shape defect elsewhere.** Quick scan of `release.yml` and `ci.yml` for checks that
  could refuse the workflow's own declared values: no second instance today. One latent
  fragility worth knowing, not a finding on current code: the static check greps the two
  `run:` blocks with a pattern containing `-e` bounded by whitespace, so a future bare
  `set -e` (rather than today's `set -euo pipefail`) added to either step would make the
  guard refuse the workflow's own source — the N6 shape again, one edit away.

### Verdict

**MERGE WITH FIXES** — one LOW (N12: wire `tools/cipher-probe-release-pipeline.sh` into
`ci.yml`). The N6 fix itself is correct, minimal, and verified against the real job env; it
is the pattern change the failed release needed and it gives up nothing, because the exact-pin
belt already covers everything the removed bare-word matches covered. No HIGH, no MEDIUM.
Tag `v0.1.0` is untouched and can be re-run once N12 is in.

### N12 re-verification — 2026-09-10 — `aad8091`

Confirmed closed at the workflow level. `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`
locally: **38 fixed, 0 weak, exit 0**, with `probe_probe_suite_is_not_run_by_ci` FIXED. The
`cipher-probes` job in `ci.yml` has no `if:`, no `continue-on-error`, actions pinned by SHA,
`permissions: contents: read`; `ci.yml` has no `paths:` filter, so it cannot be dodged by
touching only `release.yml`. Ruleset 22670337 is `active` on `refs/heads/main` with
**zero bypass actors**, `strict_required_status_checks_policy: true`, and requires
`Build & test`, `DCO sign-off`, `Cipher probes`. Run 34413322220 green on all three at
`aad8091`.

### N13 — LOW — `probe_probe_suite_is_not_run_by_ci` accepts four disabled forms

The job is correct today; the probe that is supposed to keep it correct is not. It splits the
file on step boundaries and looks for a `run:` line naming the script with no
`continue-on-error: true` in the same step. It therefore reports FIXED for all of:

| Mutation of `ci.yml` | Probe says |
| --- | --- |
| job-level `if: false` on `cipher-probes` | FIXED |
| job-level `continue-on-error: true` | FIXED |
| step-level `if: false` | FIXED |
| the `run:` line commented out with `#` | FIXED |
| step-level `continue-on-error: true` | WEAK (caught) |
| the `run:` line deleted | WEAK (caught) |

The commented-out case is the same defect the release guard's own static check already avoids
one file away, where it pipes through `grep -vE '^\s*#'` before matching. Here a single `#`
disables the suite and the suite still passes itself. The job-level `if:` case matters most in
combination with the ruleset: GitHub counts a **skipped** job as satisfying a required status
check, so `if: false` would leave `Cipher probes` green on the branch-protection page while
nothing ran.

Repro (no repo files touched): copy `ci.yml` into a scratch `.github/workflows/`, apply each
mutation above, source `probe_probe_suite_is_not_run_by_ci` and call it — it returns 1 (FIXED)
for four of the six.

Fix (Isis): strip full-line comments before matching; require the invoking step to carry no
`if:` and no `continue-on-error:` at all (not just `continue-on-error: true`); and check the
enclosing **job** block for `if:` / `continue-on-error:` as well as the step. Add
`probe_suite_probe_accepts_a_disabled_probes_job`, which builds each of the four mutations
above in a temporary directory and asserts `probe_probe_suite_is_not_run_by_ci` reports WEAK
for every one — WEAK on current code, FIXED after.

**Verdict on `aad8091`: MERGE WITH FIXES** — one LOW (N13). N12 itself is closed: the job, the
triggers and the ruleset are all correct and fail-closed. What is missing is only the
regression guard on that job, and it is a change to one awk block in a file CI already runs.

## Verdict (`7baf844`): MERGE WITH FIXES — one LOW (N14)

N13 is closed. Suite: **39 fixed, 0 weak, exit 0**. CI run 34416162458 green on
`Build & test`, `DCO sign-off`, `Cipher probes`. `_probe_suite_wired_unconditionally_in`
now strips full-line comments, splits per job, and refuses any `if:` or
`continue-on-error:` on the job or the step. Re-ran my four mutations — job-level
`if: false`, job-level `continue-on-error: true`, step-level `if: false`, `run:` line
commented out — all four now WEAK (refused). Two of my own choosing also refused:
`continue-on-error: ${{ expr }}` (no literal `true`) and `if: ${{ expr }}` at job level,
so the fix keys on the presence of the key, not on its value. Deleting the whole job:
refused. Baseline unmodified file: accepted, as it must be.

### N14 — LOW — a trailing comment still hides a disabled probes job

Comment stripping is anchored at `^[[:space:]]*#`, so only whole-line comments go. The
`run:` regex then still matches the script name when it appears **after** a `#` on a line
that runs something else:

```yaml
        run: true # CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh
```

`probe_probe_suite_is_not_run_by_ci` reports FIXED for this. CI would be green, the
required `Cipher probes` check satisfied, and no probe would have run. This is the same
defect as N13's whole-line-comment case, one variant further out.

Repro: copy `ci.yml` to a scratch `.github/workflows/`, apply the line above, source
`_probe_suite_wired_unconditionally_in` and `probe_probe_suite_is_not_run_by_ci`, call it —
returns 1 (FIXED).

Fix (Isis), using the pattern this repository already trusts twice: stop pattern-matching
and assert the **exact** command. Require the `cipher-probes` job to contain a `run:` line
whose value is string-equal to `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`
— the same exact-pin belt that makes the `MAVEN_OPTS` guard sound. Any decoration, comment
or substitution then fails equality without needing a YAML parser. Add
`probe_suite_probe_accepts_a_trailing_comment_disable`: WEAK on current code, FIXED after.

### Re-tag not performed — preconditions are not met

I was asked to delete and re-create `v0.1.0` if the verdict was MERGE. It is not, and three
independent reasons say do not do it yet:

1. **There is no new main commit to tag.** `origin/main` is `a01f03a`, which is exactly what
   `v0.1.0` already points at. PR #13 is still `OPEN`; `git merge-base --is-ancestor 39435f1
   origin/main` returns false. Re-tagging today would either re-create the identical tag or
   put a release tag on an unmerged branch — the very thing the N8 ancestry check exists to
   refuse.
2. **I must not sign it.** The release key (`1EFC858B76B00ABB6BF5A147CA5E8EFD2C575ACF`,
   Souhaile) is in this machine's keyring, so the command would succeed. Signing a release
   tag as the key holder from an agent session defeats control F3 and the human gate it
   exists to enforce. The tag is Souhaile's signature or it is worthless. Refused.
3. **The next run would fail anyway.** `gh variable list` is empty: `RELEASE_SIGNING_KEY_ID`
   is not set, so `Verify the tag signature` will exit 1 at step 6 of the checklist. Correct
   fail-closed behaviour, but it must be set before any re-run.

Order: land N14, merge PR #13 into `main` (Souhaile), set `RELEASE_SIGNING_KEY_ID`, then
Souhaile deletes `v0.1.0` local and remote and re-creates it signed on the new `main`.

## Final verdict (`c94db7a`): MERGE

N14 is closed and no finding is open. `_probe_suite_wired_unconditionally_in` now requires the
trimmed `run:` value to be string-equal to `CIPHER_PROBE_MAVEN=1 tools/cipher-probe-release-pipeline.sh`,
which is the exact-command belt this workflow already uses for `MAVEN_OPTS`. Suite: **40 fixed,
0 weak, exit 0**; CI run 34418019491 green on `Build & test`, `DCO sign-off`, `Cipher probes`
at `c94db7a`. Mutations re-run against the committed probe: the N14 trailing comment
(`run: true # <cmd>`) refused, the command commented out inside a multi-line block refused,
and two of my own — `|| true` appended (which would swallow the suite's exit 1) and
`CIPHER_PROBE_MAVEN=0` (which would silently skip the two Maven probes) — both refused, neither
of which the earlier regex would have caught. Baseline unmodified file still accepted.

Strictness now errs toward WEAK: harmless reformatting of that one line (extra inner
whitespace, a trailing `#x`) also refuses. That is the correct direction and the opposite of
N6 — it turns CI red and asks for the exact string back, rather than failing a release after
the upload. Not a finding.

**Correction to my previous pass, item 8.** I wrote that `RELEASE_SIGNING_KEY_ID` was unset on
the evidence of an empty `gh variable list`. That command lists repository variables only. The
variable is set on the **`release` environment**, which is what the publish job declares
(`environment: release`, line 66) and reads through `vars.`. Verified via
`gh api repos/1of1Canopus/agent-guard/environments/release/variables`: present, exactly 40 hex
characters, and equal to the primary fingerprint of the release key
`1EFC858B76B00ABB6BF5A147CA5E8EFD2C575ACF`, so the `Verify the tag signature` step will match a
tag signed by that key. Isis is right, my item 8 was wrong, and it is withdrawn.

Remaining before a release run, none of it a security finding and none of it mine to do:
merge PR #13 into `main`, then Souhaile deletes `v0.1.0` local and remote — never published,
the run failed before upload — and re-creates it signed on the new `main`. I did not tag.
