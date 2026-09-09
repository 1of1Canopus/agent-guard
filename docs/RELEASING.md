# Releasing Agent Guard to Maven Central

Two published artifacts:

| Artifact | What it is |
|---|---|
| `com.housedevinci:agent-guard-core` | the library |
| `com.housedevinci:agent-guard-spring-boot-starter` | the auto-configuration |
| `com.housedevinci:agent-guard-parent` | the parent POM (published because the other two point at it) |

`agent-guard-sample` is **never** published. It is a demo application.

Everything is signed, reproducible, and stops one step short of the public repository:
the pipeline uploads a bundle and the Central Portal validates it, then it waits for you
to press **Publish**. No workflow, token or agent can put an artifact on Maven Central on
its own.

---

## Part 1 - the one-off setup

Do this once, ever. Steps 1 and 2 are already done.

### 1. Central Portal account - DONE

You already publish from this account: `io.github.1of1canopus:tenantify-spring-boot-starter`
2.1.1 is on Maven Central. Nothing to do.

### 2. Verify the `com.housedevinci` namespace - DONE 2026-09-08

Verified on 2026-09-08, organisation "HouseDevinci", status **Verified**.
Kept here for the next domain-based namespace:

1. https://central.sonatype.com -> **Namespaces** -> **Add Namespace** -> type `com.housedevinci`.
2. On the new row, the menu icon -> **View ID**, copy the **Verification Key**.
3. At your DNS registrar for `housedevinci.com`, add a TXT record on the **apex** of the
   exact domain the namespace names (`com.housedevinci` -> `housedevinci.com`, not a
   subdomain):

   | Type | Name / Host | Value |
   |---|---|---|
   | `TXT` | `@` (i.e. `housedevinci.com`) | the verification key, pasted verbatim |

   Check it landed: `dig +short TXT housedevinci.com`
4. Back on the portal, **Verify Namespace**. It usually passes within minutes.
5. The TXT record can be removed once the namespace shows **Verified**.

Source: https://central.sonatype.org/register/namespace/ (read 2026-09-08).

### 3. The GPG signing key

You already have one: it signs Tenantify (`~/IdeaProjects/tenantify`, the `signingKey`
Gradle property in `~/.gradle/gradle.properties`). Either path works.

**Path A - reuse the Tenantify key.** Nothing to generate. Export it (Part 1.4 below) and
confirm it is on a public keyserver, because Central checks there:

```bash
gpg --list-secret-keys --keyid-format LONG          # note the long key id, e.g. ABCD1234EF567890
gpg --keyserver keyserver.ubuntu.com --send-keys ABCD1234EF567890
```

**Path B - a new key for this product line.** Cleaner separation: if the Tenantify key
ever has to be revoked, Agent Guard is untouched.

```bash
gpg --full-generate-key
#   kind:       (9) ECC (sign and encrypt)      [or (1) RSA and RSA, 4096 bits]
#   curve:      (1) Curve 25519
#   expires:    2y
#   real name:  HouseDevinci
#   email:      oss@housedevinci.com
#   passphrase: a long one, store it in your password manager

gpg --list-secret-keys --keyid-format LONG          # note the long key id
gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
```

Either way, keep the revocation certificate that GPG writes under
`~/.gnupg/openpgp-revocs.d/` somewhere safe and offline.

Central accepts `keyserver.ubuntu.com`, `keys.openpgp.org` and `pgp.mit.edu`. Send it to
`keyserver.ubuntu.com`; it is the one Sonatype names first and the one that has been up.
Note that `keys.openpgp.org` strips the user id unless you confirm the address by email,
which is why it is not the first choice here (QUESTIONS.md #23).

### 4. The four GitHub secrets

Repository -> **Settings** -> **Secrets and variables** -> **Actions** -> **New repository
secret**. Exactly these four names; the workflow reads no others.

| Secret name | Value |
|---|---|
| `CENTRAL_USERNAME` | the **username** half of a Central user token |
| `CENTRAL_TOKEN` | the **password** half of the same token |
| `GPG_PRIVATE_KEY` | the ASCII-armoured private key, whole block |
| `GPG_PASSPHRASE` | the passphrase for that key |

**Getting the Central user token.** https://central.sonatype.com -> your name (top right)
-> **View Account** -> **Generate User Token**. The portal shows a `<server>` snippet:

```xml
<server>
  <id>central</id>
  <username>zX1aB2cD</username>      <!-- this goes in CENTRAL_USERNAME -->
  <password>Kd9/...==</password>      <!-- this goes in CENTRAL_TOKEN    -->
</server>
```

It is shown once. Generating a new token invalidates the old one. These are the same two
values Tenantify uses as `mavenCentralUsername` / `mavenCentralPassword`.

**Exporting the GPG private key in the format the workflow expects.** ASCII-armoured, the
whole block including the `BEGIN`/`END` lines, no other text - and it must never touch the
clipboard, the filesystem, or a shell argument. `gh secret set` reading from a pipe is the
only sanctioned path: the key goes straight from `gpg`'s stdout to the encrypted secret
store and nowhere else.

```bash
gpg --armor --export-secret-keys <KEY_ID> | gh secret set GPG_PRIVATE_KEY --repo 1of1Canopus/agent-guard
gh secret set GPG_PASSPHRASE --repo 1of1Canopus/agent-guard   # prompts, reads from the tty, no history
```

Why not `pbcopy`: the macOS pasteboard is readable by every process running as your user
with no prompt, is captured by clipboard-history utilities, and - with Handoff/Universal
Clipboard on, the default - is copied to every other Apple device signed into the same
iCloud account, where it stays until something else is copied.

If your shell logs history to a file, disable it for this session first
(`HISTCONTROL=ignorespace` and a leading space on the command, or `set +o history` /
`unset HISTFILE` for the shell you are in) - `gh secret set ... < <(gpg ...)` does not put
the key on the command line, but a copy-pasted one-liner easily could later.

If you must use the web UI instead of `gh`: select the block in the terminal, paste into
the secret box, then immediately copy something harmless to clear the pasteboard.

Sanity check before setting the secret, on a throwaway keyring so you do not touch your
own, run inside a subshell so cleanup runs on any failing step, not only when you close the
terminal tab (N7 - a `trap ... EXIT` set at the top level of an interactive shell fires when
*that shell* exits, which is when the tab closes, not when one of the commands above it
fails; until then the directory holding `private-keys-v1.d` for the release key is still on
disk under `$TMPDIR` and `GNUPGHOME` is still exported over the rest of the session,
including step 3's `gpg --send-keys`):

```bash
(
  GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME" && export GNUPGHOME
  trap 'gpgconf --kill all 2>/dev/null; rm -rf "$GNUPGHOME"' EXIT
  gpg --armor --export-secret-keys <KEY_ID> | gpg --batch --import
  gpg --list-secret-keys                    # the key must appear
)
```

The subshell - the parentheses around the block - is what makes this true: the `trap` fires
when the subshell exits, at the closing `)`, whether the commands inside it succeed or one
of them fails, and `GNUPGHOME` never leaks into the outer shell you keep using afterwards.

### 5. Optional - publishing from your laptop

Only needed if you ever want to run the release by hand. Put the token in
`~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>zX1aB2cD</username>
      <password>Kd9/...==</password>
    </server>
  </servers>
</settings>
```

The server **id must be `central`**: it matches `<publishingServerId>central</publishingServerId>`
in the release profile. Then `./mvnw -B clean deploy -Prelease`.

### 6. The `release` environment and the tag signing key id

Two more one-off items, both release gates rather than merge gates - see
`docs/SECURITY-REVIEW-feat-release-pipeline.md` M5 and L7. Neither can be done from a
private repository on the free plan (`gh api repos/1of1Canopus/agent-guard/environments`
returns `total_count: 0`, and rulesets return HTTP 403). Do them together, after the
repository goes public and before tagging `v0.1.0`.

**The `release` environment.** Repository -> **Settings** -> **Environments** -> **New
environment** -> name it exactly `release` (the `publish` job in `release.yml` already
declares `environment: release`). Add Souhaile as a **required reviewer**. Then move the
four secrets from Part 1 step 4 out of repository secrets and into this environment's own
secrets, so they are unreachable from any workflow other than a run that has passed the
reviewer gate.

**The tag signing key id.** `git verify-tag` in `release.yml` is **required**, not optional
(N5): on the tag-push path the workflow now fails the job outright, before touching
anything else, if `vars.RELEASE_SIGNING_KEY_ID` is unset - there is no warn-and-continue
mode any more. Set it (a public value - it is a key id, not a secret, **Settings** ->
**Secrets and variables** -> **Actions** -> **Variables**) to the **full 40-character
fingerprint** of the GPG key you sign release tags with:

```bash
gpg --list-secret-keys --keyid-format LONG   # confirm the key, then get the full fingerprint:
gpg --fingerprint <KEY_ID> | awk '/Key fingerprint/{gsub(/[ =]/,"",$0); sub(/^Keyfingerprint/,""); print}'
```

A short key id or an email address is rejected: the check is bound to that exact
fingerprint via `git verify-tag --raw` and a `VALIDSIG` match, so a good signature from any
*other* key in the runner's keyring - including one an attacker uploaded to the same public
keyserver - no longer passes. Then tag releases with `git tag -s` (not `-a`) so there is a
signature to verify. This is a release gate, not a merge gate, but it is unconditional once
the tag-push path runs: there is no `workflow_dispatch` exemption to reason about.

The fingerprint above is always the **primary** key's, even if that key has a separate
signing subkey (`git tag -s` signs with the subkey when one exists, even when you pass `-u`
with the primary's id): the workflow's `VALIDSIG` check matches the **last** field of the
status line, which is the primary key's fingerprint whichever key actually made the
signature, so `RELEASE_SIGNING_KEY_ID` is always the value the command above prints and
never the subkey's.

---

## Part 2 - every release

### 1. Freeze and check

```bash
cd modules/B-agent-guard
./mvnw -B clean verify                     # 220 tests, 1 skip, coverage gate, licence check
./mvnw -B clean verify -Prelease -Dgpg.skip=true   # + sources and javadoc jars
scripts/verify-reproducible.sh             # two builds, identical jars
tools/cipher-probe-release-pipeline.sh     # every probe FIXED, script exits 0
```

`QUESTIONS.md` must have a decision on every open item, and the Cipher review for the
branch must be closed. That is `specs/RELEASE-PROCESS.md` steps 1 to 3.

**Release gates - true before the first tag, not before any PR merges:**

- [ ] The repository is **public** (L7). Nothing above it - the `release` environment, tag
      rulesets, and Central's own expectation of a resolvable `scm`/`url` - is available on
      a private repo.
- [ ] `oss@housedevinci.com` exists and forwards (QUESTIONS.md #21); `security@
      housedevinci.com` exists and forwards (`SECURITY.md`).
- [ ] The `release` environment exists with Souhaile as a required reviewer, and the four
      secrets live in it, not in repository secrets (Part 1 step 6, M5).
- [ ] `vars.RELEASE_SIGNING_KEY_ID` is set to the full 40-character fingerprint and release
      tags are signed with that key (`git tag -s`) - required unconditionally, the workflow
      no longer has an unsigned-tag path (Part 1 step 6, M5, N5).

### 2. Write the CHANGELOG entry

In `CHANGELOG.md`, turn `## [Unreleased]` into `## [0.1.0] - 2026-09-08` (today's date) and
open a fresh empty `## [Unreleased]` above it.

### 3. Commit and tag

`main` always carries `0.1.0-SNAPSHOT`. **You do not bump the version in the pom.** The
release version comes from the tag, and the workflow rewrites the poms inside the runner's
own checkout only; nothing is committed back. That keeps `main` buildable and keeps a
release from ever being a `-SNAPSHOT`.

```bash
git commit -am "docs(release): changelog for 0.1.0"
git tag -s v0.1.0 -m "agent-guard 0.1.0"    # -s: signed, not -a. See Part 1 step 6 (M5).
git push origin main
git push origin v0.1.0        # this starts the Release workflow
```

The tag must be `v` + the version: `v0.1.0` releases `0.1.0`. A tag whose version ends in
`-SNAPSHOT`, or that is not plain semver, is refused by the workflow's first step. The
workflow also refuses a tag whose commit is not on `main`, and refuses to run at all unless
`vars.RELEASE_SIGNING_KEY_ID` is set to the signing key's fingerprint and the tag verifies
against exactly that key (N5) - there is no unsigned-tag path any more.

### 4. Watch the workflow

**Actions** -> **Release**. Two jobs:

- **Verify, sign, upload to the Central Portal** - runs the tests, the format check, the
  coverage gate, the licence allowlist (which regenerates `THIRD-PARTY-NOTICES.txt`), the
  reproducibility check, then builds the sources and javadoc jars, signs everything with
  your key, and uploads the bundle. It stops at `validated`.
- **Sample app from a clean clone** - `specs/RELEASE-PROCESS.md` step 6: fresh checkout,
  PostgreSQL from scratch, the sample built and started, timed to its first HTTP response.
  The number appears in the job summary and belongs in the release notes.

To rehearse without tagging: **Actions** -> **Release** -> **Run workflow**, and type the
version (e.g. `0.1.0`) in the input. It behaves identically, tag or no tag.

### 5. Press Publish

Go to https://central.sonatype.com/publishing/deployments . The deployment is named
`agent-guard 0.1.0` and its state is **VALIDATED**.

- Read the component list. It must contain exactly `agent-guard-parent`,
  `agent-guard-core` and `agent-guard-spring-boot-starter`, each with a `.pom`, a `.jar`,
  a `-sources.jar`, a `-javadoc.jar` and a `.asc` for each. **No `agent-guard-sample`.**
- **Publish**.
- If something is wrong: **Drop**. Nothing has been published; fix, retag with a new patch
  version, run again. A version that reaches Maven Central can never be changed or removed,
  which is exactly why this step is a human one.

It reaches `repo1.maven.org` within about 15 to 30 minutes, and the search index a few
hours later. Confirm:

```bash
curl -s https://repo1.maven.org/maven2/com/housedevinci/agent-guard-core/maven-metadata.xml
```

### 6. After

`specs/RELEASE-PROCESS.md` steps 7 to 10: docs page, site module page updated with the
version, launch article draft, announcements, then triage issues daily for two weeks.

---

## How the pieces fit

| Where | What it does |
|---|---|
| `pom.xml`, profile `release` | sources jar, javadoc jar, GPG signature, Central Portal upload. Off by default, so `./mvnw verify` is untouched. |
| `pom.xml`, `central-publishing-maven-plugin` | `autoPublish=false`, `waitUntil=validated`, `excludeArtifacts=agent-guard-sample`. |
| `pom.xml`, `license-maven-plugin` | `THIRD-PARTY-NOTICES.txt` + the licence allowlist. Runs on **every** build, not only releases. |
| `pom.xml`, `project.build.outputTimestamp` | reproducible archives; the workflow overrides it with the committer date of the released commit. |
| `agent-guard-sample/pom.xml` | `maven.deploy.skip`, `maven.source.skip`, `maven.javadoc.skip`, `gpg.skip` - the sample is never signed or published. Kept out of the release bundle by `<excludeArtifacts>` in the release profile (L5), not by anything in this module's own pom. |
| `scripts/git-commit-timestamp.sh` | HEAD's committer date, in Maven's ISO form. |
| `scripts/verify-reproducible.sh` | builds twice, compares SHA-256 of every published jar. |
| `.github/workflows/release.yml` | the whole thing, on a tag `v*` or on demand. |

### Why not the Tenantify setup

Tenantify is Gradle and uploads its bundle with a hand-written `curl` to
`https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC`. Two
differences here, both deliberate:

- Agent Guard is Maven, so it uses `org.sonatype.central:central-publishing-maven-plugin`,
  the plugin Sonatype documents for the Portal
  (https://central.sonatype.org/publish/publish-portal-maven/ , read 2026-09-08). No
  hand-rolled HTTP, no API contract of our own to maintain.
- `publishingType=AUTOMATIC` releases to Maven Central with no human in the loop. This
  pipeline is the opposite: `autoPublish=false`. Maven Central is permanent, and a
  library that a bank puts on its classpath should not be one workflow bug away from
  being public.

The account, the token and the signing key are the same ones. Only the transport differs.
