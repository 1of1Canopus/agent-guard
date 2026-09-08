# Security policy

## Reporting a vulnerability

Email **security@housedevinci.com**.

> **Placeholder, not yet confirmed to exist.** `oss@housedevinci.com` (the address in the
> published POM's `<developers>` block) and `security@housedevinci.com` both need to exist
> and forward before `v0.1.0` is published. See `QUESTIONS.md` #21 and
> `docs/RELEASING.md`'s release gates: creating the mailbox is the maintainer's, this file is the
> engineering agent's. Do not remove this notice until the address is confirmed live.

Please do not open a public GitHub issue for a suspected vulnerability. Include:

- the version of `agent-guard-core` / `agent-guard-spring-boot-starter` affected
- a description of the vulnerability and its impact
- steps to reproduce, or a minimal repro project if practical

## Supported versions

Agent Guard is pre-1.0. Until `1.0.0`, only the latest published minor version receives
security fixes.

| Version | Supported |
|---|---|
| latest `0.x` | yes |
| older `0.x` | no |

After `1.0.0`, this table will list the latest minor of the current and previous major.

## Disclosure window

We ask for **90 days** from first report before public disclosure, to give us time to
develop, test and publish a fix and to notify known downstream users where practical. We
will acknowledge a report within 5 business days and keep the reporter updated as a fix
progresses. A fix earlier than 90 days does not obligate early public disclosure; a
reporter who needs a longer window for coordinated disclosure elsewhere should say so.

## Scope

In scope: `agent-guard-core`, `agent-guard-spring-boot-starter`, and the release pipeline
that publishes them (`.github/workflows/release.yml`, `pom.xml` release profile,
`docs/RELEASING.md`). `agent-guard-sample` is a demo application, never published, and is
in scope only insofar as a vulnerability in it also reaches the library code.
