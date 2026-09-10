
## Commit convention
Conventional Commits, enforced by `.githooks/commit-msg`. After cloning run `git config core.hooksPath .githooks`. Full rules: see this product line's shared conventions (`15-regulated-spring/specs/SHARED-CONVENTIONS.md`) or the `AGENTS.md` of the relevant lane in that repository.

## Licence of your contribution

This project is licensed under the [Functional Source License, Version 1.1, ALv2 Future
License](./LICENSE) ("FSL-1.1-ALv2"). Unlike Apache-2.0, FSL has no built-in contribution
clause, so we ask for two things from every pull request, both of them the lightweight kind
(no signed PDF, no CLA bot with legal review):

1. **Sign off every commit under the [Developer Certificate of Origin 1.1](https://developercertificate.org/)**
   (the same mechanism the Linux kernel and most CNCF projects use). Add `-s` to your commit:

   ```bash
   git commit -s -m "fix: ..."
   ```

   That appends a `Signed-off-by: Your Name <you@example.com>` trailer, which is your
   certification that you wrote the contribution or otherwise have the right to submit it
   under the DCO. `ci.yml` checks that every commit in the pull request carries one; a PR
   with an unsigned commit will not pass.

2. **You license your contribution under the project's licence, and grant HouseDevinci the
   right to relicense it.** By submitting a pull request you agree that your contribution is
   licensed to HouseDevinci under FSL-1.1-ALv2 (the same terms as the rest of the project),
   and that HouseDevinci may relicense your contribution under the Grant of Future License in
   `LICENSE` (the automatic conversion to Apache-2.0 two years after each version's release)
   or under any other licence the project moves to in the future, on the same terms as the
   rest of the codebase. This is the "simple CLA" referred to in `specs/LICENSING.md`; the DCO
   sign-off above is how it is recorded, there is nothing further to sign.

No CLA bot, no separate form: the DCO trailer plus this paragraph is the whole agreement.

## Planning and security records

Project planning and review records are maintained privately; security reports go to security@housedevinci.com.
