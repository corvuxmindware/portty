# Contributing to Portty

Thanks for your interest in Portty. Portty gives a phone real control over a
computer's terminal, so changes here affect a security boundary. That shapes how
we review: expect careful questions about anything touching pairing, credentials,
the host process, or agent permissions.

Portty is maintained by Corvux Mindware Private Limited and licensed under
Apache-2.0.

## Found a security problem? Stop here

Do not open a public issue or pull request for a vulnerability. Follow
[SECURITY.md](SECURITY.md) instead, which routes reports through GitHub's
private reporting form.

This includes anything that could weaken pairing, let a revoked device back in,
leak reconnect tokens or identity keys, or widen what a paired phone can reach.

## Before you write code

- **Small fix** - typo, obvious bug, doc correction: just send the pull request.
- **Anything larger** - new feature, refactor, dependency change, protocol or
  wire-format change: open an issue first and describe the problem you want to
  solve. This saves you from building something we cannot merge.
- **Changes to the security model** are unlikely to be accepted from a cold pull
  request. Open an issue and let's talk through the threat first.

## Setting up

The [README](README.md) is the source of truth for setup and commands. Start
with:

- [Requirements](README.md#requirements) - Rust, Node/pnpm, and the platform
  toolchains.
- [Build and install the desktop commands](README.md#build-and-install-the-desktop-commands)
- [Mobile app development](README.md#mobile-app-development)
- [Repository development commands](README.md#repository-development-commands)

You do not need the full mobile toolchain to work on the Rust side. If your
change is frontend-only, `pnpm design` in `app/` renders the real components in
a phone-sized frame with no Xcode, Android SDK, or device build.

## Checks your pull request must pass

Run these before you push. From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

If you touched the mobile Rust core:

```sh
cargo test --manifest-path app/src-tauri/Cargo.toml
```

If you touched the frontend, from `app/`:

```sh
pnpm test
pnpm exec tsc --noEmit
```

Clippy runs with `-D warnings`, so a warning is a failure. Please do not silence
one with `#[allow(...)]` unless you explain why in the code.

## Sign your commits (DCO)

Portty uses the [Developer Certificate of Origin](https://developercertificate.org/).
It is a short statement that you wrote the change, or otherwise have the right
to submit it under Apache-2.0. There is no form to sign and no account to
create.

Add a sign-off line to every commit:

```sh
git commit -s -m "Fix reconnect after host restart"
```

That appends:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and an email you can be reached at. To sign off commits you
already made:

```sh
git rebase --signoff main
```

A pull request without sign-off on every commit cannot be merged.

## Sending the pull request

You do not need write access to this repository. The normal flow:

1. Fork `corvuxmindware/portty` on GitHub.
2. Create a branch off `main` in your fork:
   `git checkout -b fix/reconnect-after-restart`
3. Make the change, run the checks above, commit with `-s`.
4. Push to your fork and open a pull request against `main`.

`main` is protected: nobody pushes to it directly, and every change lands
through a reviewed pull request.

### Branch names

Use a short prefix and a hyphenated description:

- `fix/` - a bug fix
- `feat/` - a new capability
- `docs/` - documentation only
- `chore/` - dependencies, tooling, cleanup

### Commit messages

- First line: imperative mood, under 72 characters, no trailing period.
  `Reject stale reconnect tokens after revoke`
- Then a blank line, then the body.
- Explain **why** the change is needed. The diff already shows what changed.
- Reference the issue it closes: `Closes #123`.

### What a good pull request looks like

- One logical change. Split unrelated work into separate pull requests.
- Tests for new behaviour and for the bug you fixed.
- Documentation updated in the same pull request when behaviour changes -
  especially the README command reference if you touched a command or an
  environment variable.
- No unrelated formatting churn.
- No new dependency without a reason in the pull request description. Every crate
  and package we add runs on a machine that a phone can reach, so additions get
  scrutiny.

## Never commit secrets

Pairing tickets, pairing phrases, PINs, identity keys, reconnect tokens, push
secrets, signing keys, and provider credentials are live secret material. Do not
paste them into issues, pull requests, logs, test fixtures, or screenshots. A
pairing ticket can start an enrollment attempt while pairing is open, even
though the host must still confirm the new phone.

If you need to show output from `portty pair`, `portty-host peers`, or the
`acp-probe` diagnostic, redact it first.

## Code of conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing

Contributions are accepted under [Apache-2.0](LICENSE), the same licence as the
rest of the project. Your DCO sign-off is your confirmation that you may submit
the work under those terms.
