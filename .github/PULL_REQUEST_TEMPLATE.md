## What does this change?

<!-- One or two sentences. What is different after this lands? -->

## Why?

<!-- The problem being solved. Link the issue: Closes #123 -->

## How was it tested?

<!-- Which checks you ran, and on which platform. If you tested against a real
     phone, say which OS. Redact any pairing material from pasted output. -->

- Host OS:
- Phone OS (if relevant):

## Checks

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --all-targets` passes
- [ ] Mobile Rust core tested, if touched (`cargo test --manifest-path app/src-tauri/Cargo.toml`)
- [ ] Frontend tested, if touched (`pnpm test` and `pnpm exec tsc --noEmit` in `app/`)
- [ ] Every commit is signed off (`git commit -s`) - see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Documentation updated if behaviour, a command, or an environment variable changed
- [ ] No secrets, pairing tickets, phrases, keys, or tokens anywhere in the diff or description

## Security impact

<!-- Required. Write "None" if this cannot affect the security boundary.
     Otherwise explain what changes for pairing, revocation, reconnect,
     credential storage, the host process, or agent permissions.

     If you are reporting a vulnerability, STOP. Do not open a pull request.
     Follow SECURITY.md instead. -->

## New dependencies

<!-- List any crate or package added, and why it is needed. Write "None" if
     there are none. -->
