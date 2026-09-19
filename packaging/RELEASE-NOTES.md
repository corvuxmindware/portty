# Portty release notes

> **Note on this file:** the v5 section below is stale - v6, v7 and v8 shipped
> without an entry here, so it is not a continuous history. Only the v9 section is
> current. Reconciling the gap is a deliberate call for whoever owns the notes; it
> is not done here.

## Unreleased - protocol v10

### ⚠️ Flag-day: the host and the phone must upgrade together

`PROTOCOL_VERSION` is **10**. Same rule as always - one wire generation, no
negotiation, so a v10 host refuses a v9 phone and vice versa, failing closed
before any application data moves. Ship the phone build and roll `portty-host` to
every laptop together.

### Open a terminal in your home directory, chosen from the phone

Before this, the only folders a phone could reach were inside the workspace root -
and the workspace root could only be widened **on the laptop**, with
`PORTTY_WORKSPACE`. That is no good for a product whose premise is reaching a
machine from your phone: the person holding the phone is the one who needs a
different folder.

The host now declares a set of **roots** and the phone picks among them - by
default the workspace and the user's home. New `TerminalRoot`,
`RequestKind::ListTerminalRoots` / `ListDirsIn` / `NewSessionInRoot`, and
`Frame::TerminalRoots` (index 43). All pure appends; `NewSessionIn` and
`ListWorkspaceDirs` stay frozen and still mean "relative to the workspace".

- **Roots are host-declared, and the phone asks.** An operator can restrict with
  `PORTTY_TERMINAL_ROOTS=workspace`, and a request naming a root this host does not
  serve is **refused, not substituted**. A typo (`hoem`) names no root rather than
  reading as "serve everything". The workspace is always served.
- **Still no absolute paths on the wire.** `rel` is relative to the chosen root and
  the host re-resolves it with the same `resolve_within` - normalize, canonicalize,
  re-check containment - so traversal and escaping symlinks are refused exactly as
  before, per root.
- **Terminals only, by construction.** `NewAgentSessionIn` cannot name a root, so an
  agent still cannot start outside the workspace. That confinement is a real
  boundary - the chosen directory is also the agent's ACP file-access sandbox root -
  and it is unchanged.
- **Why this is not a widening for terminals:** a paired phone can already open a
  shell and run `ls /`; there is no read-only pairing tier. What the roots add is
  convenient enumeration, which is precisely why they stop short of the agent path.

The phone-local default folder (from v9, unchanged wire) is now root-qualified,
stored as `root:rel`. **Values written before v10 have no prefix and still mean the
workspace** - that is the migration, and it is covered by a test, because getting it
wrong would silently move every existing default to a same-named folder under home.

### Verification status

Laptop-verified green: root Rust 354 tests · protocol 45 (incl. the index-43 frame,
the three appended requests, and `TerminalRoot`'s own tags, pinned now so the order
is a contract from here on) · tauri 43 · app `tsc` clean + 156 vitest + production
build · decoder fuzz 3 × 1000 runs, no crashes · clippy `-D warnings` clean on both
workspaces.

**Not device-validated:** the root switcher and starring a folder under home on a
physical phone. The secret-scan job did not run locally (`gitleaks` is not installed
on the build machine), and no Windows runner exercised the drive-letter-free
`home_dir()` path.

## Unreleased - protocol v9

### ⚠️ Flag-day: the host and the phone must upgrade together

`PROTOCOL_VERSION` is now **9** (was 8), and `MIN_SUPPORTED_PROTOCOL_VERSION ==
PROTOCOL_VERSION` by design - one wire generation, no negotiation. A v9 host will
not accept a v8 phone and vice versa; the mismatch fails closed before any
application data moves, and each side shows the directional "update the older
side" message.

**Rollout - together, not one before the other:**

1. Ship the new phone build (TestFlight / Play) from this commit.
2. Roll the new `portty-host` / CLI to every laptop at the same time.

### Phone terminals open where you tell them

- **Fixed: a phone shell ignored the workspace entirely.** `spawn_shell` never
  applied `iroh_serve::workspace_dir()`, and portable_pty does not inherit the
  daemon's cwd - so every phone terminal opened in HOME (`%USERPROFILE%` on
  Windows) rather than `PORTTY_WORKSPACE` or the launch directory, exactly the
  trap `workspace_dir`'s own doc comment warns about. The agent spawn and the
  local browser proof each applied it themselves, which is why the proof looked
  correct. **This half is a behaviour fix, not a wire change** - an old phone
  against a new host also lands in the right directory.
- **New: choose the folder.** A "Session in folder…" button browses the host's
  workspace and opens a shell in the directory you pick, reusing the v6
  `ListWorkspaceDirs` listing and the agent picker's folder browser rather than
  adding a second one. New request `RequestKind::NewSessionIn` (index 16, pure
  append); `NewSession` / `NewSessionSized` stay frozen and keep meaning "the
  workspace root". "+ New session" is unchanged and still one tap.

  Scope note: for an agent, the chosen directory is also its ACP file-access
  sandbox root, so picking deeper strictly narrows reach. For a **shell it is not
  a security boundary** - a terminal can `cd` anywhere its user can reach. The
  same `workspace::resolve_within` still normalizes, canonicalizes and re-checks
  containment (traversal and escaping symlinks are refused, not clamped), so the
  phone cannot name a directory the host will not vouch for.

### Verification status

Laptop-verified green: transport 137 · protocol 44 (incl. the index-16 round-trip
and the previously unpinned `ListAgentProviders` tag) · host 121 (incl. a PTY
probe that asks the shell its own `pwd`, and the chosen-directory accept/refuse
pair over real iroh) · tauri 39 · app `tsc` clean + 156 vitest + production build
· decoder fuzz 3 × 1000 runs, no crashes.

**Not device-validated:** the "Session in folder…" sheet on a physical phone, and
the v9 handshake against a rebuilt host. The secret-scan job did not run locally
(`gitleaks` is not installed on the build machine).

## Unreleased - protocol v5 (iOS build 1.11 · Android versionCode 1007)

### ⚠️ Flag-day: the host and the phone must upgrade together

`PROTOCOL_VERSION` is now **5** (was 4), and `MIN_SUPPORTED_PROTOCOL_VERSION == PROTOCOL_VERSION`
by design - Portty runs exactly one wire generation with no downgrade or capability
negotiation (see `crates/transport/src/frame.rs`). A v5 host will **not** accept a v4
phone, and a v5 phone will **not** connect to a v4 host; the mismatch fails closed before
any application data is exchanged.

**Rollout - do these together, not one before the other:**

1. Cut and ship the new phone build (TestFlight / Play) built from this commit.
2. Roll the new `portty-host` / CLI to laptops at the same time.

A phone left on the old build shows a first-class, directional message instead of a
cryptic error:

> This phone is running an older Portty version than the laptop. Update Portty from the
> App Store, then reconnect.

…and the laptop side shows the mirror ("update the laptop"). This is expected during the
window where only one side has upgraded.

### What changed in the wire

- **Approval resolution now carries the outcome + who answered (#49).** When a pending
  approval is answered on another device, the dismissed card no longer vanishes silently:
  every other viewer sees e.g. *"Rejected on the laptop"*, and the Decision log records the
  outcome (allowed / rejected / cancelled) and the resolver (phone / laptop / system). New
  frame `AgentPermissionResolvedInfo` (index 39, pure append). The laptop-chat relay pipe
  is intentionally left frozen - it still dismisses the card, without the richer detail.
- **Version-mismatch message names the older side (#13).** The mismatch message now uses
  the peer's wire version (from the frame-layer rejection) to say which side to update,
  instead of a generic line. The single-generation flag-day itself is intentional, not a bug.

### Also on this release (already landed on master)

Attach spinner, "answered on another device" toast, QR-scanner torch, `portty share`
flag-guard, VT-scanner RIS/DECSTR alt-screen exit + DECCKM-aware arrows, agent-feed
reconcile-by-position, glanceable pending-approval count badge, and removal of the dead
SAS/fingerprint surface.

### Verification status

Laptop-verifiable: transport 100 · host 63 · protocol 31 (incl. the index-39 round-trip)
· tauri 7 · app `tsc` clean + 54 vitest - all green.

**Not yet device-validated** (needs an Xcode / gradle build - see
[`PUSH-SETUP.md`](PUSH-SETUP.md) §5–6): the iOS/Android app-switcher privacy covers, the
iOS release (`aps-environment=production`) entitlement, and the v5 wire behaviours
end-to-end (resolved-elsewhere detail, the flag-day mismatch message).
