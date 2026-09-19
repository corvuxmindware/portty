# Portty

By Corvux Mindware Private Limited.

Portty puts a computer's terminal sessions on a phone over an authenticated,
encrypted peer-to-peer connection. Pair once, then watch and control shells,
resume saved hosts, transfer files, and handle coding-agent approvals from the
mobile app.

The desktop product is command-line only:

- `portty` wraps a shell or command and mirrors it locally and remotely.
- `portty-host` owns sessions, pairing, reconnect credentials, and the secure
  phone connection.
- `portty-push-relay` is an optional, self-hosted wake-only notification relay.
- `app/` is the Tauri 2 + SolidJS mobile app for iOS and Android.

There is no Portty macOS desktop application. On macOS, install the `portty` and
`portty-host` binaries and use the iOS app on the phone.

## Mobile build identifiers

This public source uses the example app identifier `org.example.portty` and the
Apple team placeholder `YOURTEAMID`. They are not Portty's private signing
details. Before signing a mobile build, use an app identifier you control in the
Tauri config and generated iOS/Android projects, and replace the Apple team
placeholder in the iOS project and export settings. Configure APNs and Firebase
for the same identifier if you enable push notifications. The
[packaging guide](packaging/README.md) has the platform build steps.

Changing an app identifier creates a separate app on iOS and Android. Updating
an existing TestFlight or Play testing installation requires its original
identifier and signing assets in your private build environment. Never commit
signing keys, provisioning profiles, or service credentials.

The example vendor identifier also changes the desktop host's default data
directory and the mobile credential-store service. When replacing an existing
installation, set `PORTTY_DATA_DIR` to the prior host data directory if you need
to retain its host identity and pairings.

## What Portty does

- Shares an existing terminal workflow without moving it into a browser.
- Creates phone-owned shells on the host when requested from the mobile app.
- Keeps the host as a raw terminal-byte pipe; xterm.js performs VT rendering on
  the phone.
- Runs Claude Code, Codex, OpenCode, and Goose through ACP with structured
  messages, plans, tool calls, and approval cards.
- Synchronizes one agent conversation between the phone and laptop chat.
- Stores bounded terminal scrollback and structured agent history for reconnects.
- Supports multi-host resume, biometric app lock, file transfer, and optional
  push notifications for pending approvals.
- Durably revokes a paired device and rejects stale reconnect credentials.

## Architecture

```text
local terminal ── PTY ── portty relay ── per-user IPC ── portty-host
                                                           │
                                                           │ encrypted iroh QUIC
                                                           ▼
                                                     Portty phone app

coding agent ── ACP stdio ───────────────────────── portty-host
                                                           │
                                                           └── optional wake-only
                                                               push relay
```

Terminal bytes, agent content, pairing keys, and approval decisions do not pass
through the optional push relay. A relay operator can still observe network
metadata: the connecting host's source IP, a stable random host handle, the
provider/device token supplied during registration, and wake/revoke timing. The
wake selector is phone-sealed ciphertext and notification text is generic. A
revoked phone's registration is deleted durably, and the boot-time re-register
pass drops any registration whose pairing is gone rather than re-arming it, so a
revoked device stops receiving doorbells - including the approval timing they
would otherwise reveal. See [Push setup](packaging/PUSH-SETUP.md) for the
complete architecture, metadata boundary, and provider setup.

## Requirements

For the desktop CLI and host:

- Rust stable and Cargo when building from source.
- macOS, Linux, or Windows.
- `portty` and `portty-host` installed together or both available on `PATH`.

For the mobile app:

- Node.js, Corepack, and pnpm.
- Xcode and the iOS Rust targets for iOS builds.
- Android SDK/NDK and Android Rust targets for Android builds.

Agent-specific requirements:

| Agent | Host command used by Portty | Requirement |
| --- | --- | --- |
| Claude Code | `claude-agent-acp` | Adapter installed and on `PATH`, plus an authenticated Claude setup |
| Codex | `codex-acp` | Adapter installed and on `PATH`, plus an authenticated Codex setup |
| OpenCode | `opencode acp` | `opencode` installed, configured, and on `PATH` |
| Goose | `goose acp` | `goose` installed, configured, and on `PATH` |

Portty does **not** download an adapter for you. Starting an agent is a request
from a paired phone and the adapter then runs unsandboxed as you, so an implicit
`npx -y <package>@latest` would let a remote tap execute whatever that package
publishes next. Install the adapter, or - if you want a package runner - opt in
locally with the exact command you have vetted, pinned to a version:

```bash
export PORTTY_CLAUDE_ACP_COMMAND='npx -y @agentclientprotocol/claude-agent-acp@<version>'
export PORTTY_CODEX_ACP_COMMAND='npx -y @agentclientprotocol/codex-acp@<version>'
```

A locally installed adapter always wins over these. An unpinned tag
(`@latest`, `@next`) still works but logs a warning at spawn time.

## Build and install the desktop commands

From the repository root:

```sh
cargo build --locked --release -p portty-cli -p portty-host
```

The outputs are:

```text
target/release/portty
target/release/portty-host
```

On macOS or Linux, install them into a directory on `PATH`:

```sh
mkdir -p "$HOME/.cargo/bin"
install -m 0755 target/release/portty "$HOME/.cargo/bin/portty"
install -m 0755 target/release/portty-host "$HOME/.cargo/bin/portty-host"
```

On Windows, copy `portty.exe` and `portty-host.exe` from `target\release` into
the same directory on `PATH`.

Verify the installation:

```sh
portty --help
portty-host status
```

For service setup and mobile build instructions, see the
[packaging guide](packaging/README.md).

## First run

1. Start the host:

   ```sh
   portty-host
   ```

   It prints no pairing material and starts with pairing CLOSED. The bare
   command backgrounds itself on Unix.

2. Add your phone. Pairing is always a deliberate act:

   ```sh
   portty pair
   ```

   This mints a fresh credential, prints a QR / full ticket / six-word phrase,
   and then WAITS. Leave it running - it is also the console that confirms the
   pairing. Each of the three forms is a COMPLETE key to the machine; treat them
   as temporary secret data.

3. Open the Portty app and scan or paste the ticket. When typing the bare NodeId
   instead, enter the six-word phrase too.

4. Both screens then show the same six-digit code. Check they match and answer
   `y` in the `portty pair` terminal. There is no PIN to type: the human step is
   a comparison AFTER the key exchange, which is what lets a mismatch expose a
   machine sitting in the middle. If the codes differ, say no.

5. In a laptop terminal, start sharing:

   ```sh
   portty share
   ```

6. Open that session in the phone app. Input from either device reaches the
   same wrapped PTY.

7. Check or stop the daemon later:

   ```sh
   portty-host status
   portty-host stop
   ```

## `portty` command reference

Running `portty` without a command is equivalent to `portty share`.

### `portty help`

```text
portty --help
portty -h
portty help
```

Prints the concise built-in command summary and exits without starting a shell
or daemon. Unknown commands print the same summary and exit with status 2.

### `portty share`

```text
portty share
portty share --no-daemon
portty share -- <command> [arguments...]
```

Creates a child PTY, launches the default shell, mirrors its output to the
current laptop terminal, and sends the same raw byte stream to `portty-host`.
The shared shell starts in the current directory. The laptop terminal remains
the authoritative source of PTY size; phone viewers render around that size.

If no daemon is running, `portty share` tries to start `portty-host` and waits
for its per-user IPC endpoint. If startup fails, the shell continues locally
instead of being terminated.

Options and forms:

- `--no-daemon` prevents automatic daemon startup. It still connects to a
  daemon that is already running; otherwise the session remains local-only.
- `-- <command> [arguments...]` wraps a specific command instead of the default
  shell. Use `--` so command options are not interpreted as Portty options.

Examples:

```sh
portty share
portty share -- cargo test --workspace
portty share -- htop
portty share --no-daemon
```

Inside a shared shell, plain `exit` closes the child shell and ends the Portty
session. Use `portty exit` when the shell should keep running locally.

### `portty exit`

```text
portty exit
```

Run this inside a terminal created by `portty share`. It tells the enclosing
relay to stop forwarding that session while leaving the child shell alive on
the laptop. It fails safely when used outside a shared Portty terminal.

This command is different from shell `exit`:

- `portty exit` stops sharing but keeps the shell.
- `exit` closes the shell and ends the session.

### `portty agent`

```text
portty agent <claude|codex|opencode|goose> [--new]
```

Opens a laptop chat for the same structured ACP agent session shown on the
phone. By default, Portty joins the newest live session for that provider; if
none exists it creates one. `--new` always creates a separate session.

Accepted provider aliases are:

- `claude` or `claude-code`
- `codex`
- `opencode` or `open-code`
- `goose`

Examples:

```sh
portty agent claude
portty agent codex --new
portty agent opencode
portty agent goose
```

Chat controls:

- Type a message and press Enter to send a prompt.
- `/stop` or `/cancel` cancels the active turn.
- `/mode <id>` and `/model <id>` change advertised ACP settings; the CLI prints
  available ids when the agent announces them.
- `/config <id> <value|on|off>` changes any advertised configuration option.
- `/auth <id>` starts an authentication method announced by the agent.
- `/help` lists Portty's local chat controls.
- `exit`, `quit`, Ctrl+D, or closing the chat leaves the laptop view. The agent
  continues running and remains available on the phone.
- Other slash commands remain ordinary ACP prompts for the selected provider.

Approval controls:

- Enter the displayed option number to select that exact choice.
- `y`, `yes`, or `allow` selects the first offered allow choice.
- `n`, `no`, `deny`, or `reject` selects the first offered reject choice, or
  cancels when the provider offers no reject choice.
- Answering on the phone resolves the laptop card, and answering on the laptop
  resolves the phone card.

### `portty pair`

```text
portty pair
```

**This is the only way to pair.** The daemon starts with pairing closed and no
credential in existence, so every pairing - including the very first - is this
command. It mints fresh material, opens a limited window, and prints the ticket
/ QR / phrase, without restarting active sessions. The request travels over the
current user's protected local IPC endpoint. Start `portty-host` first if no
daemon is running.

Use it to enrol your first phone, add another, or repair a device that was
intentionally revoked. Existing paired devices reconnect with stored credentials
and need no pairing material at all.

`portty pair` stays open after printing. It is also the confirmation console:
the daemon owns no terminal of its own (it detaches stdin and has no controlling
terminal), so this session is where you compare the six-digit code and approve
it. Quitting before the phone connects leaves the host with nothing to ask, and
it refuses the pairing.

The window closes as soon as one device pairs, even if time remains on it. The
ticket is single-use enrollment material, so a photographed QR cannot enrol a
second device after your phone succeeds - and while the window is still open, an
attacker using a copied ticket still has to get a human to approve a code they
cannot see. Pairing each additional phone is therefore its own `portty pair`,
which mints fresh material.

### `portty unpair`

```text
portty unpair
portty unpair <device-id-or-unique-hex-prefix>
portty unpair all
```

Manages paired phones through `portty-host`:

- No argument lists paired devices and their recent connection state.
- A complete device ID or unique hexadecimal prefix revokes one phone.
- `all` revokes every phone.

Revocation is durable. A running host commits the tombstone through its secure
local control channel and drops the live phone connection within a few seconds.
Ambiguous prefixes and unknown devices are rejected instead of guessing.

`portty-host` must be installed beside `portty`, available on `PATH`, or pointed
to by `PORTTY_HOST`.

### `portty init`

```text
portty init <powershell|bash|zsh>
```

Prints, but does not install, the shell-profile block used by Portty's automatic
portal hook. This is the review-first option when you prefer to paste or adapt
the snippet manually.

The snippet runs only for interactive shells and uses `PORTTY_RELAY=1` as a
recursion guard so the child shell is not wrapped repeatedly.

### `portty install`

```text
portty install
portty install --shell <powershell|bash|zsh>
```

Adds the marked Portty portal block to the detected shell profile:

- Bash: `~/.bashrc`
- Zsh: `~/.zshrc`
- PowerShell 7: `Documents/PowerShell/Microsoft.PowerShell_profile.ps1`
- Windows PowerShell fallback:
  `Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1`

The operation is idempotent. If the marker already exists, the profile is not
changed. Open a new terminal after installation. Every new interactive shell is
then born inside `portty share`, allowing it to appear on the phone without a
manual wrapping command.

Use `--shell` when automatic detection from `$SHELL` is unavailable or when
installing into a non-default profile.

### `portty uninstall`

```text
portty uninstall
portty uninstall --shell <powershell|bash|zsh>
```

Removes only the block between Portty's profile markers and leaves the rest of
the profile unchanged. The command is safe to repeat when no hook exists.
Already-running shared terminals are unaffected; new terminals stop being
automatically wrapped.

## `portty-host` command reference

`portty-host` owns the stable device identity, paired-peer records, session
manager, secure iroh endpoint, local relay IPC, and optional browser proof.

### `portty-host`

```text
portty-host
portty-host --foreground
portty-host --detach
```

The bare command runs `both` mode: phone hosting plus the loopback browser
terminal. On Unix it backgrounds itself by default after printing pairing
information. `--foreground` or `-f` keeps it attached for logs and debugging.
`--detach` or `-d` explicitly requests background operation. `--foreground`
and `--detach` cannot be combined.

Only one host may use a data directory at a time. A second instance refuses to
overwrite a live PID file.

### `portty-host both`

```text
portty-host both
portty-host both --detach
```

Explicit form of the default combined mode. It serves the secure phone endpoint
and the token-protected loopback browser UI over the same session manager.
Explicit modes stay in the foreground unless `--detach` is supplied.

### `portty-host serve`

```text
portty-host serve
portty-host serve --detach
```

Runs the phone host without the local browser UI. This is the correct foreground
mode for launchd, systemd, or another service manager. Service examples live in
[packaging/README.md](packaging/README.md).

### `portty-host proof`

```text
portty-host proof
```

Runs only the local browser/xterm proof server, with no iroh phone endpoint.
This is intended for offline PTY and browser-UI development. The server binds
to loopback, prints a capability-bearing URL, enforces Origin checks, and uses a
strict content security policy.

The default address is `127.0.0.1:9876`. `PORTTY_LOCAL_ADDR` can change the
loopback address or port, but non-loopback values are rejected.

### `portty-host peers`

```text
portty-host peers
```

Lists paired device IDs, reconnect-ticket presence, live connection state, and
last-seen time. Use the displayed full ID or a unique prefix with `revoke`.

### `portty-host revoke`

```text
portty-host revoke <device-id-or-unique-hex-prefix>
portty-host revoke all
```

Durably revokes reconnect credentials. When the daemon is running, the command
uses authenticated local control and waits for the daemon's committed result;
it does not fall back to racing an in-progress handshake with direct file
changes. When the daemon is offline, it updates the protected peer store.

A revoked device cannot resume with an old token. It may pair again only during
an explicitly open enrollment window.

### `portty-host status`

```text
portty-host status
```

Checks the PID file and process liveness, then reports the number of currently
connected devices from the daemon's active-state mirror. A stale PID file is
reported as not running.

### `portty-host stop`

```text
portty-host stop
```

Sends an authenticated same-user shutdown request to the running daemon on
Windows or Unix. It also identifies and cleans a stale PID file.

## Host environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORTTY_DATA_DIR` | Platform per-user application data directory | Overrides identity, peer-store, PID, active-state, agent-cache, and push-registration storage. Use separate directories for isolated test instances. |
| `PORTTY_WORKSPACE` | Host launch directory | Starting directory for phone-created shells and agents. Invalid paths fail back to the launch directory. |
| `PORTTY_CLAUDE_ACP_COMMAND` | Unset | Opt-in launcher command for the Claude ACP adapter, used only when `claude-agent-acp` is not installed. Set it to a version-pinned command you have vetted; Portty never downloads an adapter on its own. |
| `PORTTY_CODEX_ACP_COMMAND` | Unset | Same, for the Codex adapter (`codex-acp`). |
| `PORTTY_LOCAL_ADDR` | `127.0.0.1:9876` | Loopback address for `both`/`proof`. Non-loopback addresses are refused. |
| `PORTTY_KEEP_AWAKE` | Enabled | Set to `0` to disable the host's best-effort sleep inhibitor. |
| `PORTTY_SCROLLBACK_BYTES` | `262144` per terminal session | Bounded scrollback, clamped from 4 KiB to 4 MiB. |
| `PORTTY_MAX_SESSIONS` | `64` | Concurrent session cap, clamped from 1 to 1024. |
| `PORTTY_PTY_COLS` | `160` | Width for daemon-created PTYs, clamped from 20 to 500. Adopted laptop sessions keep the laptop's size. |
| `PORTTY_PTY_ROWS` | `48` | Height for daemon-created PTYs, clamped from 10 to 200. |
| `PORTTY_MAX_TRANSFER_BYTES` | `4294967296` (4 GiB) | Per-file upload/download size ceiling. Set `0` only when intentionally allowing unlimited files. Paths outside the user's home still require explicit approval. In-progress upload paths are journaled so host startup removes `.part` files left by a crash. |
| `PORTTY_QUIC_KEEPALIVE_SECS` | `10` | QUIC keepalive interval, clamped to 2–60 seconds. |
| `PORTTY_QUIC_IDLE_TIMEOUT_SECS` | `30` | Dead-peer timeout, clamped to 10–300 seconds and at least twice the keepalive interval. |
| `PORTTY_QUIC_STREAM_WINDOW_BYTES` | `4194304` (4 MiB) | Per-stream receive window for high-BDP links, clamped to 256 KiB–32 MiB. |
| `PORTTY_QUIC_CONNECTION_WINDOW_BYTES` | `16777216` (16 MiB) | Aggregate receive window, clamped to 1–64 MiB and never below the stream window. |
| `PORTTY_QUIC_SEND_WINDOW_BYTES` | `8388608` (8 MiB) | Unacknowledged send-memory ceiling, clamped to 256 KiB–64 MiB. |
| `PORTTY_APPROVAL_TTL_SECS` | `86400` | Maximum time an agent permission remains pending, clamped from 60 seconds to 7 days. |
| `PORTTY_PUSH_RELAY_URL` | Unset | Enables outbound wake/revoke calls to the optional push relay. No relay URL means no outbound push HTTP. |
| `PORTTY_PUSH_HOST_SECRET` | Generated and stored owner-only | Optional fixed 64-hex host secret for deterministic push deployment identity. |
| `PORTTY_PUSH_ADMIN_TOKEN` | Host-specific secret | Registration bearer for an admin-gated hosted push relay. |
| `PORTTY_ACP_EVENT_LOG` | Disabled | Set to `1` to write ACP diagnostic transcripts to the Portty data directory while debugging an adapter. Off by default: the log is a verbatim copy of the JSON-RPC stream, so it captures whole prompts, file contents the agent read, tool arguments, and adapter stderr. When enabled, logs are owner-only, rotate at 4 MiB × 8 per session, and share a 256 MiB host-wide oldest-first retention budget. Delete the `acp-events` directory to remove them. |
| `RUST_LOG` | `info` | Standard tracing filter for host diagnostics, for example `RUST_LOG=portty_host=debug`. |

`PORTTY_RELAY` and `PORTTY_SHARE_CTL` are internal variables set by `portty` for
recursion prevention and local detach control. Users normally should not set
them. `PORTTY_HOST` is a `portty` override pointing to a specific
`portty-host` executable.

## Optional push relay

The push relay has no command-line flags; it is configured through environment
variables and refuses to start without exactly one registration policy.

Self-hosted development example:

```sh
PORTTY_PUSH_OPEN_REGISTRATION=1 \
PORTTY_PUSH_ADDR='127.0.0.1:9877' \
cargo run -p portty-push-relay
```

Hosted, admin-gated registration:

```sh
PORTTY_PUSH_ADMIN_TOKEN='<operator secret>' \
PORTTY_PUSH_ADDR='0.0.0.0:9877' \
portty-push-relay
```

Do not set open registration and an admin token together. Production deployments
must put TLS in front of the service.

| Variable | Purpose |
| --- | --- |
| `PORTTY_PUSH_OPEN_REGISTRATION=1` | Enables self-host registration authenticated by each host's private secret. |
| `PORTTY_PUSH_ADMIN_TOKEN` | Enables operator-gated initial registration. Configure the same token on the host. |
| `PORTTY_PUSH_ADDR` | Relay listen address; defaults to `127.0.0.1:9877`. |
| `PORTTY_APNS_KEY_PATH` | Preferred automatic auth: path to the APNs `.p8` signing key. |
| `PORTTY_APNS_KEY_ID` | APNs key ID; required with `PORTTY_APNS_KEY_PATH`. |
| `PORTTY_APNS_TEAM_ID` | Apple developer Team ID; required with `PORTTY_APNS_KEY_PATH`. |
| `PORTTY_APNS_BEARER` | Compatibility fallback: a pre-minted APNs provider JWT; do not combine with key auth. |
| `PORTTY_APNS_TOPIC` | iOS bundle identifier; mandatory for APNs token authentication. |
| `PORTTY_APNS_URL` | APNs endpoint override; defaults to production. Must be `https` and on an official APNs host unless `PORTTY_PUSH_ALLOW_CUSTOM_ENDPOINTS=1`. |
| `PORTTY_FCM_SERVICE_ACCOUNT` | Preferred automatic auth: path to a Firebase/Google service-account JSON file. `GOOGLE_APPLICATION_CREDENTIALS` is also recognized. |
| `PORTTY_FCM_PROJECT` | Firebase project ID; defaults to `project_id` from the service-account file. |
| `PORTTY_FCM_BEARER` | Compatibility fallback: a pre-minted FCM OAuth access token; do not combine with service-account auth. |
| `PORTTY_FCM_URL` | FCM endpoint base override; primarily for controlled tests. Same `https` + official-host rule as `PORTTY_APNS_URL`. |
| `PORTTY_PUSH_ALLOW_CUSTOM_ENDPOINTS=1` | Permits a non-official provider host (a self-hosted proxy, or an integration test). Loosens the host allowlist only: `https` is still required except on loopback, and a URL embedding credentials is always refused. |
| `RUST_LOG` | Relay tracing filter. |

Provider endpoints are allowlisted rather than merely parsed. An APNs provider JWT
and an FCM OAuth assertion are bearer credentials for the relay's push identity, so
the configured endpoint is the party those credentials are handed to — including the
`token_uri` inside a service-account JSON file. A wrong or planted value used to
redirect signed credentials silently; it is now refused at startup.

The relay exposes `/health`, `/v1/register`, `/v1/wake`, and `/v1/revoke` for
Portty components. Registration is automatic; these endpoints are not intended
as an end-user manual `curl` workflow. See the
[push relay reference](crates/push-relay/README.md) and
[provider setup runbook](packaging/PUSH-SETUP.md).

## Mobile app development

The mobile app is a separate Cargo workspace under `app/src-tauri`.

Install frontend dependencies:

```sh
cd app
corepack enable
pnpm install --frozen-lockfile
```

Frontend commands, run from `app/`:

| Command | Explanation |
| --- | --- |
| `pnpm dev` | Starts the Vite development server. |
| `pnpm design` | Opens the live, phone-sized design workbench with fixture hosts and sessions. |
| `pnpm build` | Creates the production frontend bundle in `app/dist`. |
| `pnpm preview` | Serves the already-built frontend bundle for inspection. |
| `pnpm test` | Runs the Vitest unit suite. |
| `pnpm exec tsc --noEmit` | Type-checks the frontend without writing files. |
| `pnpm tauri ios dev` | Builds and runs an iOS development target through Tauri/Xcode. |
| `pnpm tauri ios build ...` | Creates an iOS archive; use the exact signed release command in the iOS runbook. |
| `pnpm tauri android dev` | Builds and runs an Android development target. |
| `pnpm tauri android build` | Creates the release Android App Bundle. |
| `pnpm tauri android build --apk` | Creates a release APK for sideloading. |

`pnpm design` renders the production Solid components, stylesheet, fonts, SVG
icons, and xterm inside selectable device frames. Its in-browser mock replaces
only Tauri/host I/O, so edits under `app/src/` hot-reload in the phone without a
Rust, Xcode, Android, or physical-device build. The workbench lives at
`http://127.0.0.1:1420/design-preview.html` while Vite is running.

Do not use `pnpm tauri build` to create a macOS desktop app. Portty's supported
Mac distribution is the two command-line binaries plus the iOS app.

Release instructions:

- [Mac CLI and iOS/TestFlight](packaging/MAC_IOS_BUILD_RUNBOOK.md)
- [Android/Play Store and APK](packaging/ANDROID_BUILD_RUNBOOK.md)
- [Push notifications](packaging/PUSH-SETUP.md)

## Repository development commands

Run these from the repository root unless noted otherwise:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --locked --release -p portty-cli -p portty-host
```

Run a foreground development host:

```sh
cargo run -p portty-host -- --foreground
```

Run the browser-only proof:

```sh
cargo run -p portty-host -- proof
```

Run the CLI from source:

```sh
cargo run -p portty-cli -- share
cargo run -p portty-cli -- agent codex --new
```

Validate the mobile Rust core and release configuration:

```sh
cargo test --manifest-path app/src-tauri/Cargo.toml
```

### ACP validation probe

`acp-probe` is an internal protocol diagnostic, not an end-user Portty client:

```text
cargo run -p acp-probe -- [--decision=cancel|allow|reject] [gemini|claude|codex|"custom ACP command"] [prompt]
```

It starts an ACP agent, sends a prompt intended to request a tool action, logs
the ACP wire exchange, and verifies that Portty can intercept
`session/request_permission`. The default `cancel` mode remains non-destructive.
`allow` and `reject` select the provider's matching one-shot option and fail if
the provider does not offer one, which lets a release operator validate the
full permission-response contract against authenticated real providers. Run
`allow` only in a disposable directory: it executes the requested action. The
selected agent must already be authenticated. Because the diagnostic prints raw
ACP traffic, do not use sensitive prompts or publish its output without review.

Before a release that changes ACP handling, run cancel, reject, and allow modes
against every supported real provider available to the release operator. Keep
the allow prompt confined to a disposable directory and confirm the expected
file is the only mutation. Mock-agent tests remain the deterministic CI layer;
real-provider runs are credentialed release checks and are not suitable for
unauthenticated CI.

## Security model and operational guidance

- Pairing tickets, PINs, manual pairing phrases, identity keys, reconnect tokens,
  push secrets, signing keys, and provider credentials are secret material. Do
  not commit or paste them into logs or issue reports.
- Peer reconnect tokens and revocation tombstones live in owner-only credential
  storage. Revocation wins races with stale or in-progress reconnect attempts. A
  reconnect rotates the exact token it authenticated against or it is refused, so
  two overlapping reconnects cannot each rotate away the other's result and leave
  the phone holding a credential the host no longer knows.
- Writes that another durable write depends on are themselves durable, and that
  ordering is the point rather than caution alone: a credential installed before a
  tombstone is cleared, or removed after one is added, is flushed first. Otherwise
  a crash could reorder the pair on disk into "no tombstone, revoked token still
  present". Routine reconnect rotation stays best-effort, because losing it leaves
  the peer's previous token valid and the next reconnect works.
- iroh authenticates the ticket endpoint and encrypts QUIC with TLS 1.3. Portty's
  second envelope uses separate phone→host and host→phone keys plus monotonic,
  authenticated sequence numbers; replay or authentication failure closes the
  connection. Protocol v4 requires upgrading host and phone together.
- Startup never opens enrollment and never emits a credential. A restart used
  to mint a ticket, open a five-minute window, and print both to stdout, so any
  service log became a stream of fresh keys to the machine on every restart.
  Pairing is now armed only by `portty pair` over the same-user local IPC
  socket, which prints to that operator's terminal. A host with nothing armed
  refuses first pair twice over: the window is shut, and the handshake rejects a
  first pair against a host holding no secret even if the window were reopened.
- Agent file reads **that the adapter routes through ACP** are confined to the
  workspace root by `sandboxed_acp_path`: absolute paths only, canonical realpath
  on both sides, containment check, dangling symlinks refused on create. This
  binds the `fs/read_text_file` and `fs/write_text_file` methods and the cwd of
  `terminal/create`. It does NOT bind what a command running inside a terminal
  reads, and it does not bind an adapter that reads the file itself instead of
  asking - see the adapter trust model below. The phone's sensitive-path list
  (`.env`, SSH keys, `terraform.tfstate`, database dumps) is an extra prompt on
  top of that, never the boundary itself.
  Because the root is what the boundary is worth, the host reports how broad it
  is and the phone refuses to auto-approve ANY operation - at every tier -
  when the root is the home directory, an ancestor of it, or unreported. A
  blanket tier only speaks for a body of files someone deliberately chose. An
  exact rule the user saved for one named operation still applies.
- The first-pair credential is the out-of-band secret in the ticket/QR/phrase,
  and nothing else. There is deliberately no PIN: folding a 6-digit value into
  the key gave anyone already holding the ticket a 900,000-entry offline
  dictionary, so a single captured proof recovered it. The human step is now a
  six-digit comparison code derived from the finished session - it has no
  dictionary to search, and a peer in the middle cannot make both screens agree.
  A first pair commits only after someone confirms it at the host, so a leaked
  ticket cannot silently become a paired device.
- Pairing material is one-time. The enrollment window closes on the first
  successful pair, so an observed QR cannot enrol a second device inside
  the same window. Inbound connections are admitted in two stages - a per-source
  bounded pool while a dial handshakes, and a separate pool once it has
  authenticated - so unauthenticated dials cannot occupy the capacity that paired
  phones use.
- Relay push credentials are removed from the daemon's own environment once read,
  so phone-created shells, ACP adapters, and agent-requested commands never
  inherit them. Set them through the service manager rather than a shell profile,
  since a login shell re-reads the profile in the child. On Windows, where the
  backgrounded daemon is a fresh process rather than a fork, they are handed to
  that one process explicitly and scrubbed again there before it starts anything.
- Raw ACP transcript logging is off unless `PORTTY_ACP_EVENT_LOG=1`. It records
  the JSON-RPC stream verbatim - prompts, file contents, tool arguments - so it
  is a debugging tool, not a default.
- Text an agent or adapter chooses is stripped of terminal-control and
  text-direction characters before it is displayed, on the laptop and the phone.
  Otherwise an approval could clear the screen, forge a prompt, write the
  clipboard through OSC 52, or use a bidi override to read as the opposite of what
  it runs. Terminal hyperlinks open in the system browser through the validated
  opener, never inside the app's webview.
- **Approval cards govern a cooperating adapter. They are not a sandbox.**
  Agent adapters are ordinary subprocesses started by the daemon and running as
  the same OS user with the same privileges. Nothing stops one from reading,
  writing, or executing directly without ever calling
  `session/request_permission`, and the tool `kind` that becomes a Portty
  category is self-reported by the adapter - an adapter that labels an execute as
  a read gets a read's treatment.

  So the policy engine, the tiers, the sensitive-path prompts and the workspace
  root are controls over what a WORKING agent does on your behalf. They are worth
  having: they stop an honest agent from wandering, and they stop prompt
  injection from talking an honest agent into something you did not want. They
  are not containment. A malicious or compromised adapter, or a supply-chain
  compromise of the agent binary, has your uid and is bounded only by the OS.

  Choosing an adapter is therefore a trust decision on the same level as running
  the tool directly in your shell - because that is what it is. Real containment
  needs the adapter under a restricted account or sandbox with privileged actions
  brokered outside it; that is not built, and until it is, nothing here should be
  read as protection against the adapter itself.
- Reads of credential-shaped paths (`.env`, private keys, cloud credential files,
  keystores) always prompt, at every tier, and so does any operation whose input
  has not arrived yet - an approval is never auto-approved before Portty can see
  what it touches. Provider-wide "always" grants are marked as such and need a
  second, deliberate tap, because their scope is the adapter's to define, not
  Portty's.

  Not yet covered: the operation is not FROZEN at approval time. An adapter can
  refine a tool call after the card was answered, so an approval binds the
  operation as it was described, not by digest. Closing that needs the host to
  stamp an immutable digest on the request and require it echoed in the decision.

  Worth being precise about what that would buy, because it is easy to overstate:
  a digest closes a race for an HONEST adapter, where a late refinement changes
  what the user thought they answered. It does nothing against a compromised one,
  which never needed the race - it can request permission for one thing and do
  another, or skip asking entirely. Do not read a future digest as a fix for the
  trust model above.
- Removing a saved host - or a pairing the laptop revokes - deletes that host's
  approval history and policy from the phone, so the record of what an agent ran
  there does not outlive the credential.
- An approval is never auto-approved before Portty can see what it touches. ACP
  refines a tool call after its card appears, so a card can arrive with the path
  still in flight; a missing operation input prompts at every tier rather than
  being waved through by the read policy.
- Known limitations, accepted deliberately rather than overlooked:
  - Release binaries are not code-signed, notarized, or attested, and their
    checksums are produced by the publishing job. Verify releases out of band
    until signing is set up.
  - The phone's approval log is stored by the Tauri core in an owner-only file
    marked excluded from backup, not in WebView localStorage. A log written by an
    older build is moved there and the localStorage copy deleted the next time
    that host is selected. Entries whose title or input is RECOGNIZED as
    credential-shaped - a path like `.env` or an SSH key, or a value like a bearer
    token or provider API key - have both fields redacted before being written,
    older entries are re-redacted when the log is loaded, and the whole log is
    deleted when the host is removed.

    Two limits remain. The redaction is recognition, not a guarantee: an
    unrecognized secret is still written down. And the file is confined, not
    encrypted - anything already able to read the app container as this user can
    read it. What the move removed is the copy that used to leave the device in
    every backup. Encrypting at rest, or persisting metadata only, would close
    the rest.
  - Pairing material never reaches the daemon's stdout, so a service manager's
    log cannot retain it. Startup arms nothing; `portty pair` is the only thing
    that mints a credential and it prints to that operator's terminal.
  - `RUSTSEC-2024-0429` (glib < 0.20) is present in the Tauri lockfile via
    `gtk 0.18` and cannot be bumped without a Tauri upgrade. It is Linux
    desktop-only, Portty ships no Linux desktop artifact, and Portty makes no glib
    calls - the affected `VariantStrIter` is unreachable. Compiled in CI, never
    shipped.
- Approval cards are consent UX over a cooperative agent, not a sandbox. An ACP
  adapter runs unsandboxed as the host user, with the host's credentials and its
  own filesystem and process access; asking for permission is something the
  adapter chooses to do, and the operation category it reports is its own claim.
  The cards stop an agent from doing something you did not intend. They do not
  contain an adapter that is hostile or has been compromised - install adapters
  you trust as much as your own shell, and prefer ones you installed yourself
  over a package fetched at spawn time (Portty never fetches one for you).
- Disconnecting, switching hosts, or removing a saved host tears the link down:
  the session task stops and the iroh endpoint closes, so a dropped or replaced
  host keeps no authenticated connection and cannot go on delivering session,
  terminal, approval, or transfer events. Approvals and file transfers are bound
  to the connection and pairing that created them - a decision is only ever
  delivered to the host that asked, and a transfer only ever resumes, completes,
  or retries against the host it was started with.
- Host-wide agent approval policy may persist, but per-session overrides never
  do: session ids are process-local and can be reused after a host restart.
  Learned exact approvals bind the permission category, byte-exact tool title,
  and canonical ACP input; malformed, missing, truncated, or oversized input is
  never learnable. A request that CARRIES something credential-shaped - a bearer
  header, a provider API key, an inline private key - is not learnable either: an
  exact rule has to store its title and input verbatim to match, so refusing the
  rule is the only way not to write the credential down. Rules stored by older
  builds are dropped the next time a policy is saved. A request that merely names
  a credential FILE stays learnable, because naming one operation is the explicit
  consent that lets a sensitive path be auto-approved at all. Prompt exceptions
  continue to take precedence.
- The protocol is binary postcard framing. Existing frame variants are
  append-only; reordering them breaks wire compatibility. Portty deliberately
  has no downgrade negotiation: the frame header and authenticated handshake
  both require the exact supported generation, so mixed host/phone builds fail
  closed with an unsupported-version error before application frames. Protocol
  v4 uses BLAKE3 for complete-file integrity; v3 used SHA-256.
- The host does not parse terminal bytes. It owns PTYs, bounded buffers, access
  control, and encrypted transport; xterm.js owns VT interpretation.
- File-transfer paths are treated as data, never shell commands. In-home access
  is the default; outside-home access requires explicit authorization. Each
  connection is limited to four active transfers and files default to a 4 GiB
  ceiling so stalled or accidental requests cannot grow resources without bound.
- The local browser server remains loopback-only and uses a capability URL,
  Origin validation, and a strict CSP.
- Push notifications are doorbells, not authorization. The phone acts only
  after an authenticated host reconnect or sealed control frame confirms state.
- Before any production release or TestFlight/Play upload, use a reviewed commit,
  a clean working tree, a unique build number, and the platform runbook.

## Troubleshooting

### The phone cannot find the host

```sh
portty-host status
portty-host peers
```

If the daemon is stopped, run `portty-host`. If the phone was revoked, run
`portty pair` to open an explicit repair window and pair again.

### `portty share` says it is local-only

Confirm `portty-host` is installed and on `PATH`, then start it manually:

```sh
command -v portty-host
portty-host
```

Set `PORTTY_HOST` only when intentionally using a host binary outside `PATH`.

### A paired phone is lost or no longer trusted

```sh
portty unpair
portty unpair <unique-device-prefix>
# or, for every phone:
portty unpair all
```

Do not merely remove the mobile app entry; revoke from the host so the stored
reconnect credential is durably invalidated.

### A daemon appears stuck after a crash

```sh
portty-host status
portty-host stop
```

`status` distinguishes a live daemon from a stale PID file, and `stop` cleans a
stale file on every supported desktop OS.

### Agent startup fails

Run the provider's underlying command directly to verify installation and
authentication, then retry `portty agent`. Increase host logging temporarily:

```sh
RUST_LOG=portty_host=debug portty-host --foreground
```

Never include tokens, pairing tickets, or full credential-bearing logs in a bug
report.

## License

Portty source is Copyright 2026 Corvux Mindware Private Limited and licensed
under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Bundled
third-party components and fonts keep their own licenses.
