# Portty CLI packaging and service operations

Portty's desktop-side product is a CLI distribution containing two executables:

- `portty` - wraps and shares a terminal; and
- `portty-host` - runs the paired-device daemon.

When distributing the executables, include the root `LICENSE`, `NOTICE`, and
`THIRD-PARTY-NOTICES.txt` with each archive. The mobile app also bundles font
license files under `app/src/assets/fonts/`.

For the local Mac CLI installation plus the iOS archive and TestFlight upload
workflow, follow the
[Mac CLI and iOS/TestFlight build runbook](MAC_IOS_BUILD_RUNBOOK.md). That
workflow installs only `portty` and `portty-host` on the Mac; it does not ship a
desktop application.

The rest of this file is the end-user/operator guide for running the installed
`portty-host` executable as a background service.

For an interactive first run, use bare `portty-host` to start the daemon, then
`portty pair` to enrol a phone. The daemon itself never prints pairing material
and starts with pairing closed. Use `portty-host --foreground` when debugging,
or the supervised `serve` mode below for a login service.

## Command reference

Daily driver - `portty` (run in any terminal):

```sh
portty share                    # wrap your default shell and mirror it to the phone
portty share -- <cmd> [args]    # wrap a specific command instead (a build, a TUI, …)
portty share --no-daemon        # don't auto-start the host daemon
portty agent claude             # chat with an agent (claude | codex | opencode | goose);
                                # joins the live session your phone sees, or starts one
portty agent codex --new        # always start a separate fresh session
portty pair                     # reopen the pairing window (QR/ticket), then stay
                                # open to confirm the code the phone shows
portty init <shell>             # print the shell-profile snippet (powershell|bash|zsh)
portty install [--shell <s>]    # auto-share every new interactive terminal
portty uninstall [--shell <s>]  # remove the profile hook
```

`portty agent` notes: the agent runs on this machine with your existing logins -
nothing extra to configure for an already authenticated agent. Claude Code needs
`claude-agent-acp` on PATH and Codex needs `codex-acp` (or an opt-in
`PORTTY_CLAUDE_ACP_COMMAND` / `PORTTY_CODEX_ACP_COMMAND` - Portty never fetches
an adapter itself); OpenCode needs `opencode` on PATH; Goose needs a configured
`goose` CLI. Prompts, replies, and approvals
stay in sync between the laptop chat and the phone: answer an approval on either
device and the card clears on the other. Leaving the chat (`exit` / Ctrl+C) does
NOT stop the agent - rejoin any time.

Daemon - `portty-host`:

```sh
portty-host                  # connect a phone; backgrounds itself after pairing
portty-host --foreground     # same, but keep logs in this terminal
portty-host serve            # foreground phone host (for launchd/systemd below)
portty-host peers            # list paired devices (+ who's connected)
portty-host revoke <id|all>  # forget a paired device (drops it live within ~2s)
portty-host status           # is a host running?
portty-host stop             # stop the running host
```

## Running `portty-host` as a service

Run the host in the background so it survives logout/reboot and restarts on
crash, instead of living in a terminal window. The daemon writes a PID file and
supports `status`/`stop`, so a service manager can supervise it cleanly.

Two things to know first:

- **Pair with `portty pair`.** The daemon starts with pairing CLOSED and prints
  no pairing material at all, so there is nothing in the service log to pair
  with - by design. Run `portty pair` in your own terminal: it mints fresh
  material, prints the QR, and stays open as the console where you confirm the
  six-digit code the phone shows. After you've paired once, the phone reconnects
  **by token with no pairing material at all**, so the service is "set and
  forget."
- **Point `PORTTY_WORKSPACE` at ONE PROJECT, not your home directory.** It is
  not only where shells open - it is the root an agent may read files inside
  (`sandboxed_acp_path` confines every ACP read to it). Set to your home
  directory, as the shipped files used to, the sandbox bounds nothing: `~/.ssh`,
  every other repo, `~/Documents`, all inside. The phone refuses to
  auto-approve reads when the root is that wide, so the visible symptom is a
  tap for every file the agent reads.
- **Restarts are silent.** A restarting daemon used to mint a credential, open a
  five-minute enrollment window, and print all of it to stdout - which a service
  manager retains. Anyone who could read the log, or ship it somewhere, could
  watch for a restart and enrol. Startup now arms nothing, so a restart exposes
  nothing.
- **Revocation is immediate**: `portty-host revoke <id>` drops an already-
  connected phone within ~2s (the running daemon watches its peer store).

## macOS (launchd, per-user)

```sh
# 1. Edit the plist: set the portty-host path and PORTTY_WORKSPACE.
cp packaging/launchd/org.example.portty.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/org.example.portty.plist

# Daemon log (no pairing material is ever printed here):
tail -f ~/Library/Logs/portty-host.log

# Manage:
portty-host status
portty-host peers
launchctl unload ~/Library/LaunchAgents/org.example.portty.plist   # stop
```

`KeepAlive { SuccessfulExit = false }` restarts the daemon if it crashes but not
after a clean `portty-host stop`.

## Linux (systemd, per-user)

```sh
mkdir -p ~/.config/systemd/user
cp packaging/systemd/portty-host.service ~/.config/systemd/user/
# Edit ExecStart / PORTTY_WORKSPACE first if needed.
systemctl --user daemon-reload
systemctl --user enable --now portty-host

# Daemon logs:
journalctl --user -u portty-host -f

# Manage:
portty-host status
systemctl --user stop portty-host
```

`Restart=on-failure` handles crash restarts; a clean `stop` won't be restarted.

## Windows (Scheduled Task, per-user)

The native per-user equivalent of launchd/systemd - no admin, no extra tools.
`packaging/windows/portty-host-autostart.ps1` registers a Scheduled Task that
runs `portty-host serve` at logon, restarts it on crash, and captures the log
to a per-user file:

```powershell
# from an ordinary (non-admin) PowerShell - edit the paths:
pwsh -File packaging\windows\portty-host-autostart.ps1 `
    -PorttyHost "C:\path\to\portty-host.exe" -Workspace "C:\Users\you\projects"
Start-ScheduledTask -TaskName Portty-Host

# Daemon log (per-user, kept off world-readable %TEMP%):
Get-Content "$env:LOCALAPPDATA\portty\portty-host.log" -Wait

# Manage:
portty-host.exe status
portty-host.exe stop                                            # graceful stop
Stop-ScheduledTask -TaskName Portty-Host                        # hard stop (fallback)
Unregister-ScheduledTask -TaskName Portty-Host -Confirm:$false  # remove
```

`-RestartCount`/`-RestartInterval` handle crash restarts. Stop the daemon
gracefully with `portty-host.exe stop`: it signals the daemon over its local
named-pipe control channel, so it works even though the task runs windowless
(no console, no OS signal) and lets the daemon clean up (PID file, endpoint) on
the way out. `Stop-ScheduledTask` is a hard fallback that terminates without
that cleanup. Prefer a system-wide service instead? Wrap the same binary with
[NSSM](https://nssm.cc/) pointing at `portty-host.exe serve`.

## Upgrades

Replace the `portty-host` binary, then restart the service
(`launchctl unload/load`, `systemctl --user restart portty-host`, or
`portty-host stop` and let the supervisor relaunch it). The device identity and
paired-peer store persist across upgrades in the per-user data dir.
