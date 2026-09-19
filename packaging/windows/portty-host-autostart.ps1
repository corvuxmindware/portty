<#
  Portty host autostart for Windows - a per-user Scheduled Task (the native
  equivalent of the macOS launchd LaunchAgent and the Linux systemd --user unit).
  No admin rights and no extra tools (NSSM etc.) required: it runs
  `portty-host serve` at logon, restarts it on crash, and captures the log
  to a per-user file.

  Install:
      # from an ordinary (non-admin) PowerShell:
      pwsh -File packaging\windows\portty-host-autostart.ps1 `
          -PorttyHost "C:\path\to\portty-host.exe" `
          -Workspace  "C:\Users\you\projects"

    -PorttyHost defaults to the first `portty-host.exe` on PATH.
    -Workspace  REQUIRED. Sets PORTTY_WORKSPACE - the folder new shells open in,
                and the root an agent may read files inside. Point it at ONE
                PROJECT. It used to default to your home folder, which made the
                agent file sandbox bound nothing; the phone now refuses to
                auto-approve reads when the root is that wide, so a home-folder
                workspace means a tap for every file the agent reads.

  PAIRING: prefer `portty pair` over the log. It asks the running daemon for
  FRESH pairing material over the local IPC endpoint and prints it to YOUR
  console, so no secret is left in a file that outlives the pairing:
      portty pair

  The daemon starts with pairing CLOSED and prints NO pairing material, so the
  log carries no credential. It used to print a complete first-pair key on every
  restart, and log files PERSIST - so a restart was an enrolment opportunity for
  anyone who could read them. The log is still written per-user, NOT to %TEMP%
  (which other users can read):
      Get-Content "$env:LOCALAPPDATA\portty\portty-host.log" -Wait

  Manage:
      portty-host.exe status
      portty-host.exe peers
      Start-ScheduledTask   -TaskName Portty-Host   # start now
      portty-host.exe stop                          # graceful stop (control pipe)
      Stop-ScheduledTask    -TaskName Portty-Host   # hard stop (fallback)
      Unregister-ScheduledTask -TaskName Portty-Host -Confirm:$false   # remove

  `portty-host.exe stop` shuts the daemon down gracefully over its local
  named-pipe control channel (no console or OS signal needed, which a windowless
  scheduled task lacks); `Stop-ScheduledTask` is a hard fallback.

  After pairing once, phones reconnect by token with no pairing material, so it is
  "set and forget." Revocation is immediate: `portty-host revoke <id>`.

  NOTE: this script has NOT been exercised on a Windows host from this repo's
  CI/dev environment - validate the registered task once on a real machine
  (logon start and crash-restart).
#>
[CmdletBinding()]
param(
    [string]$PorttyHost = "",
    # No default. It used to be $env:USERPROFILE, which silently made the agent
    # file sandbox cover the entire user profile. Requiring it is the whole fix:
    # a root nobody chose is a root nothing is confined to.
    [Parameter(Mandatory = $true)]
    [string]$Workspace,
    [string]$TaskName   = "Portty-Host"
)

$ErrorActionPreference = "Stop"

# Refuse the two roots that make confinement meaningless, rather than accepting
# them and leaving the phone to prompt on every single file read.
$resolvedWorkspace = (Resolve-Path -LiteralPath $Workspace).Path.TrimEnd('\')
$profileRoot = $env:USERPROFILE.TrimEnd('\')
if ($resolvedWorkspace -ieq $profileRoot -or $profileRoot.StartsWith("$resolvedWorkspace\")) {
    throw "Workspace '$resolvedWorkspace' is your user profile or wider. It is also the folder an agent may read any file inside - point -Workspace at one project instead."
}

# Resolve the binary: explicit -PorttyHost wins, else first on PATH.
if (-not $PorttyHost) {
    $found = Get-Command portty-host -ErrorAction SilentlyContinue
    if (-not $found) {
        throw "portty-host.exe not found on PATH; pass -PorttyHost <full path>."
    }
    $PorttyHost = $found.Source
}
if (-not (Test-Path -LiteralPath $PorttyHost)) {
    throw "portty-host not found at: $PorttyHost"
}

# Per-user log dir/file - no credentials are printed, but keep it out of
# world-readable %TEMP%.
$logDir = Join-Path $env:LOCALAPPDATA "portty"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir "portty-host.log"

# Action: set the workspace env, then run `serve`, appending stdout+stderr to the
# per-user log (a Scheduled Task doesn't capture console output on its own).
$inner = "set `"PORTTY_WORKSPACE=$Workspace`" && `"$PorttyHost`" serve >> `"$logFile`" 2>&1"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $inner"

# Start at this user's logon.
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

# Restart on crash (mirrors KeepAlive / Restart=on-failure); keep it alive.
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd

# Run only when this user is logged on, at their privilege level (no admin).
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Portty host - serve terminal sessions to a paired phone." `
    -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName'."
Write-Host "  binary:    $PorttyHost"
Write-Host "  workspace: $Workspace"
Write-Host "  log:       $logFile"
Write-Host ""
Write-Host "Start it now with:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "Pair a phone:       portty pair   (preferred - no secret left in the log)"
Write-Host "First-run log:      Get-Content `"$logFile`" -Wait"
