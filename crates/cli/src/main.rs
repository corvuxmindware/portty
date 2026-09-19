//! `portty` - the relay CLI.
//!
//! `portty share` wraps your shell in a pseudo-terminal (PTY), mirrors it to the
//! terminal you're already sitting in, AND tees the same byte stream to the
//! local Portty daemon over a named pipe - so a paired phone can watch and
//! control this exact terminal. It slides a relay between you and the shell
//! **from the moment you run it** (it cannot capture a terminal that already
//! existed - impossible on Windows; see roost `Portty/07`).
//!
//! `portty install` goes further: it drops a snippet in your shell profile that
//! auto-wraps every interactive shell in a portal-ready relay from birth - so
//! any terminal is shareable mid-run with no per-use command. A `PORTTY_RELAY=1`
//! guard prevents recursion; it's skipped in non-interactive shells and when
//! `portty` isn't on PATH.
//!
//! The relay never *parses* VT input; it copies raw bytes (terminal byte-pipe rule).
//! On Windows it enables the console's VT input mode when available and falls
//! back to translating Win32 console key events only for legacy consoles. If no
//! daemon is running, the terminal still mirrors locally.
//!
//! Concurrency: three OS threads do the blocking PTY/console I/O (stdin→PTY,
//! PTY→stdout+tee, resize poll - THIS terminal is the sole PTY size owner; the
//! poll applies local resizes and reports them via SizeChanged); the tokio side
//! owns the pipe (forward output, apply inbound input/kill). The PTY
//! writer/master/child are shared behind std mutexes; guards are never held
//! across an await.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use portable_pty::{Child, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use portty_protocol::relay::{HostToRelay, RelayToHost, MAX_RELAY_FRAME_BYTES};
use portty_protocol::{
    AgentConfigValue, AgentEvent, AgentPlanStatus, AgentProvider, AgentToolStatus,
    PermissionOption, PermissionOptionKind,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Bounded depth of the tee queue (relay output → daemon). Bounded so a stalled
/// daemon can't make this queue grow without limit while a fast program floods
/// output. Each frame is one PTY read (≤16 KiB), so this caps in-flight RAM at
/// ~8 MiB - same byte budget as the old 2048×4KB. The PTY drain blocks when
/// full instead of dropping terminal bytes: the local mirror is written first,
/// then normal PTY backpressure slows the child until the daemon catches up.
const RELAY_TEE_FRAMES: usize = 512;

/// The concrete stream type the relay talks to the daemon over (named pipe on
/// Windows, Unix socket elsewhere). cfg-chosen to match `connect`.
#[cfg(windows)]
type RelayStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(not(windows))]
type RelayStream = tokio::net::UnixStream;

type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;
type SharedMaster = Arc<Mutex<Box<dyn MasterPty + Send>>>;
type SharedChild = Arc<Mutex<Box<dyn Child + Send + Sync>>>;

#[derive(Clone, Copy)]
enum LocalInputMode {
    RawBytes,
    #[cfg(windows)]
    ConsoleEvents,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("share");
    match mode {
        "share" => run_share(&args[2..]).await,
        "agent" => run_agent(&args[2..]).await,
        "exit" => run_exit().await,
        "unpair" => run_unpair(&args[2..]),
        "init" => {
            print_init(&args[2..]);
            Ok(())
        }
        "install" => run_install(&args[2..]),
        "uninstall" => run_uninstall(&args[2..]),
        "pair" => run_pair().await,
        "-V" | "--version" | "version" => {
            println!("portty {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("portty: unknown command `{other}`\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    eprintln!("Portty relay");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  portty --version             print the installed version");
    eprintln!("  portty share                 wrap your default shell and share it");
    eprintln!("  portty share -- <cmd> [args] wrap a specific command instead of the shell");
    eprintln!("  portty share --no-daemon     don't auto-start the host daemon");
    eprintln!(
        "  portty agent <name> [--new]  chat with a coding agent (claude|codex|opencode|goose);"
    );
    eprintln!(
        "                               joins the live session your phone sees, or starts one"
    );
    eprintln!("  portty exit                  stop sharing the current terminal (shell keeps");
    eprintln!("                               running locally; plain `exit` closes the shell)");
    eprintln!("  portty pair                  reopen the running daemon's pairing window");
    eprintln!("                               print the QR/ticket for a new phone, then");
    eprintln!("                               confirm the code it shows (stays open)");
    eprintln!("  portty unpair [<id>|all]     forget paired phones (no arg lists them)");
    eprintln!("  portty init <shell>          print the profile snippet (powershell|bash|zsh)");
    eprintln!("  portty install [--shell <s>] add the portal hook to your shell profile");
    eprintln!("  portty uninstall [--shell <s>]  remove it");
    eprintln!();
    eprintln!("After `portty install`, every new interactive terminal is portal-ready");
    eprintln!("from birth - no per-use command needed. The host daemon auto-starts.");
    eprintln!("`portty exit` stops sharing; `exit` (or finishing the command) ends the session.");
}

/// `portty pair` - ask the RUNNING daemon to reopen its first-pair enrollment
/// window, print the current pairing credentials (QR / ticket / phrase), and
/// then STAY CONNECTED to confirm the phone's comparison code. Rides the same
/// per-user relay socket as `portty share`, so only this user can trigger it.
///
/// Staying connected is not a convenience. Since the PIN was removed, a first
/// pair completes only when a human confirms that both screens show the same
/// six-digit code, and a daemonised host owns no terminal to ask on - this
/// process is its console. Quitting before the phone connects leaves the host
/// with no approval channel, so it refuses the pairing.
async fn run_pair() -> anyhow::Result<()> {
    let stream = match connect().await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("portty: no daemon running - start one with `portty-host` first.");
            std::process::exit(1);
        }
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let msg = postcard::to_allocvec(&RelayToHost::ReopenPairing)?;
    write_framed(&mut wr, &msg).await?;
    let reply = read_framed(&mut rd).await?;
    let HostToRelay::PairingInfo {
        ticket,
        qr,
        phrase,
        window_secs,
    } = postcard::from_bytes::<HostToRelay>(&reply)?
    else {
        anyhow::bail!("unexpected reply from the daemon - is it an older build? restart it");
    };
    println!();
    println!("==========================================================");
    println!("  Pairing window reopened for ~{} min.", window_secs / 60);
    println!("  Pairing ticket (scan the QR below, or paste this):");
    println!("    {ticket}");
    println!("  Phrase:  {phrase}");
    println!("----------------------------------------------------------");
    print_qr(&qr);
    println!("==========================================================");
    println!();
    println!("  Each of these is a COMPLETE key to this machine - treat");
    println!("  them like a password.");
    println!();
    println!("  Waiting for a phone... (Ctrl-C to cancel)");
    println!("  When it connects, check the code below matches your phone.");
    println!();

    // Block until the daemon asks us to confirm a pairing, or the window shuts.
    let ask = tokio::time::timeout(
        Duration::from_secs(window_secs.max(1)),
        read_framed(&mut rd),
    )
    .await;
    let frame = match ask {
        Ok(Ok(frame)) => frame,
        Ok(Err(_)) => {
            eprintln!("portty pair: the daemon closed the connection.");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("portty pair: the pairing window closed before a phone connected.");
            eprintln!("  Run `portty pair` again when you are ready.");
            std::process::exit(1);
        }
    };
    let HostToRelay::PairingConfirmRequest { device_name, code } =
        postcard::from_bytes::<HostToRelay>(&frame)?
    else {
        anyhow::bail!("unexpected message from the daemon while waiting to confirm a pairing");
    };

    let accept = prompt_pairing_match(&device_name, &code)?;
    let answer = postcard::to_allocvec(&RelayToHost::PairingConfirmResponse { accept })?;
    write_framed(&mut wr, &answer).await?;
    if accept {
        println!("  Confirmed. The phone is now paired.");
    } else {
        println!("  Rejected. Nothing was paired.");
        println!("  If you did not expect this, someone may have your pairing");
        println!("  ticket - run `portty pair` again to replace it.");
    }
    Ok(())
}

/// Show the comparison code and read a yes/no. Anything that is not an explicit
/// yes - including a bare Enter or a closed stdin - is a no.
///
/// `device_name` is peer-supplied, so it gets its own line, well away from the
/// digits: a phone that names itself "code: 000000" must not be able to read as
/// the code.
fn prompt_pairing_match(device_name: &str, code: &str) -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    let spaced = if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    };
    println!("==========================================================");
    println!("  A phone wants to pair.");
    println!("  It calls itself: {device_name}");
    println!();
    println!("  Check that YOUR PHONE is showing this same code:");
    println!();
    println!("      {spaced}");
    println!();
    println!("  If the codes do not match, say no - something is");
    println!("  sitting between your phone and this machine.");
    println!("==========================================================");
    print!("  Do the codes match? [y/N]: ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "match" | "ok"
    ))
}

// ── portty exit / unpair - share detach + paired-device hygiene ────────────

/// Env var the share relay sets in its wrapped shell: the control endpoint a
/// nested `portty exit` uses to ask the ENCLOSING relay to stop sharing.
const SHARE_CTL_ENV: &str = "PORTTY_SHARE_CTL";

/// `portty exit` - run INSIDE a `portty share` terminal: tell the enclosing
/// relay to stop sharing (the phone sees the session end) while this shell
/// keeps running locally. Plain `exit` still closes the shell itself.
async fn run_exit() -> anyhow::Result<()> {
    let Some(endpoint) = std::env::var_os(SHARE_CTL_ENV) else {
        eprintln!("portty exit: this terminal is not a shared portty session.");
        eprintln!("  Start one with `portty share`. (Plain `exit` closes the shell.)");
        std::process::exit(2);
    };
    let endpoint = endpoint.to_string_lossy().into_owned();
    match tokio::time::timeout(Duration::from_secs(3), send_share_ctl_detach(&endpoint)).await {
        Ok(Ok(())) => Ok(()), // the relay announces "stopped sharing" itself
        Ok(Err(e)) => {
            eprintln!("portty exit: could not reach the share relay: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("portty exit: the share relay did not answer.");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
async fn send_share_ctl_detach(endpoint: &str) -> anyhow::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(endpoint).await?;
    stream.write_all(b"detach\n").await?;
    let mut ack = [0u8; 8];
    let n = stream.read(&mut ack).await?;
    anyhow::ensure!(&ack[..n] == b"ok\n", "unexpected reply from the relay");
    Ok(())
}

#[cfg(windows)]
async fn send_share_ctl_detach(endpoint: &str) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut stream = ClientOptions::new().open(endpoint)?;
    stream.write_all(b"detach\n").await?;
    let mut ack = [0u8; 8];
    let n = stream.read(&mut ack).await?;
    anyhow::ensure!(&ack[..n] == b"ok\n", "unexpected reply from the relay");
    Ok(())
}

/// Handle for the share relay's `portty exit` control endpoint.
struct ShareCtl {
    endpoint: String,
    #[cfg(not(windows))]
    path: PathBuf,
}

impl ShareCtl {
    fn cleanup(&self) {
        #[cfg(not(windows))]
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Listen for `portty exit` from inside the wrapped shell. Same-uid peers
/// only, mirroring the daemon relay socket's policy. Returns None (share
/// still works, just without detach) if the endpoint can't be created.
#[cfg(not(windows))]
fn start_share_ctl(detach: Arc<AtomicBool>) -> Option<ShareCtl> {
    let dir = portty_protocol::relay::prepare_socket_dir().ok()?;
    let path = dir.join(format!("share-ctl-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).ok()?;
    let endpoint = path.to_string_lossy().into_owned();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(peer) = stream.peer_cred() else {
                continue;
            };
            // SAFETY: getuid is always safe and never fails.
            if peer.uid() != unsafe { libc::getuid() } {
                continue;
            }
            let mut buf = [0u8; 16];
            let Ok(n) = stream.read(&mut buf).await else {
                continue;
            };
            if buf[..n].starts_with(b"detach") {
                detach.store(true, Ordering::Relaxed);
                let _ = stream.write_all(b"ok\n").await;
            }
        }
    });
    Some(ShareCtl { endpoint, path })
}

#[cfg(windows)]
fn start_share_ctl(detach: Arc<AtomicBool>) -> Option<ShareCtl> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let endpoint = format!(r"\\.\pipe\portty-share-ctl-{}", std::process::id());
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&endpoint)
        .ok()?;
    let pipe_name = endpoint.clone();
    tokio::spawn(async move {
        loop {
            if server.connect().await.is_err() {
                break;
            }
            let mut stream = server;
            server = match ServerOptions::new().create(&pipe_name) {
                Ok(next) => next,
                Err(_) => break,
            };
            let detach = detach.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                if buf[..n].starts_with(b"detach") {
                    detach.store(true, Ordering::Relaxed);
                    let _ = stream.write_all(b"ok\n").await;
                }
            });
        }
    });
    Some(ShareCtl { endpoint })
}

/// `portty unpair [<id>|all]` - forget paired phones on THIS host. A
/// convenience front for `portty-host peers` / `portty-host revoke`, so
/// day-2 pairing hygiene lives on the binary people already type.
fn run_unpair(rest: &[String]) -> anyhow::Result<()> {
    let Some(host) = locate_host_exe() else {
        eprintln!(
            "portty unpair: couldn't find `portty-host` (set PORTTY_HOST or add it to PATH)."
        );
        std::process::exit(1);
    };
    let status = match rest.first().map(String::as_str) {
        None => {
            let status = Command::new(&host).arg("peers").status()?;
            if status.success() {
                eprintln!();
                eprintln!("Remove one with:  portty unpair <hex-prefix>");
                eprintln!("Remove all with:  portty unpair all");
            }
            status
        }
        Some(target) => Command::new(&host).args(["revoke", target]).status()?,
    };
    std::process::exit(status.code().unwrap_or(1));
}

// ── portty agent - laptop chat over the phone's agent sessions ─────────────

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";

/// A permission card waiting for an answer (from here OR the phone).
struct PendingApproval {
    tool_call_id: String,
    title: String,
    options: Vec<PermissionOption>,
}

/// What the renderer is currently streaming inline, so chunk events can append
/// to one line and everything else knows to break it first.
enum Streaming {
    None,
    Assistant,
    Thought,
}

enum AgentInput {
    Send(RelayToHost),
    Help,
}

fn one_agent_arg<'a>(
    command: &str,
    mut args: impl Iterator<Item = &'a str>,
) -> Result<&'a str, String> {
    let Some(value) = args.next() else {
        return Err(format!("usage: {command} <id>"));
    };
    if args.next().is_some() {
        return Err(format!("usage: {command} <id>"));
    }
    Ok(value)
}

/// Parse only Portty's local chat controls. Unknown slash commands remain ACP
/// prompts so provider commands such as `/compact` continue to work.
fn parse_agent_input(text: &str, pending: &[PendingApproval]) -> Result<AgentInput, String> {
    let mut parts = text.split_whitespace();
    let command = parts.next().unwrap_or_default();
    let message = match command {
        "/help" => {
            if parts.next().is_some() {
                return Err("usage: /help".into());
            }
            return Ok(AgentInput::Help);
        }
        "/stop" | "/cancel" => {
            if parts.next().is_some() {
                return Err(format!("usage: {command}"));
            }
            RelayToHost::AgentCancel
        }
        "/mode" => RelayToHost::AgentSetMode {
            mode_id: one_agent_arg("/mode", parts)?.to_string(),
        },
        "/model" => RelayToHost::AgentSetModel {
            model_id: one_agent_arg("/model", parts)?.to_string(),
        },
        "/auth" => RelayToHost::AgentAuthenticate {
            method_id: one_agent_arg("/auth", parts)?.to_string(),
        },
        "/config" => {
            let Some(config_id) = parts.next() else {
                return Err("usage: /config <id> <value|on|off>".into());
            };
            let Some(value) = parts.next() else {
                return Err("usage: /config <id> <value|on|off>".into());
            };
            if parts.next().is_some() {
                return Err("usage: /config <id> <value|on|off>".into());
            }
            let value = match value.to_ascii_lowercase().as_str() {
                "on" | "true" => AgentConfigValue::Boolean(true),
                "off" | "false" => AgentConfigValue::Boolean(false),
                _ => AgentConfigValue::Select(value.to_string()),
            };
            RelayToHost::AgentSetConfig {
                config_id: config_id.to_string(),
                value,
            }
        }
        _ => match decision_for(text, pending) {
            Some((tool_call_id, option_id)) => RelayToHost::AgentDecision {
                tool_call_id,
                option_id,
            },
            None => RelayToHost::AgentPrompt {
                text: text.to_string(),
            },
        },
    };
    Ok(AgentInput::Send(message))
}

fn print_agent_help() {
    println!("{DIM}Portty controls:{RESET}");
    println!("{DIM}  /stop                  cancel the active turn{RESET}");
    println!("{DIM}  /mode <id>             change the announced ACP mode{RESET}");
    println!("{DIM}  /model <id>            change the model setting{RESET}");
    println!("{DIM}  /config <id> <value>  change any announced setting{RESET}");
    println!("{DIM}  /auth <id>             start an announced authentication method{RESET}");
    println!("{DIM}  exit                    leave without stopping the agent{RESET}");
}

/// `portty agent <claude|codex|opencode|goose>` - a laptop chat for the SAME
/// structured agent sessions the phone drives. By default it joins the newest
/// live session of that agent, so laptop and phone control ONE conversation;
/// `--new` always starts a fresh session. Leaving the chat (exit/Ctrl+C) does
/// NOT stop the agent - it keeps running for the phone; rejoin any time.
async fn run_agent(rest: &[String]) -> anyhow::Result<()> {
    let mut provider = None;
    let mut fresh = false;
    for arg in rest {
        match arg.as_str() {
            "--new" => fresh = true,
            "claude" | "claude-code" => provider = Some(AgentProvider::ClaudeCode),
            "codex" => provider = Some(AgentProvider::Codex),
            "opencode" | "open-code" => provider = Some(AgentProvider::OpenCode),
            "goose" => provider = Some(AgentProvider::Goose),
            other => {
                anyhow::bail!("unknown agent `{other}` - use claude, codex, opencode, or goose")
            }
        }
    }
    let Some(provider) = provider else {
        eprintln!("usage: portty agent <claude|codex|opencode|goose> [--new]");
        eprintln!();
        eprintln!("Joins the newest live session of that agent (the one on your phone),");
        eprintln!("or starts a new one. Prompts, replies, and approvals stay in sync on");
        eprintln!("every device. `--new` always starts a separate fresh session.");
        std::process::exit(2);
    };

    let stream = match connect().await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[portty] no daemon running - starting `portty-host` for you…");
            match wait_for_daemon().await {
                Some(s) => s,
                None => {
                    eprintln!("[portty] couldn't start a daemon. Run `portty-host`, then retry.");
                    std::process::exit(1);
                }
            }
        }
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let open = postcard::to_allocvec(&RelayToHost::OpenAgent {
        provider,
        join: !fresh,
    })?;
    write_framed(&mut wr, &open).await?;
    let reply = read_framed(&mut rd).await?;
    let HostToRelay::AgentOpened { id, title, created } = postcard::from_bytes(&reply)? else {
        anyhow::bail!("unexpected reply from the daemon - is it an older build? restart it");
    };
    println!();
    let how = if created {
        "new session"
    } else {
        "joined live session"
    };
    println!(
        "{BOLD}● {}{RESET} {DIM}- {how} {} (also on your phone){RESET}",
        safe(&title),
        id.0
    );
    println!("{DIM}  type a message + Enter · /help lists local controls and settings{RESET}");
    println!("{DIM}  `exit` leaves this chat; the agent keeps running - rejoin any time{RESET}");
    println!();

    let pending: Arc<Mutex<Vec<PendingApproval>>> = Arc::new(Mutex::new(Vec::new()));

    // stdin → prompts/decisions. Owns the write half. Plain line input, no raw
    // mode: streamed output can interleave while you type - normal for a
    // log-style chat, and it keeps every terminal quirk out of the loop.
    {
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            loop {
                let line = match lines.next_line().await {
                    Ok(Some(line)) => line,
                    Ok(None) | Err(_) => break, // Ctrl+D
                };
                let text = line.trim();
                if text.is_empty() {
                    continue;
                }
                if text == "exit" || text == "quit" {
                    break;
                }
                // Lock scope must end before the await below.
                let parsed = {
                    let cards = pending.lock().unwrap();
                    parse_agent_input(text, &cards)
                };
                let msg = match parsed {
                    Ok(AgentInput::Send(msg)) => msg,
                    Ok(AgentInput::Help) => {
                        print_agent_help();
                        continue;
                    }
                    Err(message) => {
                        eprintln!("[portty] {message}");
                        continue;
                    }
                };
                let Ok(bytes) = postcard::to_allocvec(&msg) else {
                    continue;
                };
                if write_framed(&mut wr, &bytes).await.is_err() {
                    break;
                }
            }
            println!(
                "\n[portty] left the chat - the agent keeps running. Rejoin with `portty agent`."
            );
            std::process::exit(0);
        });
    }

    // Daemon → screen. Replayed history and live updates arrive the same way;
    // `seq` de-duplicates the overlap exactly like the phone does.
    let mut last_seq = 0u64;
    let mut streaming = Streaming::None;
    let mut tool_titles: std::collections::HashMap<String, String> = Default::default();
    let mut last_usage: Option<String> = None;
    loop {
        let frame = match read_framed(&mut rd).await {
            Ok(frame) => frame,
            Err(_) => {
                break_line(&mut streaming);
                println!("[portty] connection to the daemon closed.");
                break;
            }
        };
        let Ok(msg) = postcard::from_bytes::<HostToRelay>(&frame) else {
            continue;
        };
        match msg {
            HostToRelay::AgentEvent { event } => {
                if event.seq <= last_seq {
                    continue;
                }
                last_seq = event.seq;
                render_event(
                    &event.event,
                    &mut streaming,
                    &mut tool_titles,
                    &mut last_usage,
                );
            }
            HostToRelay::AgentPermission { tool_call, options } => {
                let card = PendingApproval {
                    tool_call_id: tool_call.tool_call_id,
                    title: tool_call.title,
                    options,
                };
                break_line(&mut streaming);
                print_permission(&card);
                let mut cards = pending.lock().unwrap();
                cards.retain(|c| c.tool_call_id != card.tool_call_id);
                cards.push(card);
            }
            HostToRelay::AgentPermissionResolved { tool_call_id } => {
                let removed = {
                    let mut cards = pending.lock().unwrap();
                    let before = cards.len();
                    cards.retain(|c| c.tool_call_id != tool_call_id);
                    before != cards.len()
                };
                if removed {
                    break_line(&mut streaming);
                    println!("{DIM}✓ approval answered{RESET}");
                }
            }
            HostToRelay::AgentGone { message } => {
                break_line(&mut streaming);
                println!("[portty] {}", safe(&message));
                break;
            }
            HostToRelay::AgentError { message } => {
                break_line(&mut streaming);
                println!("{YELLOW}[portty] {}{RESET}", safe(&message));
            }
            _ => {} // terminal-mode replies never arrive on an agent connection
        }
    }
    std::process::exit(0);
}

/// End an in-progress inline stream (assistant text / thinking marker) so the
/// next item starts on its own line.
fn break_line(streaming: &mut Streaming) {
    if !matches!(streaming, Streaming::None) {
        println!();
        *streaming = Streaming::None;
    }
}

fn status_glyph(status: AgentToolStatus) -> &'static str {
    match status {
        AgentToolStatus::Completed => "✓",
        AgentToolStatus::Failed => "✗",
        AgentToolStatus::InProgress => "●",
        AgentToolStatus::Pending => "○",
    }
}

// Keep in lockstep with formatTokens in app/src/AgentView.tsx - laptop and
// phone must show the same number for the same usage event.
fn format_tokens(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{}k", (count as f64 / 1_000.0).round() as u64)
    } else {
        count.to_string()
    }
}

/// Strip terminal-control and text-direction characters from model- or
/// provider-controlled text before printing it.
///
/// Everything in an agent transcript - assistant prose, tool titles, plan items,
/// error messages, an approval card's option names - is chosen by the model or
/// the adapter, and `println!` hands it straight to the terminal emulator. Raw,
/// it can clear the screen, move the cursor, rewrite the line above with a bare
/// `\r`, retitle the window, write the user's clipboard through OSC 52, or use
/// bidi overrides to make an approval read as something other than what it will
/// run. A chat transcript needs none of that.
///
/// Kept: newline and tab (real structure in assistant text). Dropped: every other
/// C0 control including ESC and CR, DEL, the C1 range, and the bidi
/// embedding/override/isolate marks. Dropping rather than escaping leaves any
/// attempt visible as inert text (`[2J`), which is the tell you want.
fn safe(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{1}'..='\u{8}'
                    | '\u{b}'..='\u{1f}'      // C0 except \t (09) and \n (0a)
                    | '\u{0}'
                    | '\u{7f}'                // DEL
                    | '\u{80}'..='\u{9f}'     // C1, including 8-bit CSI/OSC
                    | '\u{200e}' | '\u{200f}' // LRM / RLM
                    | '\u{202a}'..='\u{202e}' // embeddings + overrides
                    | '\u{2066}'..='\u{2069}' // isolates
                    | '\u{61c}'               // Arabic letter mark
            )
        })
        .collect()
}

fn render_event(
    event: &AgentEvent,
    streaming: &mut Streaming,
    tool_titles: &mut std::collections::HashMap<String, String>,
    last_usage: &mut Option<String>,
) {
    match event {
        // The header already names the agent; nothing to draw.
        AgentEvent::SessionStarted { .. } => {}
        AgentEvent::UserMessage { text } => {
            break_line(streaming);
            println!("{CYAN}{BOLD}you ▸{RESET} {}", safe(text));
        }
        AgentEvent::TurnStarted => {
            break_line(streaming);
            println!("{DIM}⏺ working…{RESET}");
        }
        AgentEvent::MessageChunk { text } => {
            if !matches!(streaming, Streaming::Assistant) {
                break_line(streaming);
                print!("{GREEN}{BOLD}agent ▸{RESET} ");
                *streaming = Streaming::Assistant;
            }
            print!("{}", safe(text));
            let _ = std::io::stdout().flush();
        }
        // Content stays on the phone's collapsible card; here just a marker.
        AgentEvent::ThoughtChunk { .. } => {
            if !matches!(streaming, Streaming::Thought) {
                break_line(streaming);
                print!("{DIM}· thinking…{RESET}");
                let _ = std::io::stdout().flush();
                *streaming = Streaming::Thought;
            }
        }
        AgentEvent::ToolCall {
            tool_call_id,
            title,
            kind,
            status,
            ..
        } => {
            tool_titles.insert(tool_call_id.clone(), title.clone());
            break_line(streaming);
            let kind = format!("{kind:?}").to_lowercase();
            println!(
                "{DIM}⚙ {} · {kind} {}{RESET}",
                safe(title),
                status_glyph(*status)
            );
        }
        AgentEvent::ToolCallUpdate {
            tool_call_id,
            title,
            status,
            ..
        } => {
            if let Some(title) = title {
                tool_titles.insert(tool_call_id.clone(), title.clone());
            }
            // Only the outcome is worth a line; intermediate updates are noise.
            if let Some(status) = status {
                if matches!(status, AgentToolStatus::Completed | AgentToolStatus::Failed) {
                    let name = tool_titles
                        .get(tool_call_id)
                        .cloned()
                        .unwrap_or_else(|| tool_call_id.clone());
                    break_line(streaming);
                    println!("{DIM}⚙ {} {}{RESET}", safe(&name), status_glyph(*status));
                }
            }
        }
        AgentEvent::Plan { entries } => {
            break_line(streaming);
            println!("{DIM}plan:{RESET}");
            for entry in entries {
                let glyph = match entry.status {
                    AgentPlanStatus::Completed => "✓",
                    AgentPlanStatus::InProgress => "●",
                    AgentPlanStatus::Pending => "○",
                };
                println!("  {glyph} {}", safe(&entry.content));
            }
        }
        AgentEvent::TurnFinished { stop_reason } => {
            break_line(streaming);
            let usage = last_usage
                .as_deref()
                .map(|usage| format!(" · {usage}"))
                .unwrap_or_default();
            println!("{DIM}✔ done ({}){usage}{RESET}", safe(stop_reason));
        }
        AgentEvent::Error { message } => {
            break_line(streaming);
            println!("{RED}✖ {}{RESET}", safe(message));
        }
        AgentEvent::AvailableCommands { commands } => {
            if !commands.is_empty() {
                break_line(streaming);
                let names = commands
                    .iter()
                    .map(|command| format!("/{}", safe(&command.name)))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("{DIM}commands: {names}{RESET}");
            }
        }
        AgentEvent::ModeState {
            current_mode_id,
            available_modes,
        } => {
            break_line(streaming);
            println!("{DIM}mode: {}{RESET}", safe(current_mode_id));
            if !available_modes.is_empty() {
                let choices = available_modes
                    .iter()
                    .map(|mode| format!("{} ({})", safe(&mode.id), safe(&mode.name)))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("{DIM}  choices: {choices} · set with /mode <id>{RESET}");
            }
        }
        AgentEvent::ConfigOptions { options } => {
            if !options.is_empty() {
                break_line(streaming);
                for option in options {
                    let value = match &option.current_value {
                        AgentConfigValue::Select(value) => value.as_str(),
                        AgentConfigValue::Boolean(true) => "on",
                        AgentConfigValue::Boolean(false) => "off",
                    };
                    let is_model = option.category.as_deref() == Some("model");
                    let label = if is_model {
                        "model"
                    } else {
                        option.id.as_str()
                    };
                    println!("{DIM}{}: {}{RESET}", safe(label), safe(value));
                    if !option.choices.is_empty() {
                        let choices = option
                            .choices
                            .iter()
                            .map(|choice| {
                                format!("{} ({})", safe(&choice.value), safe(&choice.name))
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let command = if is_model {
                            "/model <id>".to_string()
                        } else {
                            format!("/config {} <value>", safe(&option.id))
                        };
                        println!("{DIM}  choices: {choices} · set with {command}{RESET}");
                    }
                }
            }
        }
        AgentEvent::SessionInfo { title: Some(title) } => {
            break_line(streaming);
            println!("{DIM}session: {}{RESET}", safe(title));
        }
        AgentEvent::SessionInfo { title: None } => {}
        AgentEvent::Replaying { active: true } => {
            break_line(streaming);
            println!("{DIM}replaying saved conversation…{RESET}");
        }
        AgentEvent::Replaying { active: false } => {}
        AgentEvent::AuthRequired { methods } => {
            if !methods.is_empty() {
                break_line(streaming);
                println!("{YELLOW}authentication required:{RESET}");
                for method in methods {
                    println!("  {} - {}", safe(&method.id), safe(&method.name));
                }
                println!("{DIM}start with /auth <id>{RESET}");
            }
        }
        // Streamed repeatedly during a turn; one line per update would drown
        // the chat, so it is folded into the next "done" line instead.
        AgentEvent::Usage {
            used_tokens,
            max_tokens,
            cost,
        } => {
            let cost = cost
                .as_deref()
                .map(|cost| format!(" · {}", safe(cost)))
                .unwrap_or_default();
            *last_usage = Some(format!(
                "{}/{} tokens{cost}",
                format_tokens(*used_tokens),
                format_tokens(*max_tokens),
            ));
        }
    }
}

fn print_permission(card: &PendingApproval) {
    println!();
    println!("{YELLOW}{BOLD}┌ approval needed{RESET}");
    println!("{YELLOW}│{RESET} {}", safe(&card.title));
    let mut row = String::new();
    for (i, option) in card.options.iter().enumerate() {
        use std::fmt::Write as _;
        let _ = write!(&mut row, "  [{}] {}", i + 1, safe(&option.name));
    }
    println!("{YELLOW}│{RESET}{row}");
    println!("{YELLOW}└{RESET} {DIM}answer with a number, y, or n - here or on your phone{RESET}");
}

/// Interpret an input line as an answer to the OLDEST pending approval: a
/// 1-based option number, `y` (first allow option), or `n` (first reject
/// option; cancel if the agent offered none). Anything else is a prompt.
fn decision_for(text: &str, pending: &[PendingApproval]) -> Option<(String, Option<String>)> {
    let card = pending.first()?;
    if let Ok(n) = text.parse::<usize>() {
        let option = card.options.get(n.checked_sub(1)?)?;
        return Some((card.tool_call_id.clone(), Some(option.option_id.clone())));
    }
    match text.to_ascii_lowercase().as_str() {
        "y" | "yes" | "allow" => {
            let option = card
                .options
                .iter()
                .find(|o| matches!(o.kind, PermissionOptionKind::AllowOnce))
                .or_else(|| {
                    card.options
                        .iter()
                        .find(|o| matches!(o.kind, PermissionOptionKind::AllowAlways))
                })?;
            Some((card.tool_call_id.clone(), Some(option.option_id.clone())))
        }
        "n" | "no" | "deny" | "reject" => {
            let option = card
                .options
                .iter()
                .find(|o| matches!(o.kind, PermissionOptionKind::RejectOnce))
                .or_else(|| {
                    card.options
                        .iter()
                        .find(|o| matches!(o.kind, PermissionOptionKind::RejectAlways))
                });
            Some((
                card.tool_call_id.clone(),
                option.map(|o| o.option_id.clone()),
            ))
        }
        _ => None,
    }
}

/// Render a string as a compact terminal QR (black-on-white half-blocks, with
/// a 4-module quiet zone) - same rendering as the daemon's startup banner.
fn print_qr(text: &str) {
    let code = match qrcode::QrCode::new(text) {
        Ok(c) => c,
        Err(e) => {
            println!("  (couldn't render QR: {e})");
            return;
        }
    };
    let w = code.width();
    let qz = 4; // quiet zone (QR spec) so a camera can find the edges
    let total = w + 2 * qz;
    let module = |x: usize, y: usize| -> bool {
        let mx = x as isize - qz as isize;
        let my = y as isize - qz as isize;
        mx >= 0
            && my >= 0
            && (mx as usize) < w
            && (my as usize) < w
            && code[(mx as usize, my as usize)] == qrcode::types::Color::Dark
    };
    let mut y = 0;
    while y < total {
        print!("\x1b[30;47m");
        for x in 0..total {
            let top = module(x, y);
            let bot = (y + 1 < total) && module(x, y + 1);
            let ch = match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            print!("{ch}");
        }
        println!("\x1b[0m");
        y += 2;
    }
}

/// Wrap a shell (or an explicit command after `--`) in a PTY, mirror it to the
/// current terminal, and tee it to the daemon.
async fn run_share(rest: &[String]) -> anyhow::Result<()> {
    // Parse flags, then an optional explicit command after `--` (a bare
    // positional is tolerated as the command too). Example smoke tests:
    //   `portty share --no-daemon`            default shell, don't auto-start host
    //   `portty share -- cmd /c echo hi`      run that command instead of the shell
    let mut no_daemon = false;
    let mut explicit: Option<Vec<String>> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--no-daemon" => no_daemon = true,
            "--" => {
                explicit = Some(rest[i + 1..].to_vec());
                break;
            }
            // A mistyped flag (e.g. `--help`, `--no-demon`) must be a usage error,
            // not silently spawned as the command to run. Anything meant as a
            // command goes after `--` or is a non-flag positional.
            other if other.starts_with('-') => {
                eprintln!("portty: unknown option `{other}` for `share`\n");
                eprintln!("usage: portty share [--no-daemon] [-- <command> [args...]]");
                std::process::exit(2);
            }
            _ => {
                explicit = Some(rest[i..].to_vec());
                break;
            }
        }
        i += 1;
    }

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    let pty_system = NativePtySystem::default();
    let pair = pty_system.openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    // The folder THIS terminal is in. `portty share` adopts the terminal you run
    // it from, so the shared shell should start here - otherwise portable_pty
    // falls back to your home dir (%USERPROFILE% on Windows) and the phone lands
    // at "root" instead of your project.
    let cwd = std::env::current_dir().ok();
    let (mut cmd, title) = match explicit {
        Some(argv) if !argv.is_empty() => {
            let mut c = CommandBuilder::new(&argv[0]);
            c.args(&argv[1..]);
            (c, argv[0].clone())
        }
        // Default shell: title it by the folder name so the phone's session list
        // says WHICH terminal this is (e.g. "project-portty"), not just "shell".
        _ => {
            let title = cwd
                .as_deref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "shell".to_string());
            (CommandBuilder::new_default_prog(), title)
        }
    };
    if let Some(cwd) = &cwd {
        cmd.cwd(cwd);
    }

    // `portty exit` support: hand the wrapped shell a control endpoint back to
    // THIS relay so sharing can stop without closing the shell. PORTTY_RELAY=1
    // also keeps an installed profile snippet from double-wrapping the child.
    let detach = Arc::new(AtomicBool::new(false));
    let share_ctl = start_share_ctl(detach.clone());
    if let Some(ctl) = &share_ctl {
        cmd.env(SHARE_CTL_ENV, &ctl.endpoint);
    }
    cmd.env("PORTTY_RELAY", "1");

    let child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave); // let EOF propagate to the master reader when the child exits

    let master = pair.master;
    let mut reader = master.try_clone_reader()?;

    let writer: SharedWriter = Arc::new(Mutex::new(master.take_writer()?));
    let master: SharedMaster = Arc::new(Mutex::new(master));
    let child: SharedChild = Arc::new(Mutex::new(child));
    let done = Arc::new(AtomicBool::new(false));

    // Relay → host messages (output + the final Exited). Cloned into the reader
    // thread; the original is kept to send Exited at teardown. Bounded and
    // lossless while the daemon connection is alive (see RELAY_TEE_FRAMES).
    let (to_host_tx, to_host_rx) = mpsc::channel::<RelayToHost>(RELAY_TEE_FRAMES);

    // This window's size IS the phone's grid. An adopted session is never
    // resized by a viewer (see `Session::resize`), so a cramped terminal here
    // means a cramped terminal there - plus almost no scrollback to reach, and
    // garbled repaints from anything full-screen, because the app does its
    // cursor math against these rows. That failure used to be entirely silent:
    // the phone just looked broken. Say it once, here, while resizing the
    // window is still free.
    const MIN_COMFORTABLE_COLS: u16 = 80;
    const MIN_COMFORTABLE_ROWS: u16 = 24;
    if cols < MIN_COMFORTABLE_COLS || rows < MIN_COMFORTABLE_ROWS {
        println!(
            "[portty] heads-up: this terminal is {cols}x{rows}, and the phone \
             renders the shared session at exactly that size - it cannot resize \
             it. Enlarge this window (the change is picked up live) for a usable \
             phone view.\r"
        );
    }
    println!(
        "[portty] sharing this terminal. `portty exit` stops sharing · `exit` ends the shell.\r"
    );
    #[cfg(windows)]
    let windows_input = WindowsConsoleInput::capture();
    crossterm::terminal::enable_raw_mode()?;
    #[cfg(windows)]
    let local_input_mode = if windows_input
        .as_ref()
        .is_some_and(WindowsConsoleInput::enable_vt)
    {
        LocalInputMode::RawBytes
    } else {
        LocalInputMode::ConsoleEvents
    };
    #[cfg(not(windows))]
    let local_input_mode = LocalInputMode::RawBytes;
    let _raw = RawGuard {
        #[cfg(windows)]
        windows_input,
    };

    // Keyboard/terminal replies → inner PTY. Forward the VT stream byte-for-byte.
    // Parsing and re-encoding here breaks nested TUIs: modern apps negotiate
    // Kitty keyboard modes and issue terminal queries whose input sequences must
    // reach the child unchanged. Windows uses the same stream when its console
    // supports VT input, with an event translator only as a legacy fallback.
    //
    // NOTE (sizing model): THIS terminal is the sole owner of the PTY size
    // (fixed-size model). Viewers never resize it; the daemon just learns the
    // size (Register + SizeChanged) so the phone can render around it.
    {
        let writer = writer.clone();
        thread::spawn(move || forward_local_input(writer, local_input_mode));
    }

    // inner PTY → stdout (local mirror) + tee to the daemon (the phone stream).
    let tee_thread = {
        let to_host = to_host_tx.clone();
        thread::spawn(move || {
            let mut stdout = std::io::stdout();
            // 16 KiB (matches the host's PTY reader): fewer tee messages and
            // relay frames per byte under heavy output.
            let mut buf = [0u8; 16384];
            let mut tee_open = true;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break, // inner shell exited
                    Ok(n) => {
                        let _ = stdout.write_all(&buf[..n]);
                        let _ = stdout.flush();
                        // Preserve every byte for the host ring. This runs on the
                        // blocking PTY thread, so blocking_send is appropriate;
                        // when the receiver closes, keep mirroring locally and
                        // stop attempting the tee.
                        if tee_open
                            && to_host
                                .blocking_send(RelayToHost::Output(buf[..n].to_vec()))
                                .is_err()
                        {
                            tee_open = false;
                        }
                    }
                }
            }
        })
    };

    // Pass terminal resizes through to the inner PTY, and report the new
    // authoritative size to the daemon so viewers (phone match-width mode)
    // follow it (→ `Frame::SessionSize`).
    {
        let master = master.clone();
        let to_host = to_host_tx.clone();
        thread::spawn(move || {
            let mut last = (cols, rows);
            loop {
                thread::sleep(Duration::from_millis(250));
                if let Ok(size) = crossterm::terminal::size() {
                    if size != last {
                        last = size;
                        if let Ok(m) = master.lock() {
                            let _ = m.resize(PtySize {
                                rows: size.1,
                                cols: size.0,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                        // Lossless like output: a one-shot resize must not
                        // disappear merely because the shared queue is full.
                        // This dedicated polling thread may block until the
                        // daemon drains the queue without affecting PTY I/O.
                        let _ = to_host.blocking_send(RelayToHost::SizeChanged {
                            cols: size.0,
                            rows: size.1,
                        });
                    }
                }
            }
        });
    }

    // Connect to the daemon. If none is running (and not opted out with
    // `--no-daemon`), auto-start `portty-host` and wait for its relay pipe; on
    // any failure we fall back to mirroring locally so the terminal still works.
    let stream = match connect().await {
        Ok(s) => Some(s),
        Err(_) if no_daemon => None,
        Err(_) => {
            eprintln!("[portty] no daemon running - starting `portty-host` for you…\r");
            match wait_for_daemon().await {
                Some(s) => {
                    eprintln!(
                        "[portty] daemon is up. (Fresh machine? Run `portty pair` to show the QR.)\r"
                    );
                    Some(s)
                }
                None => None,
            }
        }
    };

    let ipc_writer = match stream {
        Some(stream) => {
            let (rd, wr) = tokio::io::split(stream);
            let writer_task = spawn_ipc(
                rd,
                wr,
                to_host_rx,
                title,
                cols,
                rows,
                writer.clone(),
                child.clone(),
                done.clone(),
            );
            eprintln!("[portty] connected to daemon - this terminal is now on your phone.\r");
            Some(writer_task)
        }
        None => {
            eprintln!("[portty] couldn't reach a daemon - mirroring locally only.\r");
            eprintln!("[portty] start `portty-host` to put this terminal on your phone.\r");
            drop(to_host_rx); // tee sends now fail fast instead of buffering
            None
        }
    };

    // Wait until the shell exits OR the phone sends Kill. `portty exit` from
    // inside the wrapped shell detaches instead: the phone sees the session
    // end while this terminal keeps running locally.
    let mut detached = false;
    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }
        if !detached && detach.load(Ordering::Relaxed) {
            detached = true;
            let _ = to_host_tx.try_send(RelayToHost::Exited);
            eprintln!(
                "[portty] stopped sharing - this terminal is local-only now. `portty share` re-shares it.\r"
            );
        }
        {
            let mut c = child.lock().unwrap();
            if let Ok(Some(_)) = c.try_wait() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Drain the PTY reader first: every output chunk is queued before Exited.
    // Then wait for the pipe writer to flush Exited before terminating the
    // process, so a large final burst is not cut off by `process::exit`.
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || tee_thread.join()),
    )
    .await;
    let _ =
        tokio::time::timeout(Duration::from_secs(5), to_host_tx.send(RelayToHost::Exited)).await;
    if let Some(writer) = ipc_writer {
        let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
    }
    if let Some(ctl) = &share_ctl {
        ctl.cleanup();
    }
    drop(_raw); // restore cooked mode before the final line
    println!("\r\n[portty] session ended.\r");
    std::process::exit(0);
}

#[cfg(windows)]
async fn connect() -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::io::AsRawHandle;

    use portty_protocol::relay::{verify_named_pipe_peer, NamedPipePeer};
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = portty_protocol::relay::pipe_name()?;
    let mut stream = ClientOptions::new().open(&pipe_name)?;
    verify_named_pipe_peer(stream.as_raw_handle(), NamedPipePeer::Server)?;
    // Relay-pipe version handshake FIRST on every connection (#36): the daemon
    // rejects a skewed CLI before decoding any versioned message.
    write_framed(
        &mut stream,
        &portty_protocol::relay::RELAY_PIPE_VERSION.to_le_bytes(),
    )
    .await?;
    Ok(stream)
}

#[cfg(not(windows))]
async fn connect() -> anyhow::Result<tokio::net::UnixStream> {
    // Validate before connecting for useful diagnostics, then authenticate the
    // connected process. The peer credential check closes the TOCTOU window.
    portty_protocol::relay::validate_socket_endpoint()?;
    let mut stream = tokio::net::UnixStream::connect(portty_protocol::relay::socket_path()).await?;
    let peer = stream.peer_cred()?;
    // SAFETY: getuid is always safe and never fails.
    let our_uid = unsafe { libc::getuid() };
    anyhow::ensure!(
        peer.uid() == our_uid,
        "relay daemon belongs to uid {}, expected uid {our_uid}",
        peer.uid()
    );
    // Relay-pipe version handshake FIRST on every connection (#36): the daemon
    // rejects a skewed CLI before decoding any versioned message.
    write_framed(
        &mut stream,
        &portty_protocol::relay::RELAY_PIPE_VERSION.to_le_bytes(),
    )
    .await?;
    Ok(stream)
}

/// Spawn a daemon and wait (up to ~8s) for its relay pipe to accept a
/// connection. Returns None if no daemon could be started, or if it exits at
/// once (e.g. a port clash on the local terminal server).
async fn wait_for_daemon() -> Option<RelayStream> {
    let mut child = try_spawn_daemon()?;
    for _ in 0..80 {
        if let Ok(s) = connect().await {
            return Some(s);
        }
        // Bare `portty-host` daemonizes on Unix: the process we spawned
        // double-forks and exits 0 while the real daemon lives on. Only a
        // failure exit means it actually died - keep polling otherwise.
        if let Ok(Some(status)) = child.try_wait() {
            if !status.success() {
                return None;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Locate and launch `portty-host` detached, so it outlives this `portty`
/// process. On Windows it runs with no console window of its own.
fn try_spawn_daemon() -> Option<std::process::Child> {
    let exe = locate_host_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // New process group + detached + no window: survives the parent and
        // doesn't pop a console over the user's terminal.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW);
    }
    cmd.spawn().ok()
}

/// Find the host daemon binary: `PORTTY_HOST` env override → sibling next to
/// this exe (dev + co-installed layout) → PATH.
fn locate_host_exe() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PORTTY_HOST") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let cand = dir.join(if cfg!(windows) {
                "portty-host.exe"
            } else {
                "portty-host"
            });
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    which(if cfg!(windows) {
        "portty-host.exe"
    } else {
        "portty-host"
    })
}

/// Tiny PATH search so we don't pull in a `which` crate.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.exists() {
            return Some(cand);
        }
    }
    None
}

// ── shell-profile hook: make every terminal portal-ready from birth ───────

/// The profile block is delimited by these, so `uninstall` can remove exactly
/// the lines `install` added, even if the user edits the rest of the profile.
const MARKER_START: &str = "# >>> portty portal >>>";
const MARKER_END: &str = "# <<< portty portal <<<";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // "PowerShell" coincidentally ends in "Shell"
enum Shell {
    PowerShell,
    Bash,
    Zsh,
}

fn shell_name(sh: Shell) -> &'static str {
    match sh {
        Shell::PowerShell => "powershell",
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
    }
}

fn parse_shell(s: &str) -> Option<Shell> {
    match s.to_ascii_lowercase().as_str() {
        "powershell" | "pwsh" | "ps" => Some(Shell::PowerShell),
        "bash" | "sh" => Some(Shell::Bash),
        "zsh" => Some(Shell::Zsh),
        _ => None,
    }
}

/// The profile snippet for a shell. `PORTTY_RELAY=1` stops the inner shell from
/// re-wrapping (infinite recursion); interactive-only guards keep scripts and
/// `bash -c` / `pwsh -Command` (which don't source the profile anyway) clean.
fn init_snippet(shell: Shell) -> String {
    match shell {
        Shell::PowerShell => "\
# >>> portty portal >>>
# Makes every interactive shell portal-ready from birth: `portty share` wraps it
# so any terminal is shareable to your phone with no per-use command. Remove with
# `portty uninstall`. Skipped when PORTTY_RELAY=1 (already inside one) or portty
# isn't on PATH.
if ($env:PORTTY_RELAY -ne '1' -and (Get-Command portty -ErrorAction SilentlyContinue)) {
    $env:PORTTY_RELAY = '1'
    & portty share
    exit
}
# <<< portty portal <<<
"
        .to_string(),
        Shell::Bash | Shell::Zsh => "\
# >>> portty portal >>>
# Makes every interactive shell portal-ready from birth: `portty share` wraps it
# so any terminal is shareable to your phone with no per-use command. Remove with
# `portty uninstall`. Skipped when PORTTY_RELAY=1 (already inside one),
# non-interactive shells, or portty isn't on PATH.
if [ \"${PORTTY_RELAY:-0}\" != \"1\" ] && [[ $- == *i* ]] && command -v portty >/dev/null 2>&1; then
    export PORTTY_RELAY=1
    exec portty share
fi
# <<< portty portal <<<
"
        .to_string(),
    }
}

/// `portty init <shell>` - print the snippet (the safe primitive; paste it
/// yourself, or let `portty install` do it).
fn print_init(rest: &[String]) {
    match rest.first().and_then(|s| parse_shell(s)) {
        Some(sh) => {
            print!("{}", init_snippet(sh));
            let name = shell_name(sh);
            eprintln!("# Add the above to your {name} profile, or run: portty install");
        }
        None => {
            eprintln!("usage: portty init <powershell|bash|zsh>");
            eprintln!(
                "  prints the profile snippet that makes every interactive shell portal-ready."
            );
            std::process::exit(2);
        }
    }
}

/// `portty install [--shell <s>]` - append the portal hook to the detected (or
/// given) shell's profile. Idempotent: a no-op if the marker is already there.
fn run_install(rest: &[String]) -> anyhow::Result<()> {
    let shell = shell_arg(rest).or_else(detect_shell).ok_or_else(|| {
        anyhow::anyhow!("couldn't detect your shell; pass --shell <powershell|bash|zsh>")
    })?;
    let profile = profile_path(shell)?.ok_or_else(|| {
        anyhow::anyhow!("couldn't resolve a profile path for {}", shell_name(shell))
    })?;

    if let Some(parent) = profile.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(&profile).unwrap_or_default();
    if existing.contains(MARKER_START) {
        println!(
            "portty is already hooked into {} - no change.",
            profile.display()
        );
        return Ok(());
    }

    let mut new = existing;
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push('\n');
    new.push_str(&init_snippet(shell));
    std::fs::write(&profile, &new)?;

    println!("Added the portty portal hook to: {}", profile.display());
    println!("Open a NEW terminal and it'll be portal-ready. Remove with: portty uninstall");
    Ok(())
}

/// `portty uninstall [--shell <s>]` - remove the portal hook block.
fn run_uninstall(rest: &[String]) -> anyhow::Result<()> {
    let shell = shell_arg(rest).or_else(detect_shell).ok_or_else(|| {
        anyhow::anyhow!("couldn't detect your shell; pass --shell <powershell|bash|zsh>")
    })?;
    let profile = profile_path(shell)?.ok_or_else(|| {
        anyhow::anyhow!("couldn't resolve a profile path for {}", shell_name(shell))
    })?;

    let existing = std::fs::read_to_string(&profile).unwrap_or_default();
    if !existing.contains(MARKER_START) {
        println!(
            "No portty hook in {} - nothing to remove.",
            profile.display()
        );
        return Ok(());
    }
    std::fs::write(&profile, remove_marker_block(&existing))?;
    println!("Removed the portty portal hook from: {}", profile.display());
    Ok(())
}

/// Strip every `# >>> portty portal >>>` … `# <<< portty portal <<<` block,
/// including the trailing newline. Leaves the rest of the profile byte-for-byte.
fn remove_marker_block(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(s) = rest.find(MARKER_START) {
        out.push_str(&rest[..s]);
        let after_start = &rest[s..];
        match after_start.find(MARKER_END) {
            Some(e) => {
                let mut cut_to = s + e + MARKER_END.len();
                let bytes = rest.as_bytes();
                if cut_to < bytes.len() && bytes[cut_to] == b'\n' {
                    cut_to += 1; // swallow the line ending too
                }
                rest = &rest[cut_to..];
            }
            None => {
                // Unterminated block - drop to end (best effort).
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Pull `--shell <name>` out of the arg list.
fn shell_arg(rest: &[String]) -> Option<Shell> {
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--shell" {
            return rest.get(i + 1).and_then(|s| parse_shell(s));
        }
        i += 1;
    }
    None
}

/// Best-effort shell detection: `$SHELL` on Unix, PowerShell on Windows.
fn detect_shell() -> Option<Shell> {
    #[cfg(windows)]
    {
        let _ = which("pwsh.exe").or_else(|| which("pwsh"));
        Some(Shell::PowerShell)
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL").ok().and_then(|s| {
            if s.contains("zsh") {
                Some(Shell::Zsh)
            } else if s.contains("bash") {
                Some(Shell::Bash)
            } else {
                None
            }
        })
    }
}

/// The profile file a shell sources at interactive startup.
fn profile_path(shell: Shell) -> anyhow::Result<Option<PathBuf>> {
    let home = home_dir()?;
    Ok(Some(match shell {
        Shell::PowerShell => powershell_profile(&home)?,
        Shell::Bash => home.join(".bashrc"),
        Shell::Zsh => home.join(".zshrc"),
    }))
}

fn home_dir() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("USERPROFILE is not set"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))
    }
}

/// Prefer the PowerShell 7 profile (`Documents\PowerShell`); fall back to
/// Windows PowerShell 5.1 (`Documents\WindowsPowerShell`) when pwsh is absent.
fn powershell_profile(home: &Path) -> anyhow::Result<PathBuf> {
    let docs = home.join("Documents");
    let ps7 = docs
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    let ps5 = docs
        .join("WindowsPowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    let pwsh_present = which("pwsh.exe").or_else(|| which("pwsh")).is_some();
    Ok(if pwsh_present || ps7.exists() {
        ps7
    } else {
        ps5
    })
}

/// Wire the daemon pipe: forward relay→host messages out (Register first, then
/// output/exited), and apply inbound host→relay control to the PTY.
#[allow(clippy::too_many_arguments)]
fn spawn_ipc<R, W>(
    mut rd: R,
    mut wr: W,
    mut to_host_rx: mpsc::Receiver<RelayToHost>,
    title: String,
    cols: u16,
    rows: u16,
    writer: SharedWriter,
    child: SharedChild,
    done: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Outbound: Register, then stream output frames.
    let outbound = tokio::spawn(async move {
        let reg = RelayToHost::Register { title, cols, rows };
        if let Ok(bytes) = postcard::to_allocvec(&reg) {
            if write_framed(&mut wr, &bytes).await.is_err() {
                return;
            }
        }
        while let Some(msg) = to_host_rx.recv().await {
            let exited = matches!(&msg, RelayToHost::Exited);
            let Ok(bytes) = postcard::to_allocvec(&msg) else {
                continue;
            };
            if write_framed(&mut wr, &bytes).await.is_err() {
                break;
            }
            if exited {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // Inbound: viewer control from the daemon → apply to the PTY.
    tokio::spawn(async move {
        loop {
            let frame = match read_framed(&mut rd).await {
                Ok(f) => f,
                Err(_) => break, // pipe closed
            };
            match postcard::from_bytes::<HostToRelay>(&frame) {
                Ok(HostToRelay::Input(b)) => {
                    if let Ok(mut w) = writer.lock() {
                        let _ = w.write_all(&b);
                        let _ = w.flush();
                    }
                }
                // Fixed-size model: THIS terminal is the sole size owner -
                // viewer-driven resizes and the retired follow-the-typist
                // hand-off are ignored (only legacy daemons send them).
                Ok(HostToRelay::Resize { .. }) => {}
                Ok(HostToRelay::RestoreLocalSize) => {}
                // Only ever sent in reply to `portty pair`'s ReopenPairing;
                // a registered share relay should never receive it - ignore.
                Ok(HostToRelay::PairingInfo { .. }) => {}
                // Only meaningful on a `portty pair` console connection. A share
                // relay cannot answer it, and ignoring it means no approval is
                // sent - so the host denies the pairing, which is correct.
                Ok(HostToRelay::PairingConfirmRequest { .. }) => {}
                // Only ever a reply to a readiness `Ping`, which a share relay
                // never sends.
                Ok(HostToRelay::Pong) => {}
                // Agent-chat messages only flow on `portty agent` connections;
                // a registered share relay should never receive them - ignore.
                Ok(
                    HostToRelay::AgentOpened { .. }
                    | HostToRelay::AgentEvent { .. }
                    | HostToRelay::AgentPermission { .. }
                    | HostToRelay::AgentPermissionResolved { .. }
                    | HostToRelay::AgentGone { .. }
                    | HostToRelay::AgentError { .. }
                    | HostToRelay::RevocationResult { .. }
                    | HostToRelay::ShutdownAccepted,
                ) => {}
                Ok(HostToRelay::Kill) => {
                    if let Ok(mut c) = child.lock() {
                        let _ = c.kill();
                    }
                    done.store(true, Ordering::Relaxed);
                    break;
                }
                Err(_) => continue,
            }
        }
    });
    outbound
}

async fn read_framed<R: AsyncRead + Unpin>(rd: &mut R) -> std::io::Result<Vec<u8>> {
    let len = rd.read_u32_le().await?;
    if len > MAX_RELAY_FRAME_BYTES {
        return Err(std::io::Error::other("relay frame too large"));
    }
    let mut buf = vec![0u8; len as usize];
    rd.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed<W: AsyncWrite + Unpin>(wr: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_RELAY_FRAME_BYTES as usize {
        return Err(std::io::Error::other("relay frame too large"));
    }
    wr.write_u32_le(bytes.len() as u32).await?;
    wr.write_all(bytes).await?;
    wr.flush().await?;
    Ok(())
}

/// Copy a terminal input stream without interpreting any VT sequence.
///
/// The callback boundary keeps the PTY writer lock short so phone input can
/// share that writer. It also makes the load-bearing byte-preservation rule
/// directly testable without a real terminal.
fn pump_raw_input<R, F>(mut input: R, mut forward: F) -> std::io::Result<()>
where
    R: Read,
    F: FnMut(&[u8]) -> std::io::Result<()>,
{
    let mut buf = [0u8; 4096];
    loop {
        match input.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => forward(&buf[..n])?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn forward_local_input(writer: SharedWriter, mode: LocalInputMode) {
    match mode {
        LocalInputMode::RawBytes => {
            let stdin = std::io::stdin();
            let _ = pump_raw_input(stdin, |bytes| {
                let mut writer = writer
                    .lock()
                    .map_err(|_| std::io::Error::other("PTY writer lock poisoned"))?;
                writer.write_all(bytes)?;
                writer.flush()
            });
        }
        #[cfg(windows)]
        LocalInputMode::ConsoleEvents => loop {
            let Ok(event) = crossterm::event::read() else {
                continue;
            };
            let Some(bytes) = key_event_to_bytes(&event) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let Ok(mut writer) = writer.lock() else {
                break;
            };
            if writer.write_all(&bytes).is_err() || writer.flush().is_err() {
                break;
            }
        },
    }
}

/// Saved Windows console input state. Modern consoles can expose their native
/// VT byte stream through `ReadFile`; preserving that stream is what makes a
/// nested full-screen TUI protocol-transparent. The original mode is restored
/// exactly when the share exits.
#[cfg(windows)]
struct WindowsConsoleInput {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original_mode: u32,
}

#[cfg(windows)]
impl WindowsConsoleInput {
    fn capture() -> Option<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};

        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut original_mode = 0;
        if unsafe { GetConsoleMode(handle, &mut original_mode) } == 0 {
            return None;
        }
        Some(Self {
            handle,
            original_mode,
        })
    }

    fn enable_vt(&self) -> bool {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_INPUT,
        };

        let mut raw_mode = 0;
        if unsafe { GetConsoleMode(self.handle, &mut raw_mode) } == 0 {
            return false;
        }
        unsafe { SetConsoleMode(self.handle, raw_mode | ENABLE_VIRTUAL_TERMINAL_INPUT) != 0 }
    }

    fn restore(&self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;

        let _ = unsafe { SetConsoleMode(self.handle, self.original_mode) };
    }
}

/// Forward only key press/repeat; Windows reports a Release for every key too,
/// which would double-type if forwarded. Returns None to skip the event, or
/// `Some(empty)` for events we intentionally drop (unused media/modifier keys).
#[cfg(any(windows, test))]
fn key_event_to_bytes(ev: &crossterm::event::Event) -> Option<Vec<u8>> {
    use crossterm::event::{Event, KeyEventKind};
    match ev {
        Event::Key(k) => {
            if !matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                return None;
            }
            Some(encode_key(k))
        }
        // A paste arrives as ONE Paste event, not keystrokes: the inner app
        // enabled bracketed paste (passed through to the outer terminal), so
        // the outer terminal brackets pasted text and crossterm parses it into
        // Event::Paste. The old Key-only path silently swallowed every paste.
        // Re-wrap in the markers the inner app expects (it asked for them) and
        // normalize \n→\r, matching what terminals send for pasted newlines.
        Event::Paste(s) => {
            let body = s.replace('\n', "\r");
            let mut bytes = Vec::with_capacity(body.len() + 12);
            bytes.extend_from_slice(b"\x1b[200~");
            bytes.extend_from_slice(body.as_bytes());
            bytes.extend_from_slice(b"\x1b[201~");
            Some(bytes)
        }
        _ => None,
    }
}

/// Encode a key event as the exact bytes a PTY shell expects: ANSI sequences for
/// special keys, control bytes for Ctrl+letter, raw UTF-8 for printable chars.
#[cfg(any(windows, test))]
fn encode_key(k: &crossterm::event::KeyEvent) -> Vec<u8> {
    use crossterm::event::{KeyCode, KeyModifiers};
    match k.code {
        KeyCode::Char(c) => {
            if k.modifiers.contains(KeyModifiers::CONTROL) {
                if let Some(b) = ctrl_byte(c) {
                    return vec![b];
                }
            }
            let mut buf = c.to_string().into_bytes();
            // Alt is encoded as an ESC prefix, matching real terminals.
            if k.modifiers.contains(KeyModifiers::ALT) {
                let mut prefixed = Vec::with_capacity(buf.len() + 1);
                prefixed.push(0x1b);
                prefixed.extend_from_slice(&buf);
                buf = prefixed;
            }
            buf
        }
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => b"\x7f".to_vec(),
        KeyCode::Esc => b"\x1b".to_vec(),
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Null => Vec::new(),
        KeyCode::F(n) => f_key_bytes(n),
        _ => Vec::new(),
    }
}

/// Control byte for Ctrl+letter (and a few symbols), matching a real tty.
#[cfg(any(windows, test))]
fn ctrl_byte(c: char) -> Option<u8> {
    Some(match c {
        '@' | ' ' | '`' => 0x00,
        'a'..='z' => c as u8 - b'a' + 1,
        'A'..='Z' => c as u8 - b'A' + 1,
        '[' => 0x1b,
        '\\' => 0x1c,
        ']' => 0x1d,
        '^' => 0x1e,
        '_' => 0x1f,
        _ => return None,
    })
}

/// xterm-style F-key sequences (F1–F4 use SS3, F5–F12 use CSI~). Good enough for
/// a local terminal mirror; the phone path is unaffected.
#[cfg(any(windows, test))]
fn f_key_bytes(f: u8) -> Vec<u8> {
    match f {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        5 => b"\x1b[15~".to_vec(),
        6 => b"\x1b[17~".to_vec(),
        7 => b"\x1b[18~".to_vec(),
        8 => b"\x1b[19~".to_vec(),
        9 => b"\x1b[20~".to_vec(),
        10 => b"\x1b[21~".to_vec(),
        11 => b"\x1b[23~".to_vec(),
        12 => b"\x1b[24~".to_vec(),
        _ => Vec::new(),
    }
}

/// Restores the terminal's cooked mode when dropped - including on panic, so we
/// never leave the user's shell stuck in raw mode.
struct RawGuard {
    #[cfg(windows)]
    windows_input: Option<WindowsConsoleInput>,
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        use std::io::Write;
        // A shared TUI app (vim, htop, Claude Code, a full-screen phone view …)
        // can enable mouse/focus reporting, bracketed paste, Kitty keyboard
        // enhancements, or hide the cursor via the mirrored PTY stream - those
        // enable sequences reach THIS terminal too. If the session ends while
        // the app is still in that mode (user typed `exit`, phone disconnected,
        // app didn't clean up), reset them before restoring cooked mode. We
        // intentionally do NOT touch the alternate screen (`?1049`) so we never
        // wipe scrollback the user may want to keep.
        let mut out = std::io::stdout();
        let _ = out.write_all(
            b"\x1b[<1u\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[?25h",
        );
        let _ = out.flush();
        let _ = crossterm::terminal::disable_raw_mode();
        #[cfg(windows)]
        if let Some(input) = &self.windows_input {
            input.restore();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    #[test]
    fn raw_input_preserves_modern_tui_protocol_bytes_exactly() {
        // Kitty keyboard press/repeat/release, a keyboard-capability reply,
        // cursor-position reply, focus/mouse events, and bracketed paste. These
        // used to be decoded, downgraded, or silently dropped by Event::read.
        let input = b"\x1b[97;1:1u\x1b[97;1:2u\x1b[97;1:3u\x1b[?15u\x1b[12;40R\x1b[I\x1b[<0;4;2M\x1b[200~hello\x1b[201~";
        let mut output = Vec::new();

        pump_raw_input(std::io::Cursor::new(input), |bytes| {
            output.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();

        assert_eq!(output, input);
    }

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    #[test]
    fn ctrl_letter_is_control_byte() {
        assert_eq!(
            encode_key(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            vec![0x03]
        );
        assert_eq!(
            encode_key(&key(KeyCode::Char('a'), KeyModifiers::CONTROL)),
            vec![0x01]
        );
        assert_eq!(
            encode_key(&key(KeyCode::Char('z'), KeyModifiers::CONTROL)),
            vec![0x1a]
        );
    }

    #[test]
    fn printable_char_is_utf8() {
        assert_eq!(
            encode_key(&key(KeyCode::Char('x'), KeyModifiers::NONE)),
            b"x"
        );
        // Multi-byte char round-trips as UTF-8, not mangled.
        assert_eq!(
            encode_key(&key(KeyCode::Char('€'), KeyModifiers::NONE)),
            "€".as_bytes()
        );
    }

    #[test]
    fn special_keys_emit_ansi() {
        assert_eq!(
            encode_key(&key(KeyCode::Left, KeyModifiers::NONE)),
            b"\x1b[D"
        );
        assert_eq!(encode_key(&key(KeyCode::Up, KeyModifiers::NONE)), b"\x1b[A");
        assert_eq!(encode_key(&key(KeyCode::Enter, KeyModifiers::NONE)), b"\r");
        assert_eq!(
            encode_key(&key(KeyCode::Backspace, KeyModifiers::NONE)),
            b"\x7f"
        );
        assert_eq!(encode_key(&key(KeyCode::Tab, KeyModifiers::NONE)), b"\t");
        assert_eq!(
            encode_key(&key(KeyCode::F(5), KeyModifiers::NONE)),
            b"\x1b[15~"
        );
    }

    #[test]
    fn alt_prefixes_esc() {
        let k = encode_key(&key(KeyCode::Char('b'), KeyModifiers::ALT));
        assert_eq!(k, b"\x1bb");
    }

    #[test]
    fn release_events_are_dropped() {
        let mut k = key(KeyCode::Char('a'), KeyModifiers::NONE);
        k.kind = KeyEventKind::Release;
        assert_eq!(key_event_to_bytes(&crossterm::event::Event::Key(k)), None);
    }

    #[test]
    fn init_snippets_have_guard_and_markers() {
        for sh in [Shell::PowerShell, Shell::Bash, Shell::Zsh] {
            let s = init_snippet(sh);
            assert!(
                s.contains(">>> portty portal >>>"),
                "{sh:?} missing start marker"
            );
            assert!(
                s.contains("<<< portty portal <<<"),
                "{sh:?} missing end marker"
            );
            assert!(s.contains("PORTTY_RELAY"), "{sh:?} missing recursion guard");
        }
    }

    #[test]
    fn powershell_snippet_calls_share() {
        let s = init_snippet(Shell::PowerShell);
        assert!(s.contains("portty share"));
        assert!(s.contains("Get-Command portty")); // skips when not on PATH
    }

    #[test]
    fn bash_snippet_is_interactive_only_and_execs() {
        let s = init_snippet(Shell::Bash);
        assert!(s.contains("exec portty share"));
        assert!(s.contains("$- == *i*")); // interactive-only guard
    }

    #[test]
    fn remove_marker_block_strips_only_the_block() {
        let before = "alias x=y\n\
                      # >>> portty portal >>>\n\
                      if ...; then stuff; fi\n\
                      # <<< portty portal <<<\n\
                      export FOO=bar\n";
        let after = remove_marker_block(before);
        assert!(!after.contains("portty portal"));
        assert!(!after.contains("if ..."));
        assert!(after.contains("alias x=y"));
        assert!(after.contains("export FOO=bar"));
        // Surrounding lines survive intact (no double blank line, no lost line).
        assert_eq!(after, "alias x=y\nexport FOO=bar\n");
    }

    #[test]
    fn remove_marker_block_idempotent_when_absent() {
        let s = "nothing to see here\n";
        assert_eq!(remove_marker_block(s), s);
    }

    #[test]
    fn agent_local_controls_are_not_forwarded_as_prompts() {
        assert!(matches!(
            parse_agent_input("/mode plan", &[]).unwrap(),
            AgentInput::Send(RelayToHost::AgentSetMode { mode_id }) if mode_id == "plan"
        ));
        assert!(matches!(
            parse_agent_input("/model gpt-5", &[]).unwrap(),
            AgentInput::Send(RelayToHost::AgentSetModel { model_id }) if model_id == "gpt-5"
        ));
        assert!(matches!(
            parse_agent_input("/config thinking on", &[]).unwrap(),
            AgentInput::Send(RelayToHost::AgentSetConfig {
                config_id,
                value: AgentConfigValue::Boolean(true),
            }) if config_id == "thinking"
        ));
        assert!(matches!(
            parse_agent_input("/auth browser", &[]).unwrap(),
            AgentInput::Send(RelayToHost::AgentAuthenticate { method_id })
                if method_id == "browser"
        ));
        assert!(parse_agent_input("/mode", &[]).is_err());
        assert!(matches!(
            parse_agent_input("/compact", &[]).unwrap(),
            AgentInput::Send(RelayToHost::AgentPrompt { text }) if text == "/compact"
        ));
    }

    /// Agent text reaches the terminal emulator verbatim, so the sequences that
    /// would let a model repaint the screen, forge a prompt, or write the
    /// clipboard must not survive into `println!`.
    #[test]
    fn terminal_control_sequences_are_stripped_from_agent_text() {
        // Screen clear + cursor home, then a forged shell prompt.
        assert_eq!(
            safe("\u{1b}[2J\u{1b}[Huser@host:~$ rm -rf /"),
            "[2J[Huser@host:~$ rm -rf /"
        );
        // OSC 52 clipboard write (BEL-terminated) and a window retitle.
        assert_eq!(
            safe("\u{1b}]52;c;cGF5bG9hZA==\u{7}x"),
            "]52;c;cGF5bG9hZA==x"
        );
        // The ESC of the ST terminator goes; its trailing backslash is inert text.
        assert_eq!(safe("\u{1b}]0;trusted\u{1b}\\y"), "]0;trusted\\y");
        // A bare CR would rewrite the line the user already read.
        assert_eq!(safe("safe text\rmalicious"), "safe textmalicious");
        // 8-bit C1 CSI is the same attack without ESC.
        assert_eq!(safe("\u{9b}31m"), "31m");
        // Real structure survives.
        assert_eq!(safe("line one\nline two\tcol"), "line one\nline two\tcol");
        assert_eq!(safe("héllo ✓ 日本語"), "héllo ✓ 日本語");
    }

    /// Bidi overrides let an approval line read as the opposite of what runs.
    #[test]
    fn bidi_overrides_are_stripped_from_agent_text() {
        for mark in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{61c}',
        ] {
            let spoofed = format!("rm {mark}txt.pdf");
            assert_eq!(
                safe(&spoofed),
                "rm txt.pdf",
                "U+{:04X} survived",
                mark as u32
            );
        }
    }
}
