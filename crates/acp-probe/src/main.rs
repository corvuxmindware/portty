//! acp-probe - Portty Phase 1 ACP stdio proof.
//!
//! Spawns an ACP agent over stdio, initializes it, creates a session, sends a
//! prompt that should trigger a tool call, and **logs every
//! `session/request_permission`** the agent emits. It answers `Cancelled` by
//! default. Explicit `--decision=allow` / `--decision=reject` modes select the
//! matching one-shot option so release testing can cover the complete contract.
//!
//! This is the code-level confirmation of the research spike in
//! `Portty/09 - ACP Validation Spike Results`: can the Portty host, acting as
//! an ACP *client*, intercept an agent's approval prompt over stdio using the
//! official Rust SDK? If this prints "CAPTURED a session/request_permission",
//! the answer is yes → Phases 2–5 of the ceiling build plan are go.
//!
//! # Usage
//! ```text
//!   acp-probe [--decision=cancel|allow|reject] <agent-spec> [prompt]
//!
//!   agent-spec:
//!     gemini   -> AcpAgent::google_gemini()        (native; needs `gemini` CLI + auth)
//!     claude   -> AcpAgent::claude_agent()          (adapter; needs node + Anthropic auth)
//!     codex    -> AcpAgent::codex()                 (adapter; default; needs OpenAI auth)
//!     <cmd>    -> any "command args" run as a stdio ACP agent
//! ```
//!
//! # Headless auth (the real friction - see spike risk #2)
//! The chosen agent must already be authenticated in this shell's environment,
//! because the probe spawns the agent as a subprocess that inherits env + cwd:
//!   - codex-acp : set `CODEX_API_KEY` (or `OPENAI_API_KEY`) and `NO_BROWSER=1`
//!   - claude    : set `ANTHROPIC_API_KEY`
//!
//! The probe itself does no auth - it relies on inherited creds. If you see
//! "No session/request_permission observed", that almost always means the agent
//! needed auth it didn't have, or auto-approved without asking.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use acp::schema::v1::{
    InitializeRequest, PermissionOptionKind, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, SelectedPermissionOutcome, SessionNotification,
};
use acp::schema::ProtocolVersion;
use agent_client_protocol as acp;
use agent_client_protocol::AcpAgent;
use anyhow::{anyhow, Result};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeDecision {
    Cancel,
    Allow,
    Reject,
}

impl ProbeDecision {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "cancel" => Ok(Self::Cancel),
            "allow" => Ok(Self::Allow),
            "reject" => Ok(Self::Reject),
            _ => Err(anyhow!(
                "unknown decision `{value}` (expected cancel, allow, or reject)"
            )),
        }
    }
}

fn permission_outcome(
    request: &RequestPermissionRequest,
    decision: ProbeDecision,
) -> (RequestPermissionOutcome, bool) {
    let wanted = match decision {
        ProbeDecision::Cancel => return (RequestPermissionOutcome::Cancelled, true),
        ProbeDecision::Allow => PermissionOptionKind::AllowOnce,
        ProbeDecision::Reject => PermissionOptionKind::RejectOnce,
    };
    match request.options.iter().find(|option| option.kind == wanted) {
        Some(option) => (
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                option.option_id.clone(),
            )),
            true,
        ),
        None => (RequestPermissionOutcome::Cancelled, false),
    }
}

fn parse_args(args: Vec<String>) -> Result<(ProbeDecision, String, String)> {
    let mut decision = ProbeDecision::Cancel;
    let mut positional = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--decision=") {
            decision = ProbeDecision::parse(value)?;
        } else if arg == "--decision" {
            decision = ProbeDecision::parse(
                &args
                    .next()
                    .ok_or_else(|| anyhow!("--decision requires a value"))?,
            )?;
        } else {
            positional.push(arg);
        }
    }
    if positional.len() > 2 {
        return Err(anyhow!(
            "too many arguments (usage: acp-probe [--decision=cancel|allow|reject] <agent-spec> [prompt])"
        ));
    }
    let spec = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "codex".to_string());
    let prompt = positional.get(1).cloned().unwrap_or_else(|| {
        "Create a file named acp_probe_test.txt containing the text 'hello', then stop.".to_string()
    });
    Ok((decision, spec, prompt))
}

#[tokio::main]
async fn main() -> Result<()> {
    let (decision, spec, prompt) = parse_args(std::env::args().skip(1).collect())?;
    if decision == ProbeDecision::Allow {
        eprintln!(
            "WARNING: --decision=allow executes provider-requested actions. Run only in a disposable directory."
        );
    }

    // Build the stdio transport: spawn the agent as a subprocess. Presets handle
    // the two headliners; anything else is parsed as a raw command string.
    let agent = match spec.as_str() {
        // `AcpAgent::google_gemini()` was removed in agent-client-protocol 2.0,
        // which keeps only the claude and codex presets. Inlined verbatim from
        // what that preset expanded to, so this spike still probes all three.
        "gemini" => AcpAgent::from_str("npx -y -- @google/gemini-cli@latest --experimental-acp")?,
        "claude" => AcpAgent::claude_agent(),
        "codex" => AcpAgent::codex(),
        other => AcpAgent::from_str(other)?,
    }
    // Echo every wire line to stderr so the raw JSON-RPC is visible. This is the
    // "is the payload uniform?" part of the spike - you can see request_permission
    // arrive as standard ACP regardless of which agent is behind it.
    .with_debug(|line, _direction| {
        eprintln!("[wire] {line}");
    });

    // Shared state between the request_permission handler and main.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let perm_count = Arc::new(AtomicUsize::new(0));
    let unsatisfied_count = Arc::new(AtomicUsize::new(0));

    let cap_for_handler = captured.clone();
    let cnt_for_handler = perm_count.clone();
    let unsatisfied_for_handler = unsatisfied_count.clone();

    acp::Client
        .builder()
        .name("portty-acp-probe")
        // The make-or-break handler: the agent calls session/request_permission
        // (a server→client request); we intercept, log it, and exercise the
        // requested cancellation/one-shot allow/one-shot reject contract.
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, _cx| {
                let n = cnt_for_handler.fetch_add(1, Ordering::SeqCst) + 1;
                let pretty = format!("{:#?}", req);
                println!("\n=== session/request_permission #{n} ===\n{pretty}\n");
                *cap_for_handler.lock().await = Some(pretty);
                let (outcome, satisfied) = permission_outcome(&req, decision);
                if !satisfied {
                    unsatisfied_for_handler.fetch_add(1, Ordering::SeqCst);
                    println!(
                        "=== requested {decision:?}, but provider offered no matching option; responding: Cancelled ===\n"
                    );
                } else {
                    println!("=== responding for requested decision: {decision:?} ===\n");
                }
                responder.respond(RequestPermissionResponse::new(outcome))
            },
            acp::on_receive_request!(),
        )
        // Stream session/update notifications so we can watch the agent work.
        .on_receive_notification(
            async move |notification: SessionNotification, _cx| {
                println!("--- session/update: {:?} ---", notification.update);
                Ok(())
            },
            acp::on_receive_notification!(),
        )
        .connect_with(agent, async |cx: acp::ConnectionTo<acp::Agent>| {
            println!(">> initialize (ACP v1)");
            cx.send_request(InitializeRequest::new(ProtocolVersion::V1))
                .block_task()
                .await?;

            println!(">> session/new (cwd = current) + session/prompt");
            let mut session = cx.build_session_cwd()?.block_task().start_session().await?;
            session.send_prompt(&prompt)?;
            let final_output = session.read_to_string().await?;
            println!("\n>> agent final turn output:\n{final_output}");
            Ok(())
        })
        .await?;

    // ---- proof verdict ----
    println!("\n================= PROOF SUMMARY =================");
    let total = perm_count.load(Ordering::SeqCst);
    let unsatisfied = unsatisfied_count.load(Ordering::SeqCst);
    match captured.lock().await.take() {
        Some(_req) => {
            println!("CAPTURED a session/request_permission ({total} total).");
            println!("Requested decision mode: {decision:?} ({unsatisfied} unmatched request(s)).");
            println!("Verdict: the provider exposed the ACP permission contract over stdio.");
        }
        None => {
            println!("No session/request_permission observed ({total} total).");
            println!("Likely cause: agent auto-approved (no prompt) OR needed auth it");
            println!("didn't have. Check the [wire] stderr lines above. Not a protocol");
            println!("failure - re-run with creds set (see module docs).");
        }
    }
    // Non-zero exit when nothing was captured, so CI/scripts can tell.
    if total == 0 {
        return Err(anyhow!("no permission request was observed"));
    }
    if unsatisfied > 0 {
        return Err(anyhow!(
            "{unsatisfied} permission request(s) offered no option matching {decision:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp::schema::v1::{PermissionOption, ToolCallUpdate};

    fn request() -> RequestPermissionRequest {
        RequestPermissionRequest::new(
            "session-1",
            ToolCallUpdate::new("tool-1", Default::default()),
            vec![
                PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
                PermissionOption::new(
                    "reject-once",
                    "Reject once",
                    PermissionOptionKind::RejectOnce,
                ),
            ],
        )
    }

    #[test]
    fn allow_and_reject_select_matching_one_shot_options() {
        let request = request();
        let (allow, matched) = permission_outcome(&request, ProbeDecision::Allow);
        assert!(matched);
        assert!(
            matches!(allow, RequestPermissionOutcome::Selected(selected) if selected.option_id.to_string() == "allow-once")
        );

        let (reject, matched) = permission_outcome(&request, ProbeDecision::Reject);
        assert!(matched);
        assert!(
            matches!(reject, RequestPermissionOutcome::Selected(selected) if selected.option_id.to_string() == "reject-once")
        );
    }

    #[test]
    fn missing_requested_option_falls_back_to_cancel_and_fails_contract() {
        let request = RequestPermissionRequest::new(
            "session-1",
            ToolCallUpdate::new("tool-1", Default::default()),
            vec![PermissionOption::new(
                "reject-once",
                "Reject once",
                PermissionOptionKind::RejectOnce,
            )],
        );
        let (outcome, matched) = permission_outcome(&request, ProbeDecision::Allow);
        assert!(!matched);
        assert!(matches!(outcome, RequestPermissionOutcome::Cancelled));
    }

    #[test]
    fn decision_flag_can_precede_or_follow_provider() {
        let (decision, spec, prompt) = parse_args(vec![
            "--decision=reject".into(),
            "claude".into(),
            "test prompt".into(),
        ])
        .unwrap();
        assert_eq!(decision, ProbeDecision::Reject);
        assert_eq!(spec, "claude");
        assert_eq!(prompt, "test prompt");
    }
}
