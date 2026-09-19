#!/usr/bin/env python3
"""Mock ACP agent for the Portty acp-probe (Phase 1 deterministic proof).

Speaks just enough ACP over stdio (newline-delimited JSON-RPC 2.0) to exercise
the FULL interception loop without any real AI or authentication:

    probe -> initialize         -> mock responds {protocolVersion:1, agentCapabilities:{}}
    probe -> session/new        -> mock responds {sessionId:"sess-1"}
    probe -> session/prompt     -> mock sends session/request_permission (server->client),
                                   reads the probe's "cancelled" response,
                                   then ends the turn {stopReason:"end_turn"}

If the probe prints "CAPTURED a session/request_permission", the host-as-ACP-client
interception loop is proven end to end. No creds, no network, reproducible.

Run:
    cargo run -p acp-probe -- "python crates/acp-probe/mock_agent.py"
"""
import json
import os
import signal
import sys

PERM_ID = 9000  # server->client request id; must not collide with client ids (0,1,2,...)

# The line a session/load replays. The test asserts this reaches the timeline,
# which is the observable difference between load and resume.
REPLAYED_PROMPT = "a conversation this phone never started"


def send(obj):
    """Write one JSON-RPC message as a single LF-terminated line.

    os.write bypasses Python's text-mode CRLF translation and buffering, so the
    SDK's line reader gets clean LF frames on Windows too.
    """
    data = (json.dumps(obj) + "\n").encode("utf-8")
    os.write(sys.stdout.fileno(), data)


def request_permission():
    send(
        {
            "jsonrpc": "2.0",
            "id": PERM_ID,
            "method": "session/request_permission",
            "params": {
                "sessionId": "sess-1",
                # ToolCallUpdate: toolCallId is the only required field; the rest
                # of ToolCallUpdateFields is optional (omitted here on purpose).
                "toolCall": {
                    "toolCallId": "call-1",
                    "title": "Write acp_probe_test.txt",
                },
                "options": [
                    {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
                    {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
                ],
            },
        }
    )


def model_config(current):
    return {
        "id": "model",
        "name": "Model",
        "category": "model",
        "type": "select",
        "currentValue": current,
        "options": [
            {"value": "mock-fast", "name": "Mock Fast"},
            {"value": "mock-deep", "name": "Mock Deep"},
        ],
    }


def main():
    auth_required = "--auth" in sys.argv
    auth_on_prompt = "--auth-on-prompt" in sys.argv
    authenticated = not auth_required
    # --auth-on-prompt: session/new succeeds, but the FIRST session/prompt returns
    # AuthRequired until `authenticate` runs - exercises the host's mid-turn re-auth
    # retry (#45). Cleared by the authenticate handler.
    prompt_auth_pending = auth_on_prompt
    # --reopen-log=PATH turns on session/load + session/resume and records the
    # method the client tried FIRST.
    reopen_log = next(
        (arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--reopen-log=")),
        None,
    )
    reopen = reopen_log is not None
    reopen_seen = []
    signal_file = next(
        (arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--signal-file=")),
        None,
    )
    if signal_file:
        def record_sigterm(_signum, _frame):
            with open(signal_file, "w", encoding="utf-8") as marker:
                marker.write("sigterm")
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, record_sigterm)
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue

        # Server->client responses (e.g. our permission reply) have no "method".
        if "method" not in msg:
            continue

        mid = msg.get("id")  # None for notifications
        method = msg["method"]

        if method == "initialize":
            result = {"protocolVersion": 1, "agentCapabilities": {}}
            if reopen:
                # BOTH advertised, so the host has a real choice to get wrong.
                result["agentCapabilities"] = {
                    "loadSession": True,
                    "sessionCapabilities": {"resume": {}},
                }
            if auth_required or auth_on_prompt:
                result["authMethods"] = [
                    {
                        "id": "mock-login",
                        "name": "Mock login",
                        "description": "Deterministic test authentication",
                    }
                ]
            send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": result,
                }
            )
        elif method == "session/new":
            if not authenticated:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32000, "message": "authentication required"},
                    }
                )
                continue
            # Deliberately publish commands before session/new resolves. Clients
            # that install their reducer afterward lose this update.
            send(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "sess-1",
                        "update": {
                            "sessionUpdate": "available_commands_update",
                            "availableCommands": [
                                {
                                    "name": "review",
                                    "description": "Review the current changes",
                                    "input": {"hint": "focus"},
                                }
                            ],
                        },
                    },
                }
            )
            send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "sessionId": "sess-1",
                        "modes": {
                            "currentModeId": "default",
                            "availableModes": [
                                {"id": "default", "name": "Default"},
                                {"id": "plan", "name": "Plan"},
                            ],
                        },
                        "configOptions": [model_config("mock-fast")],
                    },
                }
            )
        # --reopen: the two ways to continue an existing conversation. They differ
        # in exactly one respect that matters to a phone - session/load REPLAYS
        # the transcript as session/update notifications, session/resume does not
        # - so the mock records which one the host reached for FIRST. A host that
        # resumes first leaves the phone with an empty timeline even though the
        # conversation is live, which is a defect no unit test can see.
        elif method in ("session/load", "session/resume") and reopen:
            if not reopen_seen:
                reopen_seen.append(method)
                with open(reopen_log, "w", encoding="utf-8") as marker:
                    marker.write(method)
            if method == "session/load":
                send(
                    {
                        "jsonrpc": "2.0",
                        "method": "session/update",
                        "params": {
                            "sessionId": msg.get("params", {}).get("sessionId", "sess-1"),
                            "update": {
                                "sessionUpdate": "user_message_chunk",
                                "content": {"type": "text", "text": REPLAYED_PROMPT},
                            },
                        },
                    }
                )
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "session/set_mode":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "authenticate":
            authenticated = True
            prompt_auth_pending = False
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "session/set_config_option":
            selected = msg.get("params", {}).get("value", "mock-fast")
            send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"configOptions": [model_config(selected)]},
                }
            )
        elif method == "session/prompt":
            if prompt_auth_pending:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32000, "message": "authentication required"},
                    }
                )
                continue
            prompt_text = "".join(
                block.get("text", "")
                for block in msg.get("params", {}).get("prompt", [])
                if block.get("type") == "text"
            )
            cancellation_case = "cancel" in prompt_text.lower()
            # 0) Forward-compat probe: a deliberately future session/update
            #    kind the client's ACP schema cannot know. The client must
            #    SKIP it rather than ending the connection. A normal chunk
            #    follows to prove known updates still flow afterwards.
            send(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "sess-1",
                        "update": {
                            "sessionUpdate": "portty_future_update",
                            "futureField": True,
                        },
                    },
                }
            )
            send(
                {
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {
                        "sessionId": "sess-1",
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "content": {"type": "text", "text": "still alive"},
                        },
                    },
                }
            )
            # 1) Ask the client (probe) for permission - the interception point.
            request_permission()
            # 2) Read the client's permission response. In the cancellation
            #    case, also require session/cancel after that response; this
            #    proves the client clears approvals before notifying cancel.
            permission_resolved = False
            cancel_received = False
            for resp_raw in sys.stdin:
                resp_line = resp_raw.strip()
                if not resp_line:
                    continue
                try:
                    resp = json.loads(resp_line)
                except Exception:
                    continue
                if resp.get("id") == PERM_ID:
                    sys.stderr.write("[mock] permission response: " + resp_line + "\n")
                    permission_resolved = True
                    if not cancellation_case:
                        break
                elif resp.get("method") == "session/cancel":
                    cancel_received = True
                if cancellation_case and permission_resolved and cancel_received:
                    break
            # 3) End the turn.
            stop_reason = "cancelled" if cancellation_case else "end_turn"
            send({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": stop_reason}})
            break
        else:
            # Unknown request -> method not found (only if it has an id).
            if mid is not None:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": "method not found"},
                    }
                )


if __name__ == "__main__":
    main()
