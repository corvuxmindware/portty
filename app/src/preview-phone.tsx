/* @refresh reload */
import { render } from "solid-js/web";
import { mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import App from "./App";
import { BiometricGate } from "./BiometricGate";
import type {
  AgentPermission,
  AgentTimelineEvent,
  SavedHost,
  SessionInfo,
} from "./lib/portty";

/**
 * Real-app fixture runner used only by preview-phone.html.
 *
 * This does not duplicate any product markup. It replaces Tauri IPC with a
 * deterministic in-browser host, then drives the same buttons a person would
 * tap. The result is the actual App/AgentView/KeyBar/xterm tree with production
 * CSS, fonts and icons, but without a Rust daemon or a paired phone.
 */

import { pendingApprovalMessage } from "./lib/notify";

const params = new URLSearchParams(window.location.search);
const scenario = params.get("scenario") ?? "home-connected";
const device = params.get("device") ?? "iphone-16-pro";
document.body.dataset.device = device;

const HOST_ID = "7f".repeat(32);
const OTHER_HOST_ID = "3a".repeat(32);
const AGENT_ID = 2;
const SECOND_AGENT_ID = 4;
const SHELL_ID = 1;

/* Keep preview interactions out of the real localhost app's storage. The
 * fixture uses a host id that can never be reached by the daemon, but the
 * biometric preference is global; proxying these keys in this iframe avoids a
 * preview click changing what the developer's real app does on next launch. */
const fixtureStorage = new Map<string, string>([["portty.biometric.enabled", "1"]]);
const storageGet = Storage.prototype.getItem;
const storageSet = Storage.prototype.setItem;
const storageRemove = Storage.prototype.removeItem;
const isFixtureKey = (key: string) =>
  key === "portty.biometric.enabled" || key.includes(HOST_ID) || key.includes(OTHER_HOST_ID);
Storage.prototype.getItem = function getPreviewItem(key: string): string | null {
  return isFixtureKey(key) ? (fixtureStorage.get(key) ?? null) : storageGet.call(this, key);
};
Storage.prototype.setItem = function setPreviewItem(key: string, value: string): void {
  if (isFixtureKey(key)) fixtureStorage.set(key, value);
  else storageSet.call(this, key, value);
};
Storage.prototype.removeItem = function removePreviewItem(key: string): void {
  if (isFixtureKey(key)) fixtureStorage.delete(key);
  else storageRemove.call(this, key);
};

const sessions: SessionInfo[] = [
  {
    id: SHELL_ID,
    title: "project-portty",
    kind: "shell",
    source: "spawned",
    has_activity: true,
  },
  {
    id: AGENT_ID,
    title: "Release hardening",
    kind: "agent",
    source: "spawned",
    has_activity: false,
  },
  {
    id: 3,
    title: "home-server logs",
    kind: "shell",
    source: "adopted",
    has_activity: false,
  },
  /* A second agent exists so "several approvals waiting" can be shown as it
     really happens - across DIFFERENT sessions, which is what makes the
     per-session dot carry information the header count cannot. */
  {
    id: SECOND_AGENT_ID,
    title: "Docs pass",
    kind: "agent",
    source: "spawned",
    has_activity: false,
  },
];

// The connected machine carries a default folder and the other does not, so both
// states of the picker's top row and the switcher's setting row are reachable
// from one fixture.
const savedHosts: SavedHost[] = [
  {
    id: HOST_ID,
    name: "Example MacBook",
    announced_name: "example-macbook",
    is_renamed: true,
    is_last: true,
    default_dir: "crates/host",
    default_root: "workspace",
  },
  {
    id: OTHER_HOST_ID,
    name: "Home server",
    announced_name: "portty-home",
    is_renamed: true,
    is_last: false,
    default_dir: null,
    default_root: null,
  },
];

const disconnectedAtBoot = new Set([
  "home-disconnected",
  "pair",
  "pair-node-id",
  "pair-confirm",
]);

const emptySessionScenarios = new Set([
  "home-empty",
  "home-disconnected",
  "pair",
  "pair-node-id",
  "pair-confirm",
]);

type OutputChannel = { onmessage: (message: ArrayBuffer) => void };
let channel: OutputChannel | null = null;
let reconnectCalls = 0;
let emittedList = false;

const later = (work: () => void, delay = 25) => window.setTimeout(work, delay);
const emitEvent = (event: string, payload: unknown, delay = 0) => {
  later(() => void emit(event, payload), delay);
};

/* Four agents in a row, so the waiting treatment can be judged at its WORST
   case rather than its best. Two separated amber cards always look fine; the
   real question is whether an 18px outer glow on adjacent cards bleeds into a
   single wash where nothing stands out. */
const crowdedSessions: SessionInfo[] = [
  { id: 11, title: "Release hardening", kind: "agent", source: "spawned", has_activity: false },
  { id: 12, title: "Docs pass", kind: "agent", source: "spawned", has_activity: false },
  { id: 13, title: "Dependency audit", kind: "agent", source: "spawned", has_activity: false },
  { id: 14, title: "Flaky test hunt", kind: "agent", source: "spawned", has_activity: false },
  { id: SHELL_ID, title: "project-portty", kind: "shell", source: "spawned", has_activity: true },
];

function currentSessions(): SessionInfo[] {
  if (emptySessionScenarios.has(scenario)) return [];
  return scenario === "home-approvals-crowded" ? crowdedSessions : sessions;
}

function sendSessionList(delay = 35): void {
  emittedList = true;
  emitEvent("portty://list", currentSessions(), delay);
}

function framed(kind: number, id: number, payload: Uint8Array = new Uint8Array()): ArrayBuffer {
  const bytes = new Uint8Array(9 + payload.byteLength);
  bytes[0] = kind;
  const view = new DataView(bytes.buffer);
  view.setBigUint64(1, BigInt(id), true);
  bytes.set(payload, 9);
  return bytes.buffer;
}

function sizeFrame(id: number, cols: number, rows: number): ArrayBuffer {
  const bytes = new Uint8Array(13);
  bytes[0] = 2;
  const view = new DataView(bytes.buffer);
  view.setBigUint64(1, BigInt(id), true);
  view.setUint16(9, cols, true);
  view.setUint16(11, rows, true);
  return bytes.buffer;
}

function terminalText(fullScreen: boolean): string {
  if (fullScreen) {
    return [
      "\u001b[?1049h\u001b[2J\u001b[H",
      "\u001b[1;32m Portty workspace status \u001b[0m\r\n",
      "\r\n",
      "  Branch       main\r\n",
      "  Tests        278 passed\r\n",
      "  Transport    connected via direct path\r\n",
      "  Agent        waiting for input\r\n",
      "\r\n",
      "  ↑/↓ move   enter open   q quit",
    ].join("");
  }
  return [
    "\u001b[38;2;163;230;53m➜  project-portty\u001b[0m git status\r\n",
    "On branch main\r\n",
    "Changes not staged for commit:\r\n",
    "  modified:   app/src/styles.css\r\n",
    "\r\n",
    "\u001b[38;2;163;230;53m➜  project-portty\u001b[0m cargo test --workspace\r\n",
    "\u001b[38;2;130;130;140m   Compiling portty-host v0.1.2\u001b[0m\r\n",
    "\u001b[38;2;130;130;140m    Finished test profile in 12.4s\u001b[0m\r\n",
    "\u001b[38;2;163;230;53mtest result: ok. 278 passed; 0 failed\u001b[0m\r\n",
    "\r\n",
    "\u001b[38;2;163;230;53m➜  project-portty\u001b[0m ",
  ].join("");
}

function streamTerminal(id: number): void {
  if (!channel || scenario === "terminal-attaching") return;
  const fullScreen = scenario === "terminal-full-screen";
  channel.onmessage(framed(1, id));
  channel.onmessage(sizeFrame(id, fullScreen ? 120 : 96, fullScreen ? 38 : 32));
  channel.onmessage(framed(0, id, new TextEncoder().encode(terminalText(fullScreen))));
}

function stickyAgentEvents(): AgentTimelineEvent[] {
  return [
    { seq: 1, event: { type: "session_started", provider: "codex" } },
    { seq: 2, event: { type: "session_info", title: "Release hardening" } },
    {
      seq: 3,
      event: {
        type: "available_commands",
        commands: [
          { name: "review", description: "Review the current changes", input_hint: "[path]" },
          { name: "test", description: "Run the relevant test suite", input_hint: null },
          { name: "compact", description: "Compact the conversation context", input_hint: null },
        ],
      },
    },
    {
      seq: 4,
      event: {
        type: "mode_state",
        current_mode_id: "default",
        available_modes: [
          { id: "default", name: "Default", description: "Balanced coding mode" },
          { id: "plan", name: "Plan", description: "Plan before changing files" },
        ],
      },
    },
    {
      seq: 5,
      event: {
        type: "config_options",
        options: [
          {
            id: "reasoning_effort",
            name: "Reasoning effort",
            description: "How much reasoning to use",
            category: "model",
            current_value: { select: "high" },
            choices: [
              { value: "medium", name: "Medium", description: null, group: null },
              { value: "high", name: "High", description: null, group: null },
              { value: "xhigh", name: "Extra high", description: null, group: null },
            ],
          },
        ],
      },
    },
    { seq: 6, event: { type: "usage", used_tokens: 18420, max_tokens: 128000, cost: "$0.42" } },
  ];
}

function permissionToolEvents(): AgentTimelineEvent[] {
  if (scenario === "agent-permission-credential") {
    return [
      {
        seq: 20,
        event: {
          type: "tool_call",
          tool_call_id: "read-key",
          title: "Read ~/.ssh/id_ed25519",
          kind: "read",
          status: "pending",
          detail: JSON.stringify({ path: "/Users/example/.ssh/id_ed25519" }, null, 2),
        },
      },
    ];
  }
  if (scenario === "agent-permission-destructive") {
    return [
      {
        seq: 20,
        event: {
          type: "tool_call",
          tool_call_id: "remove-cache",
          title: "Remove generated cache",
          kind: "delete",
          status: "pending",
          detail: JSON.stringify(
            { command: "rm -rf ./target/debug", cwd: "/Users/example/Desktop/project-portty" },
            null,
            2,
          ),
        },
      },
    ];
  }
  if (scenario === "agent-permission-stack") {
    return [
      {
        seq: 20,
        event: {
          type: "tool_call",
          tool_call_id: "run-tests",
          title: "Run workspace tests",
          kind: "execute",
          status: "pending",
          detail: JSON.stringify({ command: "cargo test --workspace", cwd: "/workspace/portty" }),
        },
      },
      {
        seq: 21,
        event: {
          type: "tool_call",
          tool_call_id: "edit-css",
          title: "Edit app/src/styles.css",
          kind: "edit",
          status: "pending",
          detail: JSON.stringify({ path: "app/src/styles.css", patch: "Update terminal header spacing" }),
        },
      },
    ];
  }
  return [
    {
      seq: 20,
      event: {
        type: "tool_call",
        tool_call_id: "run-checks",
        title: "Run repository checks",
        kind: "execute",
        status: "pending",
        detail: JSON.stringify(
          {
            command: "cargo test --workspace\npnpm --dir app test\npnpm --dir app build",
            cwd: "/Users/example/Desktop/projects/Garage/project-portty",
          },
          null,
          2,
        ),
      },
    },
  ];
}

function agentEvents(): AgentTimelineEvent[] {
  const events = stickyAgentEvents();
  if (scenario === "agent-ready" || scenario === "agent-slash-menu") return events;
  if (scenario === "agent-auth") {
    return [
      ...events,
      { seq: 7, event: { type: "replaying", active: true } },
      {
        seq: 8,
        event: {
          type: "auth_required",
          methods: [
            {
              id: "browser",
              name: "Sign in to Codex",
              description: "Continue authentication in your system browser.",
            },
          ],
        },
      },
    ];
  }

  const conversation: AgentTimelineEvent[] = [
    { seq: 7, event: { type: "user_message", text: "Review the phone UI and tighten the release." } },
    { seq: 8, event: { type: "turn_started" } },
    {
      seq: 9,
      event: {
        type: "thought_chunk",
        text: "I’ll inspect the current layout, compare the phone states, and verify the risky controls.",
      },
    },
    {
      seq: 10,
      event: {
        type: "message_chunk",
        text: "I found the current design tokens and mapped the live session, terminal, and approval surfaces.",
      },
    },
    {
      seq: 11,
      event: {
        type: "tool_call",
        tool_call_id: "read-styles",
        title: "Inspect app/src/styles.css",
        kind: "read",
        status: "completed",
        detail: JSON.stringify({ path: "app/src/styles.css", lines: "1-2800" }),
      },
    },
    {
      seq: 12,
      event: {
        type: "plan",
        entries: [
          { content: "Audit the live components", status: "completed" },
          { content: "Refine spacing and approval states", status: "in_progress" },
          { content: "Run the app checks", status: "pending" },
        ],
      },
    },
  ];

  if (scenario.startsWith("agent-permission")) {
    return [...events, ...conversation, ...permissionToolEvents()];
  }

  if (scenario === "agent-working") return [...events, ...conversation];

  return [
    ...events,
    ...conversation,
    {
      seq: 13,
      event: {
        type: "message_chunk",
        text: "\n\nThe preview now uses the real components, so CSS changes can be judged without a phone build.",
      },
    },
    { seq: 14, event: { type: "turn_finished", stop_reason: "end_turn" } },
  ];
}

function permission(
  toolCallId: string,
  title: string,
  category: AgentPermission["category"],
  /* The adapter's own wording for the provider-wide grant. It must describe the
   * tool on THIS card: every scenario used to offer "Always Allow Bash(cargo *)",
   * so the SSH-key card and the `rm -rf` card both proposed a cargo grant and
   * neither could be used to judge whether the scope wording reads correctly. */
  standingName: string,
): AgentPermission {
  return {
    id: AGENT_ID,
    tool_call: { tool_call_id: toolCallId, title },
    options: [
      { option_id: "allow-once", name: "Allow once", kind: "allow_once" },
      { option_id: "reject-once", name: "Reject", kind: "reject_once" },
      { option_id: "allow-always", name: standingName, kind: "allow_always" },
    ],
    category,
    connection: 1,
    // Every scenario but `agent-permission-broad-root` models a properly scoped
    // project, which is what makes the tier apply at all.
    workspace_scope: scenario === "agent-permission-broad-root" ? "broad" : "project",
  };
}

function pendingPermissions(): AgentPermission[] {
  switch (scenario) {
    case "agent-permission-broad-root":
      // An ORDINARY read that would normally never reach the user under the
      // default readonly tier. It only appears because the sandbox root is the
      // home folder, so the card has to explain itself or it reads as a bug.
      return [
        permission("read-src", "Read src/main.rs", "read", "Always Allow Read(src/**)"),
      ];
    case "agent-permission-credential":
      return [
        permission("read-key", "Read ~/.ssh/id_ed25519", "read", "Always Allow Read(~/.ssh/**)"),
      ];
    case "agent-permission-destructive":
      return [
        permission("remove-cache", "Remove generated cache", "destructive", "Always Allow Bash(rm *)"),
      ];
    case "agent-permission-stack":
      return [
        permission("run-tests", "Run workspace tests", "execute", "Always Allow Bash(cargo *)"),
        permission("edit-css", "Edit app/src/styles.css", "write", "Always Allow Edit(app/**)"),
      ];
    case "agent-permission-routine":
    case "agent-permission-standing":
      // Deliberately repeated: this is the fixture that exercises
      // `dedupePermissionLabel`, which collapses an adapter's own duplicated
      // scope list back into one readable clause.
      return [
        permission(
          "run-checks",
          "Run repository checks",
          "execute",
          "Always Allow Bash(cargo *), Bash(cargo *), Bash(cargo *)",
        ),
      ];
    default:
      return [];
  }
}

function attach(id: number): void {
  if (id === AGENT_ID) {
    emitEvent("portty://agent-snapshot", { id, events: agentEvents() }, 30);
    pendingPermissions().forEach((request, index) => {
      emitEvent("portty://permission", request, 70 + index * 20);
    });
    return;
  }
  later(() => streamTerminal(id), 35);
}

mockIPC(
  (command, payload) => {
    const args = (payload ?? {}) as Record<string, unknown>;
    switch (command) {
      case "biometric_platform_enforced":
        return true;
      case "plugin:biometric|status":
        return { isAvailable: true, biometryType: 2 };
      case "plugin:biometric|authenticate":
        if (scenario === "lock") return new Promise<never>(() => {});
        if (scenario === "lock-error") throw new Error("Authentication canceled");
        return undefined;
      case "consume_push_wake":
        return null;
      case "list_hosts":
        // The first-run case gets a host with NO default, so the "nothing starred
        // yet" sheet is reviewable instead of only the already-configured one.
        return scenario === "home-terminal-folder-first-star"
          ? savedHosts.map((host) => ({ ...host, default_dir: null }))
          : savedHosts;
      case "reconnect": {
        reconnectCalls += 1;
        channel = args.onOutput as unknown as OutputChannel;
        if (disconnectedAtBoot.has(scenario) && reconnectCalls === 1) {
          throw new Error("preview starts disconnected");
        }
        sendSessionList();
        return undefined;
      }
      case "pair":
        channel = args.onOutput as unknown as OutputChannel;
        // The real core emits the comparison code mid-handshake and then blocks
        // until a human confirms it at the host. `pair-confirm` reproduces that
        // wait: emit the code and never resolve, which is exactly the state the
        // user sits in.
        if (scenario === "pair-confirm") {
          emitEvent("portty://pair-code", "483921", 10);
          return new Promise<undefined>(() => {});
        }
        sendSessionList();
        return undefined;
      case "attach":
      case "resume_output":
        attach(args.id as number);
        return undefined;
      case "detach":
      case "pause_stream":
      case "resume_stream":
      case "input":
      case "agent_prompt":
      case "agent_cancel":
      case "agent_set_mode":
      case "agent_set_config":
      case "agent_authenticate":
      case "rename":
      // Echoes the stored value back like the real command, so the workbench
      // shows the row updating rather than a hardcoded folder.
      case "set_host_default_dir": {
        const rel = ((args.rel as string) ?? "").trim();
        return rel === "" ? null : rel;
      }
      case "rename_host":
      case "open_external_url":
      case "register_push":
        return undefined;
      case "disconnect":
        emitEvent("portty://disconnected", null, 15);
        return undefined;
      case "kill":
        emitEvent("portty://removed", args.id, 15);
        return undefined;
      case "permission_decision":
        emitEvent(
          "portty://permission-resolved",
          {
            id: args.id,
            tool_call_id: args.toolCallId,
            resolution: args.optionId === "reject-once" ? "rejected" : args.optionId ? "allowed" : "rejected",
            by: "phone",
          },
          15,
        );
        return undefined;
      case "new_session": {
        const info: SessionInfo = {
          id: 4,
          title: "shell 4",
          kind: "shell",
          source: "spawned",
          has_activity: false,
        };
        emitEvent("portty://added", info, 15);
        return info.id;
      }
      // A shell in a chosen folder. Titled with the folder so the workbench shows
      // the picked directory reaching the host, not just "shell 5".
      case "new_session_in": {
        const rel = (args.rel as string) ?? "";
        const info: SessionInfo = {
          id: 5,
          title: rel ? `shell · ${rel}` : "shell · workspace root",
          kind: "shell",
          source: "spawned",
          has_activity: false,
        };
        emitEvent("portty://added", info, 15);
        return info.id;
      }
      case "new_agent":
      case "new_agent_in":
      case "resume_agent_session":
        return AGENT_ID;
      case "list_agent_providers":
        return [
          { provider: "claude_code", available: true, detail: null },
          { provider: "open_code", available: false, detail: "OpenCode is not installed on this host" },
          { provider: "codex", available: true, detail: null },
        ];
      // Both roots this host serves, so the segmented switcher is exercised. The
      // restricted case is a host that answers `["workspace"]` (or an older one
      // that rejects the request), which hides the switcher entirely.
      case "list_terminal_roots":
        return ["workspace", "home"];
      case "list_workspace_dirs": {
        const rel = (args.rel as string) ?? "";
        return {
          rel,
          names: rel ? ["src", "tests"] : ["app", "crates", "design-review", "packaging"],
        };
      }
      // Home looks different from the workspace on purpose - switching roots that
      // showed identical folders would prove nothing about the wiring.
      case "list_dirs_in": {
        const rel = (args.rel as string) ?? "";
        const root = args.root as string;
        if (root !== "home") throw new Error(`preview has no root ${root}`);
        return { rel, names: rel ? ["src", "docs"] : ["Desktop", "Documents", "code", "Downloads"] };
      }
      case "new_session_in_root": {
        const rel = (args.rel as string) ?? "";
        const root = args.root as string;
        const info: SessionInfo = {
          id: 6,
          title: rel ? `shell · ${rel}` : `shell · ${root}`,
          kind: "shell",
          source: "spawned",
          has_activity: false,
        };
        emitEvent("portty://added", info, 15);
        return info.id;
      }
      case "list_agent_sessions":
        return {
          rel: (args.rel as string) ?? "",
          sessions: [
            {
              acp_session_id: "fixture-release-review",
              provider: "codex",
              title: "Release hardening",
              label: "Review the phone UI and tighten the release",
              last_active_at_unix_ms: Date.now() - 14 * 60_000,
            },
          ],
        };
      // The v11 listing, whose whole point is that the two KINDS of row look
      // different: one Portty started here (a first prompt for a label, a known
      // time), and one the laptop started (the agent's own title, and - for an
      // agent that reports no timestamp - no time at all rather than a fake one).
      case "list_agent_sessions_for": {
        const provider = (args.provider as string) ?? "claude_code";
        // The wait is a real state on a real host (an `npx` adapter takes
        // seconds to boot), and it is invisible against an instant fixture - so
        // one scenario never answers at all.
        if (scenario === "home-directory-picker-asking") {
          return new Promise(() => {});
        }
        return {
          rel: (args.rel as string) ?? "",
          sessions: [
            {
              acp_session_id: "fixture-phone-started",
              provider,
              title: "Release hardening",
              label: "Review the phone UI and tighten the release",
              last_active_at_unix_ms: Date.now() - 14 * 60_000,
            },
            {
              acp_session_id: "fixture-laptop-started",
              provider,
              title: "Fix offline PIN oracle in the pairing protocol",
              label: null,
              last_active_at_unix_ms: Date.now() - 3 * 60 * 60_000,
            },
            {
              acp_session_id: "fixture-no-timestamp",
              provider,
              title: "Audit library versions for stability",
              label: null,
              last_active_at_unix_ms: 0,
            },
          ],
        };
      }
      case "remove_host":
        return { disconnected: false, remote_revoked: true };
      case "download_file":
      case "upload_file":
        return 1;
      case "plugin:dialog|open":
      case "plugin:dialog|save":
        return null;
      case "plugin:clipboard-manager|read_text":
        return "cargo test --workspace";
      case "plugin:clipboard-manager|write_text":
        return undefined;
      default:
        throw new Error(`Unhandled preview IPC command: ${command}`);
    }
  },
  { shouldMockEvents: true },
);

/**
 * A mock iOS notification banner.
 *
 * OS chrome, not Portty UI - the same category as `SystemChrome` below. iOS
 * draws the real banner and Portty only ever supplies a title and a body, so
 * there is no layout here to design; what IS reviewable is the copy, at the
 * size and contrast someone reads it at on a lock screen.
 *
 * The text comes from the shipping `pendingApprovalMessage()` rather than being
 * retyped, so this cannot quietly disagree with what the device posts - and the
 * absence of any tool name, command or path stays visible at a glance.
 */
function NotificationBanner(props: { pendingCount: number }) {
  const message = pendingApprovalMessage(props.pendingCount);
  return (
    <div class="preview-os-banner" aria-hidden="true">
      <span class="preview-os-banner-icon">P</span>
      <span>
        <div class="preview-os-banner-title">{message.title}</div>
        <div class="preview-os-banner-body">{message.body}</div>
      </span>
      <span class="preview-os-banner-time">now</span>
    </div>
  );
}

function SystemChrome() {
  return (
    <>
      <div class="preview-system-status" aria-hidden="true">
        <span class="preview-system-time">11:18</span>
        <span class="preview-dynamic-island" />
        <span class="preview-system-icons">
          <svg width="17" height="11" viewBox="0 0 17 11" fill="currentColor">
            <rect x="0" y="7" width="3" height="4" rx="1" />
            <rect x="4.5" y="5" width="3" height="6" rx="1" />
            <rect x="9" y="2.5" width="3" height="8.5" rx="1" />
            <rect x="13.5" y="0" width="3" height="11" rx="1" />
          </svg>
          <svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round">
            <path d="M1 4.2a10.4 10.4 0 0 1 14 0" />
            <path d="M3.6 7a6.6 6.6 0 0 1 8.8 0" />
            <path d="M6.5 9.6a2.3 2.3 0 0 1 3 0" />
          </svg>
          <svg width="25" height="12" viewBox="0 0 25 12" fill="none">
            <rect x="0.5" y="0.5" width="21" height="11" rx="3" stroke="currentColor" opacity=".7" />
            <rect x="2.3" y="2.3" width="17" height="7.4" rx="1.6" fill="currentColor" />
            <path d="M23 4v4c1 0 1.5-.8 1.5-2S24 4 23 4Z" fill="currentColor" opacity=".7" />
          </svg>
        </span>
      </div>
      <div class="preview-home-indicator" aria-hidden="true" />
    </>
  );
}

function byText(selector: string, text: string): HTMLElement | null {
  return (
    [...document.querySelectorAll<HTMLElement>(selector)].find((element) =>
      element.textContent?.trim().includes(text),
    ) ?? null
  );
}

async function waitFor<T extends Element>(find: () => T | null, timeout = 5000): Promise<T> {
  const started = performance.now();
  while (performance.now() - started < timeout) {
    const found = find();
    if (found) return found;
    await new Promise((resolve) => window.setTimeout(resolve, 25));
  }
  throw new Error(`fixture target did not appear for ${scenario}`);
}

async function clickText(selector: string, text: string): Promise<void> {
  (await waitFor(() => byText(selector, text))).click();
}

async function openTerminal(): Promise<void> {
  await clickText(".portty-session-card", "project-portty");
  await waitFor(() => document.querySelector<HTMLElement>(".portty-term-zoom"));
}

async function openAgent(): Promise<void> {
  await clickText(".portty-session-card", "Release hardening");
  await waitFor(() => document.querySelector<HTMLElement>(".portty-agent-screen"));
}

async function driveScenario(): Promise<void> {
  if (scenario === "lock") {
    await waitFor(() => document.querySelector(".portty-lock"));
    return;
  }
  if (scenario === "lock-error") {
    await waitFor(() => document.querySelector(".portty-lock-error"));
    return;
  }

  /* Approvals waiting while the user stays on the home screen. This state only
     exists because the auto-attach is gated on a notification tap: an approval
     arriving during ordinary use must NOT drag the view into an agent. What the
     user gets instead is the header count plus one amber dot per waiting
     session, and this fixture is how that is judged. */
  if (scenario === "home-approvals-crowded") {
    [11, 12, 13, 14].forEach((id, index) => {
      emitEvent(
        "portty://permission",
        { ...permission(`call-${id}`, "Write src/main.rs", "write", "Always Allow Write(src/**)"), id },
        60 + index * 15,
      );
      // A second request on two of them, so mixed counts are visible too.
      if (id === 12 || id === 14) {
        emitEvent(
          "portty://permission",
          { ...permission(`call-${id}-b`, "Run cargo test", "execute", "Always Allow Execute(cargo test)"), id },
          70 + index * 15,
        );
      }
    });
    await waitFor(
      () =>
        document.querySelectorAll(".portty-session-card--waiting").length === 4
          ? document.querySelector(".portty-session-pending")
          : null,
    );
    return;
  }

  if (scenario === "home-approvals-waiting") {
    // Two on one agent and one on the other, so both a plural and a singular
    // count are on screen together - that contrast is the thing to judge.
    emitEvent(
      "portty://permission",
      permission("write-config", "Write tauri.conf.json", "write", "Always Allow Write(app/**)"),
      60,
    );
    emitEvent(
      "portty://permission",
      permission("run-tests", "Run cargo test", "execute", "Always Allow Execute(cargo test)"),
      75,
    );
    emitEvent(
      "portty://permission",
      {
        ...permission("read-docs", "Read README.md", "read", "Always Allow Read(docs/**)"),
        id: SECOND_AGENT_ID,
      },
      90,
    );
    await waitFor(() => document.querySelector(".portty-session-pending"));
    await waitFor(
      () =>
        document.querySelectorAll(".portty-session-card--waiting").length === 2
          ? document.querySelector(".portty-session-card--waiting")
          : null,
    );
    return;
  }

  switch (scenario) {
    case "home-connected":
      await waitFor(() =>
        document.querySelectorAll(".portty-session-card").length === sessions.length
          ? document.querySelector(".portty-session-card")
          : null,
      );
      break;
    case "home-empty":
      await waitFor(() => document.querySelector(".portty-empty"));
      break;
    case "home-disconnected":
      await waitFor(() => byText("button", "Reconnect"));
      break;
    case "home-host-menu":
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[aria-label="Switch host"]'))).click();
      break;
    // Same open switcher, but waiting on the per-machine setting row rather than
    // the machine list, so the screenshot cannot land before it renders.
    case "home-host-default-folder":
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[aria-label="Switch host"]'))).click();
      await waitFor(() => document.querySelector(".portty-host-menu-sub"));
      break;
    case "home-agent-picker":
      await clickText("button", "Coding agent");
      await waitFor(() => document.querySelector(".portty-agent-picker"));
      break;
    case "home-directory-picker":
      await clickText("button", "Coding agent");
      await clickText(".portty-agent-picker button", "Claude Code");
      await waitFor(() => document.querySelector(".portty-dir-session"));
      break;
    // Same screen with the conversation probe still out. Waits on the "asking"
    // line rather than the sheet, so the screenshot cannot land before the state
    // it exists to show.
    case "home-directory-picker-asking":
      await clickText("button", "Coding agent");
      await clickText(".portty-agent-picker button", "Claude Code");
      await waitFor(() => document.querySelector(".portty-dir-saved-note"));
      break;
    // Waits for the folder LIST, not the sheet: the sheet renders before the
    // host's listing lands, so screenshotting on the container would sometimes
    // catch an empty browser.
    case "home-terminal-folder-picker":
      // "+ New session" IS the folder picker now - there is no second button.
      await clickText("button", "New session");
      // The sheet opens ON the fixture host's default folder, so no navigation is
      // needed to reach the interesting state. Waiting for the STAR rather than a
      // folder row is deliberate: if the glyph ever fails to render, this state
      // times out loudly instead of quietly showing a sheet without it.
      await waitFor(() => document.querySelector(".portty-dir-star"));
      break;
    // Nothing starred yet: the sheet opens at the workspace root, the path row has
    // no star (the root is what "no default" means), and every folder ROW does -
    // which is how a first default gets set. Waits for a star inside the LIST
    // specifically, so the state fails if only the path row had one.
    case "home-terminal-folder-first-star":
      await clickText("button", "New session");
      await waitFor(() => document.querySelector(".portty-dir-row .portty-dir-star"));
      break;
    // The v10 answer to "I can't reach my folder": switch off the workspace onto
    // home, which is a root the phone can pick WITHOUT anyone touching the laptop.
    // Waits for a home-only folder name, so it fails if the switch did not
    // actually re-list rather than just repaint the chip.
    case "home-terminal-folder-home-root":
      await clickText("button", "New session");
      await waitFor(() => document.querySelector(".portty-dir-roots"));
      await clickText(".portty-dir-root", "Home");
      await waitFor(() => byText(".portty-dir-entry", "Documents"));
      break;
    case "pair":
    case "pair-node-id":
    case "pair-confirm": {
      await clickText("button", "Connect to a host");
      await waitFor(() => document.querySelector(".portty-card"));
      if (scenario === "pair-node-id") {
        const ticket = await waitFor(() => document.querySelector<HTMLTextAreaElement>(".portty-field textarea"));
        ticket.value = "a".repeat(64);
        ticket.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "a" }));
        await waitFor(() => byText(".portty-field", "6-word phrase"));
        const fields = [...document.querySelectorAll<HTMLInputElement>(".portty-field input")];
        const phrase = fields.find((field) => field.placeholder.includes("raven"));
        if (phrase) {
          phrase.value = "raven-quartz-mellow-pixel-ridge-onyx";
          phrase.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
        }
      }
      if (scenario === "pair-confirm") {
        const ticket = await waitFor(() => document.querySelector<HTMLTextAreaElement>(".portty-field textarea"));
        ticket.value = "portty1:eyJuaWQiOiJwcmV2aWV3In0";
        ticket.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "p" }));
        await clickText(".portty-btn-primary", "Pair");
        await waitFor(() => document.querySelector(".portty-pair-code__digits"));
      }
      break;
    }
    case "terminal-attaching":
      await openTerminal();
      break;
    case "terminal-fit":
      await openTerminal();
      await waitFor(() =>
        [...document.querySelectorAll<HTMLElement>(".xterm-rows")].find((row) =>
          row.textContent?.includes("project-portty"),
        ) ?? null,
      );
      break;
    case "terminal-match":
      await openTerminal();
      (await waitFor(() => byText(".portty-mode-btn", "Fit"))).click();
      break;
    case "terminal-full-screen":
      await openTerminal();
      await waitFor(() => document.querySelector(".portty-cmdbar-hint"));
      break;
    case "terminal-keys":
      await openTerminal();
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[aria-label="Show more keys"]'))).click();
      await waitFor(() => document.querySelector(".portty-keypanel"));
      break;
    case "terminal-menu":
      await openTerminal();
      (
        await waitFor(() =>
          document.querySelector<HTMLButtonElement>('[aria-label="More terminal actions"]'),
        )
      ).click();
      await waitFor(() => document.querySelector(".portty-term-menu"));
      break;
    case "terminal-select":
      await openTerminal();
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[aria-label="Show more keys"]'))).click();
      await clickText(".portty-keypanel button", "Select");
      await waitFor(() => document.querySelector(".portty-select-bar"));
      break;
    case "terminal-transfer":
      await openTerminal();
      (
        await waitFor(() =>
          document.querySelector<HTMLButtonElement>('[aria-label="Download a file from the host"]'),
        )
      ).click();
      await waitFor(() => document.querySelector(".portty-transfer-sheet"));
      break;
    case "agent-permission-routine":
    case "agent-permission-credential":
    case "agent-permission-destructive":
    case "agent-permission-stack":
    case "agent-permission-broad-root":
      await openAgent();
      if (scenario.startsWith("agent-permission")) {
        await waitFor(() => document.querySelector(".portty-agent-permission"));
      }
      break;
    case "agent-ready":
      await openAgent();
      await waitFor(() => document.querySelector(".portty-agent-empty"));
      break;
    case "agent-working":
      await openAgent();
      await waitFor(() => document.querySelector(".portty-agent-plan"));
      break;
    case "agent-auth":
      await openAgent();
      await waitFor(() => document.querySelector(".portty-agent-auth"));
      break;
    case "agent-permission-standing":
      await openAgent();
      // Standing grants live behind the "Remember this decision…" disclosure -
      // open it, then arm the grant.
      (
        await waitFor(() => document.querySelector<HTMLButtonElement>(".portty-agent-permission-actions .is-grants"))
      ).click();
      (
        await waitFor(() => document.querySelector<HTMLButtonElement>(".portty-agent-permission-grants .is-standing"))
      ).click();
      await waitFor(() => document.querySelector(".portty-agent-permission-grants .is-standing.is-armed"));
      break;
    case "agent-policy":
      await openAgent();
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[title="Approval policy"]'))).click();
      await waitFor(() => document.querySelector(".portty-policy-panel"));
      break;
    case "agent-settings":
      await openAgent();
      (await waitFor(() => document.querySelector<HTMLButtonElement>('[aria-label="Agent settings"]'))).click();
      await waitFor(() => document.querySelector(".portty-agent-settings"));
      break;
    case "agent-slash-menu": {
      await openAgent();
      const composer = await waitFor(() => document.querySelector<HTMLTextAreaElement>(".portty-agent-composer textarea"));
      composer.value = "/";
      composer.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "/" }));
      await waitFor(() => document.querySelector(".portty-agent-command-menu"));
      break;
    }
    default:
      if (!emittedList) sendSessionList();
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");

const lockScenario = scenario === "lock" || scenario === "lock-error";
/* How many pending approvals the mock OS banner should claim. Zero hides it. */
const bannerCount =
  scenario === "agent-notification-banner" ? 1 : scenario === "agent-notification-stack" ? 3 : 0;
render(
  () => (
    <>
      <SystemChrome />
      {bannerCount > 0 ? <NotificationBanner pendingCount={bannerCount} /> : null}
      {lockScenario ? (
        <BiometricGate>
          <App />
        </BiometricGate>
      ) : (
        <App />
      )}
    </>
  ),
  root,
);

void driveScenario()
  .then(() => {
    window.parent.postMessage({ type: "portty-preview-ready", scenario }, window.location.origin);
  })
  .catch((error) => {
    console.error(error);
    window.parent.postMessage(
      { type: "portty-preview-error", scenario, message: `${error}` },
      window.location.origin,
    );
  });
