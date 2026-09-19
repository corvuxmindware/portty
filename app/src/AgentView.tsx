import { createEffect, createMemo, createSignal, For, Index, on, onCleanup, Show } from "solid-js";
import type { JSX } from "solid-js";
import { Icon, type IconName } from "./Icon";
import { orderedOptions } from "./lib/approval";
import type {
  AgentPermission,
  AgentPlanEntry,
  AgentConfigOption,
  AgentConfigValue,
  AgentTimelineEvent,
  AgentToolKind,
  AgentToolStatus,
  ApprovalPolicy,
  DecisionLogEntry,
  SessionInfo,
} from "./lib/portty";
import { openExternal } from "./lib/portty";
import { safeLine, safeText } from "./lib/safeText";
import {
  exactAllowRule,
  dedupePermissionLabel,
  formatPermissionDetail,
  permissionCategory,
  permissionToolDetail,
  permissionToolInput,
  touchesSensitivePath,
  workspaceScopeAllowsTier,
} from "./lib/policy";

type FeedItem =
  | { type: "user"; text: string; seq: number }
  | { type: "assistant"; text: string; seq: number }
  | { type: "thought"; text: string; seq: number }
  | {
      type: "tool";
      id: string;
      title: string;
      kind: AgentToolKind;
      status: AgentToolStatus;
      detail: string | null;
      seq: number;
    }
  | { type: "plan"; entries: AgentPlanEntry[]; seq: number }
  | { type: "turn"; running: boolean; label: string; seq: number }
  | { type: "error"; message: string; seq: number };

type ToolItem = Extract<FeedItem, { type: "tool" }>;

interface AgentViewProps {
  session?: SessionInfo;
  events: AgentTimelineEvent[];
  permissions: AgentPermission[];
  stopping: boolean;
  sending: boolean;
  onBack: () => void;
  onStop: () => void;
  onPrompt: (text: string) => Promise<boolean>;
  onSetMode: (modeId: string) => Promise<boolean>;
  onSetConfig: (configId: string, value: AgentConfigValue) => Promise<boolean>;
  onAuthenticate: (methodId: string) => Promise<boolean>;
  onDecision: (request: AgentPermission, optionId: string | null) => void;
  onLearnExact: (request: AgentPermission) => void;
  policy: ApprovalPolicy;
  decisionLog: DecisionLogEntry[];
  onPolicyChange: (policy: ApprovalPolicy) => void;
}

/** Human label for a decision-log entry's source. Older entries predate the
 * field and read as "auto". */
function decisionSourceLabel(
  entry: Pick<DecisionLogEntry, "source" | "resolution" | "resolved_by">,
): string {
  switch (entry.source) {
    case "manual-allow":
      return "you allowed";
    case "manual-reject":
      return "you rejected";
    case "learned-exact":
      return "always-allow";
    case "resolved-elsewhere": {
      // v5 hosts record what the other viewer decided and which one; older
      // entries have neither, so fall back to the bare "elsewhere".
      const who =
        entry.resolved_by === "laptop"
          ? "laptop"
          : entry.resolved_by === "phone"
            ? "other device"
            : entry.resolved_by === "system"
              ? "agent"
              : null;
      const what =
        entry.resolution === "allowed"
          ? "allowed"
          : entry.resolution === "rejected"
            ? "rejected"
            : entry.resolution === "cancelled"
              ? "cancelled"
              : null;
      if (what && who) return `${what} · ${who}`;
      if (what) return `${what} elsewhere`;
      if (who) return `answered · ${who}`;
      return "elsewhere";
    }
    default:
      return "auto";
  }
}

function buildFeed(events: AgentTimelineEvent[]): FeedItem[] {
  const feed: FeedItem[] = [];
  const toolIndex = new Map<string, number>();
  let planIndex: number | null = null;
  let running = false;
  let lastSeq = 0;
  for (const item of events) {
    lastSeq = item.seq;
    if (item.event.type === "turn_started") running = true;
    if (item.event.type === "turn_finished") running = false;
    const event = item.event;
    switch (event.type) {
      case "session_started":
        break;
      case "user_message":
        feed.push({ type: "user", text: event.text, seq: item.seq });
        break;
      case "turn_started":
        // Only the LIVE turn renders a pill (appended after the loop) -
        // historical Working/Ready pairs are feed litter.
        break;
      case "message_chunk": {
        const last = feed.at(-1);
        if (last?.type === "assistant") last.text += event.text;
        else feed.push({ type: "assistant", text: event.text, seq: item.seq });
        break;
      }
      case "thought_chunk": {
        const last = feed.at(-1);
        if (last?.type === "thought") last.text += event.text;
        else feed.push({ type: "thought", text: event.text, seq: item.seq });
        break;
      }
      case "tool_call": {
        const tool: FeedItem = {
          type: "tool",
          id: event.tool_call_id,
          title: event.title,
          kind: event.kind,
          status: event.status,
          detail: event.detail,
          seq: item.seq,
        };
        toolIndex.set(event.tool_call_id, feed.length);
        feed.push(tool);
        break;
      }
      case "tool_call_update": {
        const index = toolIndex.get(event.tool_call_id);
        if (index == null || feed[index]?.type !== "tool") break;
        const tool = feed[index] as Extract<FeedItem, { type: "tool" }>;
        feed[index] = {
          ...tool,
          title: event.title ?? tool.title,
          kind: event.kind ?? tool.kind,
          status: event.status ?? tool.status,
          detail: event.detail ?? tool.detail,
        };
        break;
      }
      case "plan": {
        const plan: FeedItem = { type: "plan", entries: event.entries, seq: item.seq };
        if (planIndex == null) {
          planIndex = feed.length;
          feed.push(plan);
        } else {
          feed[planIndex] = plan;
        }
        break;
      }
      case "turn_finished":
        planIndex = null;
        toolIndex.clear();
        break;
      case "error":
        feed.push({ type: "error", message: event.message, seq: item.seq });
        break;
      case "available_commands":
      case "mode_state":
      case "config_options":
      case "session_info":
      case "replaying":
      case "auth_required":
      case "usage":
        break;
    }
  }
  if (running) {
    feed.push({ type: "turn", running: true, label: "Working", seq: lastSeq + 1 });
  }
  return feed;
}

// Keep in lockstep with format_tokens in crates/cli/src/main.rs - laptop and
// phone must show the same number for the same usage event.
/* Minimal, injection-safe markdown for assistant text. Everything is built as
   elements (never HTML strings), so agent output can't inject markup. Covers
   what coding agents actually emit - fenced code, inline code, bold, lists,
   headings, links - and leaves everything else as plain text. */
const MD_INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)/g;
const MD_LIST = /^\s*([-*]|\d+\.)\s+/;

function renderInline(text: string): JSX.Element {
  const parts: JSX.Element[] = [];
  let last = 0;
  for (const match of text.matchAll(MD_INLINE)) {
    const index = match.index ?? 0;
    if (index > last) parts.push(text.slice(last, index));
    if (match[1]) parts.push(<code>{match[1].slice(1, -1)}</code>);
    else if (match[2]) parts.push(<strong>{match[2].slice(2, -2)}</strong>);
    else {
      // Open in the system browser via Rust, not target="_blank": inside the
      // app's own webview a _blank link navigates the SPA away (#53). Keep href
      // for hover/long-press affordance but intercept the click.
      const url = match[4];
      parts.push(
        <a
          href={url}
          onClick={(event) => {
            event.preventDefault();
            void openExternal(url);
          }}
        >
          {match[3]}
        </a>,
      );
    }
    last = index + match[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function renderMarkdown(text: string): JSX.Element {
  const blocks: JSX.Element[] = [];
  const lines = text.split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("```")) {
      const code: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) {
        code.push(lines[i]);
        i += 1;
      }
      i += 1; // closing fence (or, mid-stream, EOF)
      blocks.push(
        <pre class="portty-md-code">
          <code>{code.join("\n")}</code>
        </pre>,
      );
      continue;
    }
    if (MD_LIST.test(line)) {
      const items: JSX.Element[] = [];
      const ordered = /^\s*\d+\./.test(line);
      while (i < lines.length && MD_LIST.test(lines[i])) {
        items.push(<li>{renderInline(lines[i].replace(MD_LIST, ""))}</li>);
        i += 1;
      }
      blocks.push(ordered ? <ol>{items}</ol> : <ul>{items}</ul>);
      continue;
    }
    const heading = line.match(/^#{1,4}\s+(.*)/);
    if (heading) {
      blocks.push(<p class="portty-md-heading">{renderInline(heading[1])}</p>);
      i += 1;
      continue;
    }
    const paragraph: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].startsWith("```") &&
      !MD_LIST.test(lines[i]) &&
      !/^#{1,4}\s/.test(lines[i])
    ) {
      paragraph.push(lines[i]);
      i += 1;
    }
    if (paragraph.length > 0) {
      blocks.push(<p>{renderInline(paragraph.join("\n"))}</p>);
    } else {
      i += 1; // blank line
    }
  }
  return blocks;
}

const formatTokens = (count: number) => {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1_000) return `${Math.round(count / 1_000)}k`;
  return String(count);
};

/**
 * Marks a scroll container with `data-scroll="none"` while its content fits, so
 * the "there is more below" fade only appears when there IS more below. A short
 * permission card must not look dimmed at the bottom for no reason, and a long
 * one must never end in a hard cut that reads as a rendering fault.
 *
 * ResizeObserver rather than a one-shot measure: the detail block, the sensitive
 * warning and the queue badge all change height after mount, and the card is
 * re-laid-out whenever the composer or the soft keyboard moves.
 */
const watchOverflow = (element: HTMLElement): void => {
  const sync = () => {
    const fits = element.scrollHeight <= element.clientHeight + 1;
    if (fits) element.dataset.scroll = "none";
    else delete element.dataset.scroll;
  };
  if (typeof ResizeObserver === "undefined") {
    queueMicrotask(sync);
    return;
  }
  const observer = new ResizeObserver(sync);
  observer.observe(element);
  // The scroll height tracks the CONTENT box, which the container's own resize
  // does not report; watch the children too.
  for (const child of Array.from(element.children)) observer.observe(child);
  onCleanup(() => observer.disconnect());
};

const toolIcon = (kind: AgentToolKind): IconName => {
  if (kind === "execute") return "terminal";
  // Delete gets its own glyph. Sharing the edit pencil meant "remove the cache"
  // and "adjust a line" arrived looking identical - and since the kind is also
  // the thing the policy engine branches on, the row should not misreport it.
  if (kind === "delete") return "trash";
  if (kind === "edit" || kind === "move") return "edit";
  if (kind === "read" || kind === "search") return "search";
  if (kind === "think") return "think";
  if (kind === "fetch") return "external-link";
  return "more";
};

/** Human labels. The raw enum ("execute", "fetch") read as debug output. */
const TOOL_KIND_LABEL: Record<AgentToolKind, string> = {
  read: "Read",
  edit: "Edit",
  delete: "Delete",
  move: "Move",
  search: "Search",
  execute: "Run",
  think: "Think",
  fetch: "Fetch",
  other: "Tool",
};

/**
 * First non-empty line of a reasoning block, for the collapsed summary.
 *
 * A row labelled "Reasoning" tells you nothing, and a turn produces several of
 * them interleaved with tool calls - so the feed became a stack of identical
 * grey rows. Showing the actual opening line makes each one skimmable, which is
 * the only reason to leave them collapsed at all.
 */
const thoughtPeek = (text: string): string => {
  const line = text.trim().split("\n").find((candidate) => candidate.trim()) ?? "";
  return line.length > 88 ? `${line.slice(0, 88).trimEnd()}…` : line;
};

/** Hard ceiling on rendered tool output. Past this the phone is laying out text
 *  nobody will read, and a single `read` of a big file janks the whole feed. */
const MAX_DETAIL_CHARS = 20_000;

/**
 * Pull the human-meaningful payload out of a raw tool result.
 *
 * Agents hand back a JSON envelope - `{"output": "...", "metadata": {...}}` -
 * and rendering it verbatim put the entire file on screen WITH its newlines
 * still escaped, so a 115-line README arrived as three screens of `\n`-littered
 * JSON. Unwrapping `output` yields the real text with real line breaks and drops
 * the metadata noise; anything else falls back to pretty-printing, and
 * non-JSON is passed through untouched.
 */
function readableDetail(raw: string): string {
  // Parse only what is worth parsing. A multi-megabyte result would block the
  // main thread inside JSON.parse before any display cap could apply, and the
  // unwrapped text would be discarded seconds later anyway.
  if (raw.length > 4 * MAX_DETAIL_CHARS) return raw;
  const trimmed = raw.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return raw;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const output = (parsed as Record<string, unknown>).output;
      if (typeof output === "string") return output;
    }
    return JSON.stringify(parsed, null, 2);
  } catch {
    return raw; // looked like JSON, wasn't - show what we were given
  }
}

/**
 * Tool output, collapsed by default.
 *
 * The feed is a conversation; tool output is evidence you consult, not prose you
 * read top to bottom. Uncollapsed it buried every surrounding message. Even
 * expanded it scrolls inside its own box rather than pushing the turn off
 * screen.
 */
function ToolDetail(props: { raw: string }) {
  const text = createMemo(() => readableDetail(props.raw));
  const lineCount = createMemo(() => text().split("\n").length);
  const clipped = createMemo(() => {
    const value = text();
    return value.length > MAX_DETAIL_CHARS
      ? `${value.slice(0, MAX_DETAIL_CHARS)}\n\n… output truncated`
      : value;
  });
  /** Short results are their own best summary - a disclosure around three lines
   *  is more chrome than content. */
  const short = createMemo(() => lineCount() <= 3 && text().length <= 220);

  return (
    <Show when={!short()} fallback={<pre>{text()}</pre>}>
      <details class="portty-agent-tool-output">
        <summary>
          <Icon name="chevron-down" class="portty-agent-tool-output-chevron" />
          <span>Output</span>
          <small>
            {lineCount()} {lineCount() === 1 ? "line" : "lines"}
          </small>
        </summary>
        <pre>{clipped()}</pre>
      </details>
    </Show>
  );
}

const statusIcon = (status: AgentToolStatus): IconName => {
  if (status === "completed") return "check";
  if (status === "failed") return "warning";
  if (status === "in_progress") return "dot";
  return "circle";
};

function ConfigControl(props: {
  option: AgentConfigOption;
  onSet: (configId: string, value: AgentConfigValue) => Promise<boolean>;
}) {
  const [pending, setPending] = createSignal(false);
  const selected = () =>
    "select" in props.option.current_value ? props.option.current_value.select : undefined;
  const checked = () =>
    "boolean" in props.option.current_value ? props.option.current_value.boolean : undefined;
  return (
    <Show
      when={selected() !== undefined}
      fallback={
        <label class="portty-agent-config-toggle" title={props.option.description ?? undefined}>
          <input
            type="checkbox"
            checked={checked() ?? false}
            disabled={pending()}
            onChange={(event) => {
              const input = event.currentTarget;
              const previous = checked() ?? false;
              setPending(true);
              void props
                .onSet(props.option.id, { boolean: input.checked })
                .then((ok) => {
                  if (!ok) input.checked = previous;
                })
                .finally(() => setPending(false));
            }}
          />
          {props.option.name}
        </label>
      }
    >
      <label title={props.option.description ?? undefined}>
        {props.option.name}
        <select
          value={selected()}
          disabled={pending()}
          onChange={(event) => {
            const select = event.currentTarget;
            const previous = selected() ?? "";
            setPending(true);
            void props
              .onSet(props.option.id, { select: select.value })
              .then((ok) => {
                if (!ok) select.value = previous;
              })
              .finally(() => setPending(false));
          }}
        >
          <For each={props.option.choices}>
            {(choice) => (
              <option value={choice.value}>
                {choice.group ? `${choice.group} · ` : ""}{choice.name}
              </option>
            )}
          </For>
        </select>
      </label>
    </Show>
  );
}

export function AgentView(props: AgentViewProps) {
  const [draft, setDraft] = createSignal("");
  const [showPolicy, setShowPolicy] = createSignal(false);
  // Agent settings (model, effort, session mode, context usage) live behind the
  // gear rather than in a strip above the composer. That strip was a horizontal
  // scroller pinned over the keyboard: on a phone its controls ran off the right
  // edge - the context counter was already unreadable - while permanently
  // spending two rows of the conversation on settings you change rarely.
  const [showSettings, setShowSettings] = createSignal(false);
  /** One panel at a time - two stacked sheets would bury the feed entirely. */
  const togglePolicy = () => {
    setShowPolicy((open) => !open);
    setShowSettings(false);
  };
  const toggleSettings = () => {
    setShowSettings((open) => !open);
    setShowPolicy(false);
  };
  /**
   * Tap anywhere outside a header panel to dismiss it - what every dropdown on
   * a phone does. Until now the only way out of either sheet was finding the
   * same small control that opened it, so a panel opened by accident stayed
   * open over the conversation.
   *
   * Capture phase, and pointerdown rather than click: the panel must be gone
   * before the tap lands on whatever is underneath, or dismissing it also
   * presses a button in the feed.
   *
   * The trigger buttons are exempt (`data-panel-toggle`) - they toggle
   * themselves, and closing here first would make the reopening tap a no-op.
   */
  createEffect(() => {
    if (!showSettings() && !showPolicy()) return;
    const dismiss = (event: PointerEvent) => {
      const target = event.target as Element | null;
      if (target?.closest?.(".portty-agent-settings, .portty-policy-panel")) return;
      if (target?.closest?.("[data-panel-toggle]")) return;
      setShowSettings(false);
      setShowPolicy(false);
    };
    document.addEventListener("pointerdown", dismiss, true);
    onCleanup(() => document.removeEventListener("pointerdown", dismiss, true));
  });
  const [settingMode, setSettingMode] = createSignal(false);
  const feed = createMemo(() => buildFeed(props.events));
  // Backward index scan - six memos re-run this on every streamed chunk, so
  // a copy+reverse per call would churn the GC exactly while text streams.
  const latest = <T extends AgentTimelineEvent["event"]["type"]>(type: T) => {
    for (let i = props.events.length - 1; i >= 0; i--) {
      const item = props.events[i];
      if (item.event.type === type) {
        return item.event as Extract<AgentTimelineEvent["event"], { type: T }>;
      }
    }
    return undefined;
  };
  const commands = createMemo(() => latest("available_commands")?.commands ?? []);
  const modeState = createMemo(() => latest("mode_state"));
  const configOptions = createMemo(() => latest("config_options")?.options ?? []);
  const authMethods = createMemo(() => latest("auth_required")?.methods ?? []);
  const replaying = createMemo(() => latest("replaying")?.active ?? false);
  const usage = createMemo(() => latest("usage"));
  const turnRunning = createMemo(() => {
    let running = false;
    for (const item of props.events) {
      if (item.event.type === "turn_started") running = true;
      if (item.event.type === "turn_finished") running = false;
    }
    return running;
  });
  /**
   * Does this row begin a fresh agent run (so it earns the avatar)?
   *
   * True at the very start and after anything the USER did. Everything the agent
   * emits afterwards - more prose, reasoning, tool calls - is one continuous
   * answer and shares the gutter without re-stamping the badge.
   */
  const startsAgentRun = (index: number) => {
    if (index === 0) return true;
    const previous = feed()[index - 1]?.type;
    return previous === "user" || previous === "turn";
  };

  /** The tail reasoning block of a turn still in flight - the only place a live
   *  "Thinking…" label is honest, since earlier blocks already finished. */
  const isThinkingNow = (index: number) => turnRunning() && index === feed().length - 1;

  /** Is there anything behind the gear? Gates the button itself. */
  const hasSettings = () =>
    (modeState()?.available_modes.length ?? 0) > 0 ||
    configOptions().length > 0 ||
    usage() !== undefined;

  const slashCommands = createMemo(() => {
    const value = draft().trimStart();
    if (!value.startsWith("/") || value.includes(" ")) return [];
    const query = value.slice(1).toLowerCase();
    return commands().filter(
      (command) =>
        command.name.toLowerCase().includes(query) ||
        command.description.toLowerCase().includes(query),
    );
  });
  const effectiveTier = () =>
    (props.session && props.policy.session_overrides[String(props.session.id)]) ?? props.policy.tier;
  // YOLO auto-approves everything recognized - an explicit two-tap opt-in, not
  // a plain select change (window.confirm is a silent no-op in WKWebView, so
  // this mirrors the app's arm/confirm pattern for destructive actions).
  const [pendingYolo, setPendingYolo] = createSignal<"host" | "session" | null>(null);
  let yoloTimer: number | undefined;
  // Same arm/confirm shape for a provider-wide "always" grant: which option id is
  // armed, cleared on a timeout so a forgotten arm cannot be completed later by an
  // unrelated tap.
  const [armedStanding, setArmedStanding] = createSignal<string | null>(null);
  let standingTimer: number | undefined;
  const armStanding = (optionId: string | null) => {
    window.clearTimeout(standingTimer);
    setArmedStanding(optionId);
    if (optionId !== null) {
      standingTimer = window.setTimeout(() => setArmedStanding(null), 3500);
    }
  };
  onCleanup(() => window.clearTimeout(standingTimer));
  /**
   * Persistent-grant disclosure on the front permission card.
   *
   * The card has to fit its whole decision above the composer. Four action rows
   * (allow/reject, the agent-wide grant with its scope line, the exact grant
   * with its canonical input, dismiss) come to 228px, which on a 667pt phone is
   * the entire layer - the command being approved was squeezed to zero height,
   * so the card asked for a decision while showing nothing to decide about.
   *
   * The two grants that OUTLIVE this decision now sit behind one tap. That is
   * not hiding them: they were already unreachable at this height, and a
   * standing grant is exactly the thing that should cost a deliberate reach
   * rather than sit under a thumb next to "Allow once".
   */
  const [showGrants, setShowGrants] = createSignal(false);
  // Collapse (and disarm) whenever the front request changes, so a disclosure
  // opened for one tool call is never already open for the next one.
  createEffect(
    on(
      () => props.permissions[0]?.tool_call.tool_call_id,
      () => {
        setShowGrants(false);
        armStanding(null);
      },
      { defer: true },
    ),
  );
  const applyTier = (scope: "host" | "session", value: string) => {
    if (scope === "host") {
      props.onPolicyChange({ ...props.policy, tier: value as ApprovalPolicy["tier"] });
      return;
    }
    if (!props.session) return;
    const overrides = { ...props.policy.session_overrides };
    if (value) overrides[String(props.session.id)] = value as ApprovalPolicy["tier"];
    else delete overrides[String(props.session.id)];
    props.onPolicyChange({ ...props.policy, session_overrides: overrides });
  };
  const requestTier = (scope: "host" | "session", value: string, select: HTMLSelectElement) => {
    window.clearTimeout(yoloTimer);
    if (value === "yolo") {
      // Snap the select back until confirmed - the policy has NOT changed yet.
      select.value =
        scope === "host"
          ? props.policy.tier
          : (props.session && props.policy.session_overrides[String(props.session.id)]) || "";
      setPendingYolo(scope);
      yoloTimer = window.setTimeout(() => setPendingYolo(null), 6000);
      return;
    }
    setPendingYolo(null);
    applyTier(scope, value);
  };
  const confirmYolo = () => {
    const scope = pendingYolo();
    if (!scope) return;
    window.clearTimeout(yoloTimer);
    setPendingYolo(null);
    applyTier(scope, "yolo");
  };
  let scroller: HTMLDivElement | undefined;
  let composer: HTMLTextAreaElement | undefined;
  // Follow the stream only while the user is already at (or near) the bottom.
  // Scrolling up to read must not be yanked back down by the next chunk. Plain
  // variable, not a signal - it must never re-run the effect. Instant (not
  // smooth) scrolling: a smooth animation reports mid-flight positions that
  // would read as "scrolled away" and break following on the next chunk.
  let followStream = true;
  const trackScroll = () => {
    if (!scroller) return;
    followStream = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 80;
  };

  createEffect(() => {
    // Track both updates and permission cards. Let Solid paint first, then keep
    // the newest work/composer in reach without stealing input focus.
    void props.events.length;
    void props.permissions.length;
    queueMicrotask(() => {
      if (followStream) scroller?.scrollTo({ top: scroller.scrollHeight });
    });
  });

  const submit = async () => {
    const text = draft().trim();
    if (!text || props.sending) return;
    if (await props.onPrompt(text)) {
      setDraft("");
      // Collapse the auto-grown textarea (programmatic clear fires no input).
      if (composer) composer.style.height = "auto";
      // Sending re-engages following even if the user had scrolled up - their
      // own message (echoed by the host) must land in view.
      followStream = true;
      scroller?.scrollTo({ top: scroller.scrollHeight });
    }
  };

  return (
    <div class="portty-agent-screen">
      <header class="portty-header portty-agent-header">
        <button class="portty-icon-btn" onClick={props.onBack} title="Back to sessions">
          <Icon name="arrow-left" />
        </button>
        <span class="portty-agent-mark">AI</span>
        <span class="portty-header-title truncate">{props.session?.title ?? "Agent"}</span>
        {/* One group, pushed right, with a tighter gap than the header's own -
            so the controls read as a related cluster instead of three items
            floating at even spacing from the title. */}
        <div class="portty-agent-header-actions">
          <button
            class="portty-policy-badge"
            data-tier={effectiveTier()}
            data-panel-toggle
            onClick={togglePolicy}
            title="Approval policy"
          >
            {effectiveTier()}
          </button>
          {/* Only offered when the agent actually exposes something to manage -
              a gear that opens an empty sheet is worse than no gear. */}
          <Show when={hasSettings()}>
            <button
              class="portty-icon-btn"
              classList={{ "portty-icon-btn-on": showSettings() }}
              data-panel-toggle
              onClick={toggleSettings}
              aria-expanded={showSettings()}
              title="Model, effort and session settings"
              aria-label="Agent settings"
            >
              <Icon name="settings" />
            </button>
          </Show>
          {/* Never gated on turnRunning(): that memo is derived from retained
              events, and a long turn can prune its own turn_started - greying
              the button out exactly when a runaway turn most needs stopping.
              Cancelling an idle session is a harmless no-op. */}
          <button
            class="portty-icon-btn portty-agent-stop"
            onClick={props.onStop}
            disabled={props.stopping}
            title="Cancel the active turn and keep this conversation"
          >
            {props.stopping ? "Stopping…" : "Stop"}
          </button>
        </div>
      </header>

      <Show when={showPolicy()}>
        <section class="portty-policy-panel" data-tier={effectiveTier()}>
          {/* The panel dropped in unlabelled and could only be closed by finding
              the badge that opened it again. Name it, and give it a way out. */}
          <div class="portty-sheet-bar">
            <h2 class="portty-sheet-title">
              <Icon name="lock" />
              Approval policy
            </h2>
            <button
              class="portty-sheet-close"
              onClick={() => setShowPolicy(false)}
              title="Close approval policy"
              aria-label="Close approval policy"
            >
              <Icon name="close" />
            </button>
          </div>
          <label>
            Host default policy
            <select
              value={props.policy.tier}
              onChange={(event) =>
                requestTier("host", event.currentTarget.value, event.currentTarget)
              }
            >
              <option value="readonly">Readonly - reads and search</option>
              <option value="edits">Edits - reads and file edits</option>
              <option value="yolo">YOLO - all recognized tools</option>
            </select>
          </label>
          <label>
            This session
            <select
              value={
                props.session
                  ? (props.policy.session_overrides[String(props.session.id)] ?? "")
                  : ""
              }
              onChange={(event) =>
                requestTier("session", event.currentTarget.value, event.currentTarget)
              }
            >
              <option value="">Use host default</option>
              <option value="readonly">Readonly</option>
              <option value="edits">Edits</option>
              <option value="yolo">YOLO</option>
            </select>
          </label>
          <Show when={pendingYolo()}>
            <button class="portty-yolo-confirm" onClick={confirmYolo}>
              Confirm YOLO {pendingYolo() === "session" ? "for this session" : "as host default"} -
              auto-approves every recognized tool
            </button>
          </Show>

          <label>
            Always prompt for exact tool titles (one per line)
            <textarea
              rows="2"
              value={props.policy.prompt_exceptions.join("\n")}
              onChange={(event) =>
                props.onPolicyChange({
                  ...props.policy,
                  prompt_exceptions: event.currentTarget.value
                    .split("\n")
                    .map((line) => line.trim())
                    .filter(Boolean),
                })
              }
            />
          </label>
          <p>Unknown tool kinds always prompt. Policy changes apply to the next request.</p>
          <Show when={props.policy.exact_allow_rules.length > 0}>
            <div class="portty-exact-rules">
              <strong>Always allow exact ({props.policy.exact_allow_rules.length})</strong>
              <For each={props.policy.exact_allow_rules}>
                {(rule) => (
                  <div class="portty-exact-rule-row">
                    <span>{rule.category}</span>
                    <code title={rule.input}>
                      {rule.title} · {rule.input}
                    </code>
                    <button
                      title="Forget this exact allow rule"
                      onClick={() =>
                        props.onPolicyChange({
                          ...props.policy,
                          exact_allow_rules: props.policy.exact_allow_rules.filter(
                            (candidate) =>
                              candidate.category !== rule.category ||
                              candidate.title !== rule.title ||
                              candidate.input !== rule.input,
                          ),
                        })
                      }
                    >
                      Remove
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
          <details>
            <summary>Decision log ({props.decisionLog.length})</summary>
            <For each={props.decisionLog.slice(0, 20)}>
              {(entry) => (
                <div class="portty-policy-log-row" data-source={entry.source ?? "auto"}>
                  <time>{new Date(entry.at).toLocaleTimeString()}</time>
                  <span class="portty-log-source">{decisionSourceLabel(entry)}</span>
                  <span>{entry.category}</span>
                  <strong>{entry.title}</strong>
                  <Show when={entry.input}>
                    <code class="portty-log-input">{entry.input}</code>
                  </Show>
                </div>
              )}
            </For>
          </details>
        </section>
      </Show>

      <Show when={showSettings()}>
        <section class="portty-agent-settings">
          <Show when={modeState()}>
            {(state) => (
              <label>
                Mode
                <select
                  value={state().current_mode_id}
                  disabled={settingMode()}
                  onChange={(event) => {
                    const select = event.currentTarget;
                    const previous = state().current_mode_id;
                    setSettingMode(true);
                    void props
                      .onSetMode(select.value)
                      .then((ok) => {
                        if (!ok) select.value = previous;
                      })
                      .finally(() => setSettingMode(false));
                  }}
                >
                  <For each={state().available_modes}>
                    {(mode) => <option value={mode.id}>{mode.name}</option>}
                  </For>
                </select>
              </label>
            )}
          </Show>
          <For each={configOptions()}>
            {(option) => <ConfigControl option={option} onSet={props.onSetConfig} />}
          </For>
          <Show when={usage()}>
            {(state) => (
              // Status, not a control - but it belongs with the settings it
              // depends on, and it is finally readable here. In the old strip it
              // sat past the right edge, clipped to "8k/".
              <div class="portty-agent-usage-row">
                <span>Context</span>
                <span
                  class="portty-agent-usage"
                  title={state().cost ? `session cost ${state().cost}` : "context window"}
                >
                  {formatTokens(state().used_tokens)}/{formatTokens(state().max_tokens)}
                  {state().cost ? ` · ${state().cost}` : ""}
                </span>
              </div>
            )}
          </Show>
        </section>
      </Show>

      <div class="portty-agent-feed" ref={scroller} onScroll={trackScroll}>
        <Show when={replaying()}>
          <div class="portty-agent-replaying">Replaying saved conversation…</div>
        </Show>
        <For each={authMethods()}>
          {(method) => (
            <div class="portty-agent-auth">
              <div>
                <strong>{method.name}</strong>
                <Show when={method.description}><p>{method.description}</p></Show>
              </div>
              <button onClick={() => void props.onAuthenticate(method.id)}>Authenticate</button>
            </div>
          )}
        </For>
        <Show
          when={feed().length > 0}
          fallback={
            <div class="portty-agent-empty">
              {/* The agent mark, matching the "Coding agent" button that starts
                  this session. A chain link here read as "connected to a host" -
                  true, but it is the terminal screen's idea, and this is the one
                  screen whose whole subject is the agent. */}
              <span><Icon name="bot" /></span>
              <strong>Agent is ready</strong>
              <p>Ask it to inspect, change, test, or explain the project on your host.</p>
            </div>
          }
        >
          {/* Index (position-keyed), NOT For (reference-keyed): buildFeed
              rebuilds all item objects each run, so For recreated every row on
              every streamed chunk - janky, and it collapsed expanded Reasoning
              blocks and dropped in-feed text selection mid-stream. The feed is
              append-only with in-place mutation, so indices are stable; Index
              reuses each row's DOM and Solid skips writes for unchanged rows.
              `item` is now an ACCESSOR - read item() inline so in-place updates
              (tool_call_update, plan) stay reactive (no capture-once IIFE). */}
          <Index each={feed()}>
            {(item, index) => (
              <>
                <Show when={item().type === "user"}>
                  <div class="portty-agent-user">{safeText((item() as Extract<FeedItem, { type: "user" }>).text)}</div>
                </Show>
                <Show when={item().type === "assistant"}>
                  {/* The avatar marks where the agent STARTS answering, not every
                      block it emits - repeating it down a long turn was noise
                      that also fought the shared gutter. */}
                  <div
                    class="portty-agent-response"
                    classList={{ "is-continuation": !startsAgentRun(index) }}
                  >
                    <Show when={startsAgentRun(index)}>
                      <span class="portty-agent-avatar">AI</span>
                    </Show>
                    <div class="portty-agent-md">
                      {renderMarkdown(safeText((item() as Extract<FeedItem, { type: "assistant" }>).text))}
                    </div>
                  </div>
                </Show>
                <Show when={item().type === "thought"}>
                  <details
                    class="portty-agent-thought"
                    classList={{ "is-live": isThinkingNow(index) }}
                  >
                    <summary>
                      <Icon name="think" class="portty-agent-thought-icon" />
                      {/* Two labels, one visible at a time (CSS swaps on [open]).
                          The preview is what makes a collapsed row skimmable,
                          but once expanded it just repeats the first line of the
                          body directly beneath it. */}
                      <span class="portty-agent-thought-peek">
                        {isThinkingNow(index)
                          ? "Thinking…"
                          : thoughtPeek(
                              safeText((item() as Extract<FeedItem, { type: "thought" }>).text),
                            )}
                      </span>
                      <span class="portty-agent-thought-label">Reasoning</span>
                      <Icon name="chevron-down" class="portty-agent-thought-chevron" />
                    </summary>
                    <p>{safeText((item() as Extract<FeedItem, { type: "thought" }>).text)}</p>
                  </details>
                </Show>
                <Show when={item().type === "tool"}>
                  <div class="portty-agent-tool" data-status={(item() as ToolItem).status}>
                    <span
                      class="portty-agent-tool-glyph"
                      data-kind={(item() as ToolItem).kind}
                    >
                      <Icon name={toolIcon((item() as ToolItem).kind)} />
                    </span>
                    <div class="portty-agent-tool-body">
                      {/* Kind reads as an EYEBROW above the title. Below it, an
                          uppercase mono enum looked like leaked debug metadata
                          rather than a label for the thing above it. */}
                      <span class="portty-agent-tool-kind">
                        {TOOL_KIND_LABEL[(item() as ToolItem).kind] ?? "Tool"}
                      </span>
                      <strong>{(item() as ToolItem).title}</strong>
                      <Show when={(item() as ToolItem).detail}>
                        <ToolDetail raw={(item() as ToolItem).detail!} />
                      </Show>
                    </div>
                    <span class="portty-agent-tool-status">
                      <Icon name={statusIcon((item() as ToolItem).status)} />
                    </span>
                  </div>
                </Show>
                <Show when={item().type === "plan"}>
                  <div class="portty-agent-plan">
                    <div class="portty-agent-card-label">Plan</div>
                    <For each={(item() as Extract<FeedItem, { type: "plan" }>).entries}>
                      {(entry) => (
                        <div class="portty-agent-plan-row" data-status={entry.status}>
                          <span><Icon name={statusIcon(entry.status)} /></span>
                          <p>{safeText(entry.content)}</p>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
                <Show when={item().type === "turn"}>
                  <div
                    class="portty-agent-turn"
                    classList={{ "is-running": (item() as Extract<FeedItem, { type: "turn" }>).running }}
                  >
                    <i /> {(item() as Extract<FeedItem, { type: "turn" }>).label}
                  </div>
                </Show>
                <Show when={item().type === "error"}>
                  <div class="portty-agent-error">
                    {(item() as Extract<FeedItem, { type: "error" }>).message}
                  </div>
                </Show>
              </>
            )}
          </Index>
        </Show>

      </div>

      {/* Approvals are the product's whole reason to interrupt a user, so they
          live in a FIXED layer above the toolbar - never inside the scroller,
          where reading back through a long turn hides them below the fold.
          The layer itself is capped, so a card longer than the cap used to push
          its own buttons past the bottom edge: the standing grants and Dismiss
          were unreachable on a 16 Pro, and on an SE the cut landed on Allow and
          Reject themselves. The card is now its own scroller with the decision
          row pinned to its bottom - the detail scrolls, the choice never moves
          off screen.

          Only the FRONT request is rendered. Two cards cannot both keep a pinned
          decision row inside one bounded layer, and the old stack did not try -
          the second card sat entirely below the scroll with nothing on screen
          admitting it existed. One decision at a time, with the queue depth
          stated on the card, also means a reflex tap can only ever answer the
          request the user is actually looking at. */}
      <Show when={props.permissions.length > 0}>
        <div class="portty-agent-permission-layer">
          <For each={props.permissions.slice(0, 1)}>
            {(request) => {
              // Everything the user needs to decide, resolved ONCE per card:
              // what category of action it is, the raw command/args, and which
              // session it belongs to - so nobody approves blind or approves the
              // wrong session's action (see D2 / cross-session hardening).
              const category = () => permissionCategory(request, props.events);
              const detail = () => permissionToolDetail(request, props.events);
              const exactInput = () => permissionToolInput(request, props.events);
              const canLearnExact = () =>
                request.options.some((option) => option.kind === "allow_once") &&
                !!exactAllowRule(category(), request.tool_call.title, exactInput());
              // Split by lifetime, not by label: one-shot answers stay on the
              // card, anything whose effect survives this decision goes behind
              // the disclosure. `orderedOptions` has already fixed the
              // positions, so filtering preserves Allow-left / Reject-right.
              const ordered = () => orderedOptions(request.options);
              const immediateOptions = () =>
                ordered().filter((option) => !option.kind.endsWith("always"));
              const standingOptions = () =>
                ordered().filter((option) => option.kind.endsWith("always"));
              const hasGrants = () => standingOptions().length > 0 || canLearnExact();
              // This card reached the user even under a permissive tier because
              // the path looks like a credential. Say so - "read a file" and
              // "hand over an SSH key" deserve different attention.
              const isSensitive = () =>
                touchesSensitivePath(request.tool_call.title, exactInput());
              // The card is neutral unless there is something real to warn
              // about. Driving that from an attribute rather than :has() keeps
              // it working on the iOS 14 deployment target, and keeps the
              // "is this dangerous" decision in one place instead of implied by
              // which children happen to be rendered.
              const risk = () => {
                if (isSensitive()) return "credential";
                const c = category();
                return c === "destructive" || c === "unknown" ? "destructive" : undefined;
              };
              // The grants render at the BOTTOM of the scrolling body, so
              // expanding the disclosure without moving the scroll leaves the
              // user looking at the request detail and a button that claims to
              // have revealed something. Bring them into view.
              let bodyEl: HTMLDivElement | undefined;
              const revealGrants = () => {
                requestAnimationFrame(() => {
                  bodyEl?.scrollTo({ top: bodyEl.scrollHeight, behavior: "smooth" });
                });
              };
              return (
              <div class="portty-agent-permission" data-risk={risk()}>
                <div class="portty-agent-permission-head">
                  <span class="portty-agent-avatar portty-agent-avatar--attention">!</span>
                  <strong>Permission required</strong>
                  <span class="portty-agent-permission-cat" data-cat={category()}>
                    {category()}
                  </span>
                  {/* Say how deep the queue is, so answering this card does not
                      look like it finished the interruption when it did not. */}
                  <Show when={props.permissions.length > 1}>
                    <span class="portty-agent-permission-queue">
                      1 of {props.permissions.length}
                    </span>
                  </Show>
                  <small class="portty-agent-permission-session">
                    {props.session?.title ? safeLine(props.session.title) : `session ${request.id}`}
                  </small>
                </div>
                {/* Everything that describes the request scrolls; the decision
                    row below does not. */}
                <div
                  class="portty-agent-permission-body"
                  ref={(el) => {
                    bodyEl = el;
                    watchOverflow(el);
                  }}
                >
                <code class="portty-agent-permission-title">{safeLine(request.tool_call.title)}</code>
                <Show when={isSensitive()}>
                  <p class="portty-agent-permission-sensitive">
                    <Icon name="warning" />
                    This path looks like a credential (key, token, or .env). Approving
                    it can hand the secret to the agent and its model.
                  </p>
                </Show>
                {/* Without this, a broad root looks like the tier is broken:
                    the user picked "readonly" and is still being asked about
                    every read. Name the cause and the fix. */}
                <Show when={!isSensitive() && !workspaceScopeAllowsTier(request.workspace_scope)}>
                  <p class="portty-agent-permission-scope">
                    <Icon name="warning" />
                    This agent can reach your whole home folder, so your policy tier
                    is not being applied. Restart the host with PORTTY_WORKSPACE set
                    to one project to stop being asked every time.
                  </p>
                </Show>
                {/* The actual command / args / cwd being approved. Without this
                    the title alone can hide what really runs. */}
                <Show when={detail()}>
                  <pre class="portty-agent-permission-detail">{safeText(formatPermissionDetail(detail()) ?? "")}</pre>
                </Show>
                {/* Standing grants live in the SCROLL region, not the pinned
                    row. Expanded, they are three tall buttons carrying scope
                    text and a canonical-input line - on a 667pt phone that
                    stack alone is taller than the whole layer, so pinning them
                    would push Dismiss (and on the smallest heights, Reject)
                    back under the composer, which is the bug this card was
                    restructured to end. Here they get room to be read in full,
                    and Allow / Reject / Dismiss stay fixed below no matter how
                    long the adapter's grant labels are. */}
                <Show when={showGrants()}>
                  <div class="portty-agent-permission-grants">
                    <For each={standingOptions()}>
                      {(option) => {
                        // A standing grant is the one control here whose effect
                        // outlives the decision, so it takes a deliberate second
                        // tap - the same arm-then-confirm the destructive
                        // controls elsewhere use.
                        const armed = () => armedStanding() === option.option_id;
                        return (
                          <button
                            classList={{ "is-standing": true, "is-armed": armed() }}
                            title="This is a standing, agent-wide grant - its scope is decided by the agent, not by Portty"
                            onClick={() => {
                              if (!armed()) {
                                armStanding(option.option_id);
                                return;
                              }
                              armStanding(null);
                              props.onDecision(request, option.option_id);
                            }}
                          >
                            {safeLine(dedupePermissionLabel(option.name))}
                            <small class="portty-agent-permission-scope">
                              {armed()
                                ? "tap again to grant agent-wide"
                                : "agent-wide, not just this one"}
                            </small>
                          </button>
                        );
                      }}
                    </For>
                    <Show when={canLearnExact()}>
                      <button class="is-exact" onClick={() => props.onLearnExact(request)}>
                        <span>Always allow this exact operation</span>
                        {/* Show the exact canonical input being memorized, so
                            the user commits to a rule they can actually see. */}
                        <Show when={exactInput()}>
                          <code class="portty-agent-permission-exact">{safeText(exactInput() ?? "")}</code>
                        </Show>
                      </button>
                    </Show>
                  </div>
                </Show>
                </div>
                <div class="portty-agent-permission-actions">
                  {/* Ordered by KIND, not by the order the agent sent them.
                      These land in a two-column grid, so agent-controlled order
                      meant Allow could sit in a different cell on different
                      cards - and on a security prompt the thing that gets people
                      is muscle memory landing on the button that used to be
                      Reject. Position is now fixed: Allow top-left, Reject
                      top-right, standing grants below. */}
                  {/* One-shot answers only. `allow_always` / `reject_always` are
                      PROVIDER-WIDE grants whose scope Portty does not define and
                      cannot see - the adapter decides what "always" covers, and
                      the label is the adapter's own text, so a benign-looking
                      "Allow" can be the standing grant. They are filtered out of
                      this row by KIND rather than by label, and rendered above
                      behind the disclosure, so nothing here can resolve to
                      anything longer-lived than this single request. */}
                  <For each={immediateOptions()}>
                    {(option) => (
                      <button
                        classList={{
                          "is-allow": option.kind.startsWith("allow"),
                          "is-reject": option.kind.startsWith("reject"),
                        }}
                        onClick={() => props.onDecision(request, option.option_id)}
                      >
                        {safeLine(dedupePermissionLabel(option.name))}
                      </button>
                    )}
                  </For>
                  {/* The disclosure itself. It states that what is behind it
                      persists - a bare "More options" would let someone open it
                      expecting more one-shot answers. */}
                  <Show when={hasGrants()}>
                    <button
                      class="is-grants"
                      aria-expanded={showGrants()}
                      onClick={() => {
                        armStanding(null);
                        setShowGrants((open) => !open);
                        if (showGrants()) revealGrants();
                      }}
                    >
                      <span>
                        {showGrants() ? "Hide standing grants" : "Remember this decision…"}
                      </span>
                      <Icon name={showGrants() ? "chevron-up" : "chevron-down"} />
                    </button>
                  </Show>
                  <button class="is-reject" onClick={() => props.onDecision(request, null)}>
                    Dismiss
                  </button>
                </div>
              </div>
              );
            }}
          </For>
        </div>
      </Show>

      <form
        class="portty-agent-composer"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Show when={slashCommands().length > 0}>
          <div class="portty-agent-command-menu">
            <For each={slashCommands()}>
              {(command) => (
                <button
                  type="button"
                  onClick={() => {
                    setDraft(`/${command.name}${command.input_hint ? " " : ""}`);
                    queueMicrotask(() => composer?.focus());
                  }}
                >
                  {/* Stacked, not a two-column grid. Each button was its own
                      grid with an `auto` first column, so every row sized its
                      name column independently and the descriptions came out
                      with a ragged left edge down the list. */}
                  <span class="portty-agent-command-line">
                    <strong>/{command.name}</strong>
                    <Show when={command.input_hint}>
                      <small>{command.input_hint}</small>
                    </Show>
                  </span>
                  <span class="portty-agent-command-desc">{command.description}</span>
                </button>
              )}
            </For>
          </div>
        </Show>
        {/* Kept enabled while sending: disabling would dismiss the iOS
            keyboard on every message (submit() already guards on sending). */}
        <textarea
          ref={composer}
          rows="1"
          value={draft()}
          placeholder="Message… - / for commands"
          onInput={(event) => {
            setDraft(event.currentTarget.value);
            // Auto-grow up to the CSS max-height, shrink back on delete.
            event.currentTarget.style.height = "auto";
            event.currentTarget.style.height = `${event.currentTarget.scrollHeight}px`;
          }}
          onKeyDown={(event) => {
            // iOS soft keyboards have no Shift: on touch, return inserts a
            // newline and sending stays on the button. Hardware keyboards
            // (iPad, desktop dev) keep Enter-to-send / Shift+Enter-newline.
            const touch = window.matchMedia("(pointer: coarse)").matches;
            if (event.key === "Enter" && !event.shiftKey && !touch) {
              event.preventDefault();
              void submit();
            }
          }}
        />
        {/* The primary button morphs into Stop while a turn streams - the
            urgent action belongs in the thumb zone, not just the header. */}
        <Show
          when={turnRunning() && !draft().trim()}
          fallback={
            <button disabled={props.sending || !draft().trim()} title="Send prompt">
              {props.sending ? "..." : <Icon name="send" />}
            </button>
          }
        >
          <button
            type="button"
            class="portty-agent-send-stop"
            disabled={props.stopping}
            title="Stop the active turn"
            onClick={() => props.onStop()}
          >
            <Icon name="stop" />
          </button>
        </Show>
      </form>
    </div>
  );
}
