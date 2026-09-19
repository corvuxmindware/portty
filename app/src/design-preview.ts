type StateGroup = "Home" | "Pairing" | "Terminal" | "Agent" | "Security";
type StateIcon = "home" | "host" | "pair" | "terminal" | "keys" | "agent" | "approval" | "lock" | "settings";

interface PreviewState {
  id: string;
  group: StateGroup;
  name: string;
  description: string;
  icon: StateIcon;
  sources: string[];
}

interface DevicePreset {
  label: string;
  width: number;
  height: number;
  dpr: number;
}

const states: PreviewState[] = [
  {
    id: "home-connected",
    group: "Home",
    name: "Connected home",
    description: "A paired host with shell, structured-agent, and adopted-terminal sessions. This is the daily starting point.",
    icon: "home",
    sources: ["App.tsx:2823", "styles.css:266", "styles.css:328", "styles.css:485"],
  },
  {
    id: "home-host-menu",
    group: "Home",
    name: "Host switcher open",
    description: "The inline host menu avoids Android's full-screen native select and keeps adding a host beside switching hosts.",
    icon: "host",
    sources: ["App.tsx:2914", "styles.css:328"],
  },
  {
    id: "home-empty",
    group: "Home",
    name: "Connected · no sessions",
    description: "The host is connected but no shell or agent exists yet. The empty copy points to both available actions.",
    icon: "home",
    sources: ["App.tsx:3002", "styles.css:876"],
  },
  {
    id: "home-disconnected",
    group: "Home",
    name: "Saved host · disconnected",
    description: "A reconnect token exists, so recovery is the primary action and fresh pairing stays secondary.",
    icon: "host",
    sources: ["App.tsx:3134", "styles.css:915"],
  },
  {
    id: "home-agent-picker",
    group: "Home",
    name: "Coding-agent picker",
    description: "Provider availability is shown before selection; missing adapters stay visible and explain why they are disabled.",
    icon: "agent",
    sources: ["App.tsx:3157", "styles.css:2599"],
  },
  {
    id: "home-directory-picker",
    group: "Home",
    name: "Agent directory picker",
    description:
      "The selected directory defines both the agent working directory and its file-access sandbox, with resumable chats below. The list is the union of two stores: conversations this phone started (labelled with their first prompt) and conversations the agent's own CLI started on the laptop (the agent's title, and no time at all when it reports none).",
    icon: "agent",
    sources: ["App.tsx:3208", "styles.css:2639"],
  },
  {
    id: "home-directory-picker-asking",
    group: "Home",
    name: "Agent directory picker · asking the agent",
    description:
      "Answering the conversation list launches the agent's ACP adapter on the host, which takes seconds. Folders render immediately and the conversations fill in beside them; until they do the primary action says \"Start new\", because \"Start here\" would claim there is nothing to resume before the answer arrived.",
    icon: "agent",
    sources: ["App.tsx:3208", "styles.css:3417"],
  },
  {
    id: "home-terminal-folder-picker",
    group: "Home",
    name: "Terminal folder picker",
    description:
      "What \"+ New session\" now opens - starting a shell and choosing where it starts are one action, so a create can never happen without showing the directory. It opens ON the saved default folder, so \"Open here\" is one tap to where you usually work, and changing the default is \"navigate away, tap that folder's star\". The caption states the gesture, since a bare icon has no hover on a phone.",
    icon: "terminal",
    sources: ["App.tsx:3390", "styles.css:3122"],
  },
  {
    id: "home-terminal-folder-home-root",
    group: "Home",
    name: "Terminal folder · Home root",
    description:
      "Browsing the user's home directory instead of the workspace. This is what makes a folder reachable WITHOUT touching the laptop - previously the workspace could only be widened with PORTTY_WORKSPACE there. The switcher only appears when the host serves more than one root; PORTTY_TERMINAL_ROOTS=workspace hides it again. Terminals only: an agent's directory is also its file-access sandbox, so the agent picker stays workspace-bound.",
    icon: "terminal",
    sources: ["App.tsx:3595", "styles.css:3122"],
  },
  {
    id: "home-terminal-folder-first-star",
    group: "Home",
    name: "Terminal folder · nothing starred",
    description:
      "First run, before any folder is the default. The sheet opens at the workspace root, which has no star of its own - the root is what \"no default\" already means - so every folder in the LIST carries one. Tapping a row's star sets the first default without opening the folder, which is what the caption promises.",
    icon: "terminal",
    sources: ["App.tsx:3556", "styles.css:3122"],
  },
  {
    id: "home-host-default-folder",
    group: "Home",
    name: "Default folder setting",
    description:
      "The per-machine default folder, hanging off the connected machine in the switcher. Only the connected row offers it - choosing a folder means browsing that host's workspace, which needs a live link. Phone-local and per host, like the nickname: nothing is sent to the laptop.",
    icon: "host",
    sources: ["App.tsx:3247", "styles.css:517"],
  },
  {
    id: "pair",
    group: "Pairing",
    name: "Pair with a host",
    description: "Saved-host recovery, setup code, and QR scanning share one scrollable screen using the actual pairing form.",
    icon: "pair",
    sources: ["App.tsx:3322", "styles.css:1139"],
  },
  {
    id: "pair-node-id",
    group: "Pairing",
    name: "Manual NodeId + phrase",
    description: "A raw 64-character NodeId reveals the six-word secret phrase field, which is the whole first-pair credential.",
    icon: "pair",
    sources: ["App.tsx:3467", "styles.css:1146"],
  },
  {
    id: "pair-confirm",
    group: "Pairing",
    name: "Confirm the pairing code",
    description: "Mid-handshake: the phone shows the six-digit comparison code and waits while a human confirms it on the host.",
    icon: "pair",
    sources: ["App.tsx:3594", "styles.css:1533"],
  },
  {
    id: "terminal-fit",
    group: "Terminal",
    name: "Shell · fit to phone",
    description: "The real xterm view, transfer and stream controls, local command composer, and current ten-key accessory row.",
    icon: "terminal",
    sources: ["App.tsx:2511", "KeyBar.tsx:198", "CommandBar.tsx:45", "styles.css:1037"],
  },
  {
    id: "terminal-match",
    group: "Terminal",
    name: "Shell · match host 1:1",
    description: "The host's authoritative grid is preserved and the terminal can pan instead of changing the remote PTY size.",
    icon: "terminal",
    sources: ["App.tsx:2538", "App.tsx:2668", "styles.css:1105"],
  },
  {
    id: "terminal-full-screen",
    group: "Terminal",
    name: "Full-screen terminal app",
    description: "Alternate-screen output forces 1:1 rendering and replaces the command composer with the single-key input hint.",
    icon: "terminal",
    sources: ["App.tsx:2747", "lib/altscreen.ts:1", "styles.css:1327"],
  },
  {
    id: "terminal-keys",
    group: "Terminal",
    name: "Expanded terminal keys",
    description: "Clipboard, control, navigation, function, and symbol groups are all reachable without a hidden horizontal tail.",
    icon: "keys",
    sources: ["KeyBar.tsx:52", "KeyBar.tsx:146", "styles.css:1425"],
  },
  {
    id: "terminal-menu",
    group: "Terminal",
    name: "Terminal overflow menu",
    description:
      "Upload, pause and end-session moved off the toolbar so the session name stays readable; a dot on the toolbar button reports state still live inside.",
    icon: "terminal",
    sources: ["App.tsx:2596", "App.tsx:2616", "styles.css:275"],
  },
  {
    id: "terminal-select",
    group: "Terminal",
    name: "Terminal text selection",
    description: "The xterm keyboard overlay becomes click-through and a docked bar explains long-press selection and copy fallback.",
    icon: "keys",
    sources: ["App.tsx:2733", "styles.css:199"],
  },
  {
    id: "terminal-transfer",
    group: "Terminal",
    name: "Download from host",
    description: "An in-app transfer sheet replaces blocking browser prompts that mobile WebViews silently ignore.",
    icon: "terminal",
    sources: ["App.tsx:1677", "App.tsx:2625", "styles.css:746"],
  },
  {
    id: "terminal-attaching",
    group: "Terminal",
    name: "Opening the portal",
    description: "The terminal stays visibly busy until the first snapshot bytes arrive instead of presenting an unexplained black screen.",
    icon: "terminal",
    sources: ["App.tsx:1160", "App.tsx:2692", "styles.css:1037"],
  },
  {
    id: "agent-ready",
    group: "Agent",
    name: "Agent ready",
    description: "A structured ACP session before the first prompt, including live mode/config metadata and the real composer.",
    icon: "agent",
    sources: ["AgentView.tsx:648", "AgentView.tsx:803", "styles.css:1579"],
  },
  {
    id: "agent-working",
    group: "Agent",
    name: "Agent working",
    description: "User prompt, reasoning, assistant markdown, tool activity, and plan rows share the production feed's single left edge.",
    icon: "agent",
    sources: ["AgentView.tsx:839", "AgentView.tsx:883", "AgentView.tsx:905", "styles.css:1695"],
  },
  {
    id: "agent-auth",
    group: "Agent",
    name: "Replay + authentication",
    description: "Conversation replay and provider authentication are explicit feed states rather than terminal text.",
    icon: "agent",
    sources: ["AgentView.tsx:803", "AgentView.tsx:808"],
  },
  {
    id: "agent-policy",
    group: "Agent",
    name: "Approval policy",
    description: "Host and session tiers, exact prompt exceptions, learned rules, and the decision log live behind the policy badge.",
    icon: "approval",
    sources: ["AgentView.tsx:698", "styles.css:683", "styles.css:726"],
  },
  {
    id: "agent-settings",
    group: "Agent",
    name: "Agent settings",
    description: "Mode, model-facing configuration, and context usage appear only when the connected agent exposes them.",
    icon: "settings",
    sources: ["AgentView.tsx:1078", "styles.css:2408"],
  },
  {
    id: "agent-slash-menu",
    group: "Agent",
    name: "Slash commands",
    description: "Typing slash opens the agent-provided command menu directly above the composer with aligned names and descriptions.",
    icon: "agent",
    sources: ["AgentView.tsx:1128", "styles.css:2471"],
  },
  {
    id: "agent-permission-routine",
    group: "Agent",
    name: "Routine permission",
    description: "A neutral execute approval with fixed Allow/Reject positions, provider-wide standing grant, exact local grant, and Dismiss.",
    icon: "approval",
    sources: ["AgentView.tsx:940", "lib/approval.ts:1", "styles.css:2211"],
  },
  {
    id: "agent-permission-standing",
    group: "Agent",
    name: "Standing grant armed",
    description: "The first tap arms the provider-wide grant; the second confirms it. Amber is reserved for this persistent scope.",
    icon: "approval",
    sources: ["AgentView.tsx:1004", "styles.css:2350"],
  },
  {
    id: "agent-permission-broad-root",
    group: "Agent",
    name: "Unscoped workspace root",
    description: "An ordinary read still prompts because the agent's sandbox root is the whole home folder, so no policy tier applies. Amber, not red - a misconfiguration, not a secret leaving.",
    icon: "approval",
    sources: ["AgentView.tsx:1195", "lib/policy.ts:419", "styles.css:2662"],
  },
  {
    id: "agent-permission-credential",
    group: "Agent",
    name: "Credential-shaped read",
    description: "Reading an SSH key turns the card into a red data-risk warning because approving can hand a secret to the model.",
    icon: "approval",
    sources: ["AgentView.tsx:952", "lib/policy.ts:291", "styles.css:2206"],
  },
  {
    id: "agent-permission-destructive",
    group: "Agent",
    name: "Destructive permission",
    description: "Destructive and unknown tool categories receive the same explicit risk treatment instead of routine-card styling.",
    icon: "approval",
    sources: ["AgentView.tsx:958", "styles.css:2245"],
  },
  {
    id: "home-approvals-waiting",
    group: "Home",
    name: "Approvals waiting, not hijacked",
    description:
      "Two agents are waiting on a decision while the user stays on the home screen. Auto-attach is gated on a notification tap, so an approval arriving during ordinary use no longer drags the view into an agent - being pulled off home while starting a session or switching hosts fought the user, and it repeated on every return. The notice is the session card itself going amber - border, tint and glow - so it names WHICH agent and a tap is unambiguous. There is deliberately no header count badge: it could only jump to one session, guessed as the oldest, which is how the old hijack felt in miniature.",
    icon: "approval",
    sources: ["App.tsx:2640", "App.tsx:3531", "styles.css:651"],
  },
  {
    id: "home-approvals-crowded",
    group: "Home",
    name: "Approvals waiting, worst case",
    description:
      "Four agents waiting in a row, two of them with more than one request. This is the stress test for the amber treatment: two separated cards always look fine, so the question is whether adjacent 18px glows bleed into one wash where nothing stands out. Judge this state, not the tidy one.",
    icon: "approval",
    sources: ["styles.css:651", "App.tsx:3531"],
  },
  {
    id: "agent-notification-banner",
    group: "Agent",
    name: "OS notification",
    description:
      "The lock-screen banner for one pending approval. iOS chrome, not Portty UI - the app only supplies a title and body, so the copy is the whole design. Deliberately carries no tool name, command, path or host: a banner is readable by whoever holds the phone. Text is rendered by the shipping pendingApprovalMessage(), so it cannot drift from the device.",
    icon: "approval",
    sources: ["lib/notify.ts:1", "preview-phone.tsx:1", "preview-phone.css:61"],
  },
  {
    id: "agent-notification-stack",
    group: "Agent",
    name: "OS notification, several waiting",
    description:
      "The same banner pluralised for three pending approvals - the count is the only thing that varies, since the detail stays sealed behind the app lock.",
    icon: "approval",
    sources: ["lib/notify.ts:1", "preview-phone.tsx:1"],
  },
  {
    id: "agent-permission-stack",
    group: "Agent",
    name: "Two approvals pending",
    description: "Multiple cards remain in a bounded, fixed layer above the composer and scroll independently from the conversation.",
    icon: "approval",
    sources: ["AgentView.tsx:940", "styles.css:2192"],
  },
  {
    id: "lock",
    group: "Security",
    name: "Biometric lock",
    description: "The real fail-closed cold-start gate prevents the app and its host connection from mounting before authentication.",
    icon: "lock",
    sources: ["BiometricGate.tsx:99", "BiometricGate.tsx:151", "styles.css:1498"],
  },
  {
    id: "lock-error",
    group: "Security",
    name: "Authentication canceled",
    description: "A canceled or failed prompt keeps the app locked and provides an explicit retry action.",
    icon: "lock",
    sources: ["BiometricGate.tsx:79", "BiometricGate.tsx:178"],
  },
];

const devices: Record<string, DevicePreset> = {
  "iphone-16-pro": { label: "iPhone 16 Pro", width: 402, height: 874, dpr: 3 },
  "iphone-16": { label: "iPhone 15/16", width: 393, height: 852, dpr: 3 },
  "iphone-se": { label: "iPhone SE", width: 375, height: 667, dpr: 2 },
  android: { label: "Android", width: 360, height: 800, dpr: 3 },
  desktop: { label: "Tauri desktop", width: 420, height: 840, dpr: 1 },
};

const iconPaths: Record<StateIcon, string> = {
  home: '<path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v10h13V10"/><path d="M9.5 20v-6h5v6"/>',
  host: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
  pair: '<path d="M10 13a5 5 0 0 0 7.5.5l2.5-2.5a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7.5-.5L4 13a5 5 0 0 0 7 7l1.5-1.5"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  keys: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 9h.01M10 9h.01M14 9h.01M18 9h.01M7 13h.01M11 13h.01M15 13h.01M18 13h.01M7 16h10"/>',
  agent: '<path d="M12 8V4H8"/><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M2 14h2M20 14h2M9 13v2M15 13v2"/>',
  approval: '<path d="M12 3 3.8 6.5v5.2c0 4.6 3.5 7.5 8.2 9.3 4.7-1.8 8.2-4.7 8.2-9.3V6.5Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V21h-4v-.1A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H3v-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3V3h4v.1A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1H21v4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
};

const tokenDefaults = [
  ["--bg", "#000000", "Background"],
  ["--surface-1", "#0d0d0f", "Surface 1"],
  ["--surface-2", "#16161a", "Surface 2"],
  ["--surface-3", "#1f1f24", "Surface 3"],
  ["--text-1", "#f4f4f5", "Primary text"],
  ["--text-2", "#a1a1aa", "Secondary text"],
  ["--text-3", "#82828c", "Tertiary text"],
  ["--lime", "#95c247", "Lime"],
  ["--lime-bright", "#b0d472", "Lime bright"],
  ["--lime-deep", "#5f8a2a", "Lime deep"],
  ["--amber", "#fbbf24", "Amber"],
  // Risk red composites from a small set rather than one value, so the picker
  // exposes the steps that actually appear on a card. `--red-rgb` /
  // `--red-deep-rgb` are the alpha-compositing forms of --red / --red-deep and
  // are not colour-pickable, so changing a swatch here previews the solid
  // surfaces; the real edit is the token block in src/styles.css.
  ["--red", "#fb7185", "Red"],
  ["--red-deep", "#881337", "Red deep"],
  ["--red-100", "#ffe4e6", "Red text"],
  ["--red-300", "#fda4af", "Red text dim"],
] as const;

const groups: StateGroup[] = ["Home", "Pairing", "Terminal", "Agent", "Security"];
const root = document.documentElement;
const phoneFrame = must<HTMLIFrameElement>("phone-frame");
const stateList = must<HTMLElement>("state-list");
const deviceSelect = must<HTMLSelectElement>("device-select");
const loading = must<HTMLElement>("frame-loading");
const canvas = must<HTMLElement>("preview-canvas");
const tokenControls = must<HTMLElement>("token-controls");
const search = must<HTMLInputElement>("state-search");

let selected = states.find((item) => item.id === location.hash.slice(1)) ?? states[0];
let deviceKey = deviceSelect.value;
let fitZoom = true;
let zoom = 0.72;
let inspectOn = false;
let textEditOn = false;
let inspectedElement: HTMLElement | null = null;
let toastTimer = 0;
const tokenOverrides = new Map<string, string>();

function must<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`#${id} not found`);
  return element as T;
}

function stateIcon(icon: StateIcon): string {
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${iconPaths[icon]}</svg>`;
}

function showToast(message: string): void {
  const toast = must<HTMLElement>("workbench-toast");
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 2200);
}

function renderStateList(filter = ""): void {
  const needle = filter.trim().toLowerCase();
  stateList.replaceChildren();
  let visible = 0;
  for (const group of groups) {
    const matches = states.filter(
      (item) =>
        item.group === group &&
        (!needle || `${item.name} ${item.description} ${item.id}`.toLowerCase().includes(needle)),
    );
    if (matches.length === 0) continue;
    visible += matches.length;
    const section = document.createElement("section");
    section.className = "state-group";
    const heading = document.createElement("h2");
    heading.className = "state-group-title";
    heading.textContent = group;
    section.append(heading);
    for (const item of matches) {
      const index = states.indexOf(item) + 1;
      const button = document.createElement("button");
      button.type = "button";
      button.className = `state-button${item.id === selected.id ? " is-active" : ""}`;
      button.dataset.state = item.id;
      button.innerHTML = `
        <span class="state-button-icon">${stateIcon(item.icon)}</span>
        <span class="state-button-label">${item.name}</span>
        <small>${String(index).padStart(2, "0")}</small>
      `;
      button.addEventListener("click", () => selectState(item));
      section.append(button);
    }
    stateList.append(section);
  }
  must<HTMLElement>("state-count").textContent = `${visible}/${states.length}`;
}

function renderInspector(): void {
  const index = states.indexOf(selected) + 1;
  must<HTMLElement>("frame-index").textContent = String(index).padStart(2, "0");
  must<HTMLElement>("frame-name").textContent = selected.name;
  must<HTMLElement>("state-icon").innerHTML = stateIcon(selected.icon);
  must<HTMLElement>("state-title").textContent = selected.name;
  must<HTMLElement>("state-id").textContent = selected.id;
  must<HTMLElement>("state-description").textContent = selected.description;

  const links = must<HTMLElement>("source-links");
  links.replaceChildren();
  for (const source of selected.sources) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = source;
    button.title = "Copy source location";
    button.addEventListener("click", () => {
      const path = `app/src/${source}`;
      void navigator.clipboard.writeText(path).then(() => showToast(`Copied ${path}`));
    });
    links.append(button);
  }
}

function loadFrame(force = false): void {
  loading.className = "frame-loading";
  loading.innerHTML = "<span></span>Loading real app state…";
  clearSelection();
  const query = new URLSearchParams({ scenario: selected.id, device: deviceKey });
  if (force) query.set("reload", String(Date.now()));
  phoneFrame.src = `/preview-phone.html?${query}`;
  must<HTMLAnchorElement>("open-phone").href = `/preview-phone.html?${new URLSearchParams({
    scenario: selected.id,
    device: deviceKey,
  })}`;
  history.replaceState(null, "", `#${selected.id}`);
}

function selectState(item: PreviewState): void {
  if (item.id === selected.id) {
    loadFrame(true);
    return;
  }
  selected = item;
  renderStateList(search.value);
  renderInspector();
  loadFrame();
  stateList.querySelector(`[data-state="${CSS.escape(item.id)}"]`)?.scrollIntoView({ block: "nearest" });
}

function currentDevice(): DevicePreset {
  return devices[deviceKey] ?? devices["iphone-16-pro"];
}

function fitScale(): number {
  const preset = currentDevice();
  const bounds = canvas.getBoundingClientRect();
  const maxWidth = Math.max(260, bounds.width - 150);
  const maxHeight = Math.max(360, bounds.height - 132);
  return Math.min(1, Math.max(0.32, Math.min(maxWidth / (preset.width + 16), maxHeight / (preset.height + 16))));
}

function applyDevice(): void {
  const preset = currentDevice();
  document.body.dataset.device = deviceKey;
  root.style.setProperty("--device-width", `${preset.width}px`);
  root.style.setProperty("--device-height", `${preset.height}px`);
  if (fitZoom) zoom = fitScale();
  applyZoom();
  must<HTMLElement>("frame-size").textContent = `${preset.width} × ${preset.height}`;
  deviceSelect.title = `${preset.label}: ${preset.width * preset.dpr} × ${preset.height * preset.dpr} physical at ${preset.dpr}×`;
}

function applyZoom(): void {
  zoom = Math.min(1.25, Math.max(0.3, zoom));
  root.style.setProperty("--device-scale", String(zoom));
  must<HTMLButtonElement>("zoom-value").textContent = fitZoom ? `Fit · ${Math.round(zoom * 100)}%` : `${Math.round(zoom * 100)}%`;
}

function setToggle(id: string, on: boolean): void {
  must<HTMLButtonElement>(id).setAttribute("aria-pressed", String(on));
}

function frameDocument(): Document | null {
  try {
    return phoneFrame.contentDocument;
  } catch {
    return null;
  }
}

function applyTokenOverrides(): void {
  const document = frameDocument();
  if (!document) return;
  for (const [name, value] of tokenOverrides) document.documentElement.style.setProperty(name, value);
}

function renderTokens(): void {
  tokenControls.replaceChildren();
  for (const [name, fallback, label] of tokenDefaults) {
    const row = document.createElement("div");
    row.className = "token-row";
    const input = document.createElement("input");
    input.type = "color";
    input.value = tokenOverrides.get(name) ?? fallback;
    input.id = `token-${name.slice(2)}`;
    input.setAttribute("aria-label", `${label} color`);
    const text = document.createElement("label");
    text.htmlFor = input.id;
    text.textContent = label;
    const value = document.createElement("code");
    value.textContent = input.value.toUpperCase();
    input.addEventListener("input", () => {
      tokenOverrides.set(name, input.value);
      value.textContent = input.value.toUpperCase();
      applyTokenOverrides();
    });
    row.append(input, text, value);
    tokenControls.append(row);
  }
}

function clearSelection(): void {
  inspectedElement?.classList.remove("portty-preview-inspected");
  inspectedElement = null;
  must<HTMLElement>("empty-selection").hidden = false;
  must<HTMLElement>("selection-data").hidden = true;
}

function describeSelection(element: HTMLElement): void {
  inspectedElement?.classList.remove("portty-preview-inspected");
  inspectedElement = element;
  element.classList.add("portty-preview-inspected");

  const style = element.ownerDocument.defaultView?.getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  must<HTMLElement>("empty-selection").hidden = true;
  must<HTMLElement>("selection-data").hidden = false;
  must<HTMLElement>("selected-element").textContent = element.tagName.toLowerCase();
  must<HTMLElement>("selected-class").textContent = [...element.classList]
    .filter((name) => name !== "portty-preview-inspected")
    .join(".") || "—";
  must<HTMLElement>("selected-size").textContent = `${rect.width.toFixed(1)} × ${rect.height.toFixed(1)} px`;
  must<HTMLElement>("selected-font").textContent = style
    ? `${style.fontSize} / ${style.lineHeight} · ${style.fontWeight}`
    : "—";
  must<HTMLElement>("selected-color").textContent = style ? style.color : "—";
  must<HTMLElement>("selected-padding").textContent = style
    ? `${style.paddingTop} ${style.paddingRight} ${style.paddingBottom} ${style.paddingLeft}`
    : "—";
  must<HTMLElement>("selected-radius").textContent = style ? style.borderRadius : "—";
}

function installFrameTools(): void {
  const document = frameDocument();
  if (!document) return;
  applyTokenOverrides();
  document.designMode = textEditOn ? "on" : "off";
  document.body.style.cursor = inspectOn ? "crosshair" : "";
  document.addEventListener(
    "click",
    (event) => {
      if (!inspectOn) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      const target = event.target;
      const FrameHTMLElement = document.defaultView?.HTMLElement;
      const FrameSVGElement = document.defaultView?.SVGElement;
      if (FrameHTMLElement && target instanceof FrameHTMLElement) {
        describeSelection(target as HTMLElement);
      } else if (
        FrameSVGElement &&
        target instanceof FrameSVGElement &&
        (target as SVGElement).parentElement
      ) {
        describeSelection((target as SVGElement).parentElement!);
      }
    },
    true,
  );
}

function changeInspect(on: boolean): void {
  inspectOn = on;
  if (on && textEditOn) changeTextEdit(false);
  setToggle("inspect-toggle", on);
  const document = frameDocument();
  if (document) document.body.style.cursor = on ? "crosshair" : "";
  if (!on) clearSelection();
  must<HTMLElement>("inspect-help").textContent = on
    ? "Click any rendered element in the phone."
    : "Turn on Inspect, then click inside the phone.";
}

function changeTextEdit(on: boolean): void {
  textEditOn = on;
  if (on && inspectOn) changeInspect(false);
  setToggle("text-toggle", on);
  const document = frameDocument();
  if (document) document.designMode = on ? "on" : "off";
  if (on) showToast("Rendered copy is temporarily editable; reload to reset it.");
}

deviceSelect.addEventListener("change", () => {
  deviceKey = deviceSelect.value;
  applyDevice();
  loadFrame();
});

must<HTMLButtonElement>("zoom-out").addEventListener("click", () => {
  fitZoom = false;
  zoom -= 0.05;
  applyZoom();
});

must<HTMLButtonElement>("zoom-in").addEventListener("click", () => {
  fitZoom = false;
  zoom += 0.05;
  applyZoom();
});

must<HTMLButtonElement>("zoom-value").addEventListener("click", () => {
  fitZoom = true;
  zoom = fitScale();
  applyZoom();
});

must<HTMLButtonElement>("grid-toggle").addEventListener("click", () => {
  const on = document.body.classList.toggle("is-grid-visible");
  setToggle("grid-toggle", on);
});

must<HTMLButtonElement>("inspect-toggle").addEventListener("click", () => changeInspect(!inspectOn));
must<HTMLButtonElement>("text-toggle").addEventListener("click", () => changeTextEdit(!textEditOn));
must<HTMLButtonElement>("reload-frame").addEventListener("click", () => loadFrame(true));

must<HTMLButtonElement>("reset-tokens").addEventListener("click", () => {
  tokenOverrides.clear();
  const document = frameDocument();
  if (document) for (const [name] of tokenDefaults) document.documentElement.style.removeProperty(name);
  renderTokens();
  showToast("Token experiments reset to src/styles.css.");
});

must<HTMLButtonElement>("copy-css").addEventListener("click", () => {
  const values = tokenDefaults.map(
    ([name, fallback]) => `  ${name}: ${tokenOverrides.get(name) ?? fallback};`,
  );
  const css = `:root {\n${values.join("\n")}\n}`;
  void navigator.clipboard.writeText(css).then(() => showToast("Copied token overrides."));
});

search.addEventListener("input", () => renderStateList(search.value));

window.addEventListener("keydown", (event) => {
  const editing = event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement;
  if (event.key === "/" && !editing) {
    event.preventDefault();
    search.focus();
    return;
  }
  if (event.key === "Escape") {
    if (document.activeElement === search && search.value) {
      search.value = "";
      renderStateList();
      return;
    }
    changeInspect(false);
    changeTextEdit(false);
    return;
  }
  if (editing || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
  event.preventDefault();
  const current = states.indexOf(selected);
  const delta = event.key === "ArrowDown" ? 1 : -1;
  const next = states[(current + delta + states.length) % states.length];
  selectState(next);
});

window.addEventListener("resize", () => {
  if (!fitZoom) return;
  zoom = fitScale();
  applyZoom();
});

window.addEventListener("message", (event) => {
  if (event.origin !== window.location.origin || event.source !== phoneFrame.contentWindow) return;
  const data = event.data as { type?: string; scenario?: string; message?: string };
  if (data.scenario !== selected.id) return;
  if (data.type === "portty-preview-ready") {
    loading.classList.add("is-ready");
    installFrameTools();
  } else if (data.type === "portty-preview-error") {
    loading.className = "frame-loading is-error";
    loading.textContent = data.message ?? "The fixture could not reach this state.";
  }
});

phoneFrame.addEventListener("load", () => {
  // HMR can reload the frame without a state change. Reapply temporary tools as
  // soon as the new same-origin document exists; the fixture's ready message
  // follows once its deterministic navigation has settled.
  applyTokenOverrides();
});

renderStateList();
renderInspector();
renderTokens();
applyDevice();
loadFrame();
