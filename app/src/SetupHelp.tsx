import { createSignal, For, onCleanup, Show } from "solid-js";
import { Icon } from "./Icon";
import {
  defaultPlatform,
  INSTALL_OPTIONS,
  installOption,
  platformAfterKey,
  type Platform,
} from "./lib/setupHelp";
import "./SetupHelp.css";

/**
 * Home's first-run card: put Portty on the computer, then pair.
 *
 * App.tsx shows it in place of the plain empty state once the saved hosts have
 * been read and there are none. That is the moment a new user - or a Play
 * reviewer - opens the app with no idea that it needs a program on the
 * computer, or where to get one. The pairing steps say what the pair screen's
 * hint says, so the two screens never disagree.
 */

// App-wide rather than per card: Home unmounts whenever the pair screen opens,
// and someone who chose Linux, went to look, and came back should still see
// Linux.
const [platform, setPlatform] = createSignal<Platform>(
  defaultPlatform(typeof navigator === "undefined" ? "" : navigator.userAgent),
);

const tabId = (option: Platform) => `portty-setup-tab-${option}`;
const PANEL_ID = "portty-setup-panel";

type CopyResult = "" | "copied" | "failed";
const COPY_LABEL: Record<CopyResult, string> = {
  "": "Copy",
  copied: "Copied",
  failed: "Copy failed",
};

export function SetupHelp(props: {
  /** Puts text on the clipboard; resolves `false` when it could not. */
  copy: (text: string) => Promise<boolean>;
  /** Opens the setup guide in the system browser. */
  onOpenGuide: () => void;
}) {
  // What the last Copy tap did, shown on the button for a moment.
  const [copyResult, setCopyResult] = createSignal<CopyResult>("");
  let resetTimer: number | undefined;
  onCleanup(() => window.clearTimeout(resetTimer));

  const option = () => installOption(platform());

  const choose = (next: Platform) => {
    setPlatform(next);
    // "Copied" was about the command that just went away.
    window.clearTimeout(resetTimer);
    setCopyResult("");
  };

  const copyCommand = async () => {
    const copying = platform();
    const ok = await props.copy(installOption(copying).command);
    // Switched tabs meanwhile: the result is about a command no longer shown.
    if (platform() !== copying) return;
    setCopyResult(ok ? "copied" : "failed");
    window.clearTimeout(resetTimer);
    resetTimer = window.setTimeout(() => setCopyResult(""), 2000);
  };

  // Only the chosen tab is in the Tab order; the arrow keys move between tabs
  // (see platformAfterKey), so a hardware keyboard reaches all three.
  const onTabKey = (event: KeyboardEvent) => {
    const next = platformAfterKey(platform(), event.key);
    if (!next) return;
    event.preventDefault();
    choose(next);
    document.getElementById(tabId(next))?.focus();
  };

  return (
    <section class="portty-setup" aria-labelledby="portty-setup-title">
      <div class="portty-empty-glyph portty-setup-glyph" aria-hidden="true">
        &gt;_
      </div>
      <div class="portty-card portty-setup-card">
        <h2 id="portty-setup-title" class="portty-setup-title">
          First, put Portty on your computer
        </h2>
        <div class="portty-setup-tabs" role="tablist" aria-label="Your computer">
          <For each={INSTALL_OPTIONS}>
            {(item) => {
              const selected = () => platform() === item.platform;
              return (
                <button
                  type="button"
                  role="tab"
                  id={tabId(item.platform)}
                  class="portty-setup-tab"
                  classList={{ "portty-setup-tab--on": selected() }}
                  aria-selected={selected()}
                  aria-controls={PANEL_ID}
                  tabIndex={selected() ? 0 : -1}
                  onClick={() => choose(item.platform)}
                  onKeyDown={onTabKey}
                >
                  {item.label}
                </button>
              );
            }}
          </For>
        </div>
        <div
          id={PANEL_ID}
          role="tabpanel"
          aria-labelledby={tabId(platform())}
          class="portty-setup-panel"
        >
          <p class="portty-setup-text">Open a terminal there and run:</p>
          <div class="portty-setup-command">
            {/* Wraps instead of scrolling: people often type it on the computer
                while reading it here, so all of it has to be in view. */}
            <code>{option().command}</code>
            <button
              type="button"
              class="portty-setup-copy"
              classList={{ "portty-setup-copy--done": copyResult() === "copied" }}
              onClick={() => void copyCommand()}
            >
              <Show when={copyResult() === "copied"}>
                <Icon name="check" />
              </Show>
              {COPY_LABEL[copyResult()]}
            </button>
          </div>
          {/* The button's new label is not announced by itself. */}
          <span class="sr-only" role="status">
            {copyResult() ? COPY_LABEL[copyResult()] : ""}
          </span>
        </div>
        <p class="portty-setup-text">Then:</p>
        <ol class="portty-setup-steps">
          <li>
            Start <code>portty-host</code>, then run <code>portty pair</code>.
          </li>
          <li>Tap “Connect to a host” below and scan the QR.</li>
          <li>
            Check that both screens show the same code, then type <code>y</code> on the
            computer.
          </li>
        </ol>
        <button
          type="button"
          class="portty-btn-ghost portty-btn-with-icon portty-setup-guide"
          onClick={() => props.onOpenGuide()}
        >
          <Icon name="external-link" />
          Setup guide
        </button>
      </div>
    </section>
  );
}
