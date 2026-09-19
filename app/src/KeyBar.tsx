import { For, Show } from "solid-js";
import { Icon, type IconName } from "./Icon";

/**
 * The accessory key bar - the thing that makes a phone terminal usable.
 *
 * Phones lack Esc, Tab, arrows, Ctrl, and the CLI punctuation (`| ~ \ / -`) that
 * hides behind long-press on the soft keyboard. This docks those keys above the
 * keyboard. A `Ctrl` latch converts the NEXT soft-keyboard letter into its
 * control byte (Ctrl+C = 0x03), and composes with the arrows for word motion
 * (see lib/keys.ts).
 *
 * TWO TIERS, because one row could never hold them all. The old single row was
 * `overflow-x: auto` with the scrollbar hidden, so ~13 of 21 keys - including
 * every arrow - sat off-screen with nothing indicating they existed.
 *
 *  - The PRIMARY row is what you reach for constantly, and it never scrolls:
 *    the keys share the width with `flex: 1 1 0`, so the row fits by
 *    construction on any phone rather than by pixel arithmetic that breaks on
 *    the next screen size. Height stays a full tap target; only width flexes.
 *  - The PANEL (⋯) is a wrapping grid holding everything else, all visible at
 *    once. It stays open until dismissed, so you can tap several keys in a row.
 *
 * Clipboard lives in the panel as words - deliberately NOT `^C`/`^V`: in a
 * terminal Ctrl+C is SIGINT (the `^C` key sends exactly that) and Ctrl+V is
 * verbatim-insert, so desktop copy/paste chords would be traps on a PTY.
 * `Paste` injects the phone clipboard at whichever surface has the caret;
 * `Select` toggles the text-selection mode (App.tsx) that lets a long-press
 * reach the terminal text.
 *
 * All keys send the exact byte sequence a PTY shell expects; the host is a dumb
 * byte pipe and never interprets them (terminal byte-pipe rule).
 */

interface KeyDef {
  label: string;
  icon?: IconName;
  /** Byte string to send (UTF-8 / ANSI). Modifier keys omit this. */
  send?: string;
  /** Spoken name for screen readers; visual-only icons are aria-hidden. */
  accessibleName: string;
}

/** Always on screen. Kept short so the row never has to scroll. */
const PRIMARY_KEYS: KeyDef[] = [
  { label: "Esc", send: "\x1b", accessibleName: "Escape" },
  { label: "Tab", send: "\t", accessibleName: "Tab" },
  { label: "^C", send: "\x03", accessibleName: "Control C" },
  { label: "", icon: "arrow-left", send: "\x1b[D", accessibleName: "Left arrow" },
  { label: "", icon: "arrow-up", send: "\x1b[A", accessibleName: "Up arrow" },
  { label: "", icon: "arrow-down", send: "\x1b[B", accessibleName: "Down arrow" },
  { label: "", icon: "arrow-right", send: "\x1b[C", accessibleName: "Right arrow" },
];

/**
 * Behind ⋯, grouped. 39 keys in one undifferentiated grid would just trade the
 * old hidden-tail problem for an unscannable wall, so each section is labelled.
 */
const PANEL_GROUPS: Array<{ title: string; keys: KeyDef[] }> = [
  {
    title: "Control",
    keys: [
      { label: "^D", send: "\x04", accessibleName: "Control D" },
      { label: "^Z", send: "\x1a", accessibleName: "Control Z" },
      { label: "^L", send: "\x0c", accessibleName: "Control L" },
      { label: "^A", send: "\x01", accessibleName: "Control A - start of line" },
      { label: "^E", send: "\x05", accessibleName: "Control E - end of line" },
      { label: "^U", send: "\x15", accessibleName: "Control U - clear line" },
      { label: "^K", send: "\x0b", accessibleName: "Control K - kill to end" },
      { label: "^W", send: "\x17", accessibleName: "Control W - kill word back" },
      { label: "^R", send: "\x12", accessibleName: "Control R - history search" },
    ],
  },
  {
    title: "Navigation",
    keys: [
      // VT220 tilde forms, not `ESC [ H`/`ESC [ F`: readline, vim and most TUIs
      // accept these, and they compose with the modifier latches through the
      // same tilde path the page keys use (lib/keys.ts).
      { label: "Home", send: "\x1b[1~", accessibleName: "Home" },
      { label: "End", send: "\x1b[4~", accessibleName: "End" },
      // Full-screen apps scroll themselves - they have no terminal scrollback
      // for the ▲▼ controls to move. Page keys are the portable way to ask a TUI
      // to scroll, and the explicit fallback when a swipe maps to something the
      // app uses for navigation instead.
      { label: "PgUp", send: "\x1b[5~", accessibleName: "Page up" },
      { label: "PgDn", send: "\x1b[6~", accessibleName: "Page down" },
      { label: "Ins", send: "\x1b[2~", accessibleName: "Insert" },
      { label: "Del", send: "\x1b[3~", accessibleName: "Delete forward" },
    ],
  },
  {
    // F1-F4 are SS3; F5 up are CSI tilde, and xterm skips 16 and 22. Needed for
    // TUI menus - htop alone wants F6 (sort) and F9 (kill).
    title: "Function",
    keys: [
      { label: "F1", send: "\x1bOP", accessibleName: "F1" },
      { label: "F2", send: "\x1bOQ", accessibleName: "F2" },
      { label: "F3", send: "\x1bOR", accessibleName: "F3" },
      { label: "F4", send: "\x1bOS", accessibleName: "F4" },
      { label: "F5", send: "\x1b[15~", accessibleName: "F5" },
      { label: "F6", send: "\x1b[17~", accessibleName: "F6" },
      { label: "F7", send: "\x1b[18~", accessibleName: "F7" },
      { label: "F8", send: "\x1b[19~", accessibleName: "F8" },
      { label: "F9", send: "\x1b[20~", accessibleName: "F9" },
      { label: "F10", send: "\x1b[21~", accessibleName: "F10" },
      { label: "F11", send: "\x1b[23~", accessibleName: "F11" },
      { label: "F12", send: "\x1b[24~", accessibleName: "F12" },
    ],
  },
  {
    // Chosen for shell frequency, weighted toward what iOS buries on its `#+=`
    // plane (two taps): `* [ ] { } < > = _ # | ~ \`. `$` and `&` are one tap but
    // far too common to leave off.
    title: "Symbols",
    keys: [
      { label: "/", send: "/", accessibleName: "Slash" },
      { label: "-", send: "-", accessibleName: "Hyphen" },
      { label: "_", send: "_", accessibleName: "Underscore" },
      { label: "|", send: "|", accessibleName: "Pipe" },
      { label: "~", send: "~", accessibleName: "Tilde" },
      { label: "\\", send: "\\", accessibleName: "Backslash" },
      { label: "$", send: "$", accessibleName: "Dollar" },
      { label: "*", send: "*", accessibleName: "Asterisk" },
      { label: "&", send: "&", accessibleName: "Ampersand" },
      { label: "=", send: "=", accessibleName: "Equals" },
      { label: "<", send: "<", accessibleName: "Less than" },
      { label: ">", send: ">", accessibleName: "Greater than" },
      { label: "[", send: "[", accessibleName: "Left bracket" },
      { label: "]", send: "]", accessibleName: "Right bracket" },
      { label: "{", send: "{", accessibleName: "Left brace" },
      { label: "}", send: "}", accessibleName: "Right brace" },
      { label: "#", send: "#", accessibleName: "Hash" },
      { label: "..", send: "..", accessibleName: "Dot dot" },
    ],
  },
];

export function KeyBar(props: {
  onKey: (s: string) => void;
  ctrl: boolean;
  onToggleCtrl: () => void;
  alt: boolean;
  onToggleAlt: () => void;
  selectMode: boolean;
  onToggleSelect: () => void;
  onPaste: () => void;
  expanded: boolean;
  onToggleExpanded: () => void;
}) {
  return (
    <div class="portty-keybar-wrap">
      <Show when={props.expanded}>
        <div class="portty-keypanel" role="group" aria-label="More terminal keys">
          <section class="portty-keypanel-group">
            <h2 class="portty-keypanel-title">Clipboard</h2>
            <div class="portty-keypanel-grid">
              <button
                class="portty-key portty-key-wide"
                onClick={props.onPaste}
                aria-label="Paste the clipboard"
              >
                Paste
              </button>
              <button
                class={`portty-key portty-key-wide ${props.selectMode ? "portty-key-active" : ""}`}
                onClick={props.onToggleSelect}
                aria-pressed={props.selectMode}
                aria-label="Select text - long-press the terminal to select and copy"
              >
                Select
              </button>
            </div>
          </section>
          <For each={PANEL_GROUPS}>
            {(group) => (
              <section class="portty-keypanel-group">
                <h2 class="portty-keypanel-title">{group.title}</h2>
                <div class="portty-keypanel-grid">
                  <For each={group.keys}>
                    {(k) => (
                      <button
                        class="portty-key"
                        onClick={() => props.onKey(k.send!)}
                        aria-label={k.accessibleName}
                      >
                        {k.icon ? <Icon name={k.icon} /> : k.label}
                      </button>
                    )}
                  </For>
                </div>
              </section>
            )}
          </For>
        </div>
      </Show>

      <div class="portty-keybar" role="toolbar" aria-label="Terminal keys">
        <button
          class={`portty-key ${props.ctrl ? "portty-key-active" : ""}`}
          onClick={props.onToggleCtrl}
          aria-pressed={props.ctrl}
          aria-label="Control modifier - makes the next key a Ctrl combination"
        >
          Ctrl
        </button>
        {/* Next to Ctrl because they compose: arming both sends Ctrl+Alt. Alt is
            the readline Meta key - Alt+B/F walk by word, Alt+. recalls the last
            argument - so it earns a primary slot despite needing a letter from
            the soft keyboard, which is already up whenever you'd reach for it. */}
        <button
          class={`portty-key ${props.alt ? "portty-key-active" : ""}`}
          onClick={props.onToggleAlt}
          aria-pressed={props.alt}
          aria-label="Alt modifier - makes the next key an Alt (Meta) combination"
        >
          Alt
        </button>
        <For each={PRIMARY_KEYS}>
          {(k) => (
            <button
              class="portty-key"
              onClick={() => props.onKey(k.send!)}
              aria-label={k.accessibleName}
            >
              {k.icon ? <Icon name={k.icon} /> : k.label}
            </button>
          )}
        </For>
        <button
          class={`portty-key ${props.expanded ? "portty-key-active" : ""}`}
          onClick={props.onToggleExpanded}
          aria-expanded={props.expanded}
          aria-label={props.expanded ? "Hide more keys" : "Show more keys"}
        >
          <Icon name="more" />
        </button>
      </div>
    </div>
  );
}
