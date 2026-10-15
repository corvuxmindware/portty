/**
 * Keyboard-app typing that is NOT a composition - send exactly what was typed,
 * once, in order.
 *
 * Why this exists (release check S15): on Android, a Bluetooth/USB keyboard key
 * (and `adb shell input text`) goes to the keyboard app first. Gboard eats the
 * key and types the character itself (`commitText`), so the WebView only sees
 * a keydown with keyCode 229 and then the inserted text. Chrome works around
 * that by replaying the real key; the Android System WebView does not.
 *
 * xterm 6.0.0 handles that 229 keydown by snapshotting its hidden textarea,
 * waiting one timer tick, and sending `newValue.replace(oldValue, "")`:
 *  - Fast typing queues several keys before the timers run. Every timer then
 *    diffs against the SAME final value, so text is sent again and again
 *    ("echo" became "echochohoo"). Fixed upstream only after 6.0.0 (xterm.js
 *    #5438 / PR #5439, in the 6.1 betas).
 *  - The diff assumes the new text was added at the END of the textarea. When
 *    it lands anywhere else - after an arrow key, or at the start as on the
 *    test phone - the whole textarea is re-sent or the text comes out
 *    backwards. Not fixed upstream.
 *  - If a composition starts before the timer runs, the timer drops the text.
 * Together with a zero-size textarea (see styles.css) that produced the phone's
 * `ohceohcoho ko-yttro…` for `echo portty-ok`.
 *
 * The browser already says exactly what each edit was: the `input` event's
 * `inputType` and `data`. So for precisely the case where xterm would run that
 * diff, we take the edit from the event instead and send it at once.
 * Compositions (normal soft-keyboard typing, swipe, voice) and real key events
 * (desktop keyboards, Enter, arrows, Ctrl keys) still go through xterm
 * untouched.
 *
 * The hook point is a private xterm method. `installImeEditInput` checks it is
 * there and otherwise leaves xterm alone; `imeInput.test.ts` pins it against
 * the installed xterm so an upgrade cannot silently drop the fix.
 */

import type { Terminal } from "@xterm/xterm";

const DEL = "\x7f";
const FORWARD_DELETE = "\x1b[3~";

/** The parts of an `input`/`beforeinput` event this module reads. */
export interface ImeEditEvent {
  inputType: string;
  data: string | null;
  isComposing: boolean;
}

/** One Backspace in the shell erases one character, not one UTF-16 unit. */
function characterCount(text: string): number {
  return Array.from(text).length;
}

const isHighSurrogate = (code: number) => code >= 0xd800 && code <= 0xdbff;
const isLowSurrogate = (code: number) => code >= 0xdc00 && code <= 0xdfff;

/**
 * What `after` dropped from `before` and what it added, found by trimming the
 * common start and end. Works wherever in the text the edit happened, and
 * never splits an emoji (surrogate pair) in half.
 */
export function textChange(before: string, after: string): { removed: string; inserted: string } {
  let start = 0;
  const shorter = Math.min(before.length, after.length);
  while (start < shorter && before.charCodeAt(start) === after.charCodeAt(start)) start++;
  if (start > 0 && isHighSurrogate(before.charCodeAt(start - 1))) start--;

  let endBefore = before.length;
  let endAfter = after.length;
  while (
    endBefore > start &&
    endAfter > start &&
    before.charCodeAt(endBefore - 1) === after.charCodeAt(endAfter - 1)
  ) {
    endBefore--;
    endAfter--;
  }
  if (endBefore < before.length && isLowSurrogate(before.charCodeAt(endBefore))) {
    endBefore++;
    endAfter++;
  }
  return { removed: before.slice(start, endBefore), inserted: after.slice(start, endAfter) };
}

/** A newline typed by the keyboard app is Enter to the terminal (same rule as xterm's paste). */
function terminalText(text: string): string {
  return text.replace(/\r?\n/g, "\r");
}

/**
 * The bytes for one keyboard-app edit made outside a composition. `before` and
 * `after` are the hidden textarea's value around the edit; they are only used
 * where the event itself does not carry the text.
 */
export function imeEditBytes(
  ev: Pick<ImeEditEvent, "inputType" | "data">,
  before: string,
  after: string,
): string {
  const { removed, inserted } = textChange(before, after);
  switch (ev.inputType) {
    case "insertText":
      // The keyboard app's own record of what it typed: exact, and correct no
      // matter where in the textarea it landed.
      return terminalText(ev.data ?? inserted);
    case "insertLineBreak":
    case "insertParagraph":
      return "\r";
    case "deleteContentBackward":
    case "deleteWordBackward":
    case "deleteSoftLineBackward":
    case "deleteHardLineBackward":
      // The browser only fires this when it removed something; one Backspace
      // per character removed (a "delete word" swipe removes several).
      return DEL.repeat(Math.max(1, characterCount(removed)));
    case "deleteContentForward":
    case "deleteWordForward":
    case "deleteSoftLineForward":
    case "deleteHardLineForward":
      return FORWARD_DELETE.repeat(Math.max(1, characterCount(removed)));
    default:
      // Replacements and anything unusual: erase what went away, then type
      // what came in.
      return DEL.repeat(characterCount(removed)) + terminalText(inserted);
  }
}

const COMPOSITION_INPUT_TYPES = new Set([
  "insertCompositionText",
  "deleteCompositionText",
  "insertFromComposition",
  "deleteByComposition",
]);

/** An edit that belongs to a composition - xterm's composition handling owns it. */
function isCompositionEdit(ev: ImeEditEvent): boolean {
  return ev.isComposing || COMPOSITION_INPUT_TYPES.has(ev.inputType);
}

/**
 * Pairs xterm's "a 229 keydown will change the textarea" with the edit that
 * follows. Pure state, so event sequences are unit-testable without a DOM.
 *
 * Android delivers each keyboard-app edit as keydown 229, the edit, keyup 229,
 * in that order. A window opens at the keydown and closes at the first edit,
 * the keyup, any other key, a composition starting, or blur. Edits outside a
 * window (real keys, compositions, a paste) are never ours to send.
 */
export class ImeEditTracker {
  private pending = false;
  private before = "";

  /** xterm hit a keyCode-229 keydown outside a composition; `value` is the textarea now. */
  imeKeydown(value: string): void {
    this.pending = true;
    this.before = value;
  }

  /** `beforeinput`: take the snapshot again, right before this exact edit. */
  beforeInput(ev: ImeEditEvent, value: string): void {
    if (this.pending && !isCompositionEdit(ev)) this.before = value;
  }

  /** `input`: the bytes for this edit, or null when it is not ours to send. */
  input(ev: ImeEditEvent, value: string): string | null {
    if (!this.pending) return null;
    this.pending = false;
    // A composition started instead: xterm's composition handling owns this
    // text, exactly where xterm's own timer would have stood down too.
    if (isCompositionEdit(ev)) return null;
    const bytes = imeEditBytes(ev, this.before, value);
    return bytes === "" ? null : bytes;
  }

  /** The window is over without an edit. */
  close(): void {
    this.pending = false;
  }
}

/** xterm 6.0.0's private composition helper - only the one method we replace. */
interface CompositionHelperHook {
  _handleAnyTextareaChanges?: () => void;
}

/** Event fields the browser sets on keyboard and input events. */
type KeyLike = Event & { keyCode?: number };
type InputLike = Event & Partial<ImeEditEvent>;

function asImeEditEvent(ev: InputLike): ImeEditEvent {
  return {
    inputType: ev.inputType ?? "",
    data: ev.data ?? null,
    isComposing: ev.isComposing ?? false,
  };
}

/** The xterm surface this needs, so tests can pass a stand-in. */
export type ImeTerminal = Pick<Terminal, "textarea" | "input">;

const HOOK = "_handleAnyTextareaChanges";

/**
 * Route keyboard-app edits made outside a composition through the browser's
 * own record of the edit (see the top of this file). Call once, after
 * `term.open()`. Returns an undo function, or null when this xterm build has no
 * matching hook - then xterm's stock behaviour stays in place.
 */
export function installImeEditInput(term: ImeTerminal): (() => void) | null {
  const textarea = term.textarea;
  const helper = (term as unknown as { _core?: { _compositionHelper?: CompositionHelperHook } })
    ._core?._compositionHelper;
  if (!textarea || !helper || typeof helper[HOOK] !== "function") return null;

  const tracker = new ImeEditTracker();
  const hadOwnHook = Object.prototype.hasOwnProperty.call(helper, HOOK);
  const stockHook = helper[HOOK];
  // xterm calls this only for a keyCode-229 keydown while no composition is
  // active or being sent: the one case its timer-and-diff path handles.
  helper[HOOK] = () => tracker.imeKeydown(textarea.value);

  const onKeyDown = (ev: Event) => {
    if ((ev as KeyLike).keyCode !== 229) tracker.close();
  };
  const onClose = () => tracker.close();
  const onBeforeInput = (ev: Event) => tracker.beforeInput(asImeEditEvent(ev), textarea.value);
  const onInput = (ev: Event) => {
    const bytes = tracker.input(asImeEditEvent(ev), textarea.value);
    // The same call xterm's diff made: onData fires, so the Ctrl/Alt latches,
    // predictive echo and the link guard see it exactly like typed keys.
    if (bytes !== null) term.input(bytes, true);
  };
  const listeners: Array<[string, (ev: Event) => void]> = [
    ["keydown", onKeyDown],
    ["keyup", onClose],
    ["compositionstart", onClose],
    ["blur", onClose],
    ["beforeinput", onBeforeInput],
    ["input", onInput],
  ];
  // xterm added its own listeners in `open()`, so these run after it.
  for (const [type, fn] of listeners) textarea.addEventListener(type, fn);

  return () => {
    if (hadOwnHook) helper[HOOK] = stockHook;
    else delete helper[HOOK];
    for (const [type, fn] of listeners) textarea.removeEventListener(type, fn);
  };
}
