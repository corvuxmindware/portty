/**
 * Key encoding for the accessory bar's modifier latches.
 *
 * Pure functions over byte strings (no xterm/DOM) so every mapping is
 * unit-testable, matching the rest of `lib/`. The host is a dumb byte pipe and
 * never interprets any of this - whatever comes out of here is exactly what the
 * PTY receives.
 */

/**
 * xterm modifier parameter: 1 + a bitmask of shift(1), alt(2), ctrl(4).
 * Only the two the key bar can latch are named.
 */
export const MOD_CTRL = 5;
export const MOD_ALT = 3;

/**
 * Ctrl + a single printable character → its control byte.
 *
 * The real ASCII rule, not just letters: `Ctrl` clears bit 6 of everything in
 * `@` through `_`, which is where `Ctrl+[` (ESC), `Ctrl+\` (SIGQUIT), `Ctrl+]`
 * (telnet escape) and `Ctrl+_` (readline undo) come from. Lowercase folds to the
 * same range. Two keys sit outside it and are special-cased by every terminal:
 * `Ctrl+Space` is NUL (readline's set-mark) and `Ctrl+?` is DEL.
 *
 * Returns null when no control byte exists, which is the caller's signal that
 * the latch could not be applied.
 */
export function toCtrlByte(d: string): string | null {
  if (d.length !== 1) return null;
  const c = d.charCodeAt(0);
  if (c === 0x20) return "\x00"; // Ctrl+Space → NUL
  if (c === 0x3f) return "\x7f"; // Ctrl+? → DEL
  if (c >= 0x40 && c <= 0x5f) return String.fromCharCode(c & 0x1f); // @ A-Z [ \ ] ^ _
  if (c >= 0x61 && c <= 0x7a) return String.fromCharCode(c & 0x1f); // a-z
  return null;
}

/**
 * Apply a modifier to one of the key bar's escape sequences.
 *
 * Cursor keys take the `CSI 1 ; <mod> <final>` form and tilde keys (PgUp/PgDn)
 * take `CSI <n> ; <mod> ~`. This is what makes Ctrl+Left/Right - word motion,
 * the single most-used editing gesture in a shell - reachable from a phone.
 *
 * A modified cursor key is ALWAYS the CSI form, even while the application has
 * requested DECCKM cursor mode: the SS3 form (`ESC O A`) has nowhere to put a
 * parameter. Callers must therefore skip their SS3 rewrite whenever this
 * returns non-null.
 *
 * Returns null for sequences with no modified encoding (Esc, Tab, bytes that are
 * already control codes, plain punctuation) - the caller sends those unchanged.
 */
export function withModifier(seq: string, modifier: number): string | null {
  const cursor = /^\x1b\[([A-D])$/.exec(seq);
  if (cursor) return `\x1b[1;${modifier}${cursor[1]}`;
  const tilde = /^\x1b\[(\d+)~$/.exec(seq);
  if (tilde) return `\x1b[${tilde[1]};${modifier}~`;
  return null;
}

/** The latched modifier state the key bar can be in. */
export interface Latches {
  ctrl: boolean;
  alt: boolean;
}

/** Combine latches into the xterm modifier parameter (Ctrl+Alt = 7). */
export function modifierParam(mods: Latches): number {
  return 1 + (mods.alt ? 2 : 0) + (mods.ctrl ? 4 : 0);
}

/**
 * Apply the latches to one typed character.
 *
 * Alt is sent as an ESC PREFIX rather than a parameter - that is the convention
 * readline and every shell built on it expect, and it is what makes the word
 * motions reachable: `Alt+B`/`Alt+F` (word back/forward), `Alt+D` (kill word),
 * `Alt+Backspace` (kill word back) and `Alt+.` (last argument of the previous
 * command, the biggest single typing saver on a phone).
 *
 * Ctrl resolves first so `Ctrl+Alt+X` is ESC followed by the control byte.
 * Multi-character input is returned untouched: latches describe ONE keypress,
 * never a paste.
 */
export function applyLatches(d: string, mods: Latches): string {
  if (d.length !== 1) return d;
  let out = d;
  if (mods.ctrl) out = toCtrlByte(out) ?? out;
  if (mods.alt) out = `\x1b${out}`;
  return out;
}

/**
 * Encode one of the key bar's sequences with the latches applied.
 *
 * Returns null when nothing is latched or the latch has no meaning for this key
 * (Esc, `..`), which is the caller's signal to send the key unchanged - and, for
 * cursor keys, to fall back to its DECCKM/SS3 rewrite. A non-null result is
 * always already in its final form and must NOT be rewritten.
 */
export function modifySequence(seq: string, mods: Latches): string | null {
  if (!mods.ctrl && !mods.alt) return null;
  const csi = withModifier(seq, modifierParam(mods));
  if (csi) return csi;
  const applied = applyLatches(seq, mods);
  return applied === seq ? null : applied;
}
