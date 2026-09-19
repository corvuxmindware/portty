// Display sanitizer for text the phone did not choose.
//
// Agent prose, tool titles, tool detail, plan items, and the option labels on an
// approval card are all written by the model or the ACP adapter. SolidJS escapes
// HTML for us, so markup injection is not the risk here - what IS the risk is
// text that renders as something other than what it says:
//
//   - Bidi embeddings, overrides, and isolates (U+202A..U+202E, U+2066..U+2069)
//     reorder a run visually. "rm <RLO>gpj.esraperp" reads as a harmless image
//     name while the bytes being approved say something else. This is the classic
//     filename-spoofing trick, and an approval card is exactly where it pays off.
//   - Zero-width and invisible characters hide characters inside a command or
//     path, so what the user reads is not what the rule they save will match.
//   - C0/C1 controls have no business in a label; a newline in a one-line title
//     silently truncates what the user sees.
//
// So: drop them. This is display-only. Rule matching keeps the raw canonical
// input (see policy.ts `exactAllowRule`), which independently refuses control
// characters - a sanitized string must never be what we compare or send.

// Written as explicit escapes on purpose: the characters these match are
// invisible, so spelling them literally would make this file unreviewable.
/** Bidi marks, embeddings, overrides, isolates, and the Arabic letter mark. */
const BIDI = /[\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/gu;
/** Zero-width space/non-joiner/joiner, word joiner, BOM. */
const INVISIBLE = /[\u200b-\u200d\u2060\ufeff]/gu;
/** C0 except tab (09) and newline (0a), plus DEL and the C1 range. */
const CONTROLS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/gu;

/**
 * Sanitize multi-line text (assistant prose, tool detail) for display. Tabs and
 * newlines are real structure and are kept; CR is not (it only ever arrives as
 * part of a line ending we do not need).
 */
export function safeText(text: string): string {
  return text.replace(BIDI, "").replace(INVISIBLE, "").replace(CONTROLS, "");
}

/**
 * Sanitize text that must render as ONE line - a tool title, an option label, a
 * session name. Beyond `safeText`, any run of whitespace becomes a single space,
 * so an embedded newline cannot push the rest of a command out of view.
 */
export function safeLine(text: string): string {
  return safeText(text).replace(/\s+/gu, " ").trim();
}
