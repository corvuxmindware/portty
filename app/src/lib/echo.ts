/**
 * Predictive local echo - mosh-style, fail-closed.
 *
 * Pure state machine (no xterm/DOM): the caller feeds keystrokes and
 * authoritative output, and gets back the provisional bytes to write. That
 * keeps every safety rule unit-testable.
 *
 * Activation rules (ALL must hold before a keystroke is predicted):
 *  - confidence ≥ 3: the remote PTY has echoed our recent keystrokes back
 *  - measured RTT ≥ 120 ms: on fast links prediction stays completely off
 *  - not in a sensitive prompt (echo-off inference below, plus a prompt-text
 *    heuristic supplied by the caller)
 *  - not on the alternate screen, with enough columns remaining for the
 *    grapheme (prediction never crosses a line boundary)
 *  - one printable grapheme with a known terminal width (1 or 2), or backspace
 *
 * Echo-off inference (the mosh timing heuristic): every sent keystroke is
 * remembered; when the oldest entries go unmatched for `staleAfter()` the
 * echo evidently stopped (password prompt, `read -s`, a TUI eating input) -
 * confidence collapses to zero and `sweep()` tells the caller to ERASE any
 * provisional cells so a typed secret never lingers on screen.
 */

const MAX_PENDING = 16;
/** Hard cap on on-screen provisional cells (bounds erase correctness too). */
const MAX_PREDICTED_CELLS = 24;
const MIN_RTT_MS = 120;
const MIN_CONFIDENCE = 3;

/**
 * Fires when the TAIL of recent terminal output looks like a prompt for a
 * secret (a keyword within ~24 chars of the cursor, optional colon, trailing
 * space). English plus a few common locale terms. Conservative on purpose: a
 * false positive costs only a little echo latency, a false negative would flash
 * a typed secret on screen for a frame.
 */
const SENSITIVE_PROMPT_RE =
  /(?:password|passphrase|pass phrase|passcode|pin|secret|otp|one[- ]time(?: password| code)?|verification code|auth(?:entication)? code|api[- ]?key|token|unlock code|mot de passe|passwort|kennwort|contrase(?:ñ|n)a|clave|senha)[^\r\n:]{0,24}:?\s*$/i;

/** Pure predicate over recent output - used to suppress predictive echo at a
 * secret prompt. Exported so it is unit-testable (#48). */
export function isSensitivePrompt(recentOutput: string): boolean {
  return SENSITIVE_PROMPT_RE.test(recentOutput);
}

export interface EchoStats {
  rttMs: number;
  confidence: number;
  predicted: number;
}

interface PredictedGrapheme {
  text: string;
  cells: 1 | 2;
}

const graphemeSegmenter =
  typeof Intl !== "undefined" && "Segmenter" in Intl
    ? new Intl.Segmenter(undefined, { granularity: "grapheme" })
    : null;

function oneGrapheme(text: string): string | null {
  if (!text) return null;
  if (!graphemeSegmenter) return Array.from(text).length === 1 ? text : null;
  const parts = [...graphemeSegmenter.segment(text)];
  return parts.length === 1 && parts[0].segment === text ? text : null;
}

function isWideCodePoint(code: number): boolean {
  return (
    code >= 0x1100 &&
    (code <= 0x115f ||
      code === 0x2329 ||
      code === 0x232a ||
      (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe10 && code <= 0xfe19) ||
      (code >= 0xfe30 && code <= 0xfe6f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6) ||
      (code >= 0x1f1e6 && code <= 0x1f1ff) ||
      (code >= 0x1f300 && code <= 0x1faff) ||
      (code >= 0x20000 && code <= 0x3fffd))
  );
}

/** Terminal cell width for one complete grapheme. Returns null for controls,
 * combining-only input, or a multi-grapheme paste. Ambiguous-width characters
 * stay width 1, matching xterm's default non-CJK locale behavior. */
export function graphemeCellWidth(text: string): 1 | 2 | null {
  const grapheme = oneGrapheme(text);
  if (!grapheme) return null;
  let hasBase = false;
  let wide = grapheme.includes("\u20e3"); // keycap sequence
  for (const scalar of Array.from(grapheme)) {
    const code = scalar.codePointAt(0)!;
    if (code === 0x200d || (code >= 0xfe00 && code <= 0xfe0f) || /\p{Mark}/u.test(scalar)) {
      continue;
    }
    if (code < 0x20 || (code >= 0x7f && code < 0xa0)) return null;
    hasBase = true;
    wide ||= isWideCodePoint(code);
  }
  if (!hasBase) return null;
  return wide ? 2 : 1;
}

function eraseGrapheme(cells: 1 | 2): string {
  // Preserve the compact legacy sequence for ordinary cells. ANSI cursor
  // movement is required for a wide cell because backspace behavior inside a
  // double-width glyph differs between terminal implementations.
  return cells === 1 ? "\b \b" : `\x1b[${cells}D${" ".repeat(cells)}\x1b[${cells}D`;
}

export class PredictiveEcho {
  private confidence = 0;
  private rtt = 0;
  private pending: Array<{ text: string; at: number }> = [];
  private predicted: PredictedGrapheme[] = [];
  private predictedCells = 0;

  /** Remember a keystroke we sent (for RTT sampling + echo-off inference). */
  noteSent(text: string, now: number): void {
    if (graphemeCellWidth(text) !== null || text === "\x7f" || text === "\b") {
      this.pending.push({ text, at: now });
      if (this.pending.length > MAX_PENDING) this.pending.shift();
    }
  }

  /**
   * A keystroke arrives. Returns the provisional bytes to write locally, or
   * null when prediction must stay off. `cellsRemaining` is the number of
   * columns from the cursor through the final column; predictions never wrap.
   */
  onInput(
    d: string,
    opts: { sensitivePrompt: boolean; altScreen: boolean; cellsRemaining: number },
    now: number,
  ): string | null {
    this.expireStale(now);
    if (
      this.confidence < MIN_CONFIDENCE ||
      this.rtt < MIN_RTT_MS ||
      opts.sensitivePrompt ||
      opts.altScreen
    ) {
      return null;
    }
    if (d === "\x7f" || d === "\b") {
      const removed = this.predicted.pop();
      if (!removed) return null;
      this.predictedCells -= removed.cells;
      return eraseGrapheme(removed.cells);
    }
    const cells = graphemeCellWidth(d);
    if (
      cells === null ||
      opts.cellsRemaining < cells ||
      this.predictedCells + cells > MAX_PREDICTED_CELLS
    ) {
      return null;
    }
    this.predicted.push({ text: d, cells });
    this.predictedCells += cells;
    // Dim + underline marks the cells as provisional. The trailing SGR reset
    // is a known, accepted trade-off: it can clobber live SGR state until the
    // next authoritative bytes repaint (they always follow - that's what a
    // confirmation IS).
    return `\x1b[2;4m${d}\x1b[0m`;
  }

  /**
   * Authoritative output arrived. Returns the erase string for any provisional
   * cells (always erase-before-parse), and samples RTT/confidence - matching
   * pending sends strictly IN ORDER, so unrelated output (logs, `cat`) can't
   * inflate confidence with an out-of-order coincidence.
   */
  onOutput(plain: string, now: number): string {
    while (this.pending.length > 0 && plain.includes(this.pending[0].text)) {
      const sample = this.pending.shift()!;
      const rtt = now - sample.at;
      this.rtt = this.rtt === 0 ? rtt : this.rtt * 0.75 + rtt * 0.25;
      this.confidence = Math.min(5, this.confidence + 1);
    }
    this.expireStale(now);
    return this.takeErase();
  }

  /**
   * Periodic check (call on a timer while the terminal is visible). When sent
   * keystrokes have gone unechoed past the deadline, prediction is evidently
   * wrong (echo off / eaten input): collapse confidence and return the erase
   * string for whatever provisional cells are showing - a typed secret must
   * not outlive one sweep.
   */
  sweep(now: number): string {
    this.expireStale(now);
    return this.confidence === 0 ? this.takeErase() : "";
  }

  /**
   * Enter/Ctrl-C/Ctrl-D ends the input context whose echo behaviour we learned.
   * The next process may disable terminal echo for a password without using a
   * prompt string we recognize, so confidence must be rebuilt from zero before
   * any character in that new context can be drawn provisionally.
   */
  commandBoundary(): string {
    this.confidence = 0;
    this.pending = [];
    return this.takeErase();
  }

  /** New session / reconnect / host switch: all learned state is stale. */
  reset(): void {
    this.confidence = 0;
    this.rtt = 0;
    this.pending = [];
    this.predicted = [];
    this.predictedCells = 0;
  }

  stats(): EchoStats {
    return {
      rttMs: Math.round(this.rtt),
      confidence: this.confidence,
      predicted: this.predicted.length,
    };
  }

  /** Unmatched beyond the deadline → the echo stopped: fail closed. */
  private expireStale(now: number): void {
    const deadline = this.staleAfter();
    const hadStale = this.pending.some((p) => now - p.at > deadline);
    if (hadStale) {
      this.pending = this.pending.filter((p) => now - p.at <= deadline);
      this.confidence = 0;
    }
  }

  private staleAfter(): number {
    // Generous multiple of the observed RTT, floored for jittery links.
    return Math.max(1000, this.rtt * 4);
  }

  private takeErase(): string {
    if (this.predicted.length === 0) return "";
    const erase = [...this.predicted].reverse().map((item) => eraseGrapheme(item.cells)).join("");
    this.predicted = [];
    this.predictedCells = 0;
    return erase;
  }
}
