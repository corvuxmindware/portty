/**
 * Local xterm modes used to render an authoritative PTY on a differently sized
 * phone grid. These bytes are written only to xterm; they never reach the host.
 */

/**
 * A fit-to-phone grid can soft-wrap before the host PTY does. Enable DEC reverse
 * wraparound there so a host `BS SP BS` erase can cross that phone-only wrap.
 * Match mode uses the host's real grid and therefore keeps normal behavior.
 */
export function localDisplayModeSequence(matchesHostGrid: boolean): string {
  return matchesHostGrid ? "\x1b[?45l" : "\x1b[?45h";
}

/**
 * The text a user currently SEES: the viewport rows (honors scrollback
 * position), right-trimmed, with trailing blank rows dropped. Backs the
 * "Copy screen" action - grabbing a build error or URL without needing a
 * working touch selection.
 *
 * Rows marked `isWrapped` are re-joined to their logical line: a long command
 * soft-wrapped over three grid rows must copy as ONE line - a newline injected
 * at a visual wrap point would run a pasted command in pieces.
 */
export function visibleScreenText(
  buffer: {
    viewportY: number;
    getLine(
      y: number,
    ): { isWrapped: boolean; translateToString(trimRight?: boolean): string } | undefined;
  },
  rows: number,
): string {
  const lines: string[] = [];
  for (let y = 0; y < rows; y++) {
    const line = buffer.getLine(buffer.viewportY + y);
    const text = line?.translateToString(true) ?? "";
    // A continuation row glues onto the line above. (When the start of the
    // logical line is scrolled off-screen, y === 0 still starts a fresh line -
    // copy only what is visible.)
    if (y > 0 && line?.isWrapped) lines[lines.length - 1] += text;
    else lines.push(text);
  }
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}

/**
 * Convert an accumulated one-finger drag into whole xterm scroll lines.
 *
 * Touch scrolling is content-following: dragging DOWN pulls the screen down and
 * uncovers older output, which is a NEGATIVE `scrollLines` amount. Only whole
 * rows are consumed - the sub-row remainder is handed back so a slow drag
 * accumulates instead of quantizing every move event to zero.
 */
export function dragScrollLines(
  accumulatedPx: number,
  rowHeightPx: number,
): { lines: number; remainderPx: number } {
  if (!Number.isFinite(accumulatedPx)) return { lines: 0, remainderPx: 0 };
  if (!(rowHeightPx > 0)) return { lines: 0, remainderPx: accumulatedPx };
  const rows = Math.trunc(accumulatedPx / rowHeightPx);
  if (rows === 0) return { lines: 0, remainderPx: accumulatedPx };
  return { lines: -rows, remainderPx: accumulatedPx - rows * rowHeightPx };
}

/**
 * Whether a one-finger drag should scroll xterm's buffer rather than let the
 * browser pan the container.
 *
 * Match mode makes the container `overflow: auto` so a pinch-zoomed grid can be
 * panned. When the grid actually overflows, that native pan owns the gesture.
 * When it does NOT (fit mode, or a match-mode grid smaller than the container -
 * e.g. an adopted 10-row terminal) nothing would move at all, so the drag is
 * ours and drives the scrollback instead. Vertical-dominant only: a sideways
 * drag stays available for panning a wide grid.
 */
export function shouldDragScroll(
  dx: number,
  dy: number,
  startThresholdPx: number,
  overflowsVertically: boolean,
): boolean {
  if (overflowsVertically) return false;
  return Math.abs(dy) >= startThresholdPx && Math.abs(dy) > Math.abs(dx);
}

/** Scale a terminal font from a two-pointer pinch and keep it readable/bounded. */
export function scaledTerminalFont(
  startFont: number,
  startDistance: number,
  currentDistance: number,
  minFont: number,
  maxFont: number,
): number {
  if (startDistance <= 0 || !Number.isFinite(currentDistance)) {
    return Math.max(minFont, Math.min(maxFont, Math.round(startFont)));
  }
  const scaled = Math.round((startFont * currentDistance) / startDistance);
  return Math.max(minFont, Math.min(maxFont, scaled));
}
