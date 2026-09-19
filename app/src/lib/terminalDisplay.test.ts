import { Terminal } from "@xterm/xterm";
import { describe, expect, it } from "vitest";
import {
  dragScrollLines,
  localDisplayModeSequence,
  scaledTerminalFont,
  shouldDragScroll,
  visibleScreenText,
} from "./terminalDisplay";

function write(term: Terminal, data: string): Promise<void> {
  return new Promise((resolve) => term.write(data, resolve));
}

describe("fit-mode terminal display", () => {
  it("erases across a phone-only soft wrap", async () => {
    const term = new Terminal({ cols: 20, rows: 4 });

    await write(term, localDisplayModeSequence(false) + "h".repeat(24));
    expect(term.modes.reverseWraparoundMode).toBe(true);
    expect(term.buffer.active.cursorX).toBe(4);
    expect(term.buffer.active.cursorY).toBe(1);
    expect(term.buffer.active.getLine(1)?.isWrapped).toBe(true);

    // A canonical PTY visually erases one input cell with BS, space, BS. The
    // host sends this as one 80-column row even though the phone wrapped at 20.
    await write(term, "\b \b".repeat(24));

    expect(term.buffer.active.cursorX).toBe(0);
    expect(term.buffer.active.cursorY).toBe(0);
    expect(term.buffer.active.getLine(0)?.translateToString(true).trim()).toBe("");
    expect(term.buffer.active.getLine(1)?.translateToString(true).trim()).toBe("");
  });

  it("keeps reverse wraparound off when xterm matches the host grid", async () => {
    const term = new Terminal({ cols: 80, rows: 24 });
    await write(term, localDisplayModeSequence(true));
    expect(term.modes.reverseWraparoundMode).toBe(false);
  });
});

describe("copy visible screen", () => {
  it("captures the viewport rows and drops trailing blank rows", async () => {
    const term = new Terminal({ cols: 20, rows: 6 });
    await write(term, "$ ls\r\nfile.txt  notes.md\r\n$ ");
    // The prompt's typed trailing space survives: translateToString(true)
    // trims only never-written cells, so authored whitespace stays content.
    expect(visibleScreenText(term.buffer.active, term.rows)).toBe("$ ls\nfile.txt  notes.md\n$ ");
  });

  it("re-joins soft-wrapped rows so a wrapped command copies as one line", async () => {
    const term = new Terminal({ cols: 10, rows: 4 });
    await write(term, "$ echo aaaabbbbcccc\r\ndone");
    expect(visibleScreenText(term.buffer.active, term.rows)).toBe("$ echo aaaabbbbcccc\ndone");
  });

  it("copies the scrolled-back view, not the live tail", () => {
    // A fake buffer: scroll APIs route through the DOM viewport, which a
    // headless Terminal doesn't have, so drive viewportY directly.
    const lines = ["one", "two", "three", "four"];
    const buffer = {
      viewportY: 0,
      getLine: (y: number) => ({ isWrapped: false, translateToString: () => lines[y] ?? "" }),
    };
    expect(visibleScreenText(buffer, 2)).toBe("one\ntwo");
    buffer.viewportY = 2;
    expect(visibleScreenText(buffer, 2)).toBe("three\nfour");
  });
});

describe("drag-to-scroll", () => {
  it("drags down to uncover older output", () => {
    // Finger down = content follows = negative scrollLines (toward history).
    expect(dragScrollLines(51, 17)).toEqual({ lines: -3, remainderPx: 0 });
    expect(dragScrollLines(-34, 17)).toEqual({ lines: 2, remainderPx: 0 });
  });

  it("carries the sub-row remainder so a slow drag still moves", () => {
    // Each move event is under one row; quantizing per-event would scroll never.
    let accum = 0;
    let total = 0;
    for (let i = 0; i < 6; i++) {
      accum += 5;
      const { lines, remainderPx } = dragScrollLines(accum, 17);
      accum = remainderPx;
      total += lines;
    }
    expect(total).toBe(-1);
    expect(accum).toBeCloseTo(13);
  });

  it("never divides by a row height the renderer hasn't measured yet", () => {
    expect(dragScrollLines(40, 0)).toEqual({ lines: 0, remainderPx: 40 });
    expect(dragScrollLines(Number.NaN, 17)).toEqual({ lines: 0, remainderPx: 0 });
  });

  it("yields to native panning when the zoomed grid overflows", () => {
    expect(shouldDragScroll(0, 40, 8, true)).toBe(false);
    expect(shouldDragScroll(0, 40, 8, false)).toBe(true);
  });

  it("claims only vertical-dominant drags past the threshold", () => {
    expect(shouldDragScroll(0, 4, 8, false)).toBe(false); // below threshold
    expect(shouldDragScroll(40, 20, 8, false)).toBe(false); // sideways pan
    expect(shouldDragScroll(-5, -30, 8, false)).toBe(true); // upward drag
  });
});

describe("terminal pinch zoom", () => {
  it("scales the font relative to the initial finger distance", () => {
    expect(scaledTerminalFont(12, 100, 150, 4, 24)).toBe(18);
    expect(scaledTerminalFont(12, 100, 50, 4, 24)).toBe(6);
  });

  it("clamps zoom to the supported font range", () => {
    expect(scaledTerminalFont(12, 100, 400, 4, 24)).toBe(24);
    expect(scaledTerminalFont(12, 100, 10, 4, 24)).toBe(4);
  });
});
