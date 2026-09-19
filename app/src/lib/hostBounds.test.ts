// Bounds on values the HOST supplies. A paired host is authenticated, not
// trusted with the phone's memory: pairing proves which machine is talking, not
// that it is behaving. These tests pin the limits that keep a hostile or simply
// buggy host from taking the app down.

import { describe, expect, it } from "vitest";
import {
  clampTerminalDimension,
  MAX_TERMINAL_DIMENSION,
  MIN_TERMINAL_DIMENSION,
} from "./portty";

describe("clampTerminalDimension", () => {
  /// The headline. `cols`/`rows` cross the wire as u16, so the worst case a host
  /// can state is 65535x65535 - about 4.3 billion cells for xterm.js to
  /// allocate, which is an out-of-memory kill rather than a slow render.
  it("bounds the maximum a u16 can express", () => {
    expect(clampTerminalDimension(65535)).toBe(MAX_TERMINAL_DIMENSION);
    expect(clampTerminalDimension(MAX_TERMINAL_DIMENSION + 1)).toBe(MAX_TERMINAL_DIMENSION);
  });

  /// Zero is the other end of the same problem: xterm.js needs at least one cell,
  /// and the match-width font calculation divides by `cols`.
  it("bounds the minimum, including zero and negatives", () => {
    expect(clampTerminalDimension(0)).toBe(MIN_TERMINAL_DIMENSION);
    expect(clampTerminalDimension(-1)).toBe(MIN_TERMINAL_DIMENSION);
  });

  /// A short or truncated frame reads as NaN. Every non-finite value collapses
  /// to the MINIMUM, including +Infinity - deliberately failing small, because
  /// this number decides an allocation and the only source of a non-finite one
  /// is corrupt input.
  it("treats every non-finite input as the minimum", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(clampTerminalDimension(bad), `${bad}`).toBe(MIN_TERMINAL_DIMENSION);
    }
  });

  /// The bound has to be generous enough that no real terminal is ever touched,
  /// or it becomes a rendering bug instead of a safety limit. A 5K display at a
  /// tiny font is a few hundred columns.
  it("leaves every plausible real terminal untouched", () => {
    for (const size of [80, 120, 160, 240, 400, 500]) {
      expect(clampTerminalDimension(size), `${size}`).toBe(size);
    }
  });

  it("floors fractional input", () => {
    expect(clampTerminalDimension(120.9)).toBe(120);
  });
});
