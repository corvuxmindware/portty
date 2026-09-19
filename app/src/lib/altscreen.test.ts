import { describe, expect, it } from "vitest";
import { AltScreenScanner } from "./altscreen";

const bytes = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("AltScreenScanner", () => {
  it("passes plain bytes through as one segment", () => {
    const segs = new AltScreenScanner().scan(bytes("hello world"));
    expect(segs).toHaveLength(1);
    expect(segs[0].alt).toBeNull();
    expect(text(segs[0].bytes)).toBe("hello world");
  });

  it("detects 1049h enter and 1049l exit, splitting at the switch", () => {
    const scanner = new AltScreenScanner();
    const enter = scanner.scan(bytes("before\x1b[?1049hvim screen"));
    expect(enter).toHaveLength(2);
    expect(enter[0].alt).toBe(true);
    expect(text(enter[0].bytes)).toBe("before\x1b[?1049h");
    expect(text(enter[1].bytes)).toBe("vim screen");
    const exit = scanner.scan(bytes("\x1b[?1049lback"));
    expect(exit[0].alt).toBe(false);
  });

  it("recognizes all three alt params, also inside multi-param lists", () => {
    for (const p of ["47", "1047", "1049", "25;1049", "1049;2004"]) {
      const segs = new AltScreenScanner().scan(bytes(`\x1b[?${p}h`));
      expect(segs[0].alt, `param ${p}`).toBe(true);
    }
  });

  it("ignores non-alt private modes and non-private CSI", () => {
    const scanner = new AltScreenScanner();
    for (const seq of ["\x1b[?25h", "\x1b[?2004h", "\x1b[1049h", "\x1b[2J"]) {
      const segs = scanner.scan(bytes(seq));
      expect(segs.every((s) => s.alt === null), seq).toBe(true);
    }
  });

  it("survives a switch sequence split across chunk boundaries", () => {
    const scanner = new AltScreenScanner();
    const whole = "\x1b[?1049h";
    for (let cut = 1; cut < whole.length; cut++) {
      scanner.reset();
      const first = scanner.scan(bytes(whole.slice(0, cut)));
      const second = scanner.scan(bytes(whole.slice(cut)));
      const flips = [...first, ...second].filter((s) => s.alt !== null);
      expect(flips, `cut at ${cut}`).toHaveLength(1);
      expect(flips[0].alt).toBe(true);
    }
  });

  it("bails out of runaway parameter strings", () => {
    const segs = new AltScreenScanner().scan(bytes(`\x1b[?${"1".repeat(64)}h`));
    expect(segs.every((s) => s.alt === null)).toBe(true);
  });

  it("reset() forgets a partial sequence", () => {
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?104")); // mid-sequence
    scanner.reset();
    const segs = scanner.scan(bytes("9h")); // completes only if state leaked
    expect(segs.every((s) => s.alt === null)).toBe(true);
  });

  it("altActive() tracks enter/exit synchronously (ahead of the render signal)", () => {
    const scanner = new AltScreenScanner();
    expect(scanner.altActive()).toBe(false);
    scanner.scan(bytes("\x1b[?1049hvim"));
    expect(scanner.altActive()).toBe(true);
    scanner.scan(bytes("\x1b[?1049lback"));
    expect(scanner.altActive()).toBe(false);
  });

  it("clears the alt gate on RIS (ESC c) full reset", () => {
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1049h")); // enter alt
    const segs = scanner.scan(bytes("junk\x1bcmore"));
    const flips = segs.filter((s) => s.alt !== null);
    expect(flips).toHaveLength(1);
    expect(flips[0].alt).toBe(false);
    expect(scanner.altActive()).toBe(false);
  });

  it("clears the alt gate on DECSTR soft reset (ESC [ ! p)", () => {
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?47h"));
    const segs = scanner.scan(bytes("\x1b[!p"));
    expect(segs.some((s) => s.alt === false)).toBe(true);
    expect(scanner.altActive()).toBe(false);
    // a bare ESC [ ! that is NOT DECSTR must not trip the reset
    const other = new AltScreenScanner();
    other.scan(bytes("\x1b[?1049h"));
    other.scan(bytes("\x1b[!q"));
    expect(other.altActive()).toBe(true);
  });

  it("tracks DECCKM application-cursor mode (?1 h/l) without splitting segments", () => {
    const scanner = new AltScreenScanner();
    expect(scanner.appCursorMode()).toBe(false);
    const setSegs = scanner.scan(bytes("prompt\x1b[?1h"));
    expect(scanner.appCursorMode()).toBe(true);
    expect(setSegs.every((s) => s.alt === null)).toBe(true); // no alt flip
    scanner.scan(bytes("\x1b[?1l"));
    expect(scanner.appCursorMode()).toBe(false);
    // ?1049 (alt) must NOT be mistaken for ?1 (DECCKM)
    const other = new AltScreenScanner();
    other.scan(bytes("\x1b[?1049h"));
    expect(other.appCursorMode()).toBe(false);
  });

  it("reset() clears tracked modes too", () => {
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1049h\x1b[?1h\x1b[?1002h"));
    expect(scanner.altActive()).toBe(true);
    expect(scanner.appCursorMode()).toBe(true);
    expect(scanner.mouseReporting()).toBe(true);
    scanner.reset();
    expect(scanner.altActive()).toBe(false);
    expect(scanner.appCursorMode()).toBe(false);
    expect(scanner.mouseReporting()).toBe(false);
  });
});

describe("mouse reporting detection", () => {
  it("tracks every reporting mode without splitting segments", () => {
    for (const param of ["9", "1000", "1001", "1002", "1003"]) {
      const scanner = new AltScreenScanner();
      const segs = scanner.scan(bytes(`\x1b[?${param}h`));
      expect(scanner.mouseReporting()).toBe(true);
      expect(segs.every((s) => s.alt === null)).toBe(true); // flag, not a flip
      scanner.scan(bytes(`\x1b[?${param}l`));
      expect(scanner.mouseReporting()).toBe(false);
    }
  });

  it("ignores encoding and focus modes that do not enable reporting", () => {
    // An app can set SGR encoding (1006) or focus tracking (1004) while mouse
    // reporting is off; treating those as "on" would make the overlay
    // click-through and silently break tap-to-type.
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1004h\x1b[?1005h\x1b[?1006h\x1b[?1015h"));
    expect(scanner.mouseReporting()).toBe(false);
  });

  it("keeps reporting on until the LAST tracking mode is disabled", () => {
    // The modes are independent - a single boolean would turn reporting off
    // here at `?1002l` even though ?1000 is still on.
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1000h\x1b[?1002h"));
    scanner.scan(bytes("\x1b[?1002l"));
    expect(scanner.mouseReporting()).toBe(true);
    scanner.scan(bytes("\x1b[?1000l"));
    expect(scanner.mouseReporting()).toBe(false);
  });

  it("handles the combined enable a TUI actually sends", () => {
    // Claude Code / vim style: tracking + SGR encoding in one sequence, torn
    // down the same way on exit.
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1002;1006h"));
    expect(scanner.mouseReporting()).toBe(true);
    scanner.scan(bytes("\x1b[?1002;1006l"));
    expect(scanner.mouseReporting()).toBe(false);
  });

  it("clears reporting on a full reset so taps can type again", () => {
    for (const seq of ["\x1bc", "\x1b[!p"]) {
      const scanner = new AltScreenScanner();
      scanner.scan(bytes("\x1b[?1003h"));
      expect(scanner.mouseReporting()).toBe(true);
      scanner.scan(bytes(seq));
      expect(scanner.mouseReporting()).toBe(false);
    }
  });

  it("does not confuse alt-screen params with mouse params", () => {
    const scanner = new AltScreenScanner();
    scanner.scan(bytes("\x1b[?1049h"));
    expect(scanner.altActive()).toBe(true);
    expect(scanner.mouseReporting()).toBe(false);
  });
});
