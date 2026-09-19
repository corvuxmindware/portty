import { describe, expect, it } from "vitest";
import {
  applyLatches,
  MOD_ALT,
  MOD_CTRL,
  modifierParam,
  modifySequence,
  toCtrlByte,
  withModifier,
} from "./keys";

describe("toCtrlByte", () => {
  it("folds both letter cases to the same control byte", () => {
    expect(toCtrlByte("c")).toBe("\x03");
    expect(toCtrlByte("C")).toBe("\x03");
    expect(toCtrlByte("a")).toBe("\x01"); // start of line
    expect(toCtrlByte("e")).toBe("\x05"); // end of line
    expect(toCtrlByte("z")).toBe("\x1a");
  });

  it("covers the @ through _ range, not just letters", () => {
    expect(toCtrlByte("@")).toBe("\x00");
    expect(toCtrlByte("[")).toBe("\x1b"); // ESC
    expect(toCtrlByte("\\")).toBe("\x1c"); // SIGQUIT
    expect(toCtrlByte("]")).toBe("\x1d");
    expect(toCtrlByte("^")).toBe("\x1e");
    expect(toCtrlByte("_")).toBe("\x1f"); // readline undo
  });

  it("special-cases Ctrl+Space and Ctrl+?", () => {
    expect(toCtrlByte(" ")).toBe("\x00"); // NUL, readline set-mark
    expect(toCtrlByte("?")).toBe("\x7f"); // DEL
  });

  it("returns null where no control byte exists", () => {
    expect(toCtrlByte("1")).toBeNull();
    expect(toCtrlByte("-")).toBeNull();
    expect(toCtrlByte("~")).toBeNull();
    expect(toCtrlByte("é")).toBeNull();
    expect(toCtrlByte("")).toBeNull();
    expect(toCtrlByte("ab")).toBeNull(); // never a whole paste
  });
});

describe("withModifier", () => {
  it("encodes modified cursor keys as CSI with a parameter", () => {
    expect(withModifier("\x1b[D", MOD_CTRL)).toBe("\x1b[1;5D"); // word left
    expect(withModifier("\x1b[C", MOD_CTRL)).toBe("\x1b[1;5C"); // word right
    expect(withModifier("\x1b[A", MOD_CTRL)).toBe("\x1b[1;5A");
    expect(withModifier("\x1b[B", MOD_CTRL)).toBe("\x1b[1;5B");
  });

  it("encodes modified tilde keys with the number preserved", () => {
    expect(withModifier("\x1b[5~", MOD_CTRL)).toBe("\x1b[5;5~"); // Ctrl+PgUp
    expect(withModifier("\x1b[6~", MOD_CTRL)).toBe("\x1b[6;5~"); // Ctrl+PgDn
  });

  it("carries any modifier, so Alt reuses the same encoding", () => {
    expect(withModifier("\x1b[D", MOD_ALT)).toBe("\x1b[1;3D");
    expect(withModifier("\x1b[6~", MOD_ALT)).toBe("\x1b[6;3~");
  });

  it("returns null for sequences with no modified form", () => {
    expect(withModifier("\x1b", MOD_CTRL)).toBeNull(); // Esc
    expect(withModifier("\t", MOD_CTRL)).toBeNull(); // Tab
    expect(withModifier("\x03", MOD_CTRL)).toBeNull(); // already a control byte
    expect(withModifier("|", MOD_CTRL)).toBeNull();
    expect(withModifier("\x1bOA", MOD_CTRL)).toBeNull(); // SS3 has no parameter slot
  });
});

describe("modifierParam", () => {
  it("matches the named constants and combines", () => {
    expect(modifierParam({ ctrl: true, alt: false })).toBe(MOD_CTRL);
    expect(modifierParam({ ctrl: false, alt: true })).toBe(MOD_ALT);
    expect(modifierParam({ ctrl: true, alt: true })).toBe(7);
    expect(modifierParam({ ctrl: false, alt: false })).toBe(1);
  });
});

describe("applyLatches", () => {
  it("sends Alt as an ESC prefix - the readline word motions", () => {
    expect(applyLatches("b", { ctrl: false, alt: true })).toBe("\x1bb"); // word back
    expect(applyLatches("f", { ctrl: false, alt: true })).toBe("\x1bf"); // word forward
    expect(applyLatches("d", { ctrl: false, alt: true })).toBe("\x1bd"); // kill word
    expect(applyLatches(".", { ctrl: false, alt: true })).toBe("\x1b."); // last argument
    expect(applyLatches("\x7f", { ctrl: false, alt: true })).toBe("\x1b\x7f"); // kill word back
  });

  it("resolves Ctrl first, so Ctrl+Alt is ESC then the control byte", () => {
    expect(applyLatches("a", { ctrl: true, alt: true })).toBe("\x1b\x01");
  });

  it("passes the character through when nothing is latched", () => {
    expect(applyLatches("b", { ctrl: false, alt: false })).toBe("b");
  });

  it("never touches multi-character input - a latch is one keypress, not a paste", () => {
    expect(applyLatches("ls -la", { ctrl: true, alt: true })).toBe("ls -la");
    expect(applyLatches("..", { ctrl: false, alt: true })).toBe("..");
  });
});

describe("modifySequence", () => {
  it("is null with no latch, so the caller keeps its SS3 rewrite", () => {
    expect(modifySequence("\x1b[A", { ctrl: false, alt: false })).toBeNull();
  });

  it("prefers the CSI parameter form for cursor and tilde keys", () => {
    expect(modifySequence("\x1b[D", { ctrl: true, alt: false })).toBe("\x1b[1;5D");
    expect(modifySequence("\x1b[D", { ctrl: false, alt: true })).toBe("\x1b[1;3D");
    expect(modifySequence("\x1b[D", { ctrl: true, alt: true })).toBe("\x1b[1;7D");
    expect(modifySequence("\x1b[5~", { ctrl: true, alt: true })).toBe("\x1b[5;7~");
  });

  it("falls back to the ESC prefix for single-byte keys", () => {
    expect(modifySequence("\t", { ctrl: false, alt: true })).toBe("\x1b\t");
    expect(modifySequence("/", { ctrl: false, alt: true })).toBe("\x1b/");
  });

  it("is null when the latch cannot apply, so the key is sent unchanged", () => {
    expect(modifySequence("\t", { ctrl: true, alt: false })).toBeNull(); // no Ctrl+Tab byte
    expect(modifySequence("..", { ctrl: true, alt: true })).toBeNull(); // multi-char
  });
});
