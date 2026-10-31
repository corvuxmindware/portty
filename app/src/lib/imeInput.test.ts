import { afterEach, describe, expect, it, vi } from "vitest";
// The real installed xterm bundle, as text - see "the hook point" below.
import xtermBundle from "@xterm/xterm/lib/xterm.mjs?raw";
import {
  ImeEditTracker,
  imeEditBytes,
  installImeEditInput,
  textChange,
  type ImeTerminal,
} from "./imeInput";

const DEL = "\x7f";

describe("textChange", () => {
  it("finds an edit wherever it landed", () => {
    expect(textChange("echo", "echo ")).toEqual({ removed: "", inserted: " " });
    expect(textChange("hce", "ohce")).toEqual({ removed: "", inserted: "o" });
    expect(textChange("echo", "ecxho")).toEqual({ removed: "", inserted: "x" });
    expect(textChange("echo", "ech")).toEqual({ removed: "o", inserted: "" });
    expect(textChange("teh ", "the ")).toEqual({ removed: "eh", inserted: "he" });
    expect(textChange("same", "same")).toEqual({ removed: "", inserted: "" });
  });

  it("never splits an emoji in half", () => {
    // 😀 and 😁 share their first UTF-16 unit.
    expect(textChange("a😀", "a😁")).toEqual({ removed: "😀", inserted: "😁" });
    expect(textChange("😀b", "😁b")).toEqual({ removed: "😀", inserted: "😁" });
    expect(textChange("ok😀", "ok")).toEqual({ removed: "😀", inserted: "" });
  });
});

describe("imeEditBytes", () => {
  it("sends inserted text from the event, not from the textarea", () => {
    // The textarea says "ohce" (text landed at the start); the event says "o".
    expect(imeEditBytes({ inputType: "insertText", data: "o" }, "hce", "ohce")).toBe("o");
    expect(imeEditBytes({ inputType: "insertText", data: "x" }, "echo", "ecxho")).toBe("x");
    expect(imeEditBytes({ inputType: "insertText", data: "😀" }, "", "😀")).toBe("😀");
  });

  it("falls back to the textarea change when the event has no data", () => {
    expect(imeEditBytes({ inputType: "insertText", data: null }, "ec", "ech")).toBe("h");
  });

  it("turns a typed newline into Enter", () => {
    expect(imeEditBytes({ inputType: "insertText", data: "ls\n" }, "", "ls\n")).toBe("ls\r");
    expect(imeEditBytes({ inputType: "insertLineBreak", data: null }, "ls", "ls\n")).toBe("\r");
  });

  it("sends one Backspace per character the keyboard app deleted", () => {
    expect(imeEditBytes({ inputType: "deleteContentBackward", data: null }, "echo", "ech")).toBe(DEL);
    // A "delete word" swipe removes several characters in one edit.
    expect(imeEditBytes({ inputType: "deleteContentBackward", data: null }, "echo", "e")).toBe(
      DEL.repeat(3),
    );
    // An emoji is one character to the shell, two UTF-16 units to JS.
    expect(imeEditBytes({ inputType: "deleteContentBackward", data: null }, "a😀", "a")).toBe(DEL);
    expect(imeEditBytes({ inputType: "deleteContentForward", data: null }, "ab", "a")).toBe(
      "\x1b[3~",
    );
  });

  it("replays a replacement as erase-then-type", () => {
    expect(imeEditBytes({ inputType: "insertReplacementText", data: null }, "teh", "the")).toBe(
      `${DEL}${DEL}he`,
    );
  });
});

describe("ImeEditTracker", () => {
  const typed = (data: string) => ({ inputType: "insertText", data, isComposing: false });

  it("sends each keyboard-app commit once, in order, wherever it lands", () => {
    const tracker = new ImeEditTracker();
    let value = "";
    const sent: string[] = [];
    for (const ch of "echo portty-ok") {
      tracker.imeKeydown(value);
      tracker.beforeInput(typed(ch), value);
      value = ch + value; // the phone put every character at the START
      const bytes = tracker.input(typed(ch), value);
      if (bytes) sent.push(bytes);
      tracker.close(); // keyup 229
    }
    expect(value).toBe("ko-yttrop ohce");
    expect(sent.join("")).toBe("echo portty-ok");
  });

  it("ignores edits it was not told about (real keys, paste)", () => {
    const tracker = new ImeEditTracker();
    expect(tracker.input(typed("e"), "e")).toBeNull();
    tracker.imeKeydown("");
    tracker.close(); // keyup came first: the window is over
    expect(tracker.input(typed("e"), "e")).toBeNull();
  });

  it("leaves compositions to xterm", () => {
    const tracker = new ImeEditTracker();
    tracker.imeKeydown("");
    const composing = { inputType: "insertCompositionText", data: "e", isComposing: true };
    expect(tracker.input(composing, "e")).toBeNull();
    // ...and the window does not linger into the next edit.
    expect(tracker.input(typed(" "), "e ")).toBeNull();
  });

  it("sends nothing for an edit that changed nothing", () => {
    const tracker = new ImeEditTracker();
    tracker.imeKeydown("echo");
    expect(tracker.input({ inputType: "insertText", data: "", isComposing: false }, "echo")).toBeNull();
  });
});

/**
 * A stand-in for xterm 6.0.0's routing of its helper textarea, with the stock
 * diff path copied from CompositionHelper._handleAnyTextareaChanges:
 * keyCode 229 outside a composition snapshots the textarea and, one timer
 * tick later, sends `newValue.replace(oldValue, "")`. Its listener is added
 * first, like xterm's own (in `open()`).
 */
class FakeXterm implements ImeTerminal {
  readonly sent: string[] = [];
  readonly textarea = Object.assign(new EventTarget(), {
    value: "",
    parentElement: null,
  }) as unknown as HTMLTextAreaElement;
  readonly _core = {
    _compositionHelper: {
      isComposing: false,
      _handleAnyTextareaChanges: (): void => {
        const ta = this.textarea;
        const oldValue = ta.value;
        setTimeout(() => {
          if (this._core._compositionHelper.isComposing) return;
          const newValue = ta.value;
          const diff = newValue.replace(oldValue, "");
          if (newValue.length > oldValue.length) this.sent.push(diff);
          else if (newValue.length < oldValue.length) this.sent.push(DEL);
          else if (newValue !== oldValue) this.sent.push(newValue);
        }, 0);
      },
    },
  };

  constructor() {
    this.textarea.addEventListener("keydown", (ev) => {
      const helper = this._core._compositionHelper;
      if ((ev as KeyboardEvent).keyCode === 229 && !helper.isComposing) {
        helper._handleAnyTextareaChanges();
      }
    });
  }

  input(data: string): void {
    this.sent.push(data);
  }

  /**
   * One keyboard-app commit as Android delivers it: keydown 229, the edit,
   * keyup 229. `atStart` puts the text where the phone put it.
   */
  commit(text: string, atStart: boolean): void {
    const ta = this.textarea;
    const fire = (type: string, extra: object) =>
      ta.dispatchEvent(Object.assign(new Event(type), extra));
    const edit = { inputType: "insertText", data: text, isComposing: false };
    fire("keydown", { keyCode: 229 });
    fire("beforeinput", edit);
    ta.value = atStart ? text + ta.value : ta.value + text;
    fire("input", edit);
    fire("keyup", { keyCode: 229 });
  }
}

describe("installImeEditInput", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** The phone's run: `adb shell input text "echo portty-ok"`, keys queued in three bursts. */
  function phoneRun(term: FakeXterm) {
    for (const burst of ["echo", " ", "portty-ok"]) {
      for (const ch of burst) term.commit(ch, true);
      vi.runAllTimers(); // xterm's timers only run once the burst is through
    }
  }

  it("reproduces the scrambled phone typing without the fix", () => {
    vi.useFakeTimers();
    const term = new FakeXterm();
    phoneRun(term);
    // The same bytes the real xterm 6.0.0 sends in headless Chrome for this
    // sequence; the phone showed the start of it: `ohceohcoho ko-yttro…`.
    expect(term.sent.join("")).toBe("ohceohcoho ko-yttropko-yttroko-yttrko-yttko-ytko-yko-kok");
  });

  it("sends exactly what was typed with the fix", () => {
    vi.useFakeTimers();
    const term = new FakeXterm();
    expect(installImeEditInput(term)).toBeTypeOf("function");
    phoneRun(term);
    expect(term.sent.join("")).toBe("echo portty-ok");
  });

  it("does not duplicate a fast burst that lands at the end", () => {
    vi.useFakeTimers();
    const term = new FakeXterm();
    installImeEditInput(term);
    for (const ch of "echo portty-ok") term.commit(ch, false);
    vi.runAllTimers();
    expect(term.sent.join("")).toBe("echo portty-ok");
  });

  it("stays out of the way while a composition is active", () => {
    vi.useFakeTimers();
    const term = new FakeXterm();
    installImeEditInput(term);
    term._core._compositionHelper.isComposing = true;
    term.commit("e", false);
    vi.runAllTimers();
    expect(term.sent).toEqual([]);
  });

  it("puts xterm back as it was when undone, and refuses a build without the hook", () => {
    vi.useFakeTimers();
    const term = new FakeXterm();
    const stock = term._core._compositionHelper._handleAnyTextareaChanges;
    const undo = installImeEditInput(term)!;
    expect(term._core._compositionHelper._handleAnyTextareaChanges).not.toBe(stock);
    undo();
    expect(term._core._compositionHelper._handleAnyTextareaChanges).toBe(stock);

    const bare = { textarea: term.textarea, input: () => {} } as ImeTerminal;
    expect(installImeEditInput(bare)).toBeNull();
  });
});

describe("the hook point in the installed xterm", () => {
  // installImeEditInput reaches into xterm's privates. If an upgrade renames or
  // reroutes them, the fix would silently switch itself off - so pin them here.
  // When this fails: re-check lib/imeInput.ts against the new xterm source.
  it("still keeps the composition helper on the core terminal", () => {
    expect(xtermBundle).toContain("get textarea(){return this._core.textarea}");
    expect(xtermBundle).toMatch(/this\._compositionHelper=this\._instantiationService\.createInstance\(/);
  });

  it("still sends a keyCode-229 keydown outside a composition to the textarea diff", () => {
    expect(xtermBundle).toMatch(
      /keydown\(\w\)\{if\(this\._isComposing\|\|this\._isSendingComposition\)\{[^}]*\}return \w\.keyCode===229\?\(this\._handleAnyTextareaChanges\(\),!1\):!0\}/,
    );
    expect(xtermBundle).toMatch(/_handleAnyTextareaChanges\(\)\{let \w=this\._textarea\.value;setTimeout\(/);
  });
});
