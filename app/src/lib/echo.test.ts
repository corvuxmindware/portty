import { describe, expect, it } from "vitest";
import { graphemeCellWidth, isSensitivePrompt, PredictiveEcho } from "./echo";

const SAFE = { sensitivePrompt: false, altScreen: false, cellsRemaining: 80 };

describe("isSensitivePrompt (predictive-echo gate, #48)", () => {
  it("fires at a secret prompt at the cursor", () => {
    for (const s of [
      "Password:",
      "password: ",
      "Enter passphrase for key '/id_ed25519': ",
      "[sudo] password for bob: ",
      "One-time code: ",
      "Verification code:",
      "API key: ",
      "Enter your PIN: ",
      "Unlock code:",
    ]) {
      expect(isSensitivePrompt(s), s).toBe(true);
    }
  });

  it("fires for common non-English locales", () => {
    for (const s of ["Mot de passe : ", "Passwort: ", "Kennwort:", "Contraseña: ", "Senha: "]) {
      expect(isSensitivePrompt(s), s).toBe(true);
    }
  });

  it("does not fire on ordinary output or a keyword far from the cursor", () => {
    for (const s of [
      "$ ls -la",
      "building project...",
      "Compiling portty-host v0.1.0",
      "Your password was updated 3 minutes ago and is now active",
      "hello world\n",
    ]) {
      expect(isSensitivePrompt(s), s).toBe(false);
    }
  });
});

/** Drive the engine to full confidence over a slow link (RTT ~200 ms). */
function primed(): { echo: PredictiveEcho; now: number } {
  const echo = new PredictiveEcho();
  let now = 0;
  for (const ch of "abc") {
    echo.noteSent(ch, now);
    now += 200;
    echo.onOutput(ch, now);
  }
  return { echo, now };
}

describe("PredictiveEcho activation gates", () => {
  it("stays off until confidence AND slow RTT are both established", () => {
    const echo = new PredictiveEcho();
    expect(echo.onInput("a", SAFE, 0)).toBeNull();
    // Fast link (10 ms echoes): confidence builds but prediction stays off.
    let now = 0;
    for (const ch of "abcdef") {
      echo.noteSent(ch, now);
      now += 10;
      echo.onOutput(ch, now);
    }
    expect(echo.onInput("x", SAFE, now)).toBeNull();
  });

  it("predicts printable ASCII with provisional styling once primed", () => {
    const { echo, now } = primed();
    const out = echo.onInput("x", SAFE, now);
    expect(out).toBe("\x1b[2;4mx\x1b[0m");
  });

  it("never predicts in sensitive prompts, alt screen, or across the last column", () => {
    const { echo, now } = primed();
    expect(echo.onInput("x", { ...SAFE, sensitivePrompt: true }, now)).toBeNull();
    expect(echo.onInput("x", { ...SAFE, altScreen: true }, now)).toBeNull();
    expect(echo.onInput("x", { ...SAFE, cellsRemaining: 0 }, now)).toBeNull();
  });

  it("predicts one narrow or wide grapheme but rejects controls and pasted text", () => {
    const { echo, now } = primed();
    expect(echo.onInput("é", SAFE, now)).toBe("\x1b[2;4mé\x1b[0m");
    expect(echo.onInput("漢", SAFE, now)).toBe("\x1b[2;4m漢\x1b[0m");
    expect(echo.onInput("e\u0301", SAFE, now)).toBe("\x1b[2;4me\u0301\x1b[0m");
    expect(echo.onInput("\r", SAFE, now)).toBeNull();
    expect(echo.onInput("\x1b[A", SAFE, now)).toBeNull(); // arrow key
    expect(echo.onInput("ab", SAFE, now)).toBeNull();
  });

  it("requires two remaining cells for CJK and emoji", () => {
    const { echo, now } = primed();
    expect(graphemeCellWidth("界")).toBe(2);
    expect(graphemeCellWidth("🙂")).toBe(2);
    expect(echo.onInput("界", { ...SAFE, cellsRemaining: 1 }, now)).toBeNull();
    expect(echo.onInput("界", { ...SAFE, cellsRemaining: 2 }, now)).not.toBeNull();
  });

  it("rebuilds confidence after a command boundary before showing input", () => {
    const { echo, now } = primed();
    expect(echo.onInput("x", SAFE, now)).not.toBeNull();
    expect(echo.commandBoundary()).toBe("\b \b");
    expect(echo.stats().confidence).toBe(0);

    // This may be a password prompt whose wording the UI does not recognize.
    // No character is displayed until this new input context proves it echoes.
    expect(echo.onInput("s", SAFE, now + 1)).toBeNull();
  });

  it("backspace only erases its own predictions", () => {
    const { echo, now } = primed();
    expect(echo.onInput("\x7f", SAFE, now)).toBeNull(); // nothing predicted yet
    echo.onInput("x", SAFE, now);
    expect(echo.onInput("\x7f", SAFE, now)).toBe("\b \b");
    expect(echo.onInput("\x7f", SAFE, now)).toBeNull(); // stack empty again
  });

  it("backspace erases both cells of a wide CJK prediction", () => {
    const { echo, now } = primed();
    echo.onInput("漢", SAFE, now);
    expect(echo.onInput("\x7f", SAFE, now)).toBe("\x1b[2D  \x1b[2D");
  });

  it("caps the number of on-screen provisional chars", () => {
    const { echo, now } = primed();
    let predictions = 0;
    for (let i = 0; i < 40; i++) {
      if (echo.onInput("x", SAFE, now)) predictions++;
    }
    expect(predictions).toBe(24);
  });

  it("caps CJK predictions by terminal cells, not UTF-16 length", () => {
    const { echo, now } = primed();
    let predictions = 0;
    for (let i = 0; i < 20; i++) {
      if (echo.onInput("漢", SAFE, now)) predictions++;
    }
    expect(predictions).toBe(12);
  });
});

describe("echo-off inference (the mosh timing heuristic)", () => {
  it("collapses confidence and erases secrets when echoes stop", () => {
    const { echo, now } = primed();
    // Type into a hidden prompt: predictions render...
    echo.onInput("s", SAFE, now);
    echo.noteSent("s", now);
    echo.onInput("3", SAFE, now + 10);
    echo.noteSent("3", now + 10);
    // ...but nothing echoes back. After the deadline, sweep() must erase the
    // two provisional cells and prediction must be off.
    const later = now + 5000;
    expect(echo.sweep(later)).toBe("\b \b\b \b");
    expect(echo.onInput("x", SAFE, later)).toBeNull();
    expect(echo.stats().confidence).toBe(0);
  });

  it("erases provisional cells before authoritative output paints", () => {
    const { echo, now } = primed();
    echo.onInput("x", SAFE, now);
    echo.noteSent("x", now);
    const erase = echo.onOutput("x", now + 200);
    expect(erase).toBe("\b \b");
    // The echo confirmed, so prediction stays available.
    expect(echo.onInput("y", SAFE, now + 200)).not.toBeNull();
  });

  it("samples RTT only for in-order matches (no log-noise inflation)", () => {
    const echo = new PredictiveEcho();
    echo.noteSent("q", 0);
    // Output that does NOT contain the oldest pending char must not sample.
    echo.onOutput("hello world", 50);
    expect(echo.stats().confidence).toBe(0);
    echo.onOutput("q", 100);
    expect(echo.stats().confidence).toBe(1);
    expect(echo.stats().rttMs).toBe(100);
  });

  it("reset() clears everything (session/host switch)", () => {
    const { echo, now } = primed();
    echo.onInput("x", SAFE, now);
    echo.reset();
    expect(echo.stats()).toEqual({ rttMs: 0, confidence: 0, predicted: 0 });
    // No stale predicted cells: sweep has nothing to erase.
    expect(echo.sweep(now + 10_000)).toBe("");
  });
});
