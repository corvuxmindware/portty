import { describe, expect, it } from "vitest";
import {
  SYSTEM_UI_EDGE_GRACE_MS,
  SYSTEM_UI_RELOCK_AFTER_MS,
  SystemUiTracker,
} from "./systemUi";

function clock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("SystemUiTracker", () => {
  it("re-locks an ordinary return from the background", () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    const hiddenAt = c.now();
    c.advance(5_000);
    expect(ui.relockOnReturn(hiddenAt)).toBe(true);
  });

  it("does not re-lock while the app's own Save dialog is still open", async () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    const dialog = deferred<string>();
    const running = ui.run(() => dialog.promise);
    const hiddenAt = c.now();
    c.advance(8_000);
    // The show edge arrives before the dialog's result is delivered.
    expect(ui.relockOnReturn(hiddenAt)).toBe(false);
    dialog.resolve("content://x");
    await expect(running).resolves.toBe("content://x");
  });

  it("does not re-lock when the show edge comes just after the dialog settled", async () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    const hiddenAt = c.now() + 50;
    await ui.run(async () => {
      c.advance(6_000);
      return null;
    });
    c.advance(SYSTEM_UI_EDGE_GRACE_MS - 1);
    expect(ui.relockOnReturn(hiddenAt)).toBe(false);
  });

  it("re-locks when the phone sat on the system screen too long", async () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    const dialog = deferred<null>();
    const running = ui.run(() => dialog.promise);
    const hiddenAt = c.now();
    c.advance(SYSTEM_UI_RELOCK_AFTER_MS);
    expect(ui.relockOnReturn(hiddenAt)).toBe(true);
    dialog.resolve(null);
    await running;
  });

  it("re-locks a later, unrelated trip to the background", async () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    await ui.run(async () => {
      c.advance(2_000);
      return null;
    });
    c.advance(60_000);
    const hiddenAt = c.now();
    c.advance(1_000);
    expect(ui.relockOnReturn(hiddenAt)).toBe(true);
  });

  it("forgets the screen even when it throws", async () => {
    const c = clock();
    const ui = new SystemUiTracker(c.now);
    await expect(
      ui.run(async () => {
        throw new Error("picker failed");
      }),
    ).rejects.toThrow("picker failed");
    c.advance(SYSTEM_UI_EDGE_GRACE_MS + 60_000);
    const hiddenAt = c.now();
    expect(ui.hidByUs(hiddenAt)).toBe(false);
  });
});
