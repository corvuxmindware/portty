import { describe, expect, it } from "vitest";
import {
  decisionKey,
  loadDecisionLog,
  migrateDecisionLogFromLocalStorage,
  persistDecisionLog,
  redactForStorage,
  REDACTED_FOR_STORAGE,
  type DecisionLogStorage,
} from "./decisionLog";
import type { DecisionLogEntry } from "./portty";

/** Map-backed stand-in for localStorage, so these tests need no DOM. */
function fakeStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  const storage: DecisionLogStorage & { raw: Map<string, string>; writes: number } = {
    raw: map,
    writes: 0,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
      storage.writes += 1;
    },
  };
  return storage;
}

const entry = (over: Partial<DecisionLogEntry> = {}): DecisionLogEntry => ({
  at: "2026-07-29T00:00:00.000Z",
  session_id: 1,
  tool_call_id: "call_1",
  title: "Read src/main.rs",
  category: "read",
  policy: "readonly",
  source: "auto",
  input: '{"path":"src/main.rs"}',
  ...over,
});

describe("redactForStorage", () => {
  it("redacts the TITLE as well as the input", async () => {
    // The title is usually where the path is, so redacting only the input left
    // the secret in storage anyway.
    const secret = entry({
      title: "Read /home/u/.ssh/id_ed25519",
      input: '{"path":"/home/u/.ssh/id_ed25519"}',
    });
    const stored = redactForStorage(secret);
    expect(stored.title).toBe(REDACTED_FOR_STORAGE);
    expect(stored.input).toBe(REDACTED_FOR_STORAGE);
    // The audit-useful metadata survives.
    expect(stored.at).toBe(secret.at);
    expect(stored.session_id).toBe(secret.session_id);
    expect(stored.tool_call_id).toBe(secret.tool_call_id);
    expect(stored.category).toBe("read");
    expect(stored.source).toBe("auto");
  });

  it("redacts credential-shaped values, not just paths", async () => {
    const stored = redactForStorage(
      entry({
        title: "Run command",
        category: "execute",
        input: '{"command":"curl -H \\"Authorization: Bearer sk-live-abcdef1234567890\\""}',
      }),
    );
    expect(stored.title).toBe(REDACTED_FOR_STORAGE);
    expect(stored.input).toBe(REDACTED_FOR_STORAGE);
  });

  it("leaves ordinary entries untouched, and identical by reference", async () => {
    const ordinary = entry();
    expect(redactForStorage(ordinary)).toBe(ordinary);
  });

  it("keeps a null input null rather than inventing a redaction", async () => {
    const stored = redactForStorage(entry({ title: "Read .env", input: null }));
    expect(stored.title).toBe(REDACTED_FOR_STORAGE);
    expect(stored.input).toBeNull();
  });

  it("handles entries from older builds that have no input field at all", async () => {
    const legacy = { ...entry(), input: undefined } as DecisionLogEntry;
    expect(() => redactForStorage(legacy)).not.toThrow();
    expect(redactForStorage(legacy)).toBe(legacy);
  });
});

describe("persistDecisionLog", () => {
  it("never writes a secret, even when memory holds one", async () => {
    const storage = fakeStorage();
    await persistDecisionLog(storage, "host-a", [
      entry({ title: "Read app/.env.production", input: '{"path":"app/.env.production"}' }),
      entry({ title: "Read src/lib.rs", input: '{"path":"src/lib.rs"}' }),
    ]);
    const written = storage.getItem(decisionKey("host-a")) ?? "";
    expect(written).not.toContain(".env.production");
    // ...while the harmless entry is stored in full.
    expect(written).toContain("src/lib.rs");
  });
});

describe("loadDecisionLog", () => {
  it("re-redacts entries written before redaction existed, and writes them back", async () => {
    // A log from an older build: full path in both fields.
    const legacy = JSON.stringify([
      entry({ title: "Read ~/.aws/credentials", input: '{"path":"~/.aws/credentials"}' }),
    ]);
    const storage = fakeStorage({ [decisionKey("host-a")]: legacy });

    const loaded = await loadDecisionLog(storage, "host-a");

    expect(loaded[0].title).toBe(REDACTED_FOR_STORAGE);
    // Cleaned in storage too - loading is the one moment we are sure to touch it.
    const after = storage.getItem(decisionKey("host-a")) ?? "";
    expect(after).not.toContain(".aws/credentials");
    expect(storage.writes).toBe(1);
  });

  it("writes nothing when there is nothing to clean", async () => {
    const clean = JSON.stringify([entry()]);
    const storage = fakeStorage({ [decisionKey("host-a")]: clean });

    const loaded = await loadDecisionLog(storage, "host-a");

    expect(loaded).toHaveLength(1);
    expect(storage.writes).toBe(0);
  });

  it("treats a missing, corrupt, or non-array log as empty instead of throwing", async () => {
    expect(await loadDecisionLog(fakeStorage(), "host-a")).toEqual([]);
    expect(await loadDecisionLog(fakeStorage({ [decisionKey("h")]: "{oops" }), "h")).toEqual([]);
    expect(await loadDecisionLog(fakeStorage({ [decisionKey("h")]: '{"a":1}' }), "h")).toEqual([]);
  });

  it("keeps hosts separate", async () => {
    const storage = fakeStorage();
    await persistDecisionLog(storage, "host-a", [entry({ title: "Read a.rs" })]);
    await persistDecisionLog(storage, "host-b", [entry({ title: "Read b.rs" })]);
    expect((await loadDecisionLog(storage, "host-a"))[0].title).toBe("Read a.rs");
    expect((await loadDecisionLog(storage, "host-b"))[0].title).toBe("Read b.rs");
  });
});

describe("migrateDecisionLogFromLocalStorage", () => {
  const localFake = (initial: Record<string, string> = {}) => {
    const map = new Map(Object.entries(initial));
    return {
      getItem: (k: string) => map.get(k) ?? null,
      removeItem: (k: string) => void map.delete(k),
      has: (k: string) => map.has(k),
    };
  };

  /// The point of the migration: the WebView copy is what ends up in an iOS
  /// backup, so importing without deleting would fix nothing.
  it("moves the log into the core store and deletes the original", async () => {
    const key = decisionKey("h");
    const local = localFake({ [key]: JSON.stringify([entry({ title: "Read a.rs" })]) });
    const core = fakeStorage();

    await migrateDecisionLogFromLocalStorage(local, core, "h");

    expect((await loadDecisionLog(core, "h"))[0].title).toBe("Read a.rs");
    expect(local.has(key)).toBe(false);
  });

  /// Deletion is unconditional. An entry too corrupt to import is still an entry
  /// sitting in a backup.
  it("deletes an unparseable original rather than leaving it behind", async () => {
    const key = decisionKey("h");
    const local = localFake({ [key]: "{not json" });
    await migrateDecisionLogFromLocalStorage(local, fakeStorage(), "h");
    expect(local.has(key)).toBe(false);
  });

  /// Migration runs on every host select, so it must not clobber the live log
  /// with a stale WebView copy that was left behind by a failed earlier run.
  it("does not overwrite a log the core store already holds", async () => {
    const key = decisionKey("h");
    const local = localFake({ [key]: JSON.stringify([entry({ title: "Read stale.rs" })]) });
    const core = fakeStorage();
    await persistDecisionLog(core, "h", [entry({ title: "Read current.rs" })]);

    await migrateDecisionLogFromLocalStorage(local, core, "h");

    expect((await loadDecisionLog(core, "h"))[0].title).toBe("Read current.rs");
    expect(local.has(key)).toBe(false);
  });

  it("is a no-op when there is nothing to migrate", async () => {
    const core = fakeStorage();
    await migrateDecisionLogFromLocalStorage(localFake(), core, "h");
    expect(await loadDecisionLog(core, "h")).toEqual([]);
  });

  /// Secrets written by a build that predates the current redaction rules must
  /// not survive the move in full.
  it("re-redacts on the way through", async () => {
    const key = decisionKey("h");
    const local = localFake({
      [key]: JSON.stringify([entry({ title: "Read /home/u/.ssh/id_ed25519" })]),
    });
    const core = fakeStorage();

    await migrateDecisionLogFromLocalStorage(local, core, "h");

    expect((await loadDecisionLog(core, "h"))[0].title).toBe(REDACTED_FOR_STORAGE);
  });
});
