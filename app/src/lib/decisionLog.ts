// Persistence rules for the agent approval log, extracted from App.tsx so the
// redaction is unit-testable (same reasoning as lib/policy.ts).
//
// The log answers "what did an agent ask to do on that machine, and what did I
// say?" - worth keeping. The split is: the IN-MEMORY log holds everything for the
// session being read, and what gets written down has its secrets removed.
//
// WHERE it is written moved. It used to be WebView localStorage, which is
// plaintext inside the app container and, on iOS, inside every device backup -
// so up to 200 commands, arguments and paths left the phone with each backup,
// protected only by the redaction below, which is pattern matching and cannot
// recognize every secret. Persistence now goes through the Tauri core into an
// owner-only, backup-excluded file (`decision_log_*` commands).
//
// The redaction stayed exactly where it was. The new location narrows who can
// read the file; it does not make it safe to write secrets into one.

import { looksLikeSecretToStore } from "./policy";
import type { DecisionLogEntry } from "./portty";

/** Per-host key. Exported so host removal can delete exactly this record. */
export const decisionKey = (host: string) => `portty:decision-log:${host}`;

/** Stands in for redacted text, so the UI can say why it is missing. */
export const REDACTED_FOR_STORAGE = "[redacted - not stored on this device]";

/** Only what this module needs from a store, so tests need no DOM and no IPC.
 *
 *  Both shapes are allowed to be async: the real backing store is now a Tauri
 *  command round-trip, while tests and the localStorage migration path are
 *  synchronous. Callers `await` either way. */
export interface DecisionLogStorage {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
}

/**
 * Strip the parts of an entry that must not be written down.
 *
 * BOTH the title and the input are redacted, not just the input. The title is
 * usually where the path actually is ("Read /home/u/.ssh/id_ed25519"), so
 * redacting only the input persisted the secret anyway - the first version of
 * this did that while being described as keeping secrets out of storage, which
 * was untrue. Detection also covers credential-shaped VALUES, since
 * `curl -H "Authorization: Bearer ..."` contains no credential-shaped filename.
 *
 * What survives: when, which session, which tool call, which category, and how it
 * was decided. Returns the SAME object when nothing needs redacting, so callers
 * can cheaply tell whether anything changed.
 */
export function redactForStorage(entry: DecisionLogEntry): DecisionLogEntry {
  // `input` is optional on entries written by older builds; absent and null are
  // the same thing here.
  const input = entry.input ?? null;
  if (!looksLikeSecretToStore(entry.title, input)) return entry;
  return {
    ...entry,
    title: REDACTED_FOR_STORAGE,
    input: input === null ? input : REDACTED_FOR_STORAGE,
  };
}

export async function persistDecisionLog(
  storage: DecisionLogStorage,
  host: string,
  entries: DecisionLogEntry[],
): Promise<void> {
  await storage.setItem(decisionKey(host), JSON.stringify(entries.map(redactForStorage)));
}

/**
 * Read a host's log, re-redacting as it loads.
 *
 * Entries written before redaction existed - or before it covered titles and
 * credential-shaped values - are still in storage in full. Loading is the one
 * moment we are guaranteed to touch them, so they are cleaned and written back
 * here rather than left for some future reader. A load with nothing to change
 * writes nothing.
 *
 * Corrupt or non-array contents yield an empty log rather than throwing: a
 * damaged audit trail must not stop the app from connecting.
 */
export async function loadDecisionLog(
  storage: DecisionLogStorage,
  host: string,
): Promise<DecisionLogEntry[]> {
  let stored: DecisionLogEntry[];
  try {
    const raw: unknown = JSON.parse((await storage.getItem(decisionKey(host))) ?? "[]");
    stored = Array.isArray(raw) ? (raw as DecisionLogEntry[]) : [];
  } catch {
    return [];
  }
  const cleaned = stored.map(redactForStorage);
  if (cleaned.some((entry, i) => entry !== stored[i])) {
    await storage.setItem(decisionKey(host), JSON.stringify(cleaned));
  }
  return cleaned;
}

/**
 * Move a host's log out of `localStorage` and into the core store, once.
 *
 * Without this the old plaintext record simply stays in the WebView - and in
 * every iOS backup taken from now on - while new entries go somewhere safer.
 * That would be the worst of both: the exposure that prompted the move, kept
 * forever, minus the entries that would have shown it was still happening.
 *
 * Runs before the first load of a host. Removal is what makes it a migration
 * rather than a copy, so it happens even when the import writes nothing.
 */
export async function migrateDecisionLogFromLocalStorage(
  local: Pick<Storage, "getItem" | "removeItem">,
  core: DecisionLogStorage,
  host: string,
): Promise<void> {
  const key = decisionKey(host);
  const raw = local.getItem(key);
  if (raw === null) return;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      // Re-redact on the way through: these entries may predate the current
      // rules, and this is the last time anything will look at them.
      const existing = JSON.parse((await core.getItem(key)) ?? "[]") as unknown;
      const alreadyThere = Array.isArray(existing) && existing.length > 0;
      if (!alreadyThere) {
        await persistDecisionLog(core, host, parsed as DecisionLogEntry[]);
      }
    }
  } catch {
    // Unparseable: nothing worth importing, but it still must not be left behind.
  }
  local.removeItem(key);
}
