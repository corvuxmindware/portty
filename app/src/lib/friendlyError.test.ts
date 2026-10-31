import { describe, expect, it } from "vitest";
import {
  cameraErrorMessage,
  detectPlatform,
  friendlyError,
  NO_CAMERA_MESSAGE,
  redactDetail,
  worthRetrying,
  worthShowingAtLaunch,
  type ErrorContext,
  type FriendlyError,
} from "./friendlyError";

/** Words a person should never have to read. */
const JARGON = [
  "WrongPin",
  "PairingClosed",
  "UnsupportedVersion",
  "transport:",
  "protocol:",
  "iroh",
  "os error",
  "re-pair",
  "PIN",
  "laptop",
  "pair failed",
  "reconnect failed",
];

function expectPlain(error: FriendlyError) {
  expect(error.message.trim()).not.toBe("");
  for (const word of JARGON) expect(error.message).not.toContain(word);
  // Every message ends a sentence - and most say what to do next.
  expect(error.message).toMatch(/[.!?]$/);
}

describe("friendlyError: pairing and reconnecting", () => {
  it("passes the core's structured error through, redacting its detail", () => {
    const error = friendlyError(
      {
        kind: "maybe_old_host",
        message:
          "Couldn't finish connecting. Your computer may have an older version of Portty. Update the Portty program on your computer to 0.1.3 or newer (check with `portty --version`), then try again.",
        detail: "handshake before any reply: transport: io: connection lost (to 192.168.1.20:4433)",
      },
      "reconnect",
    );
    expect(error.kind).toBe("maybe_old_host");
    expect(error.message).toContain("may have an older version");
    expect(error.detail).toContain("connection lost");
    expect(error.detail).not.toContain("192.168.1.20");
  });

  it.each([
    ["pair failed: protocol: pairing failed: WrongPin", "pair", "code_rejected"],
    ["pair failed: protocol: pairing failed: PairingClosed", "pair", "code_expired"],
    ["protocol: pairing failed: Cancelled", "pair", "declined"],
    ["protocol: pairing failed: RateLimited", "pair", "rate_limited"],
    ["reconnect failed - re-pair: protocol: pairing failed: WrongPin", "reconnect", "rejected"],
    ["reconnect failed - re-pair: protocol: pairing failed: PairingClosed", "reconnect", "rejected"],
    ["pair revoked by laptop", "reconnect", "revoked"],
    ["protocol: pairing failed: UnsupportedVersion", "reconnect", "version"],
    ["transport: protocol version 5 unsupported (this build speaks 11)", "pair", "version"],
    [
      "reconnect failed - re-pair: transport: iroh transport: connect: timed out",
      "reconnect",
      "unreachable",
    ],
    ["a connection attempt is already in progress", "reconnect", "busy"],
    ["pair failed: transport: io: connection lost", "pair", "lost"],
  ] as Array<[string, ErrorContext, string]>)("maps flattened %s", (raw, context, kind) => {
    const error = friendlyError(raw, context);
    expect(error.kind).toBe(kind);
    expectPlain(error);
    expect(error.detail).toBe(raw.replace("192.168.1.20", "[address]"));
  });

  it("asks to pair again only when a saved pairing was refused", () => {
    const refused = friendlyError("protocol: pairing failed: WrongPin", "reconnect");
    expect(refused.message).toContain("Pair again");

    const firstPair = friendlyError("protocol: pairing failed: WrongPin", "pair");
    expect(firstPair.message.toLowerCase()).not.toContain("pair again");
    expect(firstPair.message).toContain("scan the new QR code");

    for (const raw of ["transport: io: connection lost", "command timed out"]) {
      expect(friendlyError(raw, "reconnect").message.toLowerCase()).not.toContain("pair again");
    }
  });

  it("decides which reconnect failures are worth retrying", () => {
    const of = (kind: string): FriendlyError => ({ kind, message: "", detail: "" });
    for (const kind of ["unreachable", "lost", "maybe_old_host", "timeout", "busy", "failed"]) {
      expect(worthRetrying(of(kind))).toBe(true);
    }
    for (const kind of ["version", "rejected", "revoked", "wrong_host", "saved_damaged"]) {
      expect(worthRetrying(of(kind))).toBe(false);
    }
  });

  it("explains a failed launch reconnect only when someone has to act", () => {
    const of = (kind: string): FriendlyError => ({ kind, message: "", detail: "" });
    expect(worthShowingAtLaunch(of("maybe_old_host"))).toBe(true);
    expect(worthShowingAtLaunch(of("version"))).toBe(true);
    expect(worthShowingAtLaunch(of("rejected"))).toBe(true);
    // A computer that is simply off, or nothing saved yet: stay calm.
    expect(worthShowingAtLaunch(of("unreachable"))).toBe(false);
    expect(worthShowingAtLaunch(of("lost"))).toBe(false);
    expect(worthShowingAtLaunch(of("failed"))).toBe(false);
    expect(worthShowingAtLaunch(of("no_saved_host"))).toBe(false);
  });
});

describe("friendlyError: a link lost mid-session", () => {
  it.each([
    "connection closed before the command completed",
    "connection closed",
    "connection closed before the folder roots arrived",
  ])("says to reconnect for %s", (raw) => {
    const error = friendlyError(raw, "session");
    expect(error.kind).toBe("lost");
    expect(error.message).toContain("Reconnect");
    expectPlain(error);
  });

  it("says the computer did not answer for a timeout", () => {
    const error = friendlyError("command timed out", "agent");
    expect(error.kind).toBe("timeout");
    expectPlain(error);
  });

  it("says not connected when there is no link", () => {
    const error = friendlyError("not paired", "session");
    expect(error.kind).toBe("not_connected");
    expectPlain(error);
  });

  it("says a vanished session has ended", () => {
    const error = friendlyError("that session is no longer available", "session");
    expect(error.kind).toBe("session_gone");
    expectPlain(error);
  });
});

describe("friendlyError: file transfers", () => {
  it.each([
    [
      "cannot open upload: No such file or directory (os error 2)",
      "upload",
      "file_missing",
      "this phone",
    ],
    [
      "cannot open C:\\Users\\sam\\My Docs\\report.txt: The system cannot find the file specified. (os error 2)",
      "download",
      "file_missing",
      "isn't on your computer",
    ],
    [
      "cannot create download directory: Read-only file system (os error 30)",
      "download",
      "read_only",
      "Choose another folder",
    ],
    ["path is outside the host user's home directory", "download", "outside_home", "Allow a path"],
    ["requested path is not a regular file", "download", "not_a_file", "folder"],
    ["upload source is not a regular file", "upload", "not_a_file", "Choose a file"],
    [
      "download stopped: transfers may not exceed 4 GiB each or 6 GiB in total",
      "download",
      "too_big",
      "too big",
    ],
    ["at most 4 file transfers may run at once", "upload", "too_many_transfers", "Wait"],
    ["download failed verification 3 times - giving up", "download", "corrupted", "intact"],
    ["upload checksum mismatch", "upload", "corrupted", "intact"],
    [
      "file changed during download; start the transfer again",
      "download",
      "file_changed",
      "changed",
    ],
    [
      "transfer canceled - it belonged to a different host",
      "download",
      "host_switched",
      "another computer",
    ],
    ["could not write upload: Permission denied (os error 13)", "upload", "no_permission", "allowed"],
    ["could not save download: No space left on device (os error 28)", "download", "no_space", "space"],
    ["connection closed during upload", "upload", "lost", "start the transfer again"],
  ] as Array<[string, ErrorContext, string, string]>)(
    "maps %s",
    (raw, context, kind, words) => {
      const error = friendlyError(raw, context);
      expect(error.kind).toBe(kind);
      expect(error.message).toContain(words);
      expectPlain(error);
      // The technical text is kept, without any path in it.
      expect(error.detail).not.toMatch(/Users|sam|report\.txt/);
    },
  );

  it("falls back to a plain line, keeping the reason for Details", () => {
    const error = friendlyError("cannot rewind upload: Bad file descriptor (os error 9)", "upload");
    expect(error.message).toBe("The upload didn't work. Try again.");
    expect(error.detail).toContain("Bad file descriptor");
  });
});

describe("friendlyError: anything else", () => {
  it("adds the computer's own reason when it is already readable", () => {
    const error = friendlyError(
      "could not start agent: OpenCode is not installed on this host",
      "agent",
      "Couldn't start OpenCode.",
    );
    expect(error.message).toBe("Couldn't start OpenCode. OpenCode is not installed on this host.");
  });

  it("keeps technical reasons out of the message", () => {
    const error = friendlyError(
      "could not create session: The directory name is invalid. (os error 267)",
      "session",
      "Couldn't open a session there.",
    );
    expect(error.message).toBe("Couldn't open a session there. Try again.");
    expect(error.detail).toContain("os error 267");
  });

  it("handles Error objects and unknown values", () => {
    expect(friendlyError(new Error("command timed out")).kind).toBe("timeout");
    expect(friendlyError(undefined).message).toBe("Something went wrong. Try again.");
    expect(friendlyError({ unexpected: true }).message).toBe("Something went wrong. Try again.");
  });
});

describe("redactDetail", () => {
  it("removes pairing codes, phrases and links", () => {
    expect(redactDetail("bad ticket portty1:eyJuaWQiOiJhYmMifQ here")).toBe(
      "bad ticket [pairing code] here",
    );
    expect(redactDetail("phrase raven-quartz-mellow-pixel-ridge-onyx rejected")).toBe(
      "phrase [phrase] rejected",
    );
    expect(redactDetail("open content://com.android.providers/document/83 failed")).toBe(
      "open [link] failed",
    );
  });

  it("removes file paths but keeps the reason after them", () => {
    expect(redactDetail("cannot open C:\\Users\\sam\\My Docs\\a.txt: Access is denied.")).toBe(
      "cannot open [path]: Access is denied.",
    );
    expect(redactDetail("cannot open \\\\?\\C:\\Users\\sam\\a.txt: not found")).toBe(
      "cannot open [path]: not found",
    );
    expect(redactDetail("cannot open /home/sam/My Docs/a.txt: No such file")).toBe(
      "cannot open [path]: No such file",
    );
    expect(redactDetail("cannot open ~/project/a.txt: No such file")).toBe(
      "cannot open [path]: No such file",
    );
  });

  it("removes ids, keys, addresses and comparison codes", () => {
    expect(redactDetail(`node ${"7f".repeat(32)} unreachable`)).toBe("node [id] unreachable");
    expect(redactDetail("dial 10.0.0.12:51820 failed")).toBe("dial [address] failed");
    expect(redactDetail("dial [fe80::1:2:3:4]:443 failed")).toBe("dial [address] failed");
    expect(redactDetail("code 483921 shown")).toBe("code [code] shown");
  });

  it("leaves ordinary error text alone", () => {
    for (const text of [
      "transport: io: connection lost",
      "handshake before any reply: transport: peer closed connection",
      "protocol: pairing failed: WrongPin",
      "frame exceeds max size (2000000 bytes)",
    ]) {
      expect(redactDetail(text)).toBe(text);
    }
  });

  it("caps very long text", () => {
    expect(redactDetail("x ".repeat(1000)).length).toBeLessThanOrEqual(601);
  });
});

describe("camera errors", () => {
  const denied = Object.assign(new Error("Permission denied"), { name: "NotAllowedError" });

  it("names the right settings screen for a denied camera", () => {
    const android = cameraErrorMessage(denied, "android");
    expect(android).toBe(
      "Portty can't use the camera. Paste the pairing code from `portty pair` instead, or allow Camera in Settings → Apps → Portty → Permissions.",
    );
    expect(cameraErrorMessage(denied, "ios")).toContain("Settings → Portty → Camera");
    expect(cameraErrorMessage(denied, "other")).toContain("Paste the pairing code");
  });

  it("says when there is no camera, or it is busy", () => {
    const missing = Object.assign(new Error("Requested device not found"), {
      name: "NotFoundError",
    });
    expect(cameraErrorMessage(missing, "android")).toContain("No camera was found");
    const busy = Object.assign(new Error("Could not start video source"), {
      name: "NotReadableError",
    });
    expect(cameraErrorMessage(busy, "android")).toContain("busy");
    expect(NO_CAMERA_MESSAGE).toContain("Paste the pairing code");
  });

  it("always offers pasting the code, and never shows the browser's own words", () => {
    for (const name of ["NotAllowedError", "NotFoundError", "NotReadableError", "TypeError", ""]) {
      const message = cameraErrorMessage(
        Object.assign(new Error("Permission denied by system"), { name }),
        "android",
      );
      expect(message.toLowerCase()).toContain("paste the pairing code");
      expect(message).not.toContain("Permission denied by system");
    }
  });

  it("tells Android and iOS apart", () => {
    expect(
      detectPlatform("Mozilla/5.0 (Linux; Android 12; ONEPLUS A6003) AppleWebKit/537.36", 5),
    ).toBe("android");
    expect(detectPlatform("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", 5)).toBe("ios");
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", 5)).toBe("ios");
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", 0)).toBe("other");
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0)).toBe("other");
  });
});
