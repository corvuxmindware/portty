import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Status } from "@tauri-apps/plugin-biometric";

// Mock the Tauri plugin BEFORE importing the module under test. `vi.hoisted`
// makes the fn available to the (hoisted) mock factory without a TDZ. Only the
// async `biometricAvailability` touches `checkStatus`; the security-critical
// mapping is the pure `classifyBioStatus`, tested directly (no rejection mock).
const { checkStatus, invoke } = vi.hoisted(() => ({
  checkStatus: vi.fn(),
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-biometric", () => ({
  checkStatus,
  authenticate: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { biometricAvailability, classifyBioStatus, mustGate } from "./biometric";

const status = (over: Partial<Status>): Status =>
  ({ isAvailable: false, biometryType: 0, ...over }) as Status;

describe("classifyBioStatus - the OS-status mapping", () => {
  it("'available' when the OS reports isAvailable", () => {
    expect(classifyBioStatus(status({ isAvailable: true, biometryType: 2 }))).toBe("available");
  });

  it("classifies a biometry LOCKOUT distinctly (NOT collapsed with no-enrollment)", () => {
    expect(classifyBioStatus(status({ errorCode: "biometryLockout" }))).toBe("lockout");
  });

  it("'none' only when there is no owner credential at all", () => {
    expect(classifyBioStatus(status({ errorCode: "passcodeNotSet" }))).toBe("none");
  });

  it("'credential' when biometric isn't enrolled but a passcode can gate", () => {
    expect(classifyBioStatus(status({ errorCode: "biometryNotEnrolled" }))).toBe("credential");
    expect(classifyBioStatus(status({ errorCode: "biometryNotAvailable" }))).toBe("credential");
  });

  it("'unsupported' when the call failed (null → plugin absent/desktop)", () => {
    expect(classifyBioStatus(null)).toBe("unsupported");
  });
});

describe("biometricAvailability - async wrapper", () => {
  beforeEach(() => checkStatus.mockReset());

  it("passes the resolved status through the classifier", async () => {
    checkStatus.mockResolvedValue(status({ errorCode: "biometryLockout" }));
    expect(await biometricAvailability()).toBe("lockout");
  });
});

describe("biometricAvailability - a failing status call is not a free pass", () => {
  // `platformEnforcesLock` memoizes the core's answer, so each case needs a
  // fresh module instance.
  beforeEach(() => {
    checkStatus.mockReset();
    invoke.mockReset();
    vi.resetModules();
  });

  const availability = async () => {
    const fresh = await import("./biometric");
    return fresh.biometricAvailability();
  };

  it("GATES on mobile: the plugin is always registered there, so a throw means enforcement is broken", async () => {
    checkStatus.mockRejectedValue(new Error("plugin IPC failed"));
    invoke.mockResolvedValue(true); // cfg!(mobile)
    const avail = await availability();
    expect(avail).toBe("credential");
    expect(mustGate(avail)).toBe(true);
  });

  it("passes through on desktop dev, where the plugin genuinely isn't registered", async () => {
    checkStatus.mockRejectedValue(new Error("no plugin"));
    invoke.mockResolvedValue(false);
    expect(await availability()).toBe("unsupported");
  });

  it("passes through when there is no Tauri IPC at all (vitest / plain browser)", async () => {
    checkStatus.mockRejectedValue(new Error("no plugin"));
    invoke.mockRejectedValue(new Error("no IPC"));
    expect(await availability()).toBe("unsupported");
  });
});

describe("mustGate - fail-closed on lockout (D2 regression guard)", () => {
  it("GATES on lockout - the exact fail-open this prevents", () => {
    // If this ever flips to false, a locked-out phone opens with zero auth.
    expect(mustGate("lockout")).toBe(true);
  });

  it("gates on 'available' and 'credential'", () => {
    expect(mustGate("available")).toBe(true);
    expect(mustGate("credential")).toBe(true);
  });

  it("passes through only when nothing can enforce", () => {
    expect(mustGate("none")).toBe(false);
    expect(mustGate("unsupported")).toBe(false);
  });
});
