import { describe, expect, it } from "vitest";
import { pendingApprovalMessage, shouldNotifyPendingApproval } from "./notify";

describe("pending-approval notification rule", () => {
  it("notifies when a card is waiting and the app is off screen", () => {
    expect(shouldNotifyPendingApproval({ appVisible: false, pendingCount: 1 })).toBe(true);
  });

  /* The arrival handler already calls `attachAgent` and puts the card in front
     of the user, so a banner on top of it is noise. */
  it("stays quiet while the app is on screen", () => {
    expect(shouldNotifyPendingApproval({ appVisible: true, pendingCount: 1 })).toBe(false);
  });

  /* The policy engine runs BEFORE this. An auto-approved request needs no human,
     and buzzing a pocket for one would train the user to ignore the buzz. */
  it("stays quiet when nothing is actually pending", () => {
    expect(shouldNotifyPendingApproval({ appVisible: false, pendingCount: 0 })).toBe(false);
    expect(shouldNotifyPendingApproval({ appVisible: true, pendingCount: 0 })).toBe(false);
  });

  it("treats a negative count as nothing pending", () => {
    expect(shouldNotifyPendingApproval({ appVisible: false, pendingCount: -1 })).toBe(false);
  });
});

describe("pending-approval notification copy", () => {
  it("pluralises the count", () => {
    expect(pendingApprovalMessage(1).body).toBe("1 approval waiting");
    expect(pendingApprovalMessage(2).body).toBe("2 approvals waiting");
    expect(pendingApprovalMessage(11).body).toBe("11 approvals waiting");
  });

  /* A notification renders on the lock screen, readable by whoever is holding
     the phone. It must say a decision is waiting and nothing more - no tool
     name, command, path, or host. This is the same boundary the relay keeps for
     the push path, so the copy cannot drift apart from it unnoticed. */
  it("leaks no detail about the action being approved", () => {
    const { title, body } = pendingApprovalMessage(1);
    const text = `${title} ${body}`.toLowerCase();
    for (const leak of [
      "rm",
      "bash",
      "shell",
      "edit",
      "write",
      "read",
      "execute",
      "command",
      "/",
      "~",
      "$",
    ]) {
      expect(text).not.toContain(leak);
    }
  });

  it("says only what it needs to", () => {
    expect(pendingApprovalMessage(1).title).toBe("Portty");
    expect(pendingApprovalMessage(3).body).toMatch(/^\d+ approvals? waiting$/);
  });
});
