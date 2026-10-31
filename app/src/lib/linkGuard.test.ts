import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  HELD_INPUT_DROPPED,
  HELD_INPUT_REFUSED,
  HELD_INPUT_SESSION_GONE,
  HeldInput,
  LINK_PROBE_TIMEOUT_MS,
  LinkGuard,
  type LinkHold,
  MAX_HELD_INPUT_AGE_MS,
  MAX_HELD_INPUT_CHARS,
  needsLinkCheck,
  probeLink,
  type ReattachOutcome,
  RESUME_CHECK_AFTER_MS,
  SESSION_LIST_WAIT_MS,
} from "./linkGuard";

function deferred() {
  let resolve!: () => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A guard wired to recorders, with pings the test answers by hand. */
function harness() {
  let clock = 0;
  let settled = true;
  let drops = 0;
  const pings: Array<ReturnType<typeof deferred>> = [];
  const delivered: Array<[number, string]> = [];
  const notices: string[] = [];
  const holds: Array<LinkHold | null> = [];
  const guard = new LinkGuard({
    ping: () => {
      const ping = deferred();
      pings.push(ping);
      return ping.promise;
    },
    dropLink: () => {
      drops += 1;
    },
    linkSettled: () => settled,
    deliver: (session, data) => delivered.push([session, data]),
    notify: (message) => notices.push(message),
    onHold: (hold) => holds.push(hold),
    now: () => clock,
  });
  return {
    guard,
    pings,
    delivered,
    notices,
    holds,
    drops: () => drops,
    advance: (ms: number) => {
      clock += ms;
    },
    setSettled: (value: boolean) => {
      settled = value;
    },
  };
}

describe("needsLinkCheck", () => {
  it("keeps a quick resume instant: no check under ten seconds", () => {
    expect(needsLinkCheck(0)).toBe(false);
    expect(needsLinkCheck(RESUME_CHECK_AFTER_MS - 1)).toBe(false);
  });

  /* The field case: HOME, 62 s in the background (frozen at 30 s, host dropped
     the link at 61 s), then reopen. */
  it("checks after a long absence, when the host may already have dropped the link", () => {
    expect(needsLinkCheck(RESUME_CHECK_AFTER_MS)).toBe(true);
    expect(needsLinkCheck(62_000)).toBe(true);
  });

  it("checks when the clock cannot prove the absence was short", () => {
    expect(needsLinkCheck(-5_000)).toBe(true);
    expect(needsLinkCheck(Number.NaN)).toBe(true);
    expect(needsLinkCheck(Number.POSITIVE_INFINITY)).toBe(true);
  });
});

describe("probeLink", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("is true when the host answers in time, and leaves no timer behind", async () => {
    await expect(probeLink(() => Promise.resolve(), 3_000)).resolves.toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("is false when the round trip fails", async () => {
    await expect(probeLink(() => Promise.reject(new Error("not paired")), 3_000)).resolves.toBe(
      false,
    );
  });

  it("is false when the ping throws instead of rejecting", async () => {
    const ping = () => {
      throw new Error("boom");
    };
    await expect(probeLink(ping, 3_000)).resolves.toBe(false);
  });

  /* The dead-link case: the request sits in a QUIC buffer nobody reads. */
  it("is false when no answer comes in time, even if one turns up later", async () => {
    const late = deferred();
    const result = probeLink(() => late.promise, 3_000);
    await vi.advanceTimersByTimeAsync(3_000);
    late.resolve();
    await expect(result).resolves.toBe(false);
  });
});

describe("HeldInput", () => {
  it("releases held pieces in order, as one write", () => {
    const held = new HeldInput();
    expect(held.hold(1, "echo ", 0)).toBe(true);
    expect(held.hold(1, "bg-ok", 10)).toBe(true);
    expect(held.hold(1, "\r", 20)).toBe(true);
    expect(held.take(1, 30)).toEqual({ data: "echo bg-ok\r", dropped: 0 });
    // Taking empties it.
    expect(held.take(1, 40)).toEqual({ data: "", dropped: 0 });
  });

  it("releases nothing, and reports nothing dropped, when nothing was typed", () => {
    expect(new HeldInput().take(1, 0)).toEqual({ data: "", dropped: 0 });
  });

  /* All-or-nothing: a prefix of terminal input is not safe to replay. */
  it("refuses past the size limit and then drops ALL of it, not a prefix", () => {
    const held = new HeldInput(10, MAX_HELD_INPUT_AGE_MS);
    expect(held.hold(1, "rm -rf ", 0)).toBe(true);
    expect(held.hold(1, "build/", 1)).toBe(false);
    const release = held.take(1, 2);
    expect(release.data).toBe("");
    expect(release.dropped).toBeGreaterThan(0);
  });

  it("refuses everything after a refusal, so a later Enter cannot submit a partial line", () => {
    const held = new HeldInput(10, MAX_HELD_INPUT_AGE_MS);
    held.hold(1, "ls", 0);
    expect(held.hold(1, "x".repeat(50), 1)).toBe(false); // e.g. a big paste
    expect(held.hold(1, "\r", 2)).toBe(false);
    expect(held.take(1, 3).data).toBe("");
  });

  it("drops typing held longer than the age limit", () => {
    const held = new HeldInput();
    held.hold(1, "make deploy\r", 0);
    const release = held.take(1, MAX_HELD_INPUT_AGE_MS + 1);
    expect(release).toEqual({ data: "", dropped: "make deploy\r".length });
  });

  it("refuses new typing once the held typing is too old", () => {
    const held = new HeldInput();
    held.hold(1, "a", 0);
    expect(held.hold(1, "b", MAX_HELD_INPUT_AGE_MS + 1)).toBe(false);
  });

  it("never sends typing to a session it was not typed for", () => {
    const held = new HeldInput();
    held.hold(1, "whoami\r", 0);
    expect(held.take(2, 1)).toEqual({ data: "", dropped: "whoami\r".length });

    held.hold(1, "a", 0);
    expect(held.hold(2, "b", 1)).toBe(false);
  });

  it("clear reports what it dropped and starts fresh", () => {
    const held = new HeldInput(4, MAX_HELD_INPUT_AGE_MS);
    held.hold(1, "abcd", 0);
    held.hold(1, "e", 0); // over the limit: spoiled
    expect(held.clear()).toBe(5);
    expect(held.hold(1, "ok", 5)).toBe(true);
    expect(held.take(1, 6)).toEqual({ data: "ok", dropped: 0 });
  });

  it("holds up to the documented limit", () => {
    const held = new HeldInput();
    expect(held.hold(1, "x".repeat(MAX_HELD_INPUT_CHARS), 0)).toBe(true);
    expect(held.hold(1, "y", 1)).toBe(false);
  });
});

describe("LinkGuard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends input straight through when nothing is held (a quick resume is untouched)", () => {
    const h = harness();
    h.guard.input(1, "ls\r");
    expect(h.delivered).toEqual([[1, "ls\r"]]);
    expect(h.guard.state).toBeNull();
    expect(h.pings).toHaveLength(0);
  });

  /* The bug: typing right after a long background went straight into a link
     the host had already dropped, and vanished. It must wait for proof. */
  it("holds input typed during a resume check and sends it once the host answers", async () => {
    const h = harness();
    const check = h.guard.verify(1);
    expect(h.guard.state).toBe("checking");

    h.guard.input(1, "echo bg-ok\r");
    expect(h.delivered).toEqual([]);

    h.pings[0].resolve();
    await check;
    expect(h.delivered).toEqual([[1, "echo bg-ok\r"]]);
    expect(h.guard.state).toBeNull();
    expect(h.drops()).toBe(0);
    expect(h.holds).toEqual(["checking", null]);

    // Live again.
    h.guard.input(1, "pwd\r");
    expect(h.delivered.at(-1)).toEqual([1, "pwd\r"]);
  });

  /* The 30 s wait: nothing used to notice a dead link until QUIC's own idle
     timer fired. A check that gets no answer now replaces the link at once. */
  it("replaces the link when the check gets no answer, instead of trusting it", async () => {
    const h = harness();
    const check = h.guard.verify(1);
    h.guard.input(1, "echo bg-ok\r");

    await vi.advanceTimersByTimeAsync(LINK_PROBE_TIMEOUT_MS - 1);
    expect(h.drops()).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    await check;

    expect(h.drops()).toBe(1);
    expect(h.guard.state).toBe("reconnecting");
    expect(h.delivered).toEqual([]);
  });

  /* The whole field timeline, end to end: resume after 62 s, type at once, the
     dead link is caught by the check, the app reconnects, and the command runs. */
  it("sends what was typed, in order, once the session is back after the reconnect", async () => {
    const h = harness();
    expect(needsLinkCheck(62_000)).toBe(true);
    const check = h.guard.verify(1);
    h.guard.input(1, "echo ");
    h.advance(500);
    h.guard.input(1, "bg-ok\r");

    await vi.advanceTimersByTimeAsync(LINK_PROBE_TIMEOUT_MS);
    await check;
    expect(h.drops()).toBe(1);

    // dropLink -> `portty://disconnected` -> the app's silent-drop path.
    h.guard.linkLost(1);
    h.guard.input(1, "date\r"); // still typing while it reconnects
    h.advance(1_000);
    // The fresh link: the host's session list first, then the re-attach.
    h.guard.sessionsListed([1, 3]);
    h.guard.reattached(1);

    expect(h.delivered).toEqual([[1, "echo bg-ok\rdate\r"]]);
    expect(h.guard.state).toBeNull();
    expect(h.notices).toEqual([]);
  });

  it("does not drop a link when the check was overtaken by a link change", async () => {
    const h = harness();
    const check = h.guard.verify(1);
    // The link dropped on its own meanwhile; the reconnect already owns it.
    h.guard.linkLost(1);
    h.pings[0].reject(new Error("connection closed"));
    await check;
    expect(h.drops()).toBe(0);
    expect(h.guard.state).toBe("reconnecting");
  });

  it("acts only on the newest check", async () => {
    const h = harness();
    const first = h.guard.verify(1);
    const second = h.guard.verify(1);
    h.pings[0].reject(new Error("timed out"));
    await first;
    expect(h.drops()).toBe(0);
    h.pings[1].resolve();
    await second;
    expect(h.guard.state).toBeNull();
    expect(h.drops()).toBe(0);
  });

  it("does not act on a check result while a connect is running", async () => {
    const h = harness();
    const check = h.guard.verify(1);
    h.setSettled(false);
    h.pings[0].reject(new Error("not paired"));
    await check;
    expect(h.drops()).toBe(0);
  });

  /* Home screen or agent view: nothing to hold, but the stale "Connected" link
     should still be replaced now rather than 30 s later. */
  it("holds nothing without an open terminal, but still replaces a dead link", async () => {
    const h = harness();
    const check = h.guard.verify(null);
    expect(h.guard.state).toBeNull();
    h.pings[0].reject(new Error("timed out"));
    await check;
    expect(h.drops()).toBe(1);
    expect(h.guard.state).toBeNull();
  });

  it("drops held input visibly when the session or link is given up", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "git push\r");
    h.guard.abandon();
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_DROPPED]);
    expect(h.guard.state).toBeNull();
  });

  it("gives up quietly when nothing was held", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.abandon();
    expect(h.notices).toEqual([]);
  });

  it("reports typing it cannot hold, never swallowing it", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "x".repeat(MAX_HELD_INPUT_CHARS + 1));
    expect(h.notices).toEqual([HELD_INPUT_REFUSED]);
    h.guard.restored(1);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_REFUSED, HELD_INPUT_DROPPED]);
  });

  /* Host offline: input waits while the app keeps reconnecting, but a command
     typed long ago must not fire by surprise when the host finally returns. */
  it("drops, and says so, typing held longer than the age limit", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "make deploy\r");
    h.advance(MAX_HELD_INPUT_AGE_MS + 1);
    h.guard.restored(1);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_DROPPED]);
  });
});

/* After a reconnect, held typing replays only once the host's session list -
   the first frame on every link - shows the session survived. A host restarted
   while the phone was away has forgotten the id and ignores input for it. */
describe("LinkGuard after a reconnect", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("waits for the host's session list, then replays", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1);
    expect(h.delivered).toEqual([]);
    expect(h.guard.state).toBe("reconnecting");

    h.guard.sessionsListed([1]);
    expect(h.delivered).toEqual([[1, "ls\r"]]);
    expect(h.guard.state).toBeNull();
  });

  it("replays at once when the list already arrived", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.sessionsListed([1]);
    h.guard.reattached(1);
    expect(h.delivered).toEqual([[1, "ls\r"]]);
  });

  it("says the typing was not sent when the session did not survive", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.sessionsListed([]); // a restarted host with nothing running
    h.guard.reattached(1);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_SESSION_GONE]);
    expect(h.guard.state).toBeNull();
  });

  it("does not trust a list from before the link dropped", () => {
    const h = harness();
    h.guard.sessionsListed([1]); // the old link's list
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1);
    expect(h.delivered).toEqual([]);
    h.guard.sessionsListed([1]); // the fresh link's list
    expect(h.delivered).toEqual([[1, "ls\r"]]);
  });

  it("gives up visibly if the list never comes", async () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1);
    await vi.advanceTimersByTimeAsync(SESSION_LIST_WAIT_MS);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_DROPPED]);
    expect(h.guard.state).toBeNull();
  });

  it("keeps holding when the fresh link drops again before its list", async () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1);
    h.guard.linkLost(1); // dropped again; the wait for the old list is void
    await vi.advanceTimersByTimeAsync(SESSION_LIST_WAIT_MS);
    expect(h.notices).toEqual([]);
    expect(h.guard.state).toBe("reconnecting");
    h.guard.sessionsListed([1]);
    h.guard.reattached(1);
    expect(h.delivered).toEqual([[1, "ls\r"]]);
  });

  it("replays nothing and says nothing when nothing was typed", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.sessionsListed([]);
    h.guard.reattached(1);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([]);
    expect(h.guard.state).toBeNull();
  });
});

/* The app's reconnect toast waits on the same answer, so the user hears ONE
   truthful message: "session restored" only when it was, and otherwise one
   message that also covers any typing that went unsent. */
describe("LinkGuard reporting a re-attach", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function reports() {
    const outcomes: ReattachOutcome[] = [];
    return { outcomes, report: (outcome: ReattachOutcome) => void outcomes.push(outcome) };
  }

  it("reports a surviving session after replaying its typing, exactly as without a report", () => {
    const h = harness();
    const r = reports();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1, r.report);
    expect(r.outcomes).toEqual([]); // the list has not said yet

    h.guard.sessionsListed([1]);
    expect(h.delivered).toEqual([[1, "ls\r"]]);
    expect(h.notices).toEqual([]);
    expect(r.outcomes).toEqual([{ survived: true, unsent: 0 }]);
    expect(h.guard.state).toBeNull();
  });

  /* The field case: host restarted while the app held "echo held-c". */
  it("hands a gone session's unsent typing to the report instead of a notice of its own", () => {
    const h = harness();
    const r = reports();
    h.guard.linkLost(1);
    h.guard.input(1, "echo held-c\r");
    h.guard.sessionsListed([]); // a restarted host with nothing running
    h.guard.reattached(1, r.report);
    expect(h.delivered).toEqual([]);
    expect(h.notices).toEqual([]);
    expect(r.outcomes).toEqual([{ survived: false, unsent: "echo held-c\r".length }]);
    expect(h.guard.state).toBeNull();
  });

  it("reports a gone session with nothing unsent when nothing was typed", () => {
    const h = harness();
    const r = reports();
    h.guard.linkLost(1);
    h.guard.reattached(1, r.report);
    h.guard.sessionsListed([3]); // a new session on the restarted host, not ours
    expect(r.outcomes).toEqual([{ survived: false, unsent: 0 }]);
    expect(h.notices).toEqual([]);
  });

  /* The app leaves the dead session from inside the report, and leaving
     abandons whatever is held. That must not add a second message. */
  it("has nothing left to drop if the session is left from inside the report", () => {
    const h = harness();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.sessionsListed([]);
    h.guard.reattached(1, () => h.guard.abandon());
    expect(h.notices).toEqual([]);
    expect(h.guard.state).toBeNull();
  });

  it("does not report a wait that was given up", async () => {
    const h = harness();
    const r = reports();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1, r.report);
    h.guard.linkLost(1); // dropped again before the list
    h.guard.sessionsListed([1]); // the next link's list, before its own re-attach
    expect(r.outcomes).toEqual([]);

    h.guard.reattached(1, r.report);
    await vi.advanceTimersByTimeAsync(SESSION_LIST_WAIT_MS);
    expect(r.outcomes).toEqual([{ survived: true, unsent: 0 }]);
  });

  it("does not report when the list never comes, and the guard says what it dropped", async () => {
    const h = harness();
    const r = reports();
    h.guard.linkLost(1);
    h.guard.input(1, "ls\r");
    h.guard.reattached(1, r.report);
    await vi.advanceTimersByTimeAsync(SESSION_LIST_WAIT_MS);
    expect(r.outcomes).toEqual([]);
    expect(h.notices).toEqual([HELD_INPUT_DROPPED]);
  });
});
