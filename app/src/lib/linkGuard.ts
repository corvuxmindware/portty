// Keeps terminal input from vanishing into a link that died while the app was
// away.
//
// Android freezes a backgrounded app (stock Android ~10 s after it is cached;
// OnePlus/Oppo "Hans" ~30 s after it leaves the screen) and iOS suspends it
// within seconds. Frozen, the phone sends no QUIC keepalives, so the host drops
// the link after its 30 s idle timeout. Thawed, the phone's end still LOOKS
// open: every write lands in the local QUIC send buffer and "succeeds", and
// nothing notices the link is dead until the phone's own idle timer fires ~30 s
// later. Everything typed in that window went nowhere, with no message.
//
// So after a long absence the link must prove itself with one round trip
// before input is trusted to it. Until then - and while a dead link is being
// rebuilt - typing is HELD, then either sent in order once the session is back,
// or dropped with a visible notice. It is never written to a link that may be
// dead.

/** Hidden for less than this, a resume stays exactly as instant as before: no
 *  check and no hold. The host cannot have timed the link out yet - Android
 *  freezes no sooner than ~10 s after the app leaves the screen, and the host
 *  then waits a further 30 s of silence. */
export const RESUME_CHECK_AFTER_MS = 10_000;

/** How long the liveness round trip may take before the link counts as dead.
 *  A live link answers in one round trip (well under a second, even through a
 *  relay); too short a limit only costs a needless, harmless reconnect. */
export const LINK_PROBE_TIMEOUT_MS = 3_000;

/** Bound on typing held while the link is checked or rebuilt. */
export const MAX_HELD_INPUT_CHARS = 8 * 1024;

/** Held typing older than this is not replayed. A command typed half a minute
 *  into an outage should not run by surprise long after the user gave up on it. */
export const MAX_HELD_INPUT_AGE_MS = 30_000;

/** How long a fresh link may take to deliver the host's session list - the
 *  first frame it sends - before held typing is given up rather than replayed
 *  unconfirmed. Only a safety net: the list normally lands within a round trip. */
export const SESSION_LIST_WAIT_MS = 5_000;

/** Shown when typing cannot be held (too much, or held too long). */
export const HELD_INPUT_REFUSED = "Not sent - still reconnecting";
/** Shown when held typing is dropped instead of sent. */
export const HELD_INPUT_DROPPED = "Typing while reconnecting was not sent";
/** Shown when the session the typing was for is gone after the reconnect. */
export const HELD_INPUT_SESSION_GONE = "Not sent - that session has ended";

/** Why input is being held: the link is being checked, or rebuilt. */
export type LinkHold = "checking" | "reconnecting";

/** What a session re-attached on a fresh link turned out to be, once the host's
 *  session list said. */
export interface ReattachOutcome {
  /** The session is still on the host (and its held typing was sent). */
  survived: boolean;
  /** Characters of held typing dropped unsent because the session is gone. */
  unsent: number;
}

/**
 * Whether a resume must prove the link before trusting it.
 *
 * Measured on the wall clock on purpose: a monotonic clock stops while the
 * phone sleeps, so ten minutes face-down could read as a few seconds. A clock
 * that went backwards cannot prove the absence was short, and a check is cheap,
 * so that case checks too.
 */
export function needsLinkCheck(hiddenForMs: number): boolean {
  if (!Number.isFinite(hiddenForMs) || hiddenForMs < 0) return true;
  return hiddenForMs >= RESUME_CHECK_AFTER_MS;
}

/**
 * Resolve `true` only if `ping` answers within `timeoutMs`. Never rejects: a
 * failure and a timeout both mean "no proof the link works".
 */
export function probeLink(ping: () => Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    const settle = (alive: boolean) => {
      clearTimeout(timer);
      resolve(alive);
    };
    let answer: Promise<unknown>;
    try {
      answer = Promise.resolve(ping());
    } catch {
      // A ping that throws instead of rejecting is a failed ping, not a crash.
      settle(false);
      return;
    }
    answer.then(
      () => settle(true),
      () => settle(false),
    );
  });
}

/** The outcome of releasing held input: everything to send now, or nothing and
 *  how much was dropped. Never both. */
export interface HeldRelease {
  data: string;
  dropped: number;
}

/**
 * Typing captured while the link is not known to work, released all-or-nothing.
 *
 * All-or-nothing because terminal input is a sequence. Replaying part of it -
 * an Enter without the paste it was meant to submit, or a command without the
 * text that changed its meaning - can run something the user never typed as a
 * whole. So once any piece is refused, everything held is dropped, and the
 * caller says nothing was sent.
 */
export class HeldInput {
  private chunks: string[] = [];
  private chars = 0;
  private session: number | null = null;
  private since = 0;
  private spoiled = false;

  constructor(
    private readonly maxChars = MAX_HELD_INPUT_CHARS,
    private readonly maxAgeMs = MAX_HELD_INPUT_AGE_MS,
  ) {}

  /** Characters held so far, counting any refused piece. */
  get size(): number {
    return this.chars;
  }

  /** Hold `data` typed for `session`. `false` means it was refused - and that
   *  nothing held since the hold began will be sent either. */
  hold(session: number, data: string, now: number): boolean {
    if (this.session === null) {
      this.session = session;
      this.since = now;
    }
    this.chars += data.length;
    if (
      this.spoiled ||
      session !== this.session ||
      now - this.since > this.maxAgeMs ||
      this.chars > this.maxChars
    ) {
      this.spoiled = true;
      this.chunks = [];
      return false;
    }
    this.chunks.push(data);
    return true;
  }

  /** Empty the hold for `session`: all of it, in order, if it is whole, fresh,
   *  and was typed for that session; otherwise nothing. */
  take(session: number, now: number): HeldRelease {
    const whole =
      !this.spoiled && this.session === session && now - this.since <= this.maxAgeMs;
    const release = whole
      ? { data: this.chunks.join(""), dropped: 0 }
      : { data: "", dropped: this.chars };
    this.reset();
    return release;
  }

  /** Drop everything held. Returns how much was dropped. */
  clear(): number {
    const dropped = this.chars;
    this.reset();
    return dropped;
  }

  private reset(): void {
    this.chunks = [];
    this.chars = 0;
    this.session = null;
    this.since = 0;
    this.spoiled = false;
  }
}

export interface LinkGuardDeps {
  /** One round trip to the host. Resolves only if the host answered. */
  ping: () => Promise<unknown>;
  /** Retire the current link, so the app's normal silent-drop path reconnects
   *  now instead of at the QUIC idle timeout. */
  dropLink: () => void;
  /** True while the app sits on a settled link (paired, no connect running). A
   *  check result is acted on only then. */
  linkSettled: () => boolean;
  /** The live write path for one piece of terminal input. */
  deliver: (session: number, data: string) => void;
  /** Tell the user something they typed was not sent. */
  notify: (message: string) => void;
  /** Mirrors the hold for the UI. `null` means input flows live. */
  onHold: (hold: LinkHold | null) => void;
  now?: () => number;
  probeTimeoutMs?: number;
}

/**
 * Routes terminal input around a link that is not known to work.
 *
 * The app tells it about these moments: a resume that needs a check
 * ({@link verify}), the link going away ({@link linkLost}), the host's session
 * list arriving ({@link sessionsListed}), a session re-attached on a fresh link
 * ({@link reattached}), and the session or link being given up
 * ({@link abandon}). From a check or a drop until the session is back, input is
 * held instead of written to the link.
 */
export class LinkGuard {
  private hold: LinkHold | null = null;
  /** Bumped by every check and every link change; a check whose number moved
   *  on was overtaken and must not act. */
  private check = 0;
  /** Session ids in the host's list since the link last came back; `null`
   *  until that list arrives. */
  private listed: Set<number> | null = null;
  /** A re-attached session waiting for that list before its typing replays. */
  private awaiting: number | null = null;
  /** Who hears how that wait ended (see {@link reattached}). */
  private awaitReport: ((outcome: ReattachOutcome) => void) | undefined;
  private awaitTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly held: HeldInput;

  constructor(
    private readonly deps: LinkGuardDeps,
    held?: HeldInput,
  ) {
    this.held = held ?? new HeldInput();
  }

  get state(): LinkHold | null {
    return this.hold;
  }

  /** One piece of terminal input for `session`: live, or held. */
  input(session: number, data: string): void {
    if (this.hold === null) {
      this.deps.deliver(session, data);
      return;
    }
    if (!this.held.hold(session, data, this.now())) this.deps.notify(HELD_INPUT_REFUSED);
  }

  /**
   * Prove the current link with one round trip.
   *
   * `session` is the open terminal, whose input waits for the answer. With none
   * open (`null`) nothing is held, but a dead link is still replaced now rather
   * than when the QUIC idle timeout finally notices.
   */
  verify(session: number | null): Promise<void> {
    const check = ++this.check;
    if (session !== null) this.setHold("checking");
    return probeLink(this.deps.ping, this.deps.probeTimeoutMs ?? LINK_PROBE_TIMEOUT_MS).then(
      (alive) => {
        // Overtaken: the link dropped or was replaced, or a newer check began.
        // Dropping "the current link" now could kill a fresh, healthy one.
        if (check !== this.check || !this.deps.linkSettled()) return;
        if (alive) {
          if (this.hold === "checking" && session !== null) this.restored(session);
          return;
        }
        if (this.hold === "checking") this.setHold("reconnecting");
        this.deps.dropLink();
      },
    );
  }

  /** The link went away. Any check in flight is void, and so is the last
   *  session list. `session` is the open terminal whose input should now wait
   *  for the reconnect (`null`: none). */
  linkLost(session: number | null): void {
    this.check++;
    this.listed = null;
    this.stopAwaiting();
    if (session !== null) this.setHold("reconnecting");
  }

  /** The host's full session list arrived - the first thing it sends on every
   *  link, so after a reconnect this says which sessions survived. */
  sessionsListed(ids: readonly number[]): void {
    this.listed = new Set(ids);
    if (this.awaiting !== null) this.settle(this.awaiting, this.awaitReport);
  }

  /**
   * `session` was re-attached on a fresh link. Its held typing replays once the
   * host's list confirms the session still exists: a host that restarted while
   * the app was away has forgotten it, and silently ignores input for an id it
   * does not know - so replaying blind could lose the typing after all.
   *
   * `report` hears which it was, once the list says. With a report, a gone
   * session's dropped typing is the caller's to mention - in the one message
   * that also says the session ended - so no notice of its own is shown.
   * Without one, the guard says so itself. Not called if the wait is given up
   * (the list never came, the link dropped again, or the session was left).
   */
  reattached(session: number, report?: (outcome: ReattachOutcome) => void): void {
    this.stopAwaiting();
    if (this.listed !== null) {
      this.settle(session, report);
      return;
    }
    this.awaiting = session;
    this.awaitReport = report;
    this.awaitTimer = setTimeout(() => {
      this.awaiting = null;
      this.abandon();
    }, SESSION_LIST_WAIT_MS);
  }

  /** `session` is attached on a working link and known to exist: send what was
   *  held, in order and in one write, then let input flow live. */
  restored(session: number): void {
    this.stopAwaiting();
    this.setHold(null);
    const { data, dropped } = this.held.take(session, this.now());
    if (data) this.deps.deliver(session, data);
    if (dropped) this.deps.notify(HELD_INPUT_DROPPED);
  }

  /** The session or the link is being given up: drop anything held, and say so. */
  abandon(): void {
    this.drop(HELD_INPUT_DROPPED);
  }

  private settle(session: number, report?: (outcome: ReattachOutcome) => void): void {
    if (this.listed?.has(session)) {
      this.restored(session);
      report?.({ survived: true, unsent: 0 });
    } else if (report) {
      // Drop it all BEFORE reporting: the caller may leave the session at once,
      // and leaving abandons whatever is still held - with a second notice.
      this.stopAwaiting();
      this.setHold(null);
      report({ survived: false, unsent: this.held.clear() });
    } else {
      this.drop(HELD_INPUT_SESSION_GONE);
    }
  }

  private drop(notice: string): void {
    this.stopAwaiting();
    this.setHold(null);
    if (this.held.clear()) this.deps.notify(notice);
  }

  private stopAwaiting(): void {
    clearTimeout(this.awaitTimer);
    this.awaitTimer = undefined;
    this.awaiting = null;
    this.awaitReport = undefined;
  }

  private setHold(hold: LinkHold | null): void {
    if (this.hold === hold) return;
    this.hold = hold;
    this.deps.onHold(hold);
  }

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }
}
