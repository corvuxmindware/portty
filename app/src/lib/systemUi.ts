// The app's own trips into the phone's system screens: the file picker for an
// upload and the Save dialog for a download.
//
// Opening one hides the app, so coming back is a background -> foreground edge
// like any other, and the app lock used to treat it as one: the fingerprint
// prompt came up the moment Save was tapped. While that prompt waits, the app
// underneath is paused, so the transfer the user just asked for never started,
// and a link left idle meanwhile died without the screen hearing about it.
// The user had unlocked the app seconds before and never left it, so a quick
// return from a screen the app itself opened does not re-lock. A long one
// still does: a phone left on that screen is as unattended as any other.

/** Back within this long from a screen the app opened, the lock stays off. */
export const SYSTEM_UI_RELOCK_AFTER_MS = 2 * 60_000;

/** The hide edge can come a beat before the call starts, and the show edge a
 *  beat after its promise settles. */
export const SYSTEM_UI_EDGE_GRACE_MS = 3_000;

export class SystemUiTracker {
  private open = 0;
  private lastStarted = Number.NEGATIVE_INFINITY;
  private lastEnded = Number.NEGATIVE_INFINITY;

  constructor(private readonly now: () => number = Date.now) {}

  /** Run `show` (which opens a system screen) and remember that it did. */
  async run<T>(show: () => Promise<T>): Promise<T> {
    this.open++;
    this.lastStarted = this.now();
    try {
      return await show();
    } finally {
      this.open--;
      this.lastEnded = this.now();
    }
  }

  /** Was the app hidden at `hiddenAt` because it opened a system screen? */
  hidByUs(hiddenAt: number): boolean {
    if (this.open > 0) return true;
    return hiddenAt >= this.lastStarted - SYSTEM_UI_EDGE_GRACE_MS &&
      hiddenAt <= this.lastEnded + SYSTEM_UI_EDGE_GRACE_MS;
  }

  /**
   * Should the lock come back on a return at `now`, after being hidden since
   * `hiddenAt`? Not for a quick trip to a screen the app opened itself.
   */
  relockOnReturn(hiddenAt: number, now: number = this.now()): boolean {
    if (!this.hidByUs(hiddenAt)) return true;
    return now - hiddenAt >= SYSTEM_UI_RELOCK_AFTER_MS;
  }
}

/** The one tracker the app lock and the file screens share. */
export const systemUi = new SystemUiTracker();
