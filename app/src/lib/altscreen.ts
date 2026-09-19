/**
 * Client-side alternate-screen detector (the host stays a dumb byte pipe -
 * all VT awareness lives on the phone, per the design's hard rule #1).
 *
 * Full-screen apps (vim/htop/less) switch to the alternate screen buffer with
 * `CSI ? 1049|1047|47 h` and leave it with the matching `l`. When that happens
 * the phone must render at the PTY's REAL grid (match-width), not the
 * fit-to-phone grid - cursor-addressed paints are only correct when both sides
 * agree on cols. This scanner finds those switches so the renderer can flip
 * BEFORE the app's first full-screen paint is parsed. Detection is a tiny byte
 * DFA that survives sequences split across chunk boundaries; bytes are never
 * withheld, only split into segments, so nothing is ever delayed or reordered.
 */

/** Private-mode params that switch to/from the alternate screen buffer. */
const ALT_PARAMS = new Set(["47", "1047", "1049"]);

/**
 * Private-mode params that turn MOUSE REPORTING on: X10 (9), VT200 click
 * (1000), highlight (1001), button-event/drag (1002), any-event (1003).
 *
 * Deliberately NOT the encoding modes (1005/1006/1015) or focus tracking
 * (1004) - those change how a report is framed, not whether one is sent, and an
 * app can enable 1006 while reporting is off. Tracked as a SET because the
 * modes are independent: `?1000h ?1002h ?1002l` must leave reporting on.
 */
const MOUSE_PARAMS = new Set(["9", "1000", "1001", "1002", "1003"]);

export interface AltSegment {
  /** Bytes to write to the terminal (may end exactly on a switch sequence). */
  bytes: Uint8Array;
  /**
   * null → plain bytes. true/false → this segment ENDS with an alt-screen
   * enter/exit; apply the renderer flip after writing it and before the next.
   */
  alt: boolean | null;
}

export class AltScreenScanner {
  // 0 ground · 1 saw ESC · 2 saw ESC[ · 3 in ESC[? params · 4 saw ESC[!
  private state = 0;
  private params = "";
  // Running terminal modes, updated synchronously as bytes are scanned - so
  // callers (predictive echo, the accessory KeyBar) read the CURRENT mode
  // without waiting for the async xterm.write render callback that lags it.
  private alt = false;
  private appCursor = false;
  private mouse = new Set<string>();

  /** Forget any partial sequence AND the tracked modes: a terminal reset /
   * session switch returns the screen, cursor-key mode, and mouse reporting
   * to default. */
  reset(): void {
    this.state = 0;
    this.params = "";
    this.alt = false;
    this.appCursor = false;
    this.mouse.clear();
  }

  /** Whether the alternate screen is currently active. Synchronous - reflects
   * the last scanned chunk, ahead of the render-flip signal, so prediction can
   * suppress into a TUI immediately on the switching chunk. */
  altActive(): boolean {
    return this.alt;
  }

  /** Whether DECCKM application-cursor-key mode is active. When true, arrow
   * keys must be SS3-encoded (ESC O A) rather than CSI (ESC [ A). */
  appCursorMode(): boolean {
    return this.appCursor;
  }

  /**
   * Whether the program is asking to be told about mouse events. When true the
   * phone's full-cover keyboard overlay must go click-through so a tap reaches
   * xterm and is reported as a click; the ⌨ button summons the keyboard
   * instead. Synchronous, like the other modes.
   */
  mouseReporting(): boolean {
    return this.mouse.size > 0;
  }

  /**
   * Split a chunk at alternate-screen switches. Write each segment in order;
   * when `alt` is non-null, flip the render mode between that segment and the
   * next (xterm.write's callback is the natural sequencing point). Full resets
   * (RIS `ESC c`, DECSTR `ESC [ ! p`) emit an `alt=false` segment so the render
   * gate clears even when an app leaves the alt screen without the paired `l`.
   */
  scan(data: Uint8Array): AltSegment[] {
    const out: AltSegment[] = [];
    let start = 0;
    const flip = (i: number, alt: boolean) => {
      out.push({ bytes: data.subarray(start, i + 1), alt });
      start = i + 1;
      this.alt = alt;
    };
    for (let i = 0; i < data.length; i++) {
      const b = data[i];
      switch (this.state) {
        case 0:
          if (b === 0x1b) this.state = 1;
          break;
        case 1: // ESC
          if (b === 0x5b /* [ */) {
            this.state = 2;
          } else if (b === 0x63 /* c → RIS, hard reset */) {
            this.state = 0;
            this.appCursor = false;
            this.mouse.clear();
            flip(i, false);
          } else {
            this.state = b === 0x1b ? 1 : 0;
          }
          break;
        case 2: // ESC [
          if (b === 0x3f /* ? */) {
            this.state = 3;
            this.params = "";
          } else if (b === 0x21 /* ! */) {
            this.state = 4;
          } else {
            this.state = b === 0x1b ? 1 : 0;
          }
          break;
        case 3: // ESC [ ? …params
          if ((b >= 0x30 && b <= 0x39) || b === 0x3b /* digit or ; */) {
            this.params += String.fromCharCode(b);
            if (this.params.length > 32) this.state = 0; // runaway - bail
          } else if (b === 0x68 || b === 0x6c /* h | l */) {
            this.state = 0;
            const set = b === 0x68;
            const parts = this.params.split(";");
            // DECCKM (?1): a mode flag only - no render flip, no segment split.
            if (parts.some((p) => p === "1")) this.appCursor = set;
            // Mouse reporting: same - a flag, not a re-layout. Per-param so a
            // combined `?1002;1006h` and a later `?1002l` both land correctly.
            for (const p of parts) {
              if (!MOUSE_PARAMS.has(p)) continue;
              if (set) this.mouse.add(p);
              else this.mouse.delete(p);
            }
            if (parts.some((p) => ALT_PARAMS.has(p))) flip(i, set);
          } else {
            this.state = b === 0x1b ? 1 : 0;
          }
          break;
        case 4: // ESC [ !  →  DECSTR soft reset (ESC [ ! p)
          if (b === 0x70 /* p */) {
            this.state = 0;
            this.appCursor = false;
            // Strictly, DECSTR does not reset mouse reporting - but this file
            // already treats a soft reset as clearing the alt gate and DECCKM,
            // and a click-through overlay that outlives the app owning it is
            // the worse failure (taps would never type again). Clear it.
            this.mouse.clear();
            flip(i, false);
          } else {
            this.state = b === 0x1b ? 1 : 0;
          }
          break;
      }
    }
    if (start < data.length || out.length === 0) {
      out.push({ bytes: data.subarray(start), alt: null });
    }
    return out;
  }
}
