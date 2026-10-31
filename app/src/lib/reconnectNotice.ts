// What the app says after it reconnects on its own, and where it leaves the user.
//
// A reconnect can come back to a host that no longer has the session the user
// was in: the host restarted (a restart ends every session it ran), or the
// session ended while the phone was away. Only the host's first session list on
// the new link can tell, so the message waits for that list - and then says ONE
// thing. It used to say "session restored" up front, and a held-typing notice
// then contradicted it a moment later.

/** The link came back; no session was open. */
export const RECONNECTED = "Reconnected";
/** The link came back and the open session is still on the host. */
export const RECONNECTED_SESSION_RESTORED = "Reconnected - session restored";
/** The link came back, but the open session is gone from the host. */
export const RECONNECTED_SESSION_ENDED = "Reconnected - that session ended on the computer";
/** As above, and what was typed while the link was down went nowhere. */
export const RECONNECTED_SESSION_ENDED_UNSENT = "Reconnected - that session ended, typing not sent";

export interface ReconnectFacts {
  /** The session on screen when the link came back; `null` when none was (the
   *  session list, pairing). */
  session: number | null;
  /** Whether the host's first list on the new link still has `session`.
   *  Ignored without a session. */
  survived: boolean;
  /** Characters of typing held for `session` and dropped unsent because it is
   *  gone. */
  unsent: number;
  /** The link was down long enough for the user to have seen it go. A blip
   *  they never saw needs no news. */
  noticeable: boolean;
}

export interface ReconnectNotice {
  /** The one message to show, or `null` for none. */
  message: string | null;
  /** Leave the dead session's screen for the list. */
  backToList: boolean;
}

/** Decide the one message an auto-reconnect earns, and whether the session
 *  screen has to go because its session did not survive. */
export function reconnectNotice(facts: ReconnectFacts): ReconnectNotice {
  if (facts.session !== null && !facts.survived) {
    // Said however short the outage was: the screen is about to change under
    // the user, and they need to know why.
    return {
      message: facts.unsent > 0 ? RECONNECTED_SESSION_ENDED_UNSENT : RECONNECTED_SESSION_ENDED,
      backToList: true,
    };
  }
  if (!facts.noticeable) return { message: null, backToList: false };
  return {
    message: facts.session === null ? RECONNECTED : RECONNECTED_SESSION_RESTORED,
    backToList: false,
  };
}
