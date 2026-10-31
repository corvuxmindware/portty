import { describe, expect, it } from "vitest";
import {
  RECONNECTED,
  RECONNECTED_SESSION_ENDED,
  RECONNECTED_SESSION_ENDED_UNSENT,
  RECONNECTED_SESSION_RESTORED,
  reconnectNotice,
} from "./reconnectNotice";

describe("reconnectNotice", () => {
  it("says the session was restored only when the host still has it", () => {
    expect(reconnectNotice({ session: 1, survived: true, unsent: 0, noticeable: true })).toEqual({
      message: RECONNECTED_SESSION_RESTORED,
      backToList: false,
    });
  });

  it("stays quiet about a blip the user never saw, when the session survived", () => {
    expect(reconnectNotice({ session: 1, survived: true, unsent: 0, noticeable: false })).toEqual({
      message: null,
      backToList: false,
    });
  });

  /* The field bug: the host restarted (its list came back empty) and the app
     said "session restored" next to "Not sent - that session has ended". */
  it("says once that a gone session ended, and leaves it for the list", () => {
    expect(reconnectNotice({ session: 1, survived: false, unsent: 0, noticeable: true })).toEqual({
      message: RECONNECTED_SESSION_ENDED,
      backToList: true,
    });
  });

  it("folds unsent typing into that same one message", () => {
    const notice = reconnectNotice({ session: 1, survived: false, unsent: 12, noticeable: true });
    expect(notice).toEqual({ message: RECONNECTED_SESSION_ENDED_UNSENT, backToList: true });
    expect(notice.message).not.toContain("restored");
  });

  it("explains a gone session even after a short outage, since the screen changes", () => {
    expect(reconnectNotice({ session: 1, survived: false, unsent: 0, noticeable: false })).toEqual({
      message: RECONNECTED_SESSION_ENDED,
      backToList: true,
    });
  });

  /* On the list there is no session to restore, so the old toast's claim was
     never true there; the toast itself still shows when it used to. */
  it("says a plain 'Reconnected' with no session open, and only after a noticeable outage", () => {
    expect(reconnectNotice({ session: null, survived: false, unsent: 0, noticeable: true })).toEqual({
      message: RECONNECTED,
      backToList: false,
    });
    expect(reconnectNotice({ session: null, survived: false, unsent: 0, noticeable: false })).toEqual({
      message: null,
      backToList: false,
    });
  });

  it("keeps every message short, for a toast on a phone-width screen", () => {
    for (const message of [
      RECONNECTED,
      RECONNECTED_SESSION_RESTORED,
      RECONNECTED_SESSION_ENDED,
      RECONNECTED_SESSION_ENDED_UNSENT,
    ]) {
      expect(message.length).toBeLessThanOrEqual(50);
    }
  });
});
