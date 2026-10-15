import { describe, expect, it } from "vitest";
import {
  defaultPlatform,
  INSTALL_OPTIONS,
  installOption,
  platformAfterKey,
} from "./setupHelp";

// Real user agents, so the guess is tested against what the WebViews send.
const ANDROID_WEBVIEW =
  "Mozilla/5.0 (Linux; Android 12; ONEPLUS A6003 Build/SKQ1.211113.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.122 Mobile Safari/537.36";
const IPHONE_WKWEBVIEW =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";
// iPadOS asks for desktop sites by default, so an iPad says "Macintosh".
const IPAD_DESKTOP_MODE =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15";
const WINDOWS_BROWSER =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

describe("INSTALL_OPTIONS", () => {
  // Word for word what the download repo's README and the website publish. A
  // typo here is a command that fails on the user's computer, so pin them.
  it("gives the published install command for each computer", () => {
    expect(INSTALL_OPTIONS.map(({ platform, label, command }) => [platform, label, command])).toEqual([
      ["windows", "Windows", "winget install CorvuxMindware.Portty"],
      ["macos", "macOS", "brew install mrtechnoo/tap/portty"],
      [
        "linux",
        "Linux",
        "curl -fsSL https://raw.githubusercontent.com/mrtechnoo/portty/main/install.sh | sh",
      ],
    ]);
  });

  it("keeps every command on one clean line, so a copy pastes as one command", () => {
    for (const { command } of INSTALL_OPTIONS) {
      expect(command).toBe(command.trim());
      expect(command).not.toMatch(/[\r\n\t]/);
    }
  });

  it("finds the option for each platform", () => {
    for (const platform of ["windows", "macos", "linux"] as const) {
      expect(installOption(platform).platform).toBe(platform);
    }
  });
});

describe("defaultPlatform", () => {
  it("opens on macOS next to an iPhone or iPad", () => {
    expect(defaultPlatform(IPHONE_WKWEBVIEW)).toBe("macos");
    expect(defaultPlatform(IPAD_DESKTOP_MODE)).toBe("macos");
  });

  // Android's user agent contains "Linux" - picking the Linux tab from it would
  // show most Android users a command for a computer they do not have.
  it("opens on Windows next to an Android phone", () => {
    expect(defaultPlatform(ANDROID_WEBVIEW)).toBe("windows");
  });

  it("falls back to Windows when the system is unknown", () => {
    expect(defaultPlatform("")).toBe("windows");
    expect(defaultPlatform(WINDOWS_BROWSER)).toBe("windows");
  });
});

describe("platformAfterKey", () => {
  it("steps through the tabs with the arrow keys and wraps at the ends", () => {
    expect(platformAfterKey("windows", "ArrowRight")).toBe("macos");
    expect(platformAfterKey("macos", "ArrowRight")).toBe("linux");
    expect(platformAfterKey("linux", "ArrowRight")).toBe("windows");
    expect(platformAfterKey("windows", "ArrowLeft")).toBe("linux");
    expect(platformAfterKey("linux", "ArrowLeft")).toBe("macos");
  });

  it("jumps to the first and last tab with Home and End", () => {
    expect(platformAfterKey("macos", "Home")).toBe("windows");
    expect(platformAfterKey("macos", "End")).toBe("linux");
  });

  it("ignores every other key", () => {
    for (const key of ["Enter", " ", "Tab", "ArrowUp", "ArrowDown", "a"]) {
      expect(platformAfterKey("macos", key)).toBeNull();
    }
  });
});
