// First-run help: how to get the Portty program onto the computer.
//
// The phone app can do nothing on its own - it needs `portty-host` running on
// the computer it connects to, and a new user who opens the app has no way to
// know that. So while no host is saved, Home shows a setup card (SetupHelp.tsx)
// with the install command for each kind of computer.

export type Platform = "windows" | "macos" | "linux";

export interface InstallOption {
  platform: Platform;
  /** The tab label. */
  label: string;
  /** One line to run in a terminal on the computer, exactly as published. */
  command: string;
}

/**
 * One command per platform, word for word what the public download repo's
 * README (mrtechnoo/portty) and the website's install section give. Change
 * them together.
 *
 * Scoop is left out on purpose: it takes two commands (add the bucket, then
 * install), and the setup guide the card links to has it.
 */
export const INSTALL_OPTIONS: readonly InstallOption[] = [
  { platform: "windows", label: "Windows", command: "winget install CorvuxMindware.Portty" },
  { platform: "macos", label: "macOS", command: "brew install mrtechnoo/tap/portty" },
  {
    platform: "linux",
    label: "Linux",
    command: "curl -fsSL https://raw.githubusercontent.com/mrtechnoo/portty/main/install.sh | sh",
  },
];

/** The install option for `platform`. */
export function installOption(platform: Platform): InstallOption {
  return INSTALL_OPTIONS.find((option) => option.platform === platform) ?? INSTALL_OPTIONS[0];
}

/**
 * Which tab opens first. The phone cannot see the computer, so this is only a
 * guess from the phone's own system: next to an iPhone or iPad a Mac is the
 * better first guess, and next to anything else Windows, the most common
 * desktop. Every tab is one tap away, and nothing else depends on the guess.
 *
 * Android's user agent says "Linux" too - it must never pick the Linux tab.
 */
export function defaultPlatform(userAgent: string): Platform {
  return /iPhone|iPad|iPod|Macintosh/.test(userAgent) ? "macos" : "windows";
}

/**
 * The tab a key press moves to inside the tab row: Left/Right step and wrap
 * around, Home/End jump to the ends - the usual keys for a row of tabs, so a
 * hardware keyboard can switch them. `null` for any other key.
 */
export function platformAfterKey(current: Platform, key: string): Platform | null {
  const order = INSTALL_OPTIONS.map((option) => option.platform);
  const at = Math.max(0, order.indexOf(current));
  switch (key) {
    case "ArrowRight":
      return order[(at + 1) % order.length];
    case "ArrowLeft":
      return order[(at - 1 + order.length) % order.length];
    case "Home":
      return order[0];
    case "End":
      return order[order.length - 1];
    default:
      return null;
  }
}
