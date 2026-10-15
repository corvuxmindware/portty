import { describe, expect, it } from "vitest";
import { splitNotices } from "./notices";
import shipped from "../../public/third-party-notices.txt?raw";
import packageJson from "../../package.json?raw";

const RULE = "=".repeat(40);
const THIN = "-".repeat(40);

describe("splitNotices", () => {
  it("cuts at each boxed heading and keeps every line", () => {
    const text = [
      "OPEN-SOURCE LICENCES",
      "",
      RULE,
      "1. FONTS AND ICONS",
      RULE,
      "",
      "Lucide icons - ISC [2]",
      "",
      THIN,
      "[2] ISC License",
      "Used by: Lucide icons",
      THIN,
      "",
      "Permission to use...",
    ].join("\n");
    const blocks = splitNotices(text);
    expect(blocks).toHaveLength(3);
    expect(blocks[0]).toBe("OPEN-SOURCE LICENCES");
    expect(blocks[1].startsWith(`${RULE}\n1. FONTS AND ICONS\n${RULE}`)).toBe(true);
    expect(blocks[1].endsWith("Lucide icons - ISC [2]")).toBe(true);
    expect(blocks[2].startsWith(`${THIN}\n[2] ISC License`)).toBe(true);
    // Only the blank line before each heading goes; the screen draws that gap.
    expect(blocks.join("\n\n")).toBe(text);
  });

  it("does not cut at the closing rule of a heading or at short rules", () => {
    const text = ["intro", "", RULE, "title", RULE, "", "-----", "", "body"].join("\n");
    expect(splitNotices(text)).toEqual(["intro", [RULE, "title", RULE, "", "-----", "", "body"].join("\n")]);
  });

  it("never makes an empty first block", () => {
    expect(splitNotices(`\n${RULE}\ntitle`)).toEqual([`\n${RULE}\ntitle`]);
  });

  it("reads Windows line endings and a trailing newline", () => {
    expect(splitNotices(`a\r\n\r\n${RULE}\r\nb\r\n`)).toEqual(["a", `${RULE}\nb`]);
  });

  it("returns nothing for an empty file", () => {
    expect(splitNotices("")).toEqual([]);
    expect(splitNotices("\n")).toEqual([]);
  });
});

/*
 * The shipped notices must keep up with what the app ships. A failure here
 * means a dependency changed without regenerating the file: run
 * `node scripts/app-notices/generate.mjs` and commit the result.
 */
describe("third-party-notices.txt", () => {
  const notices = shipped.replace(/\r\n?/g, "\n");

  it("lists every runtime npm dependency", () => {
    const { dependencies } = JSON.parse(packageJson) as { dependencies: Record<string, string> };
    for (const name of Object.keys(dependencies)) {
      // @tauri-apps/plugin-* and the rest are listed as "<name> <version> - <licence>".
      expect(notices, name).toMatch(new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")} \\d`, "m"));
    }
  });

  it("credits the bundled font and icons", () => {
    expect(notices).toMatch(/^JetBrains Mono Nerd Font Mono/m);
    expect(notices).toMatch(/^Lucide icons/m);
  });

  it("has a text for every [number] the lists point to", () => {
    const [lists, texts] = notices.split(/^\d+\. LICENCE AND NOTICE TEXTS$/m);
    expect(texts, "the licence texts section").toBeDefined();
    const headings = new Set([...texts.matchAll(/^\[(\d+)\] /gm)].map((match) => match[1]));
    // Component lines start at the margin; the indented lines under them are
    // copyright notices, which can hold bracketed years like "[2017]".
    const componentLines = lists.split("\n").filter((line) => !line.startsWith(" "));
    const pointers = new Set(
      componentLines.flatMap((line) => [...line.matchAll(/ \[(\d+)\](?= |$)/g)].map((match) => match[1])),
    );
    expect(pointers.size).toBeGreaterThan(1);
    for (const pointer of pointers) expect(headings.has(pointer), `[${pointer}]`).toBe(true);
    expect(texts).toContain("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION");
  });
});
