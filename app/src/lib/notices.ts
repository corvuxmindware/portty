/**
 * The open-source notices file (app/public/third-party-notices.txt, written by
 * scripts/app-notices/generate.mjs). It ships inside the app and is fetched only
 * when the licences screen opens - about 400 KB of text nobody else needs.
 */
export const NOTICES_URL = `${import.meta.env.BASE_URL}third-party-notices.txt`;

/** The rule line the generator draws above each section and each licence text. */
const RULE = /^(?:={40}|-{40})$/;

/**
 * Cuts the notices into blocks at each boxed heading (a rule line after a blank
 * line), so the screen can render them as separate elements and let the WebView
 * skip laying out the ones that are off screen. The blank line between two
 * blocks is dropped - the screen puts that space back - so joining the blocks
 * with "\n\n" gives the original text, with Windows line endings made plain.
 */
export function splitNotices(text: string): string[] {
  const lines = text.replace(/\r\n?/g, "\n").replace(/\n+$/, "").split("\n");
  if (lines.length === 1 && lines[0] === "") return [];
  const blocks: string[] = [];
  let current: string[] = [];
  lines.forEach((line, index) => {
    if (RULE.test(line) && index > 1 && lines[index - 1] === "" && current.length > 1) {
      blocks.push(current.slice(0, -1).join("\n"));
      current = [];
    }
    current.push(line);
  });
  blocks.push(current.join("\n"));
  return blocks;
}
