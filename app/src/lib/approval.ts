/**
 * Ordering for approval-card buttons.
 *
 * Pure so it is testable: this decides where the Allow and Reject buttons land,
 * and getting it wrong is a security bug, not a cosmetic one.
 *
 * Approval options arrive in whatever order the agent sent them and render into
 * a two-column grid. Left as-is, `Allow` could occupy a different cell on
 * different cards - and what catches people on a security prompt is muscle
 * memory landing on the button that used to be `Reject`. Fixing the rank fixes
 * the position: Allow top-left, Reject top-right, standing grants below.
 */

/**
 * One-shot decisions first - the common case, and the only ones whose scope
 * Portty can actually see. The provider-wide standing grants sort after them;
 * they render full-width and carry their own arm/confirm step.
 */
const OPTION_RANK: Record<string, number> = {
  allow_once: 0,
  reject_once: 1,
  allow_always: 2,
  reject_always: 3,
};

/** Unknown kinds sort last rather than displacing a button the user knows. */
const UNKNOWN_RANK = 99;

export function orderedOptions<T extends { kind: string }>(options: readonly T[]): T[] {
  // Array.prototype.sort is stable, so equal ranks keep the agent's relative
  // order and two options of the same kind never swap between renders.
  return [...options].sort(
    (a, b) => (OPTION_RANK[a.kind] ?? UNKNOWN_RANK) - (OPTION_RANK[b.kind] ?? UNKNOWN_RANK),
  );
}
