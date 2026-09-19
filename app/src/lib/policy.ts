// Pure policy-engine logic (extracted from App.tsx so it is unit-testable).
// Fail-closed by construction: anything that isn't an explicit allow prompts.
//
// SCOPE OF THIS FILE. It decides what a COOPERATING adapter is allowed to do
// without asking. It is not a sandbox and cannot be one: adapters are ordinary
// subprocesses running as the same OS user, free to read, write and execute
// without ever calling `session/request_permission`, and the tool `kind` behind
// every `PermissionCategory` here is self-reported by the adapter. An adapter
// that lies about a category, or simply acts without asking, is outside
// everything below.
//
// That is worth stating because the rules here read like enforcement. They are
// enforcement over an honest agent's behaviour - which is the thing prompt
// injection actually attacks - and nothing at all over a compromised one.

import type {
  AgentPermission,
  AgentTimelineEvent,
  AgentToolKind,
  ApprovalPolicy,
  ExactAllowRule,
  PermissionCategory,
  WorkspaceScope,
} from "./portty";

export const DEFAULT_POLICY: ApprovalPolicy = {
  tier: "readonly",
  session_overrides: {},
  prompt_exceptions: [],
  exact_allow_rules: [],
};

const MAX_EXACT_RULE_TITLE = 512;
const MAX_EXACT_RULE_INPUT = 4096;
const RECOGNIZED_CATEGORIES = new Set<PermissionCategory>([
  "read",
  "write",
  "execute",
  "network",
  "destructive",
]);

/** Build a persistable exact rule without changing command semantics. In
 * particular this does not trim, case-fold, normalize Unicode, or collapse
 * whitespace: any of those can turn one shell command into another. */
type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function stableJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(stableJson);
  if (value !== null && typeof value === "object") {
    const sorted: { [key: string]: JsonValue } = {};
    for (const key of Object.keys(value).sort()) sorted[key] = stableJson(value[key]);
    return sorted;
  }
  return value;
}

/** ACP tool input is delivered as pretty JSON. Parse and recursively sort
 * object keys so semantically identical objects produce one stable exact key.
 * Invalid/truncated/oversized input is not learnable. */
export function canonicalToolInput(detail: string | null): string | null {
  if (!detail || detail.length > MAX_EXACT_RULE_INPUT) return null;
  try {
    const canonical = JSON.stringify(stableJson(JSON.parse(detail) as JsonValue));
    return canonical.length <= MAX_EXACT_RULE_INPUT ? canonical : null;
  } catch {
    return null;
  }
}

/** The most recent `detail` + `kind` for a tool call, merging the initial
 * `tool_call` with any later `tool_call_update`s (a null field on an update
 * means "unchanged"). ACP refines a tool call AFTER its approval card first
 * appears, so exact-allow, the displayed detail, and the category must all
 * track the LATEST tool call - not the initial one the card was built from
 * (#50). Null when the id was never seen. */
function latestToolFields(
  events: AgentTimelineEvent[],
  toolCallId: string,
): { detail: string | null; kind: AgentToolKind | null } | null {
  let seen = false;
  let detail: string | null = null;
  let kind: AgentToolKind | null = null;
  for (const { event } of events) {
    if (event.type === "tool_call" && event.tool_call_id === toolCallId) {
      seen = true;
      detail = event.detail;
      kind = event.kind;
    } else if (event.type === "tool_call_update" && event.tool_call_id === toolCallId) {
      seen = true;
      if (event.detail !== null) detail = event.detail;
      if (event.kind !== null) kind = event.kind;
    }
  }
  return seen ? { detail, kind } : null;
}

export function permissionToolInput(
  request: AgentPermission,
  events: AgentTimelineEvent[],
): string | null {
  const latest = latestToolFields(events, request.tool_call.tool_call_id);
  return latest ? canonicalToolInput(latest.detail) : null;
}

/**
 * The RAW tool input to SHOW the user at decision time - the command / args /
 * path they are actually approving. Unlike `permissionToolInput` this is NOT
 * canonicalized (key-sorted); it is the agent's own pretty detail, for display
 * only, never for rule matching. Null when the tool call carried no detail.
 */
export function permissionToolDetail(
  request: AgentPermission,
  events: AgentTimelineEvent[],
): string | null {
  return latestToolFields(events, request.tool_call.tool_call_id)?.detail ?? null;
}

/** Keys whose value IS the thing being approved, in preference order. */
const DETAIL_PRIMARY_KEYS = ["command", "cmd", "script"] as const;

/**
 * Make a tool detail readable before it is shown.
 *
 * The detail arrives as a JSON object - `{"command":"gh api …\necho …"}` - so a
 * multi-command script renders as ONE run-on line with a literal backslash-n in
 * it. `safeText` is not the culprit: it keeps real newlines on purpose. The
 * newlines are still escaped inside the JSON string at that point, and a wall of
 * unreadable text on an approval card is a security problem, not a cosmetic one -
 * nobody can judge what they cannot parse.
 *
 * Every other key is still printed after the command. Showing only the command
 * would be the easy version and the wrong one: a field this function chose to
 * hide is a field the user approved without seeing. Anything unrecognized falls
 * back to indented JSON, and anything unparseable is passed through untouched.
 */
export function formatPermissionDetail(detail: string | null): string | null {
  if (detail === null) return null;
  const trimmed = detail.trim();
  if (!trimmed.startsWith("{")) return detail;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return detail; // not JSON after all - show exactly what we were given
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return detail;
  const obj = parsed as Record<string, unknown>;
  const primary = DETAIL_PRIMARY_KEYS.find(
    (k) => typeof obj[k] === "string" && (obj[k] as string).length > 0,
  );
  if (primary === undefined) {
    // No command-shaped field: indenting at least puts each key on its own line.
    try {
      return JSON.stringify(parsed, null, 2);
    } catch {
      return detail;
    }
  }
  const lines: string[] = [obj[primary] as string];
  const rest = Object.keys(obj).filter((k) => k !== primary);
  if (rest.length > 0) {
    lines.push("");
    for (const key of rest) {
      const value = obj[key];
      lines.push(`${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`);
    }
  }
  return lines.join("\n");
}

/**
 * Collapse a permission option label that repeats the same rule.
 *
 * Adapters build these by joining one entry per matched rule, and a command
 * hitting the same pattern five times yields "Always Allow Bash(gh api *),
 * Bash(gh api *), Bash(gh api *), Bash(gh api *), Bash(gh api *)" - which
 * overflows the button and buries the scope line under it.
 *
 * Only BYTE-IDENTICAL entries are collapsed, so nothing the agent asked for is
 * hidden: five copies of one rule grant exactly what one copy grants. Entries
 * that differ at all are every one kept, because on this button the difference
 * between two rules is the whole decision. The leading verb ("Always allow …")
 * is split off first so the first entry compares equal to the bare ones.
 */
export function dedupePermissionLabel(name: string): string {
  const parts = name
    .split(/,\s*/u)
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length < 2) return name;
  const leading = /^(.*?\ballow\s+)(.*)$/iu.exec(parts[0]);
  const prefix = leading ? leading[1] : "";
  const head = leading ? leading[2] : parts[0];
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const part of [head, ...parts.slice(1)]) {
    if (seen.has(part)) continue;
    seen.add(part);
    unique.push(part);
  }
  if (unique.length === parts.length) return name; // nothing repeated
  return prefix + unique.join(", ");
}

/**
 * Build a storable "always allow exactly this" rule, or null if it isn't one we
 * are willing to keep.
 *
 * The content check below is as much a part of that as the shape checks. An exact
 * rule has to persist the title and the canonical input VERBATIM - that is what
 * makes it exact - and it lands in the same plaintext `localStorage` as the
 * approval log, which on iOS goes into device backups. The log's answer,
 * redaction, is not available here: a redacted rule matches nothing. So the only
 * way not to write a credential down is to refuse the rule. That is also the
 * better answer on its own terms - a standing auto-approval for an operation
 * carrying a live token is not something to store more carefully, it is something
 * not to have.
 *
 * The bar is [`looksLikeSecretValue`], NOT the broader
 * [`looksLikeSecretToStore`] the log uses. A rule for `Read .env` stores a
 * filename, not a credential, and naming one operation is exactly the explicit
 * consent that lets a sensitive path be auto-approved at all (see
 * `policyAllows`). Refusing those would delete that escape hatch to prevent
 * writing down a path an attacker could guess.
 *
 * Because `persistentPolicy` re-validates every stored rule through this
 * function, rules written before this check existed are dropped the next time a
 * policy is loaded and saved - no separate migration path.
 */
export function exactAllowRule(
  category: PermissionCategory,
  title: string,
  input: string | null,
): ExactAllowRule | null {
  const canonicalInput = canonicalToolInput(input);
  if (
    !RECOGNIZED_CATEGORIES.has(category) ||
    title.length === 0 ||
    title.length > MAX_EXACT_RULE_TITLE ||
    title !== title.trim() ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(title) ||
    canonicalInput === null ||
    canonicalInput !== input ||
    looksLikeSecretValue(title, canonicalInput)
  ) {
    return null;
  }
  return { category: category as ExactAllowRule["category"], title, input: canonicalInput };
}

const ruleKey = (rule: ExactAllowRule) =>
  JSON.stringify([rule.category, rule.title, rule.input]);

export function hasExactAllowRule(
  policy: ApprovalPolicy,
  category: PermissionCategory,
  title: string,
  input: string | null,
): boolean {
  const candidate = exactAllowRule(category, title, input);
  if (!candidate || !Array.isArray(policy.exact_allow_rules)) return false;
  const key = ruleKey(candidate);
  return policy.exact_allow_rules.some((rule) => ruleKey(rule) === key);
}

export function learnExactAllowRule(
  policy: ApprovalPolicy,
  category: PermissionCategory,
  title: string,
  input: string | null,
): ApprovalPolicy | null {
  const candidate = exactAllowRule(category, title, input);
  if (!candidate) return null;
  if (hasExactAllowRule(policy, category, title, input)) return policy;
  return {
    ...policy,
    exact_allow_rules: [...(policy.exact_allow_rules ?? []), candidate],
  };
}

/**
 * Only host-wide policy is durable. Session ids are process-local and restart
 * at 1 whenever the host restarts, so persisting an override could silently
 * grant an unrelated future session the old session's trust.
 */
export function persistentPolicy(policy: ApprovalPolicy): ApprovalPolicy {
  const exact_allow_rules: ExactAllowRule[] = [];
  const seen = new Set<string>();
  if (Array.isArray(policy.exact_allow_rules)) {
    for (const stored of policy.exact_allow_rules) {
      const rule = exactAllowRule(stored?.category, stored?.title, stored?.input);
      if (!rule || seen.has(ruleKey(rule))) continue;
      seen.add(ruleKey(rule));
      exact_allow_rules.push(rule);
    }
  }
  return { ...policy, session_overrides: {}, exact_allow_rules };
}

/** The category of a permission request. New hosts stamp it on the frame
 * (`PolicyPermissionRequest`); the timeline scan is the fallback for cards
 * relayed by older hosts. Anything unresolvable is `unknown` → always prompt. */
export function permissionCategory(
  request: AgentPermission,
  events: AgentTimelineEvent[],
): PermissionCategory {
  if (request.category) return request.category;
  const latest = latestToolFields(events, request.tool_call.tool_call_id);
  if (!latest) return "unknown";
  if (latest.kind === "read" || latest.kind === "search") return "read";
  if (latest.kind === "edit" || latest.kind === "move") return "write";
  if (latest.kind === "execute") return "execute";
  if (latest.kind === "fetch") return "network";
  if (latest.kind === "delete") return "destructive";
  return "unknown";
}

/**
 * Filenames and path fragments that make an operation worth a human look no
 * matter which tier is active, because reading one of these is not "reading a
 * file" - it is taking a credential.
 *
 * The default tier auto-allows every recognized READ, which is right for source
 * files and wrong for `.env`, an SSH private key, a cloud credentials file, or a
 * keystore: those sit in an ordinary workspace, an agent can ask for them without
 * ever writing anything, and the transcript then carries the secret off the
 * machine. Matching is deliberately broad and lowercase - a false prompt costs
 * one tap, a missed one costs a credential.
 */
/// A path can arrive bare, quoted inside JSON, or after "Read ", so the
/// boundary is "anything that is not part of a name" rather than a path
/// separator. Hyphen and underscore count as name characters, which is what keeps
/// `a-secret.txt` and `.dockerignore` from matching.
const B = String.raw`(?:^|[^a-z0-9_-])`;
const E = String.raw`(?:$|[^a-z0-9_-])`;
const sensitive = (body: string) => new RegExp(`${B}${body}${E}`);
/// An EXTENSION is preceded by the rest of the filename, so it takes no leading
/// boundary - only a trailing one (`server.pem`, but not `foo.keys`).
const sensitiveExtension = (body: string) => new RegExp(`${body}${E}`);

const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  sensitive(String.raw`\.env`), //                    .env, .env.local, app/.env.production
  sensitive(String.raw`\.(?:ssh|gnupg|aws|azure|kube|docker|netrc|npmrc|pypirc)`),
  sensitive(String.raw`\.(?:pgpass|my\.cnf|dbpass)`),
  sensitive(String.raw`id_(?:rsa|dsa|ecdsa|ed25519)`),
  sensitive(String.raw`\.?(?:git-credentials|credentials|secrets?|htpasswd)`),
  sensitiveExtension(String.raw`\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk|asc)`),
  sensitive(String.raw`(?:service[-_]?account|application_default_credentials)`),
  sensitive(String.raw`\.config[\\/](?:gh|gcloud)`),
  sensitive(String.raw`\.local[\\/]share[\\/]keyrings`),
  sensitive(String.raw`(?:shadow|sudoers)`),
  // Portty's own credentials: a copied identity is a copied pairing.
  sensitive(String.raw`(?:portty-peers\.dat|identity\.bin)`),
  // Infrastructure state. `terraform.tfstate` is the standout: it is routinely
  // committed inside a repo - so it is INSIDE the sandbox, where the root check
  // cannot help - and it stores provider credentials, DB passwords and private
  // keys in plaintext.
  sensitiveExtension(String.raw`\.(?:tfstate|tfvars)`),
  // Databases carry whatever the application stored, including password hashes
  // and session tokens.
  sensitiveExtension(String.raw`\.(?:sqlite3?|db|dump)`),
  // A dump names itself: `dump.sql`, `db-dump.sql.gz`, `pg_dump.tar`. Matching
  // the NAME rather than the `.sql` extension keeps ordinary migrations quiet -
  // prompting on every `001_init.sql` would be the noise that trains people to
  // tap through the prompts that matter.
  /dump[a-z0-9_-]*\.(?:sql|gz|zip|tar|bz2)/,
];

/**
 * Does this operation touch something credential-shaped? Checks the title and
 * the raw tool input together, since which one carries the path depends on the
 * adapter. Exported for the UI, which flags the card as well as prompting.
 */
export function touchesSensitivePath(title: string, input: string | null): boolean {
  const haystack = `${title}\n${input ?? ""}`.toLowerCase();
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(haystack));
}

/**
 * Secrets that are VALUES rather than paths - an API key pasted into a command, a
 * bearer header, a token in a URL.
 *
 * Path patterns cannot see these at all: `curl -H "Authorization: Bearer sk-..."`
 * touches no credential-shaped filename, so a path-only check calls it ordinary.
 * These are checked case-sensitively where the prefix is (`ghp_`, `sk-`), because
 * lowercasing a haystack destroys the very shape that identifies them.
 *
 * Used for deciding what may be WRITTEN DOWN, not for approval decisions: a value
 * that looks like a key is a reason not to persist a log entry, whereas prompting
 * on every long base64 string would be noise.
 */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\b(?:bearer|authorization)\b\s*[:=]?\s*\S/i, //     auth headers
  /\b(?:sk|pk|rk)[-_][A-Za-z0-9]{16,}/, //                provider API keys
  /\bgh[pousr]_[A-Za-z0-9]{20,}/, //                       GitHub tokens
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/, //                     Slack tokens
  /\bAKIA[0-9A-Z]{16}\b/, //                               AWS access key id
  /\bAIza[0-9A-Za-z_-]{20,}/, //                            Google API key
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, //       JWTs
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/, //                 inline private keys
  /\b(?:password|passwd|secret|token|api[-_]?key)\b\s*[:=]\s*\S/i,
  /\/\/[^/\s:@]+:[^/\s@]+@/, //                            credentials in a URL
];

/**
 * Does this text CONTAIN a credential, as opposed to merely naming a file that
 * holds one? `Authorization: Bearer sk-live-...` contains one; `Read .env` does
 * not - the secret there is the file's contents, which never enter the request.
 *
 * That distinction decides what may be persisted. Storing the value is storing
 * the secret; storing the path stores a filename an attacker could have guessed.
 */
export function looksLikeSecretValue(title: string, input: string | null): boolean {
  const raw = `${title}\n${input ?? ""}`;
  return SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(raw));
}

/**
 * Would writing this down persist a secret, or a record of reaching for one?
 * True for a credential-shaped PATH or a credential-shaped VALUE, in either the
 * title or the input.
 *
 * Deliberately broader than both [`touchesSensitivePath`] and
 * [`looksLikeSecretValue`], because the approval log can afford it: a false
 * positive costs one unreadable line, a false negative costs a durable secret.
 * Rule storage cannot afford the same breadth - see [`exactAllowRule`].
 */
export function looksLikeSecretToStore(title: string, input: string | null): boolean {
  return touchesSensitivePath(title, input) || looksLikeSecretValue(title, input);
}

/**
 * Is the agent's sandbox root narrow enough for a TIER to speak for what is
 * inside it?
 *
 * A tier is a blanket statement about a body of files, so it only means anything
 * if someone chose that body. `"project"` is a directory the user picked;
 * anything else - the home directory, an ancestor of it, a filesystem root, or a
 * scope the host did not report - is not, and `readonly` there would quietly
 * mean "read anything I own" instead of "read this project".
 *
 * Absent is broad on purpose: the phone must not infer a narrow root from a
 * missing field.
 */
export function workspaceScopeAllowsTier(scope: WorkspaceScope | undefined): boolean {
  return scope === "project";
}

/**
 * Should this request be auto-approved under `policy`? Pure decision only -
 * the caller still checks for an `allow_once` option, sends the decision, and
 * writes the log. Rules:
 *  - `unknown` NEVER auto-approves (even under yolo)
 *  - prompt_exceptions (exact title match) always prompt
 *  - a MISSING operation input never auto-approves (see below)
 *  - a credential-shaped path always prompts, at every tier, UNLESS the user
 *    saved an exact rule for that precise operation
 *  - a BROAD sandbox root disables every tier (see `workspaceScopeAllowsTier`)
 *  - an explicit category + title + canonical raw-input rule grants that operation
 *  - readonly → read only; edits → read + write; yolo → everything recognized
 */
export function policyAllows(
  policy: ApprovalPolicy,
  sessionId: number,
  category: PermissionCategory,
  title: string,
  input: string | null = null,
  scope: WorkspaceScope | undefined = undefined,
): boolean {
  if (category === "unknown" || policy.prompt_exceptions.includes(title)) return false;
  // An exact rule is the user naming this one operation, secrets included, so it
  // still wins - but a tier is a blanket statement and must not cover a
  // credential the user never looked at.
  if (hasExactAllowRule(policy, category, title, input)) return true;
  // No input means WE DO NOT KNOW WHAT THIS OPERATION TOUCHES, so no tier may
  // wave it through.
  //
  // ACP delivers the tool detail in timeline events, and it refines a tool call
  // AFTER the approval card first appears (see `latestToolFields`, #50). A card
  // titled "Read file" with the path still in flight therefore used to be
  // auto-approved under the default read tier, and only then did an update reveal
  // it was `.env` or an SSH key - the sensitive-path check had nothing to match
  // on at the moment that mattered. Prompting instead costs one tap on adapters
  // that are slow to describe themselves; the alternative is approving an
  // operation nobody could see.
  if (input === null) return false;
  if (touchesSensitivePath(title, input)) return false;
  // A tier cannot speak for a root nobody scoped. This sits AFTER the exact-rule
  // check on purpose: naming one operation is still the user's to grant, however
  // wide the root is. It is the blanket statement that stops applying.
  if (!workspaceScopeAllowsTier(scope)) return false;
  const tier = policy.session_overrides[String(sessionId)] ?? policy.tier;
  return (
    tier === "yolo" || category === "read" || (tier === "edits" && category === "write")
  );
}
