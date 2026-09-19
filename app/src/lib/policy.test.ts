import { describe, expect, it } from "vitest";
import {
  canonicalToolInput,
  dedupePermissionLabel,
  exactAllowRule,
  formatPermissionDetail,
  learnExactAllowRule,
  permissionCategory,
  permissionToolDetail,
  permissionToolInput,
  persistentPolicy,
  policyAllows,
  looksLikeSecretToStore,
  touchesSensitivePath,
  workspaceScopeAllowsTier,
} from "./policy";
import type {
  AgentPermission,
  AgentTimelineEvent,
  ApprovalPolicy,
  WorkspaceScope,
} from "./portty";

/** A sandbox root the user actually chose. Every tier-matrix case passes this
 *  explicitly: a tier only speaks for a scoped root, and leaving it implicit
 *  would hide the gate these tests are meant to sit on top of. */
const PROJECT: WorkspaceScope = "project";

const policy = (overrides: Partial<ApprovalPolicy> = {}): ApprovalPolicy => ({
  tier: "readonly",
  session_overrides: {},
  prompt_exceptions: [],
  exact_allow_rules: [],
  ...overrides,
});

describe("policyAllows (tier semantics - the plan's acceptance matrix)", () => {
  // Every call passes a concrete input on purpose: a MISSING input is its own
  // fail-closed rule (tested separately), and these cases are about the tier
  // matrix, not about what happens before the detail arrives.
  const IN = '{"path":"foo.rs"}';
  it("readonly auto-approves reads only", () => {
    const p = policy({ tier: "readonly" });
    expect(policyAllows(p, 1, "read", "Read foo.rs", IN, PROJECT)).toBe(true);
    expect(policyAllows(p, 1, "write", "Edit foo.rs", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "execute", "Run: ls", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "network", "Fetch url", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "destructive", "Delete foo", IN, PROJECT)).toBe(false);
  });

  it("edits auto-approves reads + writes, still prompts exec/network/destructive", () => {
    const p = policy({ tier: "edits" });
    expect(policyAllows(p, 1, "read", "t", IN, PROJECT)).toBe(true);
    expect(policyAllows(p, 1, "write", "t", IN, PROJECT)).toBe(true);
    expect(policyAllows(p, 1, "execute", "t", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "network", "t", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "destructive", "t", IN, PROJECT)).toBe(false);
  });

  it("yolo auto-approves everything recognized", () => {
    const p = policy({ tier: "yolo" });
    for (const c of ["read", "write", "execute", "network", "destructive"] as const) {
      expect(policyAllows(p, 1, c, "t", IN, PROJECT)).toBe(true);
    }
  });

  it("unknown categories NEVER auto-approve - even under yolo (fail closed)", () => {
    expect(policyAllows(policy({ tier: "yolo" }), 1, "unknown", "t", IN, PROJECT)).toBe(false);
    expect(policyAllows(policy({ tier: "readonly" }), 1, "unknown", "t", IN, PROJECT)).toBe(false);
  });

  it("prompt exceptions beat every tier", () => {
    const p = policy({ tier: "yolo", prompt_exceptions: ["Run: rm -rf build/"] });
    expect(policyAllows(p, 1, "execute", "Run: rm -rf build/", IN, PROJECT)).toBe(false);
    expect(policyAllows(p, 1, "execute", "Run: ls", IN, PROJECT)).toBe(true);
  });

  it("per-session override wins over the host tier - for exactly that session", () => {
    const p = policy({ tier: "readonly", session_overrides: { "7": "yolo" } });
    expect(policyAllows(p, 7, "execute", "t", IN, PROJECT)).toBe(true);
    expect(policyAllows(p, 8, "execute", "t", IN, PROJECT)).toBe(false);
  });

  it("learns only the exact category and byte-for-byte tool title", () => {
    const learned = learnExactAllowRule(
      policy({ tier: "readonly" }),
      "execute",
      "Run: cargo test -p core",
      '{"command":"cargo test -p core"}',
    )!;
    const input = '{"command":"cargo test -p core"}';
    expect(policyAllows(learned, 1, "execute", "Run: cargo test -p core", input, PROJECT)).toBe(true);
    expect(policyAllows(learned, 1, "execute", "Run: cargo  test -p core", input, PROJECT)).toBe(false);
    expect(policyAllows(learned, 1, "execute", "run: cargo test -p core", input, PROJECT)).toBe(false);
    expect(policyAllows(learned, 1, "network", "Run: cargo test -p core", input, PROJECT)).toBe(false);
    expect(
      policyAllows(
        learned,
        1,
        "execute",
        "Run: cargo test -p core",
        '{"command":"cargo test --all"}',
      PROJECT,
    ),
    ).toBe(false);
  });

  it("always-prompt exceptions override learned exact allows", () => {
    const title = "Run deployment";
    const input = '{"command":"deploy"}';
    const learned = learnExactAllowRule(policy(), "execute", title, input)!;
    learned.prompt_exceptions = [title];
    expect(policyAllows(learned, 1, "execute", title, input, PROJECT)).toBe(false);
  });
});

describe("workspace scope - a tier only speaks for a root someone chose", () => {
  const IN = '{"path":"src/main.rs"}';

  /// The headline. The shipped service files pointed the sandbox root at the
  /// home directory, so `readonly` auto-approved reads of everything the user
  /// owned - and a filename blocklist was all that stood in the way of
  /// `~/work/other/terraform.tfstate` or `~/Documents/anything`.
  it("refuses every tier inside a broad root", () => {
    for (const tier of ["readonly", "edits", "yolo"] as const) {
      expect(policyAllows(policy({ tier }), 1, "read", "Read src/main.rs", IN, "broad")).toBe(
        false,
      );
      expect(policyAllows(policy({ tier }), 1, "write", "Edit src/main.rs", IN, "broad")).toBe(
        false,
      );
    }
  });

  it("allows the tier normally inside a project root", () => {
    expect(policyAllows(policy(), 1, "read", "Read src/main.rs", IN, "project")).toBe(true);
  });

  /// An absent scope must read as broad. A phone that inferred "project" from a
  /// missing field would auto-approve exactly when it knows least.
  it("treats an absent or unrecognized scope as broad", () => {
    expect(policyAllows(policy(), 1, "read", "Read src/main.rs", IN, undefined)).toBe(false);
    expect(
      policyAllows(policy(), 1, "read", "Read src/main.rs", IN, "nonsense" as WorkspaceScope),
    ).toBe(false);
    expect(workspaceScopeAllowsTier(undefined)).toBe(false);
    expect(workspaceScopeAllowsTier("broad")).toBe(false);
    expect(workspaceScopeAllowsTier("project")).toBe(true);
  });

  /// The scope disables the BLANKET statement, not the user's specific one.
  /// Naming one operation stays theirs to grant however wide the root is -
  /// otherwise a broad root would leave no way to work at all.
  it("still honours an exact rule inside a broad root", () => {
    const saved = policy({
      exact_allow_rules: [{ category: "read", title: "Read src/main.rs", input: IN }],
    });
    expect(policyAllows(saved, 1, "read", "Read src/main.rs", IN, "broad")).toBe(true);
  });

  /// Scope is not a substitute for the other fail-closed rules.
  it("does not rescue unknown categories or missing input in a project root", () => {
    expect(policyAllows(policy(), 1, "unknown", "?", IN, "project")).toBe(false);
    expect(policyAllows(policy(), 1, "read", "Read file", null, "project")).toBe(false);
  });
});

describe("sensitive paths added for infrastructure and database state", () => {
  /// `terraform.tfstate` is the case the root check CANNOT catch: it lives
  /// inside the repo, so it is inside any correctly-scoped sandbox, and it holds
  /// provider credentials in plaintext.
  it("flags terraform state and vars", () => {
    for (const path of [
      "terraform.tfstate",
      "infra/terraform.tfstate.backup",
      "envs/prod.tfvars",
    ]) {
      expect(touchesSensitivePath(`Read ${path}`, `{"path":"${path}"}`), path).toBe(true);
    }
  });

  it("flags database files and dumps", () => {
    for (const path of ["app.sqlite", "data.sqlite3", "users.db", "backup.dump", "db-dump.sql.gz", "pg_dump.tar"]) {
      expect(touchesSensitivePath(`Read ${path}`, `{"path":"${path}"}`), path).toBe(true);
    }
  });

  /// The noise bound. Prompting on every migration would train people to tap
  /// through the prompts that matter, which is how the sensitive-path check
  /// stops working at all.
  it("leaves ordinary source and migrations alone", () => {
    for (const path of [
      "migrations/001_init.sql",
      "src/db.rs",
      "schema.sql",
      "docs/database.md",
      "dumpster.ts",
    ]) {
      expect(touchesSensitivePath(`Read ${path}`, `{"path":"${path}"}`), path).toBe(false);
    }
  });
});

describe("exactAllowRule", () => {
  it("rejects unsafe or ambiguous rules instead of canonicalizing commands", () => {
    const input = '{"command":"tool"}';
    expect(exactAllowRule("unknown", "tool", input)).toBeNull();
    expect(exactAllowRule("execute", " tool", input)).toBeNull();
    expect(exactAllowRule("execute", "tool\nnext", input)).toBeNull();
    expect(exactAllowRule("execute", "x".repeat(513), input)).toBeNull();
    expect(exactAllowRule("execute", "tool", null)).toBeNull();
    expect(exactAllowRule("execute", "tool", "not json")).toBeNull();
  });

  it("keeps meaningful internal whitespace exact", () => {
    expect(exactAllowRule("execute", "Run: printf 'a  b'", '{"command":"printf a  b"}')).toEqual({
      category: "execute",
      title: "Run: printf 'a  b'",
      input: '{"command":"printf a  b"}',
    });
  });

  it("canonicalizes nested JSON keys without altering strings", () => {
    expect(canonicalToolInput('{ "z": 1, "a": { "y": 2, "x": "a  b" } }')).toBe(
      '{"a":{"x":"a  b","y":2},"z":1}',
    );
  });

  // An exact rule stores title + input verbatim, in the same plaintext storage
  // as the approval log. The log can redact; a rule that redacted would no
  // longer match anything, so the only option is to refuse it.
  it("refuses to store a rule whose input carries a credential", () => {
    expect(
      exactAllowRule(
        "execute",
        "Run command",
        '{"command":"curl -H \\"Authorization: Bearer sk-live-abcdef1234567890\\" https://api.example.com"}',
      ),
    ).toBeNull();
  });

  // The line is "contains a credential", not "mentions a credential file". A
  // path is a filename, and naming one operation is the explicit consent that
  // lets a sensitive path be auto-approved at all - refusing these would remove
  // that escape hatch to avoid storing a guessable filename.
  it("still stores a rule that only NAMES a credential file", () => {
    expect(exactAllowRule("read", "Read .env", '{"path":".env"}')).toEqual({
      category: "read",
      title: "Read .env",
      input: '{"path":".env"}',
    });
  });

  it("still stores ordinary rules, secrets being the exception not the rule", () => {
    expect(exactAllowRule("read", "Read src/main.rs", '{"path":"src/main.rs"}')).toEqual({
      category: "read",
      title: "Read src/main.rs",
      input: '{"path":"src/main.rs"}',
    });
  });
});

describe("persistentPolicy", () => {
  it("persists host policy but strips process-local session overrides", () => {
    expect(
      persistentPolicy(
        policy({
          tier: "edits",
          session_overrides: { "1": "yolo", "9": "readonly" },
          prompt_exceptions: ["Run deployment"],
          exact_allow_rules: [
            { category: "execute", title: "Run tests", input: '{"command":"test"}' },
          ],
        }),
      ),
    ).toEqual({
      tier: "edits",
      session_overrides: {},
      prompt_exceptions: ["Run deployment"],
      exact_allow_rules: [
        { category: "execute", title: "Run tests", input: '{"command":"test"}' },
      ],
    });
  });

  it("drops malformed and duplicate stored rules", () => {
    const cleaned = persistentPolicy({
      ...policy(),
      exact_allow_rules: [
        { category: "execute", title: "Run tests", input: '{"command":"test"}' },
        { category: "execute", title: "Run tests", input: '{"command":"test"}' },
        { category: "unknown", title: "mystery", input: "{}" } as never,
        { category: "network", title: " bad", input: '{"url":"https://example.com"}' },
      ],
    });
    expect(cleaned.exact_allow_rules).toEqual([
      { category: "execute", title: "Run tests", input: '{"command":"test"}' },
    ]);
  });

  // Re-validating on load IS the migration: a rule stored before the content
  // check existed is dropped the next time the policy is saved.
  it("drops a secret-bearing rule written by an older build", () => {
    const cleaned = persistentPolicy({
      ...policy(),
      exact_allow_rules: [
        {
          category: "network",
          title: "Fetch api.example.com",
          input: '{"header":"Authorization: Bearer sk-live-abcdef1234567890"}',
        },
        { category: "execute", title: "Run tests", input: '{"command":"test"}' },
      ],
    });
    expect(cleaned.exact_allow_rules).toEqual([
      { category: "execute", title: "Run tests", input: '{"command":"test"}' },
    ]);
  });
});

describe("permissionCategory", () => {
  const request = (category?: AgentPermission["category"]): AgentPermission => ({
    id: 1,
    tool_call: { tool_call_id: "call_1", title: "t" },
    options: [],
    category,
    connection: 1,
  });
  const toolEvent = (kind: string): AgentTimelineEvent => ({
    seq: 1,
    event: {
      type: "tool_call",
      tool_call_id: "call_1",
      title: "t",
      kind: kind as never,
      status: "pending",
      detail: null,
    },
  });

  it("prefers the frame-stamped category", () => {
    expect(permissionCategory(request("destructive"), [toolEvent("read")])).toBe("destructive");
  });

  it("falls back to the timeline tool kind for legacy hosts", () => {
    expect(permissionCategory(request(), [toolEvent("edit")])).toBe("write");
    expect(permissionCategory(request(), [toolEvent("fetch")])).toBe("network");
    expect(permissionCategory(request(), [toolEvent("delete")])).toBe("destructive");
  });

  it("resolves to unknown when nothing identifies the tool", () => {
    expect(permissionCategory(request(), [])).toBe("unknown");
    expect(permissionCategory(request(), [toolEvent("think")])).toBe("unknown");
  });

  it("extracts only canonical raw input from the matching initial tool call", () => {
    const events = [
      {
        ...toolEvent("execute"),
        event: {
          ...toolEvent("execute").event,
          detail: '{ "cwd": "/tmp", "command": "cargo test" }',
        },
      },
    ] as AgentTimelineEvent[];
    expect(permissionToolInput(request("execute"), events)).toBe(
      '{"command":"cargo test","cwd":"/tmp"}',
    );
    expect(permissionToolInput(request("execute"), [])).toBeNull();
  });

  it("tracks a later tool_call_update's detail + kind, not the initial ones (#50)", () => {
    const update = (detail: string | null, kind: string | null): AgentTimelineEvent => ({
      seq: 2,
      event: {
        type: "tool_call_update",
        tool_call_id: "call_1",
        title: null,
        kind: kind as never,
        status: "pending",
        detail,
      },
    });
    const initial = {
      ...toolEvent("read"),
      event: { ...toolEvent("read").event, detail: '{"command":"ls"}' },
    } as AgentTimelineEvent;
    // A later update refines the command AND escalates read -> execute: the
    // card, exact-allow, and the category must all follow the update.
    const updated = [initial, update('{"command":"rm -rf /tmp/x"}', "execute")];
    expect(permissionToolInput(request(), updated)).toBe('{"command":"rm -rf /tmp/x"}');
    expect(permissionToolDetail(request(), updated)).toBe('{"command":"rm -rf /tmp/x"}');
    expect(permissionCategory(request(), updated)).toBe("execute");
    // A null field on an update means "unchanged" - keep the last known values.
    const unchanged = [initial, update(null, null)];
    expect(permissionToolInput(request(), unchanged)).toBe('{"command":"ls"}');
    expect(permissionCategory(request(), unchanged)).toBe("read");
  });
});

describe("sensitive paths - a credential read is not a routine read", () => {
  const secrets = [
    ".env",
    "app/.env.production",
    "/home/u/.ssh/id_ed25519",
    "~/.aws/credentials",
    "deploy/server.pem",
    "certs/bundle.p12",
    "release.keystore",
    "/home/u/.npmrc",
    "/etc/shadow",
    "gcp/service-account.json",
    "~/.config/gh/hosts.yml",
    "~/.local/share/portty/identity.bin",
  ];

  it("flags credential-shaped paths in the title or the tool input", () => {
    for (const path of secrets) {
      expect(touchesSensitivePath(`Read ${path}`, null), path).toBe(true);
      expect(touchesSensitivePath("Read file", JSON.stringify({ path })), path).toBe(true);
    }
  });

  it("leaves ordinary source files alone", () => {
    for (const path of [
      "src/main.rs",
      "README.md",
      "app/src/App.tsx",
      "environment.yml",
      "docs/key-concepts.md",
      "keyboard.ts",
      "test/fixtures/secretly-not-a-secret.txt.md",
    ]) {
      expect(touchesSensitivePath(`Read ${path}`, null), path).toBe(false);
    }
  });

  it("does NOT auto-approve a credential read at any tier", () => {
    for (const tier of ["readonly", "edits", "yolo"] as const) {
      expect(
        policyAllows(policy({ tier }), 1, "read", "Read .env", '{"path":".env"}', PROJECT),
      ).toBe(false);
    }
    // ...while an ordinary read with a KNOWN path still flows through.
    expect(
      policyAllows(policy(), 1, "read", "Read src/main.rs", '{"path":"src/main.rs"}', PROJECT),
    ).toBe(true);
  });

  // ACP refines a tool call AFTER its card appears, so a card can arrive before
  // the path does. Auto-approving then approves an operation nobody - including
  // this engine - could actually see.
  it("never auto-approves an operation whose input has not arrived yet", () => {
    for (const tier of ["readonly", "edits", "yolo"] as const) {
      expect(policyAllows(policy({ tier }), 1, "read", "Read file", null, PROJECT), tier).toBe(false);
      expect(policyAllows(policy({ tier }), 1, "write", "Edit file", null, PROJECT), tier).toBe(false);
    }
    // The same card, once its detail lands, decides normally either way.
    expect(policyAllows(policy(), 1, "read", "Read file", '{"path":"src/lib.rs"}', PROJECT)).toBe(true);
    expect(
      policyAllows(policy(), 1, "read", "Read file", '{"path":"/home/u/.ssh/id_rsa"}', PROJECT),
    ).toBe(false);
  });

  it("still honours an EXACT rule the user saved for that precise operation", () => {
    // Naming one operation is explicit consent; a tier is not.
    const saved = policy({
      exact_allow_rules: [{ category: "read", title: "Read .env", input: '{"path":".env"}' }],
    });
    expect(policyAllows(saved, 1, "read", "Read .env", '{"path":".env"}', PROJECT)).toBe(true);
    // A different secret is not covered by that rule.
    expect(policyAllows(saved, 1, "read", "Read .env.prod", '{"path":".env.prod"}', PROJECT)).toBe(
      false,
    );
  });
});

describe("looksLikeSecretToStore - what must not be written down", () => {
  it("catches credential-shaped VALUES that no path pattern can see", () => {
    // The gap the path-only check had: none of these touch a credential-shaped
    // filename, so `touchesSensitivePath` calls them ordinary.
    const values = [
      'curl -H "Authorization: Bearer sk-live-abcdef1234567890abcdef"',
      "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
      "curl https://user:hunter2@internal.example/deploy",
      "psql postgres://admin:s3cr3t@db.internal:5432/app",
      'echo "password: hunter2" >> config.yml',
      "slack-cli --token xoxb-1234567890-abcdefghijkl",
      "GOOGLE_API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstu",
    ];
    for (const value of values) {
      expect(looksLikeSecretToStore("Run command", value), value).toBe(true);
    }
    // A JWT and an inline private key, wherever they appear.
    expect(
      looksLikeSecretToStore("Run", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"),
    ).toBe(true);
    expect(looksLikeSecretToStore("Write key", "-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
  });

  it("still catches credential-shaped PATHS, in the title or the input", () => {
    expect(looksLikeSecretToStore("Read /home/u/.ssh/id_ed25519", null)).toBe(true);
    expect(looksLikeSecretToStore("Read file", '{"path":".env.production"}')).toBe(true);
  });

  it("leaves ordinary operations alone", () => {
    for (const [title, input] of [
      ["Read src/main.rs", '{"path":"src/main.rs"}'],
      ["Run command", '{"command":"cargo test --workspace"}'],
      ["Run command", '{"command":"git commit -m \'fix: token bucket refill\'"}'],
      ["Fetch url", '{"url":"https://docs.rs/tokio"}'],
      ["Edit README.md", '{"path":"README.md"}'],
    ] as const) {
      expect(looksLikeSecretToStore(title, input), title).toBe(false);
    }
  });

  it("is broader than the approval check, on purpose", () => {
    // Redaction may over-trigger - the cost is one unreadable log line. Approval
    // must not, or every long string would prompt.
    const bearer = 'curl -H "Authorization: Bearer abc123def456"';
    expect(looksLikeSecretToStore("Run command", bearer)).toBe(true);
    expect(touchesSensitivePath("Run command", bearer)).toBe(false);
  });
});

describe("formatPermissionDetail", () => {
  it("restores the newlines a multi-command script was written with", () => {
    // The exact shape from the phone: six commands in one JSON string. Rendered
    // raw this is one run-on line ending "... head -40\necho ..." on screen.
    const detail = JSON.stringify({
      command: 'gh api repos/x/y --jq \'{name}\'\necho "=== LANGUAGES ==="\ngh api repos/x/y/languages',
    });
    expect(formatPermissionDetail(detail)).toBe(
      'gh api repos/x/y --jq \'{name}\'\necho "=== LANGUAGES ==="\ngh api repos/x/y/languages',
    );
  });

  it("never drops a field the user is approving", () => {
    // Showing only `command` would hide the directory it runs in.
    const detail = JSON.stringify({ command: "rm -rf build", cwd: "/etc", timeout: 30 });
    const out = formatPermissionDetail(detail) ?? "";
    expect(out.startsWith("rm -rf build")).toBe(true);
    expect(out).toContain("cwd: /etc");
    expect(out).toContain("timeout: 30");
  });

  it("indents an object with no command-shaped field", () => {
    const out = formatPermissionDetail('{"path":"src/main.rs"}') ?? "";
    expect(out).toBe('{\n  "path": "src/main.rs"\n}');
  });

  it("passes through anything it cannot parse, unchanged", () => {
    expect(formatPermissionDetail("rm -rf /tmp/x")).toBe("rm -rf /tmp/x");
    expect(formatPermissionDetail("{not json")).toBe("{not json");
    expect(formatPermissionDetail("[1,2]")).toBe("[1,2]");
    expect(formatPermissionDetail(null)).toBe(null);
  });

  it("ignores a command field that is empty or not a string", () => {
    expect(formatPermissionDetail('{"command":""}')).toBe('{\n  "command": ""\n}');
    expect(formatPermissionDetail('{"command":42}')).toBe('{\n  "command": 42\n}');
  });
});

describe("dedupePermissionLabel", () => {
  it("collapses the repeated rule from the phone screenshot", () => {
    const name =
      "Always Allow Bash(gh api *), Bash(gh api *), Bash(gh api *), Bash(gh api *), Bash(gh api *)";
    expect(dedupePermissionLabel(name)).toBe("Always Allow Bash(gh api *)");
  });

  it("keeps rules that differ, because the difference is the decision", () => {
    const name = "Always Allow Bash(gh api *), Bash(rm *), Bash(gh api *)";
    expect(dedupePermissionLabel(name)).toBe("Always Allow Bash(gh api *), Bash(rm *)");
  });

  it("leaves a single-rule label untouched", () => {
    expect(dedupePermissionLabel("Always Allow Bash(gh api *)")).toBe(
      "Always Allow Bash(gh api *)",
    );
    expect(dedupePermissionLabel("Allow once")).toBe("Allow once");
  });

  it("returns the original string when nothing repeats", () => {
    const name = "Always Allow Bash(a), Bash(b), Bash(c)";
    expect(dedupePermissionLabel(name)).toBe(name);
  });

  it("does not collapse entries that differ only by case", () => {
    // Rule matching is case-sensitive, so Bash(GH *) is not Bash(gh *).
    const name = "Always Allow Bash(GH *), Bash(gh *)";
    expect(dedupePermissionLabel(name)).toBe(name);
  });
});
