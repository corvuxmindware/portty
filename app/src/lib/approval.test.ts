import { describe, expect, it } from "vitest";
import { orderedOptions } from "./approval";

const kinds = (options: Array<{ kind: string }>) => options.map((option) => option.kind);

describe("orderedOptions", () => {
  it("puts Allow and Reject in fixed positions whatever order the agent sent", () => {
    const sent = [
      { kind: "reject_always" },
      { kind: "allow_once" },
      { kind: "reject_once" },
      { kind: "allow_always" },
    ];
    expect(kinds(orderedOptions(sent))).toEqual([
      "allow_once",
      "reject_once",
      "allow_always",
      "reject_always",
    ]);
  });

  it("produces the SAME layout from a differently ordered payload", () => {
    // The actual guarantee: two agents describing the same choice must not
    // produce two different button layouts.
    const a = orderedOptions([{ kind: "allow_once" }, { kind: "reject_once" }]);
    const b = orderedOptions([{ kind: "reject_once" }, { kind: "allow_once" }]);
    expect(kinds(a)).toEqual(kinds(b));
  });

  it("sorts unknown kinds last instead of displacing a known button", () => {
    const sent = [{ kind: "something_new" }, { kind: "allow_once" }, { kind: "reject_once" }];
    expect(kinds(orderedOptions(sent))).toEqual([
      "allow_once",
      "reject_once",
      "something_new",
    ]);
  });

  it("keeps the agent's relative order within one kind", () => {
    const sent = [
      { kind: "allow_once", id: "a" },
      { kind: "allow_once", id: "b" },
      { kind: "reject_once", id: "r" },
    ];
    expect(orderedOptions(sent).map((option) => option.id)).toEqual(["a", "b", "r"]);
  });

  it("does not mutate the array it was given", () => {
    const sent = [{ kind: "reject_once" }, { kind: "allow_once" }];
    orderedOptions(sent);
    expect(kinds(sent)).toEqual(["reject_once", "allow_once"]);
  });
});
