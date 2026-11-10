import { describe, expect, expectTypeOf, it } from "vitest";
import * as auth from "./index.js";
import type { LogActorView, LogClassView, LogEntryView, SecurityLogView } from "./index.js";

// A consumer names the class through LogEntryView; it is Go's account.LogClasses().
expectTypeOf<LogEntryView["class"]>().toEqualTypeOf<"change" | "session">();
expectTypeOf<LogClassView["class"]>().toEqualTypeOf<LogEntryView["class"]>();
expectTypeOf<SecurityLogView["entries"]>().toEqualTypeOf<readonly LogEntryView[]>();
expectTypeOf<LogEntryView["actor"]>().toEqualTypeOf<LogActorView>();

describe("package root (node)", () => {
  it("loads outside a browser", () => {
    expect("document" in globalThis).toBe(false);
    expect(typeof auth.createAuthClient).toBe("function");
  });
});
