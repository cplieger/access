import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { assign } from "./navigate.js";
import { withStepUp } from "./stepup.js";
import type { StepUpOptions, StepUpPrompt } from "./stepup.js";
import { fakeServer, refusal } from "./test-helpers/server.js";
import type { Answer, FakeServer } from "./test-helpers/server.js";
import { forbidStorage } from "./test-helpers/storage.js";
import { assertionCredential } from "./test-helpers/credential.js";
import { fixture, isObject } from "./test-helpers/wire.js";

vi.mock("./navigate.js", () => ({ assign: vi.fn() }));

const ACTION = "POST /api/auth/sessions/revoke-others";
const ME = "GET /api/auth/me";
const recent = refusal(403, "auth_recent_auth_required");
const noContent: Answer = { status: 204 };
const me: Answer = { status: 200, body: fixture("MeResponse") };
const request: Answer = {
  status: 200,
  body: { ceremony: "c-get", public_key: { publicKey: { challenge: "Y2g" } } },
};

forbidStorage();

beforeEach(() => {
  vi.stubGlobal("PublicKeyCredential", {});
});

const original = location.pathname + location.search + location.hash;
afterEach(() => {
  history.replaceState(history.state, "", original);
});

function run(s: FakeServer, o: Partial<StepUpOptions>): ReturnType<typeof withStepUp<void>> {
  return withStepUp(s.client, () => s.client.revokeOtherSessions(), {
    prompt: () => Promise.resolve("cancel"),
    password: () => Promise.resolve(null),
    code: () => Promise.resolve(null),
    navigate: () => {
      throw new Error("navigated");
    },
    ...o,
  });
}
const routes = (s: FakeServer): string[] => s.sent.map((x) => x.route);
const choose = (m: Awaited<ReturnType<StepUpPrompt>>): StepUpPrompt =>
  vi.fn(() => Promise.resolve(m));

describe("withStepUp: results that need no step-up", () => {
  const cases: readonly (readonly [string, Answer])[] = [
    ["a success", noContent],
    ["another refusal", refusal(403, "auth_forbidden")],
    [
      "a recent-auth refusal with a reason",
      refusal(403, "auth_recent_auth_required", "reenable_needs_other_method"),
    ],
  ];
  for (const [what, answer] of cases) {
    it(`returns ${what} as done, without a prompt or a retry`, async () => {
      const prompt = choose("password");
      const s = fakeServer({ [ACTION]: answer });
      const out = await run(s, { prompt });
      expect(out.kind).toBe("done");
      expect(prompt).not.toHaveBeenCalled();
      expect(routes(s)).toEqual([ACTION]);
    });
  }
});

describe("withStepUp: sign_in_again", () => {
  const stale = refusal(403, "auth_recent_auth_required", "sign_in_again");

  it("runs signInAgain and retries the action once when it resolves true", async () => {
    const prompt = choose("password");
    const signInAgain = vi.fn(() => Promise.resolve(true));
    const s = fakeServer({ [ACTION]: [stale, noContent] });
    const out = await run(s, { prompt, signInAgain });
    expect(out).toMatchObject({ kind: "done", result: { ok: true, status: 204 } });
    expect(signInAgain).toHaveBeenCalledOnce();
    expect(prompt).not.toHaveBeenCalled();
    expect(routes(s)).toEqual([ACTION, ACTION]);
  });

  it("returns the retry's refusal as done and never loops", async () => {
    const signInAgain = vi.fn(() => Promise.resolve(true));
    const s = fakeServer({ [ACTION]: stale });
    const out = await run(s, { signInAgain });
    expect(out).toMatchObject({
      kind: "done",
      result: { ok: false, code: "auth_recent_auth_required" },
    });
    expect(signInAgain).toHaveBeenCalledOnce();
    expect(routes(s)).toEqual([ACTION, ACTION]);
  });

  it("is cancelled when signInAgain resolves false", async () => {
    const prompt = choose("password");
    const s = fakeServer({ [ACTION]: stale });
    expect(await run(s, { prompt, signInAgain: () => Promise.resolve(false) })).toEqual({
      kind: "cancelled",
    });
    expect(prompt).not.toHaveBeenCalled();
    expect(routes(s)).toEqual([ACTION]);
  });

  it("returns the refusal as done without signInAgain", async () => {
    const prompt = choose("password");
    const s = fakeServer({ [ACTION]: stale });
    const out = await run(s, { prompt });
    expect(out).toMatchObject({
      kind: "done",
      result: { ok: false, code: "auth_recent_auth_required" },
    });
    expect(prompt).not.toHaveBeenCalled();
    expect(routes(s)).toEqual([ACTION]);
  });
});

describe("withStepUp: password", () => {
  it("steps up with the password and retries the action once", async () => {
    const prompt = choose("password");
    const s = fakeServer({
      [ACTION]: [recent, noContent],
      [ME]: me,
      "POST /api/auth/stepup/password": noContent,
    });
    const out = await run(s, { prompt, password: () => Promise.resolve("hunter22") });
    expect(out).toMatchObject({ kind: "done", result: { ok: true, status: 204 } });
    expect(routes(s)).toEqual([ACTION, ME, "POST /api/auth/stepup/password", ACTION]);
    expect(s.sent[2]?.body).toEqual({ password: "hunter22" });
    const view = fixture("MeResponse");
    expect(prompt).toHaveBeenCalledExactlyOnceWith(isObject(view) ? view["methods"] : undefined, [
      "password",
      "passkey",
      "oidc",
      "totp",
    ]);
  });

  it("returns the retry's refusal as done and never loops", async () => {
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      "POST /api/auth/stepup/password": noContent,
    });
    const out = await run(s, {
      prompt: choose("password"),
      password: () => Promise.resolve("hunter22"),
    });
    expect(out).toMatchObject({
      kind: "done",
      result: { ok: false, code: "auth_recent_auth_required" },
    });
    expect(routes(s)).toEqual([ACTION, ME, "POST /api/auth/stepup/password", ACTION]);
  });

  it("is cancelled when the user gives no password", async () => {
    const s = fakeServer({ [ACTION]: recent, [ME]: me });
    expect(await run(s, { prompt: choose("password") })).toEqual({ kind: "cancelled" });
    expect(routes(s)).toEqual([ACTION, ME]);
  });

  it("fails without a retry when the password is refused", async () => {
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      "POST /api/auth/stepup/password": refusal(401, "auth_invalid_credentials"),
    });
    const out = await run(s, {
      prompt: choose("password"),
      password: () => Promise.resolve("wrong"),
    });
    expect(out).toMatchObject({
      kind: "step-up-failed",
      error: { ok: false, status: 401, code: "auth_invalid_credentials" },
    });
    expect(routes(s)).toEqual([ACTION, ME, "POST /api/auth/stepup/password"]);
  });
});

// meWith is the MeResponse fixture with its methods' password_step_up and totp.usable set.
function meWith(passwordStepUp: boolean, totpUsable: boolean): Answer {
  const view = fixture("MeResponse") as {
    methods: { password_step_up: boolean; totp: { usable: boolean } };
  };
  view.methods.password_step_up = passwordStepUp;
  view.methods.totp.usable = totpUsable;
  return { status: 200, body: view };
}

describe("withStepUp: code", () => {
  const STEP = "POST /api/auth/stepup/code";

  it("steps up with the code and retries the action once", async () => {
    const s = fakeServer({ [ACTION]: [recent, noContent], [ME]: me, [STEP]: noContent });
    const out = await run(s, { prompt: choose("totp"), code: () => Promise.resolve("123456") });
    expect(out).toMatchObject({ kind: "done", result: { ok: true, status: 204 } });
    expect(routes(s)).toEqual([ACTION, ME, STEP, ACTION]);
    expect(s.sent[2]?.body).toEqual({ code: "123456" });
  });

  it("is cancelled when the user gives no code", async () => {
    const s = fakeServer({ [ACTION]: recent, [ME]: me });
    expect(await run(s, { prompt: choose("totp") })).toEqual({ kind: "cancelled" });
    expect(routes(s)).toEqual([ACTION, ME]);
  });

  it("fails without a retry when the code is refused", async () => {
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      [STEP]: refusal(401, "auth_code_invalid", "code_reused"),
    });
    const out = await run(s, { prompt: choose("totp"), code: () => Promise.resolve("123456") });
    expect(out).toMatchObject({ kind: "step-up-failed", error: { code: "auth_code_invalid" } });
    expect(routes(s)).toEqual([ACTION, ME, STEP]);
  });
});

describe("withStepUp: what it offers", () => {
  const cases: readonly (readonly [boolean, boolean, readonly string[]])[] = [
    [true, true, ["password", "passkey", "oidc", "totp"]],
    [false, true, ["passkey", "oidc", "totp"]],
    [true, false, ["password", "passkey", "oidc"]],
    [false, false, ["passkey", "oidc"]],
  ];
  for (const [passwordStepUp, totpUsable, offered] of cases) {
    it(`offers ${offered.join(", ")} with password_step_up ${String(passwordStepUp)} and totp.usable ${String(totpUsable)}`, async () => {
      const prompt = choose("cancel");
      const s = fakeServer({ [ACTION]: recent, [ME]: meWith(passwordStepUp, totpUsable) });
      await run(s, { prompt });
      expect(prompt).toHaveBeenCalledExactlyOnceWith(expect.anything(), offered);
    });
  }

  for (const [choice, passwordStepUp, totpUsable] of [
    ["password", false, true],
    ["totp", true, false],
  ] as const) {
    it(`answers a ${choice} choice it did not offer cancelled, with no request`, async () => {
      const s = fakeServer({ [ACTION]: recent, [ME]: meWith(passwordStepUp, totpUsable) });
      const out = await run(s, {
        prompt: choose(choice),
        password: () => Promise.resolve("hunter22"),
        code: () => Promise.resolve("123456"),
      });
      expect(out).toEqual({ kind: "cancelled" });
      expect(routes(s)).toEqual([ACTION, ME]);
    });
  }
});

describe("withStepUp: passkey", () => {
  it("reads stepped-up from the 204 finish and retries the action once", async () => {
    vi.spyOn(navigator.credentials, "get").mockResolvedValue(assertionCredential() as never);
    const s = fakeServer({
      [ACTION]: [recent, noContent],
      [ME]: me,
      "POST /api/auth/stepup/passkey/begin": request,
      "POST /api/auth/stepup/passkey/finish": noContent,
    });
    const out = await run(s, { prompt: choose("passkey") });
    expect(out).toMatchObject({ kind: "done", result: { ok: true } });
    expect(routes(s)).toEqual([
      ACTION,
      ME,
      "POST /api/auth/stepup/passkey/begin",
      "POST /api/auth/stepup/passkey/finish",
      ACTION,
    ]);
  });

  it("is cancelled when the user dismisses the authenticator", async () => {
    vi.spyOn(navigator.credentials, "get").mockRejectedValue(
      new DOMException("x", "NotAllowedError"),
    );
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      "POST /api/auth/stepup/passkey/begin": request,
    });
    expect(await run(s, { prompt: choose("passkey") })).toEqual({ kind: "cancelled" });
    expect(routes(s)).toEqual([ACTION, ME, "POST /api/auth/stepup/passkey/begin"]);
  });

  it("fails with the ceremony's outcome and no retry", async () => {
    vi.spyOn(navigator.credentials, "get").mockResolvedValue(assertionCredential() as never);
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      "POST /api/auth/stepup/passkey/begin": request,
      "POST /api/auth/stepup/passkey/finish": refusal(401, "auth_assertion_failed"),
    });
    expect(await run(s, { prompt: choose("passkey") })).toEqual({
      kind: "step-up-failed",
      error: { kind: "verification-failed" },
    });
    expect(routes(s).filter((r) => r === ACTION)).toHaveLength(1);
  });
});

describe("withStepUp: OIDC", () => {
  const START = "POST /api/auth/oidc/start/stepup";
  const start: Answer = { status: 200, body: fixture("OIDCStartResponse") };
  const url = (() => {
    const v = fixture("OIDCStartResponse");
    return isObject(v) ? v["url"] : undefined;
  })();

  it("starts with the redirect option, navigates to the IdP and never re-runs the action", async () => {
    const navigate = vi.fn();
    const s = fakeServer({ [ACTION]: recent, [ME]: me, [START]: start });
    const out = await run(s, {
      prompt: choose("oidc"),
      redirect: "/security?continue=n",
      navigate,
    });
    expect(out).toEqual({ kind: "redirecting" });
    expect(navigate).toHaveBeenCalledExactlyOnceWith(url);
    expect(routes(s)).toEqual([ACTION, ME, START]);
    expect(s.sent[2]?.body).toEqual({ redirect: "/security?continue=n" });
  });

  const defaults: readonly (readonly [string, string, string])[] = [
    ["the path and query", `/p?q=${"a".repeat(512 - "/p?q=".length)}`, "path+query"],
    ["the path alone when the query overflows", `/p?q=${"a".repeat(513 - "/p?q=".length)}`, "/p"],
    ["/ when the path overflows", `/${"a".repeat(512)}?q=1`, "/"],
  ];
  for (const [what, at, want] of defaults) {
    it(`defaults the redirect to ${what}, within 512 UTF-8 bytes`, async () => {
      history.replaceState(history.state, "", at);
      const s = fakeServer({ [ACTION]: recent, [ME]: me, [START]: start });
      await run(s, { prompt: choose("oidc"), navigate: vi.fn() });
      expect(s.sent[2]?.body).toEqual({
        redirect: want === "path+query" ? location.pathname + location.search : want,
      });
      if (want === "path+query") {
        expect(new TextEncoder().encode(location.pathname + location.search).length).toBe(512);
      }
    });
  }

  it("fails and navigates nowhere when the start is refused", async () => {
    const navigate = vi.fn();
    const s = fakeServer({
      [ACTION]: recent,
      [ME]: me,
      [START]: refusal(400, "auth_bad_request", "redirect_too_long"),
    });
    const out = await run(s, { prompt: choose("oidc"), navigate });
    expect(out).toMatchObject({ kind: "step-up-failed", error: { status: 400 } });
    expect(navigate).not.toHaveBeenCalled();
  });

  it("navigates with location.assign by default", async () => {
    history.replaceState(history.state, "", "/security");
    const s = fakeServer({ [ACTION]: recent, [ME]: me, [START]: start });
    const out = await withStepUp(s.client, () => s.client.revokeOtherSessions(), {
      prompt: choose("oidc"),
      password: () => Promise.resolve(null),
      code: () => Promise.resolve(null),
    });
    expect(out).toEqual({ kind: "redirecting" });
    expect(assign).toHaveBeenCalledExactlyOnceWith(url);
    expect(s.sent[2]?.body).toEqual({ redirect: "/security" });
  });
});

describe("withStepUp: no step-up", () => {
  it("is cancelled when the prompt cancels", async () => {
    const s = fakeServer({ [ACTION]: recent, [ME]: me });
    expect(await run(s, { prompt: choose("cancel") })).toEqual({ kind: "cancelled" });
    expect(routes(s)).toEqual([ACTION, ME]);
  });

  it("fails without a prompt when the account's methods cannot be read", async () => {
    const prompt = choose("password");
    const s = fakeServer({ [ACTION]: recent, [ME]: refusal(503, "auth_unavailable") });
    expect(await run(s, { prompt })).toMatchObject({
      kind: "step-up-failed",
      error: { status: 503, code: "auth_unavailable" },
    });
    expect(prompt).not.toHaveBeenCalled();
  });
});
