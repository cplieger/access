import { describe, expect, it } from "vitest";
import {
  completePendingLink,
  oidcSignInURL,
  pendingLink,
  readOIDCReturn,
  startOIDC,
} from "./oidc.js";
import { fakeServer, refusal } from "./test-helpers/server.js";
import { fixture, queries, routes } from "./test-helpers/wire.js";
import { forbidStorage } from "./test-helpers/storage.js";

forbidStorage();

const ok = (name: string): { status: number; body: unknown } => ({
  status: 200,
  body: fixture(name),
});

describe("oidcSignInURL", () => {
  const { client } = fakeServer({});
  const signIn = routes.find((r) => r.name === "authOIDCStartSignIn");

  it("is the sign-in start route under the OIDC prefix", () => {
    expect(signIn?.method).toBe("GET");
    expect(oidcSignInURL(client)).toBe(signIn?.path.replace("{oidcPrefix}", client.oidcPrefix));
  });

  it("carries the redirect, encoded, as the only query key the route declares", () => {
    const u = new URL(oidcSignInURL(client, "/settings?tab=a&b=1#x"), "https://app.example");
    expect([...u.searchParams.keys()]).toEqual(queries.get("authOIDCStartSignIn"));
    expect(u.searchParams.get("redirect")).toBe("/settings?tab=a&b=1#x");
    expect(u.hash).toBe("");
  });

  it("sends no redirect key for an empty redirect", () => {
    expect(oidcSignInURL(client, "")).toBe("/api/auth/oidc/start/signin");
  });
});

describe("startOIDC", () => {
  it("posts the redirect to the link or step-up start and returns the IdP URL", async () => {
    const s = fakeServer({
      "POST /api/auth/oidc/start/link": ok("OIDCStartResponse"),
      "POST /api/auth/oidc/start/stepup": ok("OIDCStartResponse"),
    });
    expect(await startOIDC(s.client, "link", "/settings")).toMatchObject({
      ok: true,
      data: fixture("OIDCStartResponse"),
    });
    expect(await startOIDC(s.client, "stepup")).toMatchObject({ ok: true });
    expect(s.sent.map((x) => [x.route, x.body])).toEqual([
      ["POST /api/auth/oidc/start/link", { redirect: "/settings" }],
      ["POST /api/auth/oidc/start/stepup", {}],
    ]);
  });

  it("returns the server's refusal", async () => {
    const s = fakeServer({
      "POST /api/auth/oidc/start/stepup": refusal(400, "auth_bad_request", "redirect_too_long"),
    });
    expect(await startOIDC(s.client, "stepup", `/${"a".repeat(512)}`)).toMatchObject({
      ok: false,
      status: 400,
      code: "auth_bad_request",
    });
  });
});

describe("readOIDCReturn", () => {
  const cases: readonly (readonly [string, unknown])[] = [
    ["", { kind: "none" }],
    ["?tab=security", { kind: "none" }],
    ["?oidc=not_linked", { kind: "not_linked" }],
    ["?a=1&oidc=linked", { kind: "linked" }],
    ["?oidc=stepped_up&continue=n", { kind: "stepped_up" }],
    ["oidc=stepped_up", { kind: "stepped_up" }],
    ["?oidc=signed_in", { kind: "none" }],
    ["?oidc=linked&oidc=stepped_up", { kind: "none" }],
    ["?auth_error=auth_oidc_failed", { kind: "error", code: "auth_oidc_failed" }],
    ["?auth_error=auth_from_the_future", { kind: "error", code: undefined }],
    ["?auth_error=constructor", { kind: "error", code: undefined }],
    ["?auth_error=", { kind: "error", code: undefined }],
    ["?auth_error=auth_oidc_failed&auth_error=auth_busy", { kind: "error", code: undefined }],
    ["?oidc=stepped_up&auth_error=auth_oidc_failed", { kind: "error", code: "auth_oidc_failed" }],
  ];
  for (const [search, want] of cases) {
    it(`reads ${JSON.stringify(search)}`, () => {
      expect(readOIDCReturn(search)).toEqual(want);
    });
  }
});

describe("pendingLink and completePendingLink", () => {
  it("read the pending identity and link it", async () => {
    const s = fakeServer({
      "GET /api/auth/oidc/pending": ok("PendingLinkResponse"),
      "POST /api/auth/oidc/link": ok("MeResponse"),
    });
    expect(await pendingLink(s.client)).toMatchObject({
      ok: true,
      data: fixture("PendingLinkResponse"),
    });
    expect(await completePendingLink(s.client)).toMatchObject({
      ok: true,
      data: fixture("MeResponse"),
    });
    expect(s.sent.map((x) => x.route)).toEqual([
      "GET /api/auth/oidc/pending",
      "POST /api/auth/oidc/link",
    ]);
  });
});
