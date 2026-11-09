import { createFetch } from "@cplieger/reactive/fetch";
import type { ApiResult } from "@cplieger/reactive/fetch";
import { describe, expect, expectTypeOf, it } from "vitest";
import { createAuthClient } from "./client.js";
import type { AuthReason } from "./wire.js";
import { authReason } from "./wire.js";
import type { AuthClient, PublicKeyCredentialJSON } from "./client.js";
import { fakeServer } from "./test-helpers/server.js";
import { fixture, queries, routes } from "./test-helpers/wire.js";
import type { WireRoute } from "./test-helpers/wire.js";

const PREFIX = "/api/auth";
const OIDC_PREFIX = "/api/auth/oidc";
const CEREMONY = "cer-1";
const credential = {
  id: "Y3JlZA",
  rawId: "Y3JlZA",
  type: "public-key",
  response: { clientDataJSON: "e30", authenticatorData: "AA", signature: "AA" },
  clientExtensionResults: {},
} as unknown as PublicKeyCredentialJSON;

interface Sent {
  readonly method: string;
  readonly url: URL;
  readonly headers: Headers;
  readonly body: unknown;
}

interface Stub {
  readonly client: AuthClient;
  readonly sent: Sent[];
}

// The client runs on a real FetchInstance; only the network seam is replaced, answering every
// request with the status and JSON body given.
function stub(status: number, body?: unknown): Stub {
  const sent: Sent[] = [];
  const fetchFn = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const raw = init?.body;
    sent.push({
      method: init?.method ?? "GET",
      url: new URL(String(input), "https://app.example"),
      headers: new Headers(init?.headers),
      body: typeof raw === "string" ? (JSON.parse(raw) as unknown) : raw,
    });
    return Promise.resolve(
      body === undefined
        ? new Response(null, { status })
        : new Response(JSON.stringify(body), {
            status,
            headers: { "Content-Type": "application/json" },
          }),
    );
  };
  const client = createAuthClient({
    fetch: createFetch({ fetchFn: fetchFn as typeof fetch }),
    prefix: PREFIX,
    oidcPrefix: OIDC_PREFIX,
  });
  return { client, sent };
}

type Call = (c: AuthClient, body: never) => Promise<ApiResult<unknown>>;

interface Binding {
  readonly method: keyof AuthClient;
  readonly call: Call;
  // A WebAuthn finish route: the body is the browser's credential JSON, not a wire type.
  readonly credential?: true;
}

// The one hand-written part: which client method serves which accesshttp route. Path
// parameters are 7 and "password"; a body argument is the route's request fixture.
const bindings: Readonly<Record<string, Binding>> = {
  authState: { method: "state", call: (c) => c.state() },
  authSetupPassword: { method: "setupPassword", call: (c, b) => c.setupPassword(b) },
  authSetupPasskeyBegin: { method: "setupPasskeyBegin", call: (c, b) => c.setupPasskeyBegin(b) },
  authSetupPasskeyFinish: {
    method: "setupPasskeyFinish",
    call: (c) => c.setupPasskeyFinish(CEREMONY, credential),
    credential: true,
  },
  authLoginPassword: { method: "loginPassword", call: (c, b) => c.loginPassword(b) },
  authLoginPasskeyBegin: { method: "loginPasskeyBegin", call: (c) => c.loginPasskeyBegin() },
  authLoginPasskeyFinish: {
    method: "loginPasskeyFinish",
    call: (c) => c.loginPasskeyFinish(CEREMONY, credential),
    credential: true,
  },
  authLogout: { method: "logout", call: (c) => c.logout() },
  authOIDCStartLink: { method: "oidcStartLink", call: (c, b) => c.oidcStartLink(b) },
  authOIDCStartStepUp: { method: "oidcStartStepUp", call: (c, b) => c.oidcStartStepUp(b) },
  authOIDCPending: { method: "oidcPending", call: (c) => c.oidcPending() },
  authOIDCLinkPending: { method: "oidcLinkPending", call: (c) => c.oidcLinkPending() },
  authOIDCUnlink: { method: "oidcUnlink", call: (c) => c.oidcUnlink() },
  authRecoveryStart: { method: "recoveryStart", call: (c, b) => c.recoveryStart(b) },
  authRecoveryPassword: { method: "recoveryPassword", call: (c, b) => c.recoveryPassword(b) },
  authRecoveryPasskeyBegin: {
    method: "recoveryPasskeyBegin",
    call: (c) => c.recoveryPasskeyBegin(),
  },
  authRecoveryPasskeyFinish: {
    method: "recoveryPasskeyFinish",
    call: (c) =>
      c.recoveryPasskeyFinish(CEREMONY, credential, { keepSessions: false, keepKeys: false }),
    credential: true,
  },
  authInviteAcceptPassword: {
    method: "inviteAcceptPassword",
    call: (c, b) => c.inviteAcceptPassword(b),
  },
  authMe: { method: "me", call: (c) => c.me() },
  authProfile: { method: "updateProfile", call: (c, b) => c.updateProfile(b) },
  authMethodReenable: { method: "reenableMethod", call: (c) => c.reenableMethod("password") },
  authStepUpPassword: { method: "stepUpPassword", call: (c, b) => c.stepUpPassword(b) },
  authStepUpPasskeyBegin: { method: "stepUpPasskeyBegin", call: (c) => c.stepUpPasskeyBegin() },
  authStepUpPasskeyFinish: {
    method: "stepUpPasskeyFinish",
    call: (c) => c.stepUpPasskeyFinish(CEREMONY, credential),
    credential: true,
  },
  authPasswordSet: { method: "setPassword", call: (c, b) => c.setPassword(b) },
  authPasswordRemove: { method: "removePassword", call: (c, b) => c.removePassword(b) },
  authPasskeys: { method: "passkeys", call: (c) => c.passkeys() },
  authPasskeyRegisterBegin: {
    method: "passkeyRegisterBegin",
    call: (c) => c.passkeyRegisterBegin(),
  },
  authPasskeyRegisterFinish: {
    method: "passkeyRegisterFinish",
    call: (c) => c.passkeyRegisterFinish(CEREMONY, credential),
    credential: true,
  },
  authPasskeyRename: { method: "renamePasskey", call: (c, b) => c.renamePasskey(7, b) },
  authPasskeyRemove: { method: "removePasskey", call: (c) => c.removePasskey(7) },
  authWebAuthnSignals: { method: "webauthnSignals", call: (c) => c.webauthnSignals() },
  authSessions: { method: "sessions", call: (c) => c.sessions() },
  authSessionRename: { method: "renameSession", call: (c, b) => c.renameSession("7", b) },
  authSessionRevoke: { method: "revokeSession", call: (c) => c.revokeSession("7") },
  authSessionsRevokeOthers: {
    method: "revokeOtherSessions",
    call: (c) => c.revokeOtherSessions(),
  },
  authKeys: { method: "keys", call: (c) => c.keys() },
  authKeyCreate: { method: "createKey", call: (c, b) => c.createKey(b) },
  authKeyRevoke: { method: "revokeKey", call: (c) => c.revokeKey(7) },
  authAdminUsers: { method: "adminUsers", call: (c) => c.adminUsers() },
  authAdminUserCreate: { method: "adminCreateUser", call: (c, b) => c.adminCreateUser(b) },
  authAdminUserUpdate: { method: "adminUpdateUser", call: (c, b) => c.adminUpdateUser(7, b) },
  authAdminUserDelete: { method: "adminDeleteUser", call: (c) => c.adminDeleteUser(7) },
  authAdminRecovery: { method: "adminIssueRecovery", call: (c, b) => c.adminIssueRecovery(7, b) },
  authAdminInvite: { method: "adminInvite", call: (c, b) => c.adminInvite(b) },
  authAdminKeys: { method: "adminKeys", call: (c) => c.adminKeys() },
  authAdminKeyRevoke: { method: "adminRevokeKey", call: (c) => c.adminRevokeKey(7) },
  authAdminTokens: { method: "adminTokens", call: (c) => c.adminTokens() },
  authAdminSecurityLog: { method: "adminSecurityLog", call: (c) => c.adminSecurityLog() },
};

const jsonRoutes = routes.filter((r) => r.kind === "json");

function binding(name: string): Binding {
  if (!Object.hasOwn(bindings, name)) {
    throw new Error(`no client method for route ${name}`);
  }
  const b = bindings[name];
  if (b === undefined) {
    throw new Error(`no client method for route ${name}`);
  }
  return b;
}

function expectedPath(r: WireRoute): string {
  return r.path
    .replace("{prefix}", PREFIX)
    .replace("{oidcPrefix}", OIDC_PREFIX)
    .replace("{id}", "7")
    .replace("{method}", "password");
}

function responseBody(r: WireRoute): unknown {
  if (r.response === null) {
    return undefined;
  }
  const one = fixture(r.response);
  return r.array ? [one, one] : one;
}

describe("PublicKeyCredentialJSON", () => {
  it("fits the DOM library's JSON types on both legs, and the client sends the body unchanged", async () => {
    expectTypeOf<RegistrationResponseJSON>().toExtend<PublicKeyCredentialJSON>();
    expectTypeOf<AuthenticationResponseJSON>().toExtend<PublicKeyCredentialJSON>();
    const json: AuthenticationResponseJSON = {
      id: "Y3JlZA",
      rawId: "Y3JlZA",
      type: "public-key",
      response: { authenticatorData: "AA", clientDataJSON: "e30", signature: "AQI" },
      clientExtensionResults: {},
    };
    const s = fakeServer({ "POST /api/auth/stepup/passkey/finish": { status: 204 } });
    expect((await s.client.stepUpPasskeyFinish("c", json)).ok).toBe(true);
    expect(s.sent[0]?.body).toEqual(json);
  });
});

// Method, Role and TokenPurpose take app-defined values (types.go), and the server returns
// them as stored.
describe("app-defined methods, roles and purposes", () => {
  const me = fixture("MeResponse") as {
    user: object;
    session: object;
    methods: { locks: object[] };
  };
  const user = { ...(fixture("UserView") as object), role: "moderator" };
  const session = { ...(fixture("SessionView") as object), method: "agent" };
  const token = { ...(fixture("TokenView") as object), role: "moderator", purpose: "app_purpose" };
  const signedIn = { ...(fixture("SignedInResponse") as object), user };
  const appMe = {
    ...me,
    user,
    session: { ...me.session, method: "agent" },
    methods: { ...me.methods, locks: me.methods.locks.map((l) => ({ ...l, method: "agent" })) },
  };

  it.each<[string, unknown, (c: AuthClient) => Promise<ApiResult<unknown>>]>([
    ["me()", appMe, (c) => c.me()],
    ["adminUsers()", [user], (c) => c.adminUsers()],
    ["sessions()", [session], (c) => c.sessions()],
    ["adminTokens()", [token], (c) => c.adminTokens()],
    ["loginPassword()", signedIn, (c) => c.loginPassword({ username: "u", password: "p" })],
  ])("%s decodes them", async (_, body, call) => {
    const result = await call(stub(200, body).client);
    expect(result).toMatchObject({ ok: true, data: body });
  });

  it.each([
    ["an empty role", { ...user, role: "" }],
    ["a role that is not a string", { ...user, role: 1 }],
  ])("adminUsers() refuses %s", async (_, u) => {
    expect((await stub(200, [u]).client.adminUsers()).ok).toBe(false);
  });
});

describe("the route table", () => {
  it("binds every JSON route to exactly one client method, and every method to one route", () => {
    const { client } = stub(204);
    const methods = Object.keys(client).filter(
      (k) => typeof client[k as keyof AuthClient] === "function",
    );
    expect(methods).toHaveLength(49);
    expect(jsonRoutes).toHaveLength(49);
    expect(Object.keys(bindings).sort()).toEqual(jsonRoutes.map((r) => r.name).sort());
    expect(
      Object.values(bindings)
        .map((b) => b.method)
        .sort(),
    ).toEqual(methods.sort());
    expect(new Set(routes.map((r) => r.name)).size).toBe(routes.length);
  });

  it("leaves only the two OIDC navigations to oidcSignInURL and the IdP", () => {
    expect(
      routes
        .filter((r) => r.kind === "redirect")
        .map((r) => r.name)
        .sort(),
    ).toEqual(["authOIDCCallback", "authOIDCStartSignIn"]);
  });

  it("has no two routes on one method and path", () => {
    const keys = routes.map((r) => `${r.method} ${r.path}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe.each(jsonRoutes)("$name", (route) => {
  const b = binding(route.name);
  const request = route.request === null ? undefined : fixture(route.request);

  it(`${b.method} sends the route's method, path and body once, and decodes its answer`, async () => {
    const answer = responseBody(route);
    const { client, sent } = stub(route.response === null ? 204 : 200, answer);
    const result = await b.call(client, request as never);

    expect(sent).toHaveLength(1);
    const req = sent[0];
    expect(req?.method).toBe(route.method);
    expect(req?.url.pathname).toBe(expectedPath(route));
    expect(req?.url.search).toBe("");
    if (b.credential === true) {
      expect(route.request).toBeNull();
      expect(req?.body).toEqual(credential);
      expect(req?.headers.get("X-Auth-Ceremony")).toBe(CEREMONY);
    } else {
      expect(req?.body).toEqual(request);
      expect(req?.headers.has("X-Auth-Ceremony")).toBe(false);
    }
    expect(req?.headers.get("Content-Type")).toBe(
      req?.body === undefined ? null : "application/json",
    );
    expect(result).toMatchObject({ ok: true, data: answer });
  });

  if (route.response !== null) {
    it(`${b.method} refuses a 2xx body that is not ${route.response}`, async () => {
      const { client } = stub(200, route.array ? [{}] : {});
      const result = await b.call(client, request as never);
      expect(result).toMatchObject({ ok: false, status: 200, code: "decode" });
    });
  }

  it(`${b.method} returns a server refusal with its code and body`, async () => {
    const body = { code: "auth_recent_auth_required", error: "x", reason: "r" };
    const { client } = stub(403, body);
    const result = await b.call(client, request as never);
    expect(result).toMatchObject({ ok: false, status: 403, code: body.code, body });
  });
});

describe("queries", () => {
  function keys(s: Stub): string[] {
    return [...new Set(s.sent[0]?.url.searchParams.keys())].sort();
  }

  it("lists only routes the client sends or navigates to", () => {
    for (const name of queries.keys()) {
      expect(
        routes.map((r) => r.name),
        name,
      ).toContain(name);
    }
    const sentByClient = [...queries.keys()].filter((n) => jsonRoutes.some((r) => r.name === n));
    expect(sentByClient.sort()).toEqual([
      "authAdminSecurityLog",
      "authAdminUsers",
      "authLoginPasskeyBegin",
      "authRecoveryPasskeyFinish",
    ]);
  });

  it("loginPasskeyBegin sends mediation=conditional only when asked", async () => {
    const s = stub(200, fixture("CeremonyResponse"));
    await s.client.loginPasskeyBegin({ mediation: "conditional" });
    expect(keys(s)).toEqual(queries.get("authLoginPasskeyBegin"));
    expect(s.sent[0]?.url.searchParams.get("mediation")).toBe("conditional");
    const none = stub(200, fixture("CeremonyResponse"));
    await none.client.loginPasskeyBegin({});
    expect(none.sent[0]?.url.search).toBe("");
  });

  it.each([
    [
      { keepSessions: true, keepKeys: true },
      { keep_sessions: "true", keep_keys: "true" },
    ],
    [{ keepSessions: true, keepKeys: false }, { keep_sessions: "true" }],
    [{ keepSessions: false, keepKeys: true }, { keep_keys: "true" }],
    [{ keepSessions: false, keepKeys: false }, {}],
  ])("recoveryPasskeyFinish with %o sends %o", async (flags, query) => {
    const s = stub(204);
    await s.client.recoveryPasskeyFinish(CEREMONY, credential, flags);
    expect(Object.fromEntries(s.sent[0]?.url.searchParams ?? [])).toEqual(query);
  });

  it("recoveryPasskeyFinish can send exactly its route's keys", async () => {
    const s = stub(204);
    await s.client.recoveryPasskeyFinish(CEREMONY, credential, {
      keepSessions: true,
      keepKeys: true,
    });
    expect(keys(s)).toEqual(queries.get("authRecoveryPasskeyFinish"));
  });

  it("adminUsers sends /users with no query, and /users?key=12 with a key", async () => {
    const all = stub(200, [fixture("UserView")]);
    await all.client.adminUsers();
    expect(all.sent.map((r) => r.url.pathname + r.url.search)).toEqual([`${PREFIX}/users`]);
    const one = stub(200, [fixture("UserView")]);
    await one.client.adminUsers({ key: 12 });
    expect(one.sent.map((r) => r.url.pathname + r.url.search)).toEqual([`${PREFIX}/users?key=12`]);
    expect(keys(one)).toEqual(queries.get("authAdminUsers"));
  });

  it("adminSecurityLog sends GET /security-log with no query, and no kinds for an empty list", async () => {
    for (const q of [undefined, {}, { kinds: [] }, { oldestFirst: false }]) {
      const s = stub(200, fixture("SecurityLogView"));
      const result = await s.client.adminSecurityLog(q);
      expect(s.sent.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`)).toEqual([
        `GET ${PREFIX}/security-log`,
      ]);
      expect(result).toMatchObject({ ok: true, data: fixture("SecurityLogView") });
    }
  });

  it("adminSecurityLog joins kinds with a comma and sends each set key", async () => {
    const s = stub(200, fixture("SecurityLogView"));
    await s.client.adminSecurityLog({ user: 3, kinds: ["a.b", "signed_in"], limit: 20 });
    expect(s.sent.map((r) => r.url.search)).toEqual(["?user=3&kinds=a.b%2Csigned_in&limit=20"]);
  });

  it("adminSecurityLog sends oldest_first=true for oldestFirst, beside its bounds", async () => {
    const s = stub(200, fixture("SecurityLogView"));
    await s.client.adminSecurityLog({ oldestFirst: true });
    await s.client.adminSecurityLog({ after: 50, oldestFirst: true });
    expect(s.sent.map((r) => r.url.search)).toEqual([
      "?oldest_first=true",
      "?after=50&oldest_first=true",
    ]);
  });

  it("adminSecurityLog can send exactly its route's keys", async () => {
    const s = stub(200, fixture("SecurityLogView"));
    await s.client.adminSecurityLog({
      user: 1,
      actor: 2,
      actorKey: 3,
      after: 4,
      before: 5,
      kinds: ["signed_in"],
      limit: 6,
      oldestFirst: true,
    });
    expect(Object.fromEntries(s.sent[0]?.url.searchParams ?? [])).toEqual({
      user: "1",
      actor: "2",
      actor_key: "3",
      after: "4",
      before: "5",
      kinds: "signed_in",
      limit: "6",
      oldest_first: "true",
    });
    expect(keys(s)).toEqual(queries.get("authAdminSecurityLog"));
  });

  it("adminSecurityLog gives a refused filter's log_kind reason as an AuthReason", async () => {
    const body = { code: "auth_bad_request", error: "x", reason: "log_kind" };
    const result = await stub(400, body).client.adminSecurityLog({ kinds: ["a.b", ""] });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const reason = authReason(result);
      expectTypeOf(reason).toEqualTypeOf<AuthReason | undefined>();
      expect(reason).toBe("log_kind");
    }
  });

  it("adminTokens sends GET /tokens", async () => {
    const s = stub(200, [fixture("TokenView")]);
    await s.client.adminTokens();
    expect(s.sent.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`)).toEqual([
      `GET ${PREFIX}/tokens`,
    ]);
  });
});

describe("path parameters", () => {
  it("encodes a session ID or method as one path segment", async () => {
    const s = stub(204);
    await s.client.revokeSession("a/b?c#d");
    await s.client.reenableMethod("../x");
    expect(s.sent.map((r) => r.url.pathname)).toEqual([
      `${PREFIX}/sessions/a%2Fb%3Fc%23d`,
      `${PREFIX}/methods/..%2Fx/reenable`,
    ]);
    expect(s.sent.every((r) => r.url.search === "")).toBe(true);
  });

  it("exposes the prefixes it was built with", () => {
    const { client } = stub(204);
    expect([client.prefix, client.oidcPrefix]).toEqual([PREFIX, OIDC_PREFIX]);
  });
});
