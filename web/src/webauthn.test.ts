import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeServer, refusal } from "./test-helpers/server.js";
import type { Answer } from "./test-helpers/server.js";
import { fixture } from "./test-helpers/wire.js";
import {
  passkeySupport,
  recoverWithPasskey,
  registerPasskey,
  sendSignals,
  setupWithPasskey,
  signInWithPasskey,
  stepUpWithPasskey,
  toCreationOptions,
  toRequestOptions,
} from "./webauthn.js";
import { forbidStorage } from "./test-helpers/storage.js";
import {
  assertionCredential,
  assertionJSON,
  attestationCredential,
  attestationJSON,
} from "./test-helpers/credential.js";

forbidStorage();

const CRED_ID = "Y3JlZA";

const creation: Answer = {
  status: 200,
  body: {
    ceremony: "c-create",
    public_key: {
      publicKey: {
        challenge: "Y2g",
        rp: { name: "App" },
        user: { id: "aGFuZGxl", name: "alice", displayName: "Alice" },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        extensions: { credProps: true },
      },
    },
  },
};
const request: Answer = {
  status: 200,
  body: { ceremony: "c-get", public_key: { publicKey: { challenge: "Y2g", rpId: "rp.example" } } },
};
const ok = (name: string): Answer => ({ status: 200, body: fixture(name) });
const noContent: Answer = { status: 204 };

function credentialsCreate(impl: () => Promise<unknown>): ReturnType<typeof vi.fn> {
  const f = vi.fn(impl);
  vi.spyOn(navigator.credentials, "create").mockImplementation(f as never);
  return f;
}
function credentialsGet(impl: () => Promise<unknown>): ReturnType<typeof vi.fn> {
  const f = vi.fn(impl);
  vi.spyOn(navigator.credentials, "get").mockImplementation(f as never);
  return f;
}
const resolves = (): Promise<unknown> => Promise.resolve(assertionCredential());
const attests = (): Promise<unknown> => Promise.resolve(attestationCredential());
const throws = (name: string) => (): Promise<unknown> =>
  Promise.reject(name === "" ? new TypeError("not a DOMException") : new DOMException("x", name));

// A platform with no parse*FromJSON and no signals, so the ceremonies use the base64url
// fallback and no test reaches the real authenticator.
function bareplatform(extra: Record<string, unknown> = {}): void {
  vi.stubGlobal("PublicKeyCredential", { ...extra });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("the DOMException outcome mapping", () => {
  // Every name classifyDOMException handles, its default arm and a throw that is no DOMException.
  const names = [
    "TimeoutError",
    "AbortError",
    "NotAllowedError",
    "InvalidStateError",
    "SecurityError",
    "",
  ];
  const signIn: Record<string, unknown> = {
    TimeoutError: { kind: "timeout" },
    AbortError: { kind: "cancelled" },
    NotAllowedError: { kind: "cancelled" },
    InvalidStateError: { kind: "failed", error: "InvalidStateError" },
    SecurityError: { kind: "failed", error: "SecurityError" },
    "": { kind: "failed", error: "" },
  };
  const register: Record<string, unknown> = {
    ...signIn,
    InvalidStateError: { kind: "duplicate" },
  };

  for (const name of names) {
    it(`get leg: ${name || "a non-DOMException throw"}`, async () => {
      bareplatform();
      credentialsGet(throws(name));
      const s = fakeServer({ "POST /api/auth/login/passkey/begin": request });
      expect(await signInWithPasskey(s.client)).toEqual(signIn[name]);
      expect(s.sent.map((x) => x.route)).toEqual(["POST /api/auth/login/passkey/begin"]);

      const u = fakeServer({ "POST /api/auth/stepup/passkey/begin": request });
      expect(await stepUpWithPasskey(u.client)).toEqual(signIn[name]);
      expect(u.sent).toHaveLength(1);
    });

    it(`create leg: ${name || "a non-DOMException throw"}`, async () => {
      bareplatform();
      credentialsCreate(throws(name));
      const s = fakeServer({ "POST /api/auth/passkeys/begin": creation });
      expect(await registerPasskey(s.client)).toEqual(register[name]);
      expect(s.sent.map((x) => x.route)).toEqual(["POST /api/auth/passkeys/begin"]);

      const r = fakeServer({ "POST /api/auth/recovery/passkey/begin": creation });
      expect(await recoverWithPasskey(r.client, { keepSessions: false, keepKeys: false })).toEqual(
        register[name],
      );
      expect(r.sent).toHaveLength(1);

      // Setup has no exclusion list to collide with, so the name is a plain failure there.
      const t = fakeServer({ "POST /api/auth/setup/passkey/begin": creation });
      expect(await setupWithPasskey(t.client, { username: "alice" })).toEqual(
        name === "InvalidStateError" ? signIn[name] : register[name],
      );
      expect(t.sent).toHaveLength(1);
    });
  }

  it("a ceremony the browser resolves with no credential is cancelled", async () => {
    bareplatform();
    credentialsGet(() => Promise.resolve(null));
    credentialsCreate(() => Promise.resolve(null));
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/passkeys/begin": creation,
    });
    expect(await signInWithPasskey(s.client)).toEqual({ kind: "cancelled" });
    expect(await registerPasskey(s.client)).toEqual({ kind: "cancelled" });
    expect(s.sent).toHaveLength(2);
  });
});

describe("signInWithPasskey", () => {
  it("runs the conditional ceremony and finishes with the ceremony header", async () => {
    bareplatform();
    const get = credentialsGet(resolves);
    const abort = new AbortController();
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": ok("CeremonyResponse"),
      "POST /api/auth/login/passkey/finish": ok("SignedInResponse"),
    });
    const out = await signInWithPasskey(s.client, {
      mediation: "conditional",
      signal: abort.signal,
    });
    expect(out).toEqual({ kind: "signed-in", result: fixture("SignedInResponse") });
    expect(s.sent.map((x) => x.route)).toEqual([
      "POST /api/auth/login/passkey/begin?mediation=conditional",
      "POST /api/auth/login/passkey/finish",
    ]);
    expect(s.sent[1]?.headers.get("X-Auth-Ceremony")).toBe("c1");
    expect(s.sent[1]?.body).toEqual(assertionJSON);
    const arg = get.mock.calls[0]?.[0] as CredentialRequestOptions;
    expect(arg.mediation).toBe("conditional");
    expect(arg.signal).toBe(abort.signal);
    expect([...new Uint8Array(arg.publicKey?.challenge as ArrayBuffer)]).toEqual([
      ...new TextEncoder().encode("challenge"),
    ]);
  });

  it("sends no mediation key and no signal when none is given", async () => {
    bareplatform();
    const get = credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/login/passkey/finish": ok("SignedInResponse"),
    });
    expect((await signInWithPasskey(s.client)).kind).toBe("signed-in");
    expect(s.sent[0]?.route).toBe("POST /api/auth/login/passkey/begin");
    const arg = get.mock.calls[0]?.[0] as CredentialRequestOptions;
    expect("mediation" in arg).toBe(false);
    expect("signal" in arg).toBe(false);
  });

  it("returns a begin refusal as failed without asking the authenticator", async () => {
    bareplatform();
    const get = credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": refusal(503, "auth_passkeys_unavailable"),
    });
    const out = await signInWithPasskey(s.client);
    expect(out).toMatchObject({
      kind: "failed",
      error: { ok: false, status: 503, code: "auth_passkeys_unavailable" },
    });
    expect(get).not.toHaveBeenCalled();
  });

  it("refuses creation options from a get route as a decode failure", async () => {
    bareplatform();
    const get = credentialsGet(resolves);
    const s = fakeServer({ "POST /api/auth/login/passkey/begin": creation });
    expect(await signInWithPasskey(s.client)).toMatchObject({
      kind: "failed",
      error: { ok: false, status: 0, code: "decode" },
    });
    expect(get).not.toHaveBeenCalled();
    expect(s.sent).toHaveLength(1);
  });

  const refused: readonly (readonly [string, number, unknown])[] = [
    ["auth_ceremony_invalid", 400, { kind: "ceremony-expired" }],
    ["auth_assertion_failed", 401, { kind: "verification-failed" }],
  ];
  for (const [code, status, want] of refused) {
    it(`maps a finish ${code} for sign-in and step-up`, async () => {
      bareplatform();
      credentialsGet(resolves);
      const s = fakeServer({
        "POST /api/auth/login/passkey/begin": request,
        "POST /api/auth/login/passkey/finish": refusal(status, code),
        "POST /api/auth/stepup/passkey/begin": request,
        "POST /api/auth/stepup/passkey/finish": refusal(status, code),
      });
      expect(await signInWithPasskey(s.client)).toEqual(want);
      expect(await stepUpWithPasskey(s.client)).toEqual(want);
    });
  }

  it("returns any other finish refusal as failed with the server's error", async () => {
    bareplatform();
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/login/passkey/finish": refusal(429, "auth_rate_limited"),
    });
    expect(await signInWithPasskey(s.client)).toMatchObject({
      kind: "failed",
      error: { status: 429, code: "auth_rate_limited" },
    });
  });

  it("signals an unknown credential to the provider with the ceremony's RP ID", async () => {
    const signalUnknownCredential = vi.fn(() => Promise.resolve());
    bareplatform({ signalUnknownCredential });
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/login/passkey/finish": refusal(401, "auth_unknown_credential"),
    });
    expect(await signInWithPasskey(s.client)).toEqual({ kind: "unknown-credential" });
    expect(signalUnknownCredential).toHaveBeenCalledExactlyOnceWith({
      rpId: "rp.example",
      credentialId: CRED_ID,
    });
  });

  it("falls back to this page's host when the options name no RP ID", async () => {
    const signalUnknownCredential = vi.fn(() => Promise.reject(new Error("refused")));
    bareplatform({ signalUnknownCredential });
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/stepup/passkey/begin": ok("CeremonyResponse"),
      "POST /api/auth/stepup/passkey/finish": refusal(401, "auth_unknown_credential"),
    });
    expect(await stepUpWithPasskey(s.client)).toEqual({ kind: "unknown-credential" });
    expect(signalUnknownCredential).toHaveBeenCalledExactlyOnceWith({
      rpId: location.hostname,
      credentialId: CRED_ID,
    });
  });

  it("answers unknown-credential where the browser has no signal", async () => {
    bareplatform();
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/login/passkey/finish": refusal(401, "auth_unknown_credential"),
    });
    expect(await signInWithPasskey(s.client)).toEqual({ kind: "unknown-credential" });
  });

  it("waits at most 2 s for a signal that never settles", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const signalUnknownCredential = vi.fn(() => new Promise<void>(() => undefined));
    bareplatform({ signalUnknownCredential });
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/login/passkey/begin": request,
      "POST /api/auth/login/passkey/finish": refusal(401, "auth_unknown_credential"),
    });
    let out: unknown;
    const run = signInWithPasskey(s.client).then((o) => (out = o));
    // Frames, not timers: vi.waitFor would advance the fake clock past the deadline.
    for (let i = 0; i < 100 && signalUnknownCredential.mock.calls.length === 0; i++) {
      await new Promise((r) => requestAnimationFrame(r));
    }
    expect(signalUnknownCredential).toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1999);
    expect(out).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await run;
    expect(out).toEqual({ kind: "unknown-credential" });
  });
});

describe("stepUpWithPasskey", () => {
  it("reads stepped-up from the finish route's 204", async () => {
    bareplatform();
    credentialsGet(resolves);
    const s = fakeServer({
      "POST /api/auth/stepup/passkey/begin": request,
      "POST /api/auth/stepup/passkey/finish": noContent,
    });
    expect(await stepUpWithPasskey(s.client)).toEqual({ kind: "stepped-up" });
    expect(s.sent.map((x) => x.route)).toEqual([
      "POST /api/auth/stepup/passkey/begin",
      "POST /api/auth/stepup/passkey/finish",
    ]);
    expect(s.sent[1]?.headers.get("X-Auth-Ceremony")).toBe("c-get");
  });
});

describe("registerPasskey", () => {
  it("registers, then sends the provider the server's signals", async () => {
    const signalAllAcceptedCredentials = vi.fn(() => Promise.resolve());
    bareplatform({ signalAllAcceptedCredentials });
    const create = credentialsCreate(attests);
    const s = fakeServer({
      "POST /api/auth/passkeys/begin": creation,
      "POST /api/auth/passkeys/finish": ok("PasskeyView"),
      "GET /api/auth/webauthn/signals": ok("Signals"),
    });
    expect(await registerPasskey(s.client)).toEqual({
      kind: "registered",
      passkey: fixture("PasskeyView"),
    });
    expect(s.sent.map((x) => x.route)).toEqual([
      "POST /api/auth/passkeys/begin",
      "POST /api/auth/passkeys/finish",
      "GET /api/auth/webauthn/signals",
    ]);
    expect(s.sent[1]?.headers.get("X-Auth-Ceremony")).toBe("c-create");
    expect(s.sent[1]?.body).toEqual(attestationJSON);
    const arg = create.mock.calls[0]?.[0] as CredentialCreationOptions;
    expect(arg.publicKey?.rp).toEqual({ name: "App" });
    expect(signalAllAcceptedCredentials).toHaveBeenCalledOnce();
  });

  it("refuses request options from a create route as a decode failure", async () => {
    bareplatform();
    const create = credentialsCreate(attests);
    const s = fakeServer({ "POST /api/auth/passkeys/begin": request });
    expect(await registerPasskey(s.client)).toMatchObject({
      kind: "failed",
      error: { status: 0, code: "decode" },
    });
    expect(create).not.toHaveBeenCalled();
  });

  const refused: readonly (readonly [string, unknown])[] = [
    ["auth_not_discoverable", { kind: "not-discoverable" }],
    ["auth_duplicate_credential", { kind: "duplicate" }],
  ];
  for (const [code, want] of refused) {
    it(`maps a finish ${code} for registration and recovery`, async () => {
      bareplatform();
      credentialsCreate(attests);
      const s = fakeServer({
        "POST /api/auth/passkeys/begin": creation,
        "POST /api/auth/passkeys/finish": refusal(400, code),
        "POST /api/auth/recovery/passkey/begin": creation,
        "POST /api/auth/recovery/passkey/finish": refusal(400, code),
      });
      expect(await registerPasskey(s.client)).toEqual(want);
      expect(await recoverWithPasskey(s.client, { keepSessions: false, keepKeys: false })).toEqual(
        want,
      );
      expect(s.sent.some((x) => x.route.includes("signals"))).toBe(false);
    });
  }

  it("returns any other finish refusal as failed and sends no signals", async () => {
    bareplatform({ signalAllAcceptedCredentials: vi.fn() });
    credentialsCreate(attests);
    const s = fakeServer({
      "POST /api/auth/passkeys/begin": creation,
      "POST /api/auth/passkeys/finish": refusal(400, "auth_registration_failed"),
    });
    expect(await registerPasskey(s.client)).toMatchObject({
      kind: "failed",
      error: { status: 400, code: "auth_registration_failed" },
    });
    expect(s.sent).toHaveLength(2);
  });
});

describe("the finish body", () => {
  it("forwards no extension output when the options requested none", async () => {
    bareplatform();
    credentialsCreate(() => Promise.resolve(attestationCredential({ legacy: true })));
    const { extensions: _e, ...publicKey } = (
      creation.body as { public_key: { publicKey: Record<string, unknown> } }
    ).public_key.publicKey;
    const s = fakeServer({
      "POST /api/auth/passkeys/begin": {
        status: 200,
        body: { ceremony: "c-create", public_key: { publicKey } },
      },
      "POST /api/auth/passkeys/finish": ok("PasskeyView"),
    });
    expect((await registerPasskey(s.client)).kind).toBe("registered");
    expect(s.sent[1]?.body).toEqual({
      id: CRED_ID,
      rawId: CRED_ID,
      type: "public-key",
      response: { attestationObject: "_-8", clientDataJSON: "e30" },
      clientExtensionResults: {},
    });
  });

  it("omits a null user handle from an assertion", async () => {
    bareplatform();
    credentialsGet(() => Promise.resolve(assertionCredential({ userHandle: null })));
    const s = fakeServer({
      "POST /api/auth/stepup/passkey/begin": request,
      "POST /api/auth/stepup/passkey/finish": noContent,
    });
    expect(await stepUpWithPasskey(s.client)).toEqual({ kind: "stepped-up" });
    const { userHandle: _u, ...response } = assertionJSON.response;
    expect(s.sent[1]?.body).toEqual({ ...assertionJSON, response });
  });
});

describe("setupWithPasskey", () => {
  it("sends the token and username and signs the first user in", async () => {
    bareplatform();
    credentialsCreate(attests);
    const s = fakeServer({
      "POST /api/auth/setup/passkey/begin": creation,
      "POST /api/auth/setup/passkey/finish": ok("SignedInResponse"),
    });
    expect(await setupWithPasskey(s.client, { token: "t", username: "alice" })).toEqual({
      kind: "signed-in",
      result: fixture("SignedInResponse"),
    });
    expect(s.sent[0]?.body).toEqual({ token: "t", username: "alice" });
    expect(s.sent[1]?.headers.get("X-Auth-Ceremony")).toBe("c-create");
  });

  it("maps an expired ceremony, and any other refusal to failed", async () => {
    bareplatform();
    credentialsCreate(attests);
    const expired = fakeServer({
      "POST /api/auth/setup/passkey/begin": creation,
      "POST /api/auth/setup/passkey/finish": refusal(400, "auth_ceremony_invalid"),
    });
    expect(await setupWithPasskey(expired.client, { username: "alice" })).toEqual({
      kind: "ceremony-expired",
    });
    const taken = fakeServer({
      "POST /api/auth/setup/passkey/begin": creation,
      "POST /api/auth/setup/passkey/finish": refusal(409, "auth_setup_complete"),
    });
    expect(await setupWithPasskey(taken.client, { username: "alice" })).toMatchObject({
      kind: "failed",
      error: { status: 409, code: "auth_setup_complete" },
    });
  });
});

describe("recoverWithPasskey", () => {
  it("sends the keep flags as the finish route's query and reads its 204", async () => {
    bareplatform();
    credentialsCreate(attests);
    const s = fakeServer({
      "POST /api/auth/recovery/passkey/begin": creation,
      "POST /api/auth/recovery/passkey/finish": noContent,
    });
    expect(await recoverWithPasskey(s.client, { keepSessions: true, keepKeys: true })).toEqual({
      kind: "recovered",
    });
    expect(s.sent[1]?.route).toBe(
      "POST /api/auth/recovery/passkey/finish?keep_sessions=true&keep_keys=true",
    );
    expect(s.sent[1]?.headers.get("X-Auth-Ceremony")).toBe("c-create");
  });
});

describe("sendSignals", () => {
  it("asks nothing of the server where the browser has neither signal", async () => {
    bareplatform();
    const s = fakeServer({});
    await sendSignals(s.client);
    vi.stubGlobal("PublicKeyCredential", undefined);
    await sendSignals(s.client);
    expect(s.sent).toEqual([]);
  });

  it("sends both signals from the server's answer", async () => {
    const signalAllAcceptedCredentials = vi.fn(() => Promise.resolve());
    const signalCurrentUserDetails = vi.fn(() => Promise.resolve());
    bareplatform({ signalAllAcceptedCredentials, signalCurrentUserDetails });
    const s = fakeServer({ "GET /api/auth/webauthn/signals": ok("Signals") });
    await sendSignals(s.client);
    expect(signalAllAcceptedCredentials).toHaveBeenCalledExactlyOnceWith({
      rpId: "app.example.com",
      userId: "aGFuZGxl",
      allAcceptedCredentialIds: ["Y3JlZGVudGlhbA"],
    });
    expect(signalCurrentUserDetails).toHaveBeenCalledExactlyOnceWith({
      rpId: "app.example.com",
      userId: "aGFuZGxl",
      name: "alice",
      displayName: "Alice",
    });
  });

  it("sends one signal even when the other rejects or throws", async () => {
    const signalAllAcceptedCredentials = vi.fn(() => {
      throw new Error("sync throw");
    });
    const signalCurrentUserDetails = vi.fn(() => Promise.resolve());
    bareplatform({ signalAllAcceptedCredentials, signalCurrentUserDetails });
    const s = fakeServer({ "GET /api/auth/webauthn/signals": ok("Signals") });
    await expect(sendSignals(s.client)).resolves.toBeUndefined();
    expect(signalCurrentUserDetails).toHaveBeenCalledOnce();
  });

  it("sends nothing when the server refuses the signals route", async () => {
    const signalAllAcceptedCredentials = vi.fn(() => Promise.resolve());
    bareplatform({ signalAllAcceptedCredentials });
    const s = fakeServer({ "GET /api/auth/webauthn/signals": refusal(401, "auth_required") });
    await expect(sendSignals(s.client)).resolves.toBeUndefined();
    expect(signalAllAcceptedCredentials).not.toHaveBeenCalled();
  });
});

describe("passkeySupport", () => {
  it("is all false with no PublicKeyCredential", async () => {
    vi.stubGlobal("PublicKeyCredential", undefined);
    expect(await passkeySupport()).toEqual({ webauthn: false, conditional: false });
  });

  it("reads the conditional probe, and a rejecting probe as false", async () => {
    bareplatform({ isConditionalMediationAvailable: () => Promise.resolve(true) });
    expect(await passkeySupport()).toEqual({ webauthn: true, conditional: true });
    bareplatform({ isConditionalMediationAvailable: () => Promise.reject(new Error("x")) });
    expect(await passkeySupport()).toEqual({ webauthn: true, conditional: false });
    bareplatform();
    expect(await passkeySupport()).toEqual({ webauthn: true, conditional: false });
  });
});

describe("toCreationOptions and toRequestOptions", () => {
  const bytes = (b: BufferSource): number[] => [
    ...new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer),
  ];

  it("decodes base64url where the browser has no parse*FromJSON", () => {
    bareplatform();
    const o = toCreationOptions({
      challenge: "_-8",
      rp: { name: "App" },
      user: { id: "AQI", name: "a", displayName: "A" },
      pubKeyCredParams: [],
      excludeCredentials: [{ id: "AwQ", type: "public-key", transports: ["usb"] }],
      extensions: { credProps: true },
      hints: ["security-key"],
    });
    expect(bytes(o.challenge)).toEqual([0xff, 0xef]);
    expect(bytes(o.user.id)).toEqual([1, 2]);
    expect(o.excludeCredentials?.map((d) => bytes(d.id))).toEqual([[3, 4]]);
    expect(o.excludeCredentials?.[0]?.transports).toEqual(["usb"]);
    expect(o.extensions).toEqual({ credProps: true });
    expect("hints" in o).toBe(false);

    const r = toRequestOptions({
      challenge: "AA",
      rpId: "x",
      allowCredentials: [{ id: "BQ", type: "public-key" }],
    });
    expect(bytes(r.challenge)).toEqual([0]);
    expect(r.rpId).toBe("x");
    expect(r.allowCredentials?.map((d) => bytes(d.id))).toEqual([[5]]);
    expect(r.allowCredentials?.[0] && "transports" in r.allowCredentials[0]).toBe(false);
  });

  it("hands the JSON to the browser's own parsers when it has them", () => {
    const created = { challenge: new ArrayBuffer(1) };
    const requested = { challenge: new ArrayBuffer(2) };
    const parseCreationOptionsFromJSON = vi.fn(() => created);
    const parseRequestOptionsFromJSON = vi.fn(() => requested);
    bareplatform({ parseCreationOptionsFromJSON, parseRequestOptionsFromJSON });
    const cjson = {
      challenge: "AA",
      rp: { name: "a" },
      user: { id: "AA", name: "a", displayName: "a" },
      pubKeyCredParams: [],
    };
    expect(toCreationOptions(cjson)).toBe(created);
    expect(parseCreationOptionsFromJSON).toHaveBeenCalledWith(cjson);
    expect(toRequestOptions({ challenge: "AA" })).toBe(requested);
    expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith({ challenge: "AA" });
  });
});
