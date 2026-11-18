import type { ApiErr, ApiResult } from "@cplieger/reactive/fetch";
import type { AuthClient, PublicKeyCredentialJSON } from "./client.js";
import { authCode } from "./wire.js";
import type {
  CeremonyResponse,
  EnrolmentOutcome,
  PasskeyView,
  RegisterPasskeyBeginRequest,
  SecondFactorProof,
  SignInOutcome,
  SignedInResponse,
} from "./wire.js";

/** A DOMException's name from the authenticator call, or "" for a throw that is not a DOMException. */
export type DOMExceptionName = string;

export type RegisterOutcome =
  | {
      readonly kind: "registered";
      readonly passkey: PasskeyView;
      /** The recovery code this registration issued: show it once. */
      readonly recovery_code?: string;
    }
  | { readonly kind: "cancelled" }
  | { readonly kind: "duplicate" }
  | { readonly kind: "timeout" }
  | { readonly kind: "not-discoverable" }
  | { readonly kind: "failed"; readonly error: ApiErr | DOMExceptionName };

export type PasskeySignInOutcome =
  | { readonly kind: "signed-in"; readonly result: SignedInResponse }
  | { readonly kind: "cancelled" }
  | { readonly kind: "timeout" }
  | { readonly kind: "ceremony-expired" }
  | { readonly kind: "unknown-credential" }
  | { readonly kind: "verification-failed" }
  | { readonly kind: "failed"; readonly error: ApiErr | DOMExceptionName };

/** A step-up signs nobody in: /stepup/passkey/finish answers 204, so success carries no SignedInResponse. */
export type StepUpOutcome =
  { readonly kind: "stepped-up" } | Exclude<PasskeySignInOutcome, { kind: "signed-in" }>;

/** A passkey second step's answer: the sign-in step's, or why no assertion was made or taken. */
export type SecondPasskeyOutcome =
  | { readonly kind: "answered"; readonly result: SignInOutcome }
  | Exclude<PasskeySignInOutcome, { kind: "signed-in" }>;

/** A set_credential passkey's answer: the sign-in step's, or why no passkey was registered. */
export type SetPasskeyOutcome =
  | { readonly kind: "answered"; readonly result: SignInOutcome }
  | Exclude<RegisterOutcome, { kind: "registered" }>;

/**
 * A passkey enrolment's answer, pendingPasskey's and signUpWithPasskey's: the sign-in it
 * completed or the account it made wait for approval, or why no passkey was bound.
 */
export type PasskeyEnrolmentOutcome =
  | { readonly kind: "answered"; readonly result: EnrolmentOutcome }
  | Exclude<RegisterOutcome, { kind: "registered" }>;

/** A passkey proof for a change that needs a current second factor, or why none was made. */
export type PasskeyProofOutcome =
  | { readonly kind: "proof"; readonly proof: SecondFactorProof }
  | Extract<PasskeySignInOutcome, { kind: "cancelled" | "timeout" | "failed" }>;

interface Platform {
  readonly isConditionalMediationAvailable?: () => Promise<boolean>;
  readonly parseCreationOptionsFromJSON?: (
    o: PublicKeyCredentialCreationOptionsJSON,
  ) => PublicKeyCredentialCreationOptions;
  readonly parseRequestOptionsFromJSON?: (
    o: PublicKeyCredentialRequestOptionsJSON,
  ) => PublicKeyCredentialRequestOptions;
  readonly signalAllAcceptedCredentials?: (o: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: string[];
  }) => Promise<void>;
  readonly signalCurrentUserDetails?: (o: {
    rpId: string;
    userId: string;
    name: string;
    displayName: string;
  }) => Promise<void>;
  readonly signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
}

function platform(): Platform | undefined {
  return (globalThis as { readonly PublicKeyCredential?: Platform }).PublicKeyCredential;
}

function credentials(): CredentialsContainer | undefined {
  return (globalThis as { readonly navigator?: { readonly credentials?: CredentialsContainer } })
    .navigator?.credentials;
}

/** Whether this browser can run a ceremony, and the conditional (autofill) one. Never rejects. */
export async function passkeySupport(): Promise<{
  readonly webauthn: boolean;
  readonly conditional: boolean;
}> {
  const pk = platform();
  if (pk === undefined || credentials() === undefined) {
    return { webauthn: false, conditional: false };
  }
  const probe = pk.isConditionalMediationAvailable;
  let conditional = false;
  if (typeof probe === "function") {
    try {
      conditional = await probe.call(pk);
    } catch {
      conditional = false;
    }
  }
  return { webauthn: true, conditional };
}

function bytes(b64url: string): ArrayBuffer {
  const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out.buffer;
}

function credentialDescriptors(
  list: readonly PublicKeyCredentialDescriptorJSON[],
): PublicKeyCredentialDescriptor[] {
  return list.map((d) => ({
    id: bytes(d.id),
    type: d.type as PublicKeyCredentialType,
    ...(d.transports === undefined ? {} : { transports: d.transports as AuthenticatorTransport[] }),
  }));
}

/**
 * The options navigator.credentials.create takes, through PublicKeyCredential's own
 * parseCreationOptionsFromJSON where the browser has it, else by decoding the base64url fields.
 * @internal
 */
export function toCreationOptions(
  json: PublicKeyCredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  const pk = platform();
  const parse = pk?.parseCreationOptionsFromJSON;
  if (typeof parse === "function") {
    return parse.call(pk, json);
  }
  const { challenge, user, excludeCredentials, hints: _hints, extensions: _ext, ...rest } = json;
  return {
    ...rest,
    challenge: bytes(challenge),
    user: { ...user, id: bytes(user.id) },
    ...(excludeCredentials === undefined
      ? {}
      : { excludeCredentials: credentialDescriptors(excludeCredentials) }),
    ...(json.extensions?.credProps === undefined
      ? {}
      : { extensions: { credProps: json.extensions.credProps } }),
  } as PublicKeyCredentialCreationOptions;
}

/**
 * The options navigator.credentials.get takes, as toCreationOptions builds them.
 * @internal
 */
export function toRequestOptions(
  json: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  const pk = platform();
  const parse = pk?.parseRequestOptionsFromJSON;
  if (typeof parse === "function") {
    return parse.call(pk, json);
  }
  const { challenge, allowCredentials, hints: _hints, extensions: _ext, ...rest } = json;
  return {
    ...rest,
    challenge: bytes(challenge),
    ...(allowCredentials === undefined
      ? {}
      : { allowCredentials: credentialDescriptors(allowCredentials) }),
  } as PublicKeyCredentialRequestOptions;
}

type Verdict =
  | { readonly kind: "timeout" | "cancelled" | "duplicate" }
  | { readonly kind: "failed"; readonly name: DOMExceptionName };

// AbortSignal.timeout() aborts with TimeoutError, not AbortError; AbortError is the caller
// cancelling its own (conditional) ceremony, NotAllowedError the user dismissing the prompt.
function classifyDOMException(e: unknown): Verdict {
  if (!(e instanceof DOMException)) {
    return { kind: "failed", name: "" };
  }
  switch (e.name) {
    case "TimeoutError":
      return { kind: "timeout" };
    case "AbortError":
    case "NotAllowedError":
      return { kind: "cancelled" };
    case "InvalidStateError":
      return { kind: "duplicate" };
    default:
      return { kind: "failed", name: e.name };
  }
}

// A 2xx begin answer of the other ceremony kind is the route's decode failure, as the client
// reports a body that is not its type.
function wrongKind(): ApiErr {
  return { ok: false, status: 0, code: "decode", error: "ceremony options of the wrong kind" };
}

function creationJSON(r: CeremonyResponse): PublicKeyCredentialCreationOptionsJSON | undefined {
  const pk = r.public_key.publicKey;
  return "rp" in pk ? pk : undefined;
}

function requestJSON(r: CeremonyResponse): PublicKeyCredentialRequestOptionsJSON | undefined {
  const pk = r.public_key.publicKey;
  return "rp" in pk ? undefined : pk;
}

function base64url(buffer: ArrayBuffer): string {
  let binary = "";
  for (const b of new Uint8Array(buffer)) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

// Built from the raw buffers, not toJSON(), which the browsers taking the options fallback above
// lack. Only credProps.rk is forwarded, on the create leg: it is the one extension output the
// server reads.
function finishBody(cred: PublicKeyCredential, credProps: boolean): PublicKeyCredentialJSON {
  const attachment = (cred as { readonly authenticatorAttachment?: unknown })
    .authenticatorAttachment;
  const head = {
    id: cred.id,
    rawId: base64url(cred.rawId),
    type: cred.type,
    ...(typeof attachment === "string" ? { authenticatorAttachment: attachment } : {}),
  };
  if ("attestationObject" in cred.response) {
    const r = cred.response as AuthenticatorAttestationResponse;
    const rk = credProps ? rkOf(cred.getClientExtensionResults()) : undefined;
    return {
      ...head,
      response: {
        attestationObject: base64url(r.attestationObject),
        clientDataJSON: base64url(r.clientDataJSON),
        ...transportsOf(r),
      },
      clientExtensionResults: rk === undefined ? {} : { credProps: { rk } },
    };
  }
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    ...head,
    response: {
      authenticatorData: base64url(r.authenticatorData),
      clientDataJSON: base64url(r.clientDataJSON),
      signature: base64url(r.signature),
      ...(r.userHandle === null ? {} : { userHandle: base64url(r.userHandle) }),
    },
    clientExtensionResults: {},
  };
}

// getTransports is absent on older engines; the body then carries no transports.
function transportsOf(r: AuthenticatorAttestationResponse): { transports?: string[] } {
  const get = (r as { readonly getTransports?: unknown }).getTransports;
  const list: unknown = typeof get === "function" ? get.call(r) : undefined;
  return Array.isArray(list)
    ? { transports: list.filter((t): t is string => typeof t === "string") }
    : {};
}

function rkOf(results: AuthenticationExtensionsClientOutputs): boolean | undefined {
  const rk = (results as { readonly credProps?: { readonly rk?: unknown } }).credProps?.rk;
  return typeof rk === "boolean" ? rk : undefined;
}

type Created =
  | {
      readonly kind: "credential";
      readonly ceremony: string;
      readonly json: PublicKeyCredentialJSON;
    }
  | Exclude<RegisterOutcome, { kind: "registered" | "not-discoverable" }>;

async function create(begin: ApiResult<CeremonyResponse>): Promise<Created> {
  if (!begin.ok) {
    return { kind: "failed", error: begin };
  }
  const json = creationJSON(begin.data);
  if (json === undefined) {
    return { kind: "failed", error: wrongKind() };
  }
  try {
    const cred = await credentials()?.create({ publicKey: toCreationOptions(json) });
    if (cred === null || cred === undefined) {
      return { kind: "cancelled" };
    }
    return {
      kind: "credential",
      ceremony: begin.data.ceremony,
      json: finishBody(cred as PublicKeyCredential, json.extensions?.credProps === true),
    };
  } catch (e: unknown) {
    const v = classifyDOMException(e);
    return v.kind === "failed" ? { kind: "failed", error: v.name } : v;
  }
}

type Got =
  | {
      readonly kind: "credential";
      readonly ceremony: string;
      readonly json: PublicKeyCredentialJSON;
      readonly id: string;
      readonly rpId: string;
    }
  | Extract<PasskeySignInOutcome, { kind: "cancelled" | "timeout" | "failed" }>;

async function get(
  begin: ApiResult<CeremonyResponse>,
  o?: { readonly mediation?: "conditional"; readonly signal?: AbortSignal },
): Promise<Got> {
  if (!begin.ok) {
    return { kind: "failed", error: begin };
  }
  const json = requestJSON(begin.data);
  if (json === undefined) {
    return { kind: "failed", error: wrongKind() };
  }
  const request: CredentialRequestOptions = {
    publicKey: toRequestOptions(json),
    ...(o?.mediation === undefined ? {} : { mediation: o.mediation }),
    ...(o?.signal === undefined ? {} : { signal: o.signal }),
  };
  try {
    const cred = await credentials()?.get(request);
    if (cred === null || cred === undefined) {
      return { kind: "cancelled" };
    }
    return {
      kind: "credential",
      ceremony: begin.data.ceremony,
      json: finishBody(cred as PublicKeyCredential, false),
      id: cred.id,
      rpId: json.rpId ?? location.hostname,
    };
  } catch (e: unknown) {
    const v = classifyDOMException(e);
    switch (v.kind) {
      case "failed":
        return { kind: "failed", error: v.name };
      case "duplicate":
        // Only the create leg has an exclusion list, so here the name means no duplicate.
        return { kind: "failed", error: "InvalidStateError" };
      default:
        return { kind: v.kind };
    }
  }
}

async function assertionRefused(
  res: ApiErr,
  got: { readonly id: string; readonly rpId: string },
): Promise<Exclude<PasskeySignInOutcome, { kind: "signed-in" }>> {
  switch (authCode(res)) {
    case "auth_unknown_credential": {
      const pk = platform();
      const signal = pk?.signalUnknownCredential;
      if (typeof signal === "function") {
        await bounded(() => signal.call(pk, { rpId: got.rpId, credentialId: got.id }));
      }
      return { kind: "unknown-credential" };
    }
    case "auth_ceremony_invalid":
      return { kind: "ceremony-expired" };
    case "auth_assertion_failed":
      return { kind: "verification-failed" };
    default:
      return { kind: "failed", error: res };
  }
}

function registrationRefused(res: ApiErr): Exclude<RegisterOutcome, { kind: "registered" }> {
  switch (authCode(res)) {
    case "auth_not_discoverable":
      return { kind: "not-discoverable" };
    case "auth_duplicate_credential":
      return { kind: "duplicate" };
    default:
      return { kind: "failed", error: res };
  }
}

/** Signs in with a passkey; mediation "conditional" runs the autofill ceremony, and signal aborts it. */
export async function signInWithPasskey(
  c: AuthClient,
  o?: { readonly mediation?: "conditional"; readonly signal?: AbortSignal },
): Promise<PasskeySignInOutcome> {
  const got = await get(
    await c.loginPasskeyBegin(o?.mediation === undefined ? undefined : { mediation: o.mediation }),
    o,
  );
  if (got.kind !== "credential") {
    return got;
  }
  const res = await c.loginPasskeyFinish(got.ceremony, got.json);
  return res.ok ? { kind: "signed-in", result: res.data } : assertionRefused(res, got);
}

/** Completes a pending sign-in's passkey second step for ticket. */
export async function loginSecondPasskey(
  c: AuthClient,
  ticket: string,
): Promise<SecondPasskeyOutcome> {
  const got = await get(await c.loginSecondPasskeyBegin({ ticket }));
  if (got.kind !== "credential") {
    return got;
  }
  const res = await c.loginSecondPasskeyFinish(got.ceremony, got.json);
  return res.ok ? { kind: "answered", result: res.data } : assertionRefused(res, got);
}

/** Registers a passkey in place of the temporary password that minted ticket, signing in. */
export async function loginSetPasskey(c: AuthClient, ticket: string): Promise<SetPasskeyOutcome> {
  const made = await create(await c.loginSetPasskeyBegin({ ticket }));
  if (made.kind !== "credential") {
    return made;
  }
  const res = await c.loginSetPasskeyFinish(made.ceremony, made.json);
  return res.ok ? { kind: "answered", result: res.data } : registrationRefused(res);
}

/** Registers a passkey as a pending sign-in's enrolment for ticket, completing the sign-in. */
export async function pendingPasskey(
  c: AuthClient,
  ticket: string,
): Promise<PasskeyEnrolmentOutcome> {
  const made = await create(await c.pendingPasskeyBegin({ ticket }));
  if (made.kind !== "credential") {
    return made;
  }
  const res = await c.pendingPasskeyFinish(made.ceremony, made.json);
  return res.ok ? { kind: "answered", result: res.data } : registrationRefused(res);
}

/**
 * An assertion from one of the signed-in user's passkeys, as the proof removeTOTP,
 * removePasskey, passkeyRegisterBegin and registerPasskey take; the server spends it once.
 */
export async function passkeyProof(c: AuthClient): Promise<PasskeyProofOutcome> {
  const got = await get(await c.stepUpPasskeyBegin());
  if (got.kind !== "credential") {
    return got;
  }
  const { json } = got;
  if (!("signature" in json.response)) {
    return { kind: "failed", error: wrongKind() };
  }
  return {
    kind: "proof",
    proof: { ceremony: got.ceremony, assertion: { ...json, response: json.response } },
  };
}

/**
 * Registers a passkey for the signed-in user, then sends the provider the server's signals;
 * proof is needed while methods.second_factor_held.
 */
export async function registerPasskey(
  c: AuthClient,
  proof?: SecondFactorProof,
): Promise<RegisterOutcome> {
  const made = await create(await c.passkeyRegisterBegin(proof));
  if (made.kind !== "credential") {
    return made;
  }
  const res = await c.passkeyRegisterFinish(made.ceremony, made.json);
  if (!res.ok) {
    return registrationRefused(res);
  }
  await sendSignals(c);
  const { passkey, recovery_code } = res.data;
  return recovery_code === undefined
    ? { kind: "registered", passkey }
    : { kind: "registered", passkey, recovery_code };
}

/** Creates an account with a passkey while state().registration is not "off". */
export async function signUpWithPasskey(
  c: AuthClient,
  r: RegisterPasskeyBeginRequest,
): Promise<PasskeyEnrolmentOutcome> {
  const made = await create(await c.registerPasskeyBegin(r));
  if (made.kind !== "credential") {
    return made;
  }
  const res = await c.registerPasskeyFinish(made.ceremony, made.json);
  return res.ok ? { kind: "answered", result: res.data } : registrationRefused(res);
}

/** Creates the first user with a passkey; a create-leg duplicate is a failed InvalidStateError here. */
export async function setupWithPasskey(
  c: AuthClient,
  r: { readonly token?: string; readonly username: string },
): Promise<PasskeySignInOutcome> {
  const made = await create(await c.setupPasskeyBegin(r));
  if (made.kind === "duplicate") {
    return { kind: "failed", error: "InvalidStateError" };
  }
  if (made.kind !== "credential") {
    return made;
  }
  const res = await c.setupPasskeyFinish(made.ceremony, made.json);
  if (res.ok) {
    return { kind: "signed-in", result: res.data };
  }
  return authCode(res) === "auth_ceremony_invalid"
    ? { kind: "ceremony-expired" }
    : { kind: "failed", error: res };
}

export async function stepUpWithPasskey(c: AuthClient): Promise<StepUpOutcome> {
  const got = await get(await c.stepUpPasskeyBegin());
  if (got.kind !== "credential") {
    return got;
  }
  const res = await c.stepUpPasskeyFinish(got.ceremony, got.json);
  return res.ok ? { kind: "stepped-up" } : assertionRefused(res, got);
}

// Safari can leave a Signal API promise pending forever
// (https://bugs.webkit.org/show_bug.cgi?id=278339); a signal is a hint, so it never blocks
// the caller for longer than this.
const SIGNAL_DEADLINE_MS = 2000;

async function bounded(send: () => Promise<unknown>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const quiet = Promise.resolve()
      .then(send)
      .then(
        () => undefined,
        () => undefined,
      );
    const deadline = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, SIGNAL_DEADLINE_MS);
    });
    await Promise.race([quiet, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Tells the passkey provider which credentials the server still accepts and the user's current
 * name, where the browser supports each signal. Never rejects, and waits at most 2 s per signal.
 */
export async function sendSignals(c: AuthClient): Promise<void> {
  const pk = platform();
  if (pk === undefined) {
    return;
  }
  const all = pk.signalAllAcceptedCredentials;
  const details = pk.signalCurrentUserDetails;
  if (typeof all !== "function" && typeof details !== "function") {
    return;
  }
  const res = await c.webauthnSignals();
  if (!res.ok) {
    return;
  }
  const { allAcceptedCredentials: a, currentUserDetails: d } = res.data;
  // Independent, not in series: Safari can hang or reject one, which must not suppress the other.
  const sent: Promise<void>[] = [];
  if (typeof all === "function") {
    sent.push(
      bounded(() =>
        all.call(pk, {
          rpId: a.rpId,
          userId: a.userId,
          allAcceptedCredentialIds: [...a.allAcceptedCredentialIds],
        }),
      ),
    );
  }
  if (typeof details === "function") {
    sent.push(bounded(() => details.call(pk, { ...d })));
  }
  await Promise.all(sent);
}
