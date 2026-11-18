import type {
  ApiResult,
  FetchInstance,
  HttpMethod,
  RequestOptions,
} from "@cplieger/reactive/fetch";
import {
  list,
  parseCeremonyResponse,
  parseKeyCreatedResponse,
  parseKeyView,
  parseMeResponse,
  parseOIDCStartResponse,
  parsePasskeyView,
  parsePendingLinkResponse,
  parseReadiness,
  parseSecurityLogView,
  parseSessionView,
  parseSignInOutcome,
  parseSignedInResponse,
  parseStateResponse,
  parseTOTPBeginResponse,
  parsePendingTOTPBeginResponse,
  parseEnrolmentOutcome,
  parseRegistrationOutcome,
  parseRecoveryCodeIssuedResponse,
  parseRecoveryCodeResponse,
  parsePasskeyRegisteredResponse,
  parseTokenResponse,
  parseTemporaryPasswordResponse,
  parseTokenView,
  parseUserView,
  parseWebAuthnSignals,
} from "./wire.js";
import type {
  CeremonyResponse,
  InviteAcceptRequest,
  InviteRequest,
  TemporaryPasswordOptions,
  TemporaryPasswordResponse,
  KeyCreatedResponse,
  KeyView,
  LoginRequest,
  MeResponse,
  NameRequest,
  NewKeyRequest,
  NewUserRequest,
  OIDCStartResponse,
  OwnerRequest,
  PasskeyView,
  PasswordChangeRequest,
  PasswordRemoveRequest,
  PasswordRequest,
  PendingCreateRequest,
  PendingLinkByAdminRequest,
  PendingLinkResponse,
  ProfileRequest,
  Readiness,
  RedirectRequest,
  RegisterPasskeyBeginRequest,
  RegisterPasswordRequest,
  RegistrationOutcome,
  SecondFactorProof,
  SecurityLogView,
  SessionView,
  SetupPasskeyBeginRequest,
  SetupPasswordRequest,
  SignInOutcome,
  SignedInResponse,
  StateResponse,
  TOTPBeginResponse,
  PendingTOTPBeginResponse,
  EnrolmentOutcome,
  TOTPFinishRequest,
  RecoveryCodeIssuedResponse,
  RecoveryCodeResponse,
  PasskeyRegisteredResponse,
  TicketRequest,
  TokenRequest,
  TokenResponse,
  TokenView,
  UserUpdateRequest,
  UserView,
  Validator,
  WebAuthnSignals,
  SSOMode,
} from "./wire.js";

export interface AuthClientOptions {
  /** The app's instance: its credentials mode, base URL and error hook apply to every call. */
  readonly fetch: FetchInstance;
  /** accesshttp.Config.Prefix. */
  readonly prefix: string;
  /** accesshttp.Config.OIDCPrefix. */
  readonly oidcPrefix: string;
}

/**
 * A finish route's body as the ceremonies build it: clientExtensionResults carries only credProps.rk
 * on the create leg, the one extension output the server reads.
 */
export type PublicKeyCredentialJSON =
  | {
      readonly id: string;
      readonly rawId: string;
      readonly type: string;
      readonly authenticatorAttachment?: string;
      readonly response: {
        readonly attestationObject: string;
        readonly clientDataJSON: string;
        readonly transports?: readonly string[];
      };
      readonly clientExtensionResults: { readonly credProps?: { readonly rk?: boolean } };
    }
  | {
      readonly id: string;
      readonly rawId: string;
      readonly type: string;
      readonly authenticatorAttachment?: string;
      readonly response: {
        readonly authenticatorData: string;
        readonly clientDataJSON: string;
        readonly signature: string;
        readonly userHandle?: string;
      };
      readonly clientExtensionResults: { readonly credProps?: { readonly rk?: boolean } };
    };

/**
 * One method per JSON route of accesshttp, each decoded through wire.ts: a 2xx body that is not
 * the route's type is the fetch instance's "decode" failure. The two redirect routes are
 * navigations, built by oidcSignInURL.
 */
export interface AuthClient {
  readonly prefix: string;
  readonly oidcPrefix: string;
  state(): Promise<ApiResult<StateResponse>>;
  /** pending enrol under "Require a second factor", with nothing created yet. */
  setupPassword(r: SetupPasswordRequest): Promise<ApiResult<SignInOutcome>>;
  setupPasskeyBegin(r: SetupPasskeyBeginRequest): Promise<ApiResult<CeremonyResponse>>;
  setupPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<SignedInResponse>>;
  loginPassword(r: LoginRequest): Promise<ApiResult<SignInOutcome>>;
  /** A pending sign-in's code step; continue with the answer's newest ticket. */
  loginCode(ticket: string, code: string): Promise<ApiResult<SignInOutcome>>;
  /** loginSecondPasskey's begin: a ceremony limited to the ticket's user's passkeys. */
  loginSecondPasskeyBegin(r: TicketRequest): Promise<ApiResult<CeremonyResponse>>;
  loginSecondPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<SignInOutcome>>;
  /** A pending sign-in's recovery-code step: a pending enrolment marked recovered, never a session. */
  loginRecoveryCode(ticket: string, code: string): Promise<ApiResult<SignInOutcome>>;
  /** A set_credential step's password: signed_in, or pending enrol under "Require a second factor". */
  loginSetPassword(ticket: string, password: string): Promise<ApiResult<SignInOutcome>>;
  /** loginSetPasskey's begin: a registration for the ticket's user. */
  loginSetPasskeyBegin(r: TicketRequest): Promise<ApiResult<CeremonyResponse>>;
  loginSetPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<SignInOutcome>>;
  /** A pending enrolment's TOTP begin; the ticket keeps the secret for pendingTOTPFinish. */
  pendingTOTPBegin(r: TicketRequest): Promise<ApiResult<PendingTOTPBeginResponse>>;
  /** Binds the authenticator pendingTOTPBegin showed and completes the sign-in. */
  pendingTOTPFinish(ticket: string, code: string): Promise<ApiResult<EnrolmentOutcome>>;
  /** pendingPasskey's begin: a registration for the ticket's user. */
  pendingPasskeyBegin(r: TicketRequest): Promise<ApiResult<CeremonyResponse>>;
  pendingPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<EnrolmentOutcome>>;
  loginPasskeyBegin(o?: {
    readonly mediation?: "conditional";
  }): Promise<ApiResult<CeremonyResponse>>;
  loginPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<SignedInResponse>>;
  logout(): Promise<ApiResult<void>>;
  oidcStartLink(r: RedirectRequest): Promise<ApiResult<OIDCStartResponse>>;
  oidcStartStepUp(r: RedirectRequest): Promise<ApiResult<OIDCStartResponse>>;
  /** Accept an invite by single sign-on: go to the answer's URL. The token travels in the body only. */
  inviteAcceptOIDC(r: TokenRequest): Promise<ApiResult<OIDCStartResponse>>;
  oidcPending(): Promise<ApiResult<PendingLinkResponse>>;
  /** The pending screen's "Create a new account"; a taken name keeps the pending state. */
  oidcCreatePending(r: PendingCreateRequest): Promise<ApiResult<SignedInResponse>>;
  /** Under sso "only": link the pending identity to an account with its admin's temporary password. */
  oidcLinkByAdmin(r: PendingLinkByAdminRequest): Promise<ApiResult<SignedInResponse>>;
  oidcLinkPending(): Promise<ApiResult<MeResponse>>;
  oidcUnlink(): Promise<ApiResult<void>>;
  /** pending enrol under "Require a second factor", with the invite not yet spent. */
  inviteAcceptPassword(r: InviteAcceptRequest): Promise<ApiResult<SignInOutcome>>;
  /** Only while state().registration is not "off": signed in, pending enrol under the rule, or waiting. */
  registerPassword(r: RegisterPasswordRequest): Promise<ApiResult<RegistrationOutcome>>;
  /** signUpWithPasskey's begin. */
  registerPasskeyBegin(r: RegisterPasskeyBeginRequest): Promise<ApiResult<CeremonyResponse>>;
  registerPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<EnrolmentOutcome>>;
  me(): Promise<ApiResult<MeResponse>>;
  updateProfile(r: ProfileRequest): Promise<ApiResult<MeResponse>>;
  reenableMethod(method: string): Promise<ApiResult<void>>;
  stepUpPassword(r: PasswordRequest): Promise<ApiResult<void>>;
  /** Offered only while methods.totp.usable. */
  stepUpCode(code: string): Promise<ApiResult<void>>;
  /** From Account under recent sign-in and HTTPS, for a user with a password. */
  beginTOTP(): Promise<ApiResult<TOTPBeginResponse>>;
  /** current_code is the replaced authenticator's code, required when one is enrolled. */
  finishTOTP(r: TOTPFinishRequest): Promise<ApiResult<RecoveryCodeIssuedResponse>>;
  /**
   * A proof while methods.totp.usable; none for an authenticator the app turned off, which
   * needs a recent sign-in instead (withStepUp).
   */
  removeTOTP(proof?: SecondFactorProof): Promise<ApiResult<void>>;
  /** Under recent sign-in and HTTPS, with a current code or passkey: the new code, shown once. */
  regenerateRecoveryCode(proof: SecondFactorProof): Promise<ApiResult<RecoveryCodeResponse>>;
  stepUpPasskeyBegin(): Promise<ApiResult<CeremonyResponse>>;
  stepUpPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<void>>;
  /** recovery_code is set when a first password issued one: show it once. */
  setPassword(r: PasswordChangeRequest): Promise<ApiResult<RecoveryCodeIssuedResponse>>;
  removePassword(r: PasswordRemoveRequest): Promise<ApiResult<void>>;
  passkeys(): Promise<ApiResult<readonly PasskeyView[]>>;
  /** proof while methods.second_factor_held. */
  passkeyRegisterBegin(proof?: SecondFactorProof): Promise<ApiResult<CeremonyResponse>>;
  passkeyRegisterFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<PasskeyRegisteredResponse>>;
  renamePasskey(id: number, r: NameRequest): Promise<ApiResult<void>>;
  /** proof while methods.second_factor_held. */
  removePasskey(id: number, proof?: SecondFactorProof): Promise<ApiResult<void>>;
  webauthnSignals(): Promise<ApiResult<WebAuthnSignals>>;
  sessions(): Promise<ApiResult<readonly SessionView[]>>;
  renameSession(id: string, r: NameRequest): Promise<ApiResult<void>>;
  revokeSession(id: string): Promise<ApiResult<void>>;
  revokeOtherSessions(): Promise<ApiResult<void>>;
  /** A session, or a key with the create-keys scope; renameKey and revokeKey admit the same, and a key may revoke itself. */
  keys(): Promise<ApiResult<readonly KeyView[]>>;
  /**
   * A label another unexpired key of the user carries, compared after NFC and
   * case folding, is auth_key_label_taken; an empty one is auth_bad_request
   * with reason label_empty.
   */
  createKey(r: NewKeyRequest): Promise<ApiResult<KeyCreatedResponse>>;
  /** The label follows createKey's rule; the key's own label is free, so a key can be recased. */
  renameKey(id: number, r: NameRequest): Promise<ApiResult<void>>;
  /**
   * A new secret for the same key, which needs recent auth. The old secret
   * keeps working until the new one is first used or details.previous_until
   * passes, so a leaked key is revoked, not rotated.
   */
  rotateKey(id: number): Promise<ApiResult<KeyCreatedResponse>>;
  revokeKey(id: number): Promise<ApiResult<void>>;
  /** key lists the users any key in that key's lineage acted on (GET /users?key=). */
  adminUsers(o?: { readonly key?: number }): Promise<ApiResult<readonly UserView[]>>;
  adminCreateUser(r: NewUserRequest): Promise<ApiResult<UserView>>;
  adminUpdateUser(id: number, r: UserUpdateRequest): Promise<ApiResult<UserView>>;
  /** Owners only, under recent auth; an owner needs a password or a passkey. */
  adminSetOwner(id: number, r: OwnerRequest): Promise<ApiResult<UserView>>;
  /** Admins, or a key with the admin scope, with no step-up. A refusal is the body's: an owner sees its own change's. */
  adminSSOReadiness(mode: SSOMode): Promise<ApiResult<Readiness>>;
  /** Owners only, under recent auth: answers exactly the refusal adminSSOReadiness showed. */
  adminApplySSO(mode: SSOMode): Promise<ApiResult<void>>;
  adminDeleteUser(id: number): Promise<ApiResult<void>>;
  /** Removes the user's identity-provider link and ends all their sessions. */
  adminUnlinkOIDC(id: number): Promise<ApiResult<void>>;
  /** Unlinks the user and issues the temporary password the admin link takes, in one step. */
  adminRelinkOIDC(
    id: number,
    options: TemporaryPasswordOptions,
  ): Promise<ApiResult<TemporaryPasswordResponse>>;
  adminTemporaryPassword(
    id: number,
    options: TemporaryPasswordOptions,
  ): Promise<ApiResult<TemporaryPasswordResponse>>;
  /** Deletes the user's authenticator app and recovery code and ends their sessions; password and passkeys stay. */
  adminResetSecondFactor(id: number): Promise<ApiResult<void>>;
  adminInvite(r: InviteRequest): Promise<ApiResult<TokenResponse>>;
  adminTokens(): Promise<ApiResult<readonly TokenView[]>>;
  adminKeys(): Promise<ApiResult<readonly KeyView[]>>;
  adminRevokeKey(id: number): Promise<ApiResult<void>>;
  /**
   * Newest first, or oldest first when oldestFirst is true; after and before are bounds only.
   * kinds empty or absent is every kind.
   */
  adminSecurityLog(q?: {
    readonly user?: number;
    readonly actor?: number;
    readonly actorKey?: number;
    readonly after?: number;
    readonly before?: number;
    readonly kinds?: readonly string[];
    readonly limit?: number;
    readonly oldestFirst?: boolean;
  }): Promise<ApiResult<SecurityLogView>>;
}

// The fetch instance's decoder contract is to throw on a mismatch, which it turns into a
// "decode" failure; a wire.ts validator answers undefined instead.
function decoder<T>(validate: Validator<T>): (v: unknown) => T {
  return (v) => {
    const out = validate(v);
    if (out === undefined) {
      throw new TypeError("response body is not the route's wire type");
    }
    return out;
  };
}

function query(params: Readonly<Record<string, string | undefined>>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) {
      q.set(k, v);
    }
  }
  const s = q.toString();
  return s === "" ? "" : `?${s}`;
}

const seg = encodeURIComponent;
const num = (n: number | undefined): string | undefined =>
  n === undefined ? undefined : String(n);

export function createAuthClient(opts: AuthClientOptions): AuthClient {
  const { fetch: f, prefix, oidcPrefix } = opts;

  function json<T>(
    method: HttpMethod,
    path: string,
    validate: Validator<T>,
    o: RequestOptions<T> = {},
  ): Promise<ApiResult<T>> {
    return f.requestRaw<T>(method, path, { ...o, decoder: decoder(validate) });
  }
  function empty(method: HttpMethod, path: string, body?: unknown): Promise<ApiResult<void>> {
    return f.requestRaw<undefined>(method, path, {
      ignoreBody: true,
      ...(body === undefined ? {} : { body }),
    });
  }
  function finish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): { readonly body: unknown; readonly headers: Readonly<Record<string, string>> } {
    return { body: credential, headers: { "X-Auth-Ceremony": ceremony } };
  }
  const p = (path: string): string => prefix + path;
  const o = (path: string): string => oidcPrefix + path;
  const passkeyList = list(parsePasskeyView);
  const sessionList = list(parseSessionView);
  const keyList = list(parseKeyView);
  const userList = list(parseUserView);
  const tokenList = list(parseTokenView);

  return {
    prefix,
    oidcPrefix,
    state: () => json("GET", p("/state"), parseStateResponse),
    setupPassword: (r) => json("POST", p("/setup/password"), parseSignInOutcome, { body: r }),
    setupPasskeyBegin: (r) =>
      json("POST", p("/setup/passkey/begin"), parseCeremonyResponse, { body: r }),
    setupPasskeyFinish: (c, cred) =>
      json("POST", p("/setup/passkey/finish"), parseSignedInResponse, finish(c, cred)),
    loginPassword: (r) => json("POST", p("/login/password"), parseSignInOutcome, { body: r }),
    loginCode: (ticket, code) =>
      json("POST", p("/login/code"), parseSignInOutcome, { body: { ticket, code } }),
    loginSecondPasskeyBegin: (r) =>
      json("POST", p("/login/second-passkey/begin"), parseCeremonyResponse, { body: r }),
    loginSecondPasskeyFinish: (c, cred) =>
      json("POST", p("/login/second-passkey/finish"), parseSignInOutcome, finish(c, cred)),
    loginRecoveryCode: (ticket, code) =>
      json("POST", p("/login/recovery-code"), parseSignInOutcome, { body: { ticket, code } }),
    loginSetPassword: (ticket, password) =>
      json("POST", p("/login/set-password"), parseSignInOutcome, { body: { ticket, password } }),
    loginSetPasskeyBegin: (r) =>
      json("POST", p("/login/set-passkey/begin"), parseCeremonyResponse, { body: r }),
    loginSetPasskeyFinish: (c, cred) =>
      json("POST", p("/login/set-passkey/finish"), parseSignInOutcome, finish(c, cred)),
    pendingTOTPBegin: (r) =>
      json("POST", p("/pending/totp/begin"), parsePendingTOTPBeginResponse, { body: r }),
    pendingTOTPFinish: (ticket, code) =>
      json("POST", p("/pending/totp/finish"), parseEnrolmentOutcome, { body: { ticket, code } }),
    pendingPasskeyBegin: (r) =>
      json("POST", p("/pending/passkey/begin"), parseCeremonyResponse, { body: r }),
    pendingPasskeyFinish: (c, cred) =>
      json("POST", p("/pending/passkey/finish"), parseEnrolmentOutcome, finish(c, cred)),
    loginPasskeyBegin: (q) =>
      json(
        "POST",
        p(`/login/passkey/begin${query({ mediation: q?.mediation })}`),
        parseCeremonyResponse,
      ),
    loginPasskeyFinish: (c, cred) =>
      json("POST", p("/login/passkey/finish"), parseSignedInResponse, finish(c, cred)),
    logout: () => empty("POST", p("/logout")),
    oidcStartLink: (r) => json("POST", o("/start/link"), parseOIDCStartResponse, { body: r }),
    oidcStartStepUp: (r) => json("POST", o("/start/stepup"), parseOIDCStartResponse, { body: r }),
    inviteAcceptOIDC: (r) => json("POST", o("/start/invite"), parseOIDCStartResponse, { body: r }),
    oidcPending: () => json("GET", p("/oidc/pending"), parsePendingLinkResponse),
    oidcCreatePending: (r) =>
      json("POST", p("/oidc/pending/create"), parseSignedInResponse, { body: r }),
    oidcLinkByAdmin: (r) =>
      json("POST", p("/oidc/pending/link"), parseSignedInResponse, { body: r }),
    oidcLinkPending: () => json("POST", p("/oidc/link"), parseMeResponse),
    oidcUnlink: () => empty("DELETE", p("/oidc/link")),
    inviteAcceptPassword: (r) =>
      json("POST", p("/invite/password"), parseSignInOutcome, { body: r }),
    registerPassword: (r) =>
      json("POST", p("/register/password"), parseRegistrationOutcome, { body: r }),
    registerPasskeyBegin: (r) =>
      json("POST", p("/register/passkey/begin"), parseCeremonyResponse, { body: r }),
    registerPasskeyFinish: (c, cred) =>
      json("POST", p("/register/passkey/finish"), parseEnrolmentOutcome, finish(c, cred)),
    me: () => json("GET", p("/me"), parseMeResponse),
    updateProfile: (r) => json("PUT", p("/profile"), parseMeResponse, { body: r }),
    reenableMethod: (m) => empty("POST", p(`/methods/${seg(m)}/reenable`)),
    stepUpPassword: (r) => empty("POST", p("/stepup/password"), r),
    stepUpCode: (code) => empty("POST", p("/stepup/code"), { code }),
    beginTOTP: () => json("POST", p("/totp/begin"), parseTOTPBeginResponse),
    finishTOTP: (r) =>
      json("POST", p("/totp/finish"), parseRecoveryCodeIssuedResponse, { body: r }),
    removeTOTP: (proof) => empty("DELETE", p("/totp"), proof),
    regenerateRecoveryCode: (proof) =>
      json("POST", p("/recovery-code"), parseRecoveryCodeResponse, { body: proof }),
    stepUpPasskeyBegin: () => json("POST", p("/stepup/passkey/begin"), parseCeremonyResponse),
    stepUpPasskeyFinish: (c, cred) =>
      f.requestRaw<undefined>("POST", p("/stepup/passkey/finish"), {
        ...finish(c, cred),
        ignoreBody: true,
      }),
    setPassword: (r) => json("PUT", p("/password"), parseRecoveryCodeIssuedResponse, { body: r }),
    removePassword: (r) => empty("DELETE", p("/password"), r),
    passkeys: () => json("GET", p("/passkeys"), passkeyList),
    passkeyRegisterBegin: (proof) =>
      json(
        "POST",
        p("/passkeys/begin"),
        parseCeremonyResponse,
        proof === undefined ? {} : { body: proof },
      ),
    passkeyRegisterFinish: (c, cred) =>
      json("POST", p("/passkeys/finish"), parsePasskeyRegisteredResponse, finish(c, cred)),
    renamePasskey: (id, r) => empty("PUT", p(`/passkeys/${String(id)}`), r),
    removePasskey: (id, proof) => empty("DELETE", p(`/passkeys/${String(id)}`), proof),
    webauthnSignals: () => json("GET", p("/webauthn/signals"), parseWebAuthnSignals),
    sessions: () => json("GET", p("/sessions"), sessionList),
    renameSession: (id, r) => empty("PUT", p(`/sessions/${seg(id)}`), r),
    revokeSession: (id) => empty("DELETE", p(`/sessions/${seg(id)}`)),
    revokeOtherSessions: () => empty("POST", p("/sessions/revoke-others")),
    keys: () => json("GET", p("/apikeys"), keyList),
    createKey: (r) => json("POST", p("/apikeys"), parseKeyCreatedResponse, { body: r }),
    renameKey: (id, r) => empty("PUT", p(`/apikeys/${String(id)}`), r),
    rotateKey: (id) => json("POST", p(`/apikeys/${String(id)}/rotate`), parseKeyCreatedResponse),
    revokeKey: (id) => empty("DELETE", p(`/apikeys/${String(id)}`)),
    adminUsers: (q) => json("GET", p(`/users${query({ key: num(q?.key) })}`), userList),
    adminCreateUser: (r) => json("POST", p("/users"), parseUserView, { body: r }),
    adminUpdateUser: (id, r) => json("PUT", p(`/users/${String(id)}`), parseUserView, { body: r }),
    adminSetOwner: (id, r) =>
      json("PUT", p(`/users/${String(id)}/owner`), parseUserView, { body: r }),
    adminSSOReadiness: (mode) => json("GET", p(`/sso/readiness${query({ mode })}`), parseReadiness),
    adminApplySSO: (mode) => empty("PUT", p("/sso"), { mode }),
    adminDeleteUser: (id) => empty("DELETE", p(`/users/${String(id)}`)),
    adminUnlinkOIDC: (id) => empty("DELETE", p(`/users/${String(id)}/oidc`)),
    adminRelinkOIDC: (id, options) =>
      json("POST", p(`/users/${String(id)}/oidc/relink`), parseTemporaryPasswordResponse, {
        body: options,
      }),
    adminTemporaryPassword: (id, options) =>
      json("POST", p(`/users/${String(id)}/temporary-password`), parseTemporaryPasswordResponse, {
        body: options,
      }),
    adminResetSecondFactor: (id) => empty("DELETE", p(`/users/${String(id)}/second-factor`)),
    adminInvite: (r) => json("POST", p("/invites"), parseTokenResponse, { body: r }),
    adminTokens: () => json("GET", p("/tokens"), tokenList),
    adminKeys: () => json("GET", p("/admin/apikeys"), keyList),
    adminRevokeKey: (id) => empty("DELETE", p(`/admin/apikeys/${String(id)}`)),
    adminSecurityLog: (q) =>
      json(
        "GET",
        p(
          `/security-log${query({
            user: num(q?.user),
            actor: num(q?.actor),
            actor_key: num(q?.actorKey),
            after: num(q?.after),
            before: num(q?.before),
            kinds: q?.kinds === undefined || q.kinds.length === 0 ? undefined : q.kinds.join(","),
            limit: num(q?.limit),
            oldest_first: q?.oldestFirst === true ? "true" : undefined,
          })}`,
        ),
        parseSecurityLogView,
      ),
  };
}
