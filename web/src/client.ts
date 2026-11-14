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
  parseRecoveryResponse,
  parseSecurityLogView,
  parseSessionView,
  parseSignedInResponse,
  parseStateResponse,
  parseTokenResponse,
  parseTokenView,
  parseUserView,
  parseWebAuthnSignals,
} from "./wire.js";
import type {
  CeremonyResponse,
  InviteAcceptRequest,
  InviteRequest,
  KeyCreatedResponse,
  KeyView,
  LoginRequest,
  MeResponse,
  NameRequest,
  NewKeyRequest,
  NewUserRequest,
  OIDCStartResponse,
  PasskeyView,
  PasswordChangeRequest,
  PasswordRemoveRequest,
  PasswordRequest,
  PendingLinkResponse,
  ProfileRequest,
  RecoverPasswordRequest,
  RecoveryResponse,
  RedirectRequest,
  SecurityLogView,
  SessionView,
  SetupPasskeyBeginRequest,
  SetupPasswordRequest,
  SignedInResponse,
  StateResponse,
  TTLRequest,
  TokenRequest,
  TokenResponse,
  TokenView,
  UserUpdateRequest,
  UserView,
  Validator,
  WebAuthnSignals,
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
 * A finish route's body as the ceremonies build it: clientExtensionResults carries only an output
 * the begin options requested (credProps on the create leg), because go-webauthn refuses any other.
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

export interface RecoverFlags {
  readonly keepSessions: boolean;
  readonly keepKeys: boolean;
}

/**
 * One method per JSON route of accesshttp, each decoded through wire.ts: a 2xx body that is not
 * the route's type is the fetch instance's "decode" failure. The two redirect routes are
 * navigations, built by oidcSignInURL.
 */
export interface AuthClient {
  readonly prefix: string;
  readonly oidcPrefix: string;
  state(): Promise<ApiResult<StateResponse>>;
  setupPassword(r: SetupPasswordRequest): Promise<ApiResult<SignedInResponse>>;
  setupPasskeyBegin(r: SetupPasskeyBeginRequest): Promise<ApiResult<CeremonyResponse>>;
  setupPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<SignedInResponse>>;
  loginPassword(r: LoginRequest): Promise<ApiResult<SignedInResponse>>;
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
  oidcPending(): Promise<ApiResult<PendingLinkResponse>>;
  oidcLinkPending(): Promise<ApiResult<MeResponse>>;
  oidcUnlink(): Promise<ApiResult<void>>;
  recoveryStart(r: TokenRequest): Promise<ApiResult<RecoveryResponse>>;
  recoveryPassword(r: RecoverPasswordRequest): Promise<ApiResult<void>>;
  recoveryPasskeyBegin(): Promise<ApiResult<CeremonyResponse>>;
  recoveryPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
    o: RecoverFlags,
  ): Promise<ApiResult<void>>;
  inviteAcceptPassword(r: InviteAcceptRequest): Promise<ApiResult<SignedInResponse>>;
  me(): Promise<ApiResult<MeResponse>>;
  updateProfile(r: ProfileRequest): Promise<ApiResult<MeResponse>>;
  reenableMethod(method: string): Promise<ApiResult<void>>;
  stepUpPassword(r: PasswordRequest): Promise<ApiResult<void>>;
  stepUpPasskeyBegin(): Promise<ApiResult<CeremonyResponse>>;
  stepUpPasskeyFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<void>>;
  setPassword(r: PasswordChangeRequest): Promise<ApiResult<void>>;
  removePassword(r: PasswordRemoveRequest): Promise<ApiResult<void>>;
  passkeys(): Promise<ApiResult<readonly PasskeyView[]>>;
  passkeyRegisterBegin(): Promise<ApiResult<CeremonyResponse>>;
  passkeyRegisterFinish(
    ceremony: string,
    credential: PublicKeyCredentialJSON,
  ): Promise<ApiResult<PasskeyView>>;
  renamePasskey(id: number, r: NameRequest): Promise<ApiResult<void>>;
  removePasskey(id: number): Promise<ApiResult<void>>;
  webauthnSignals(): Promise<ApiResult<WebAuthnSignals>>;
  sessions(): Promise<ApiResult<readonly SessionView[]>>;
  renameSession(id: string, r: NameRequest): Promise<ApiResult<void>>;
  revokeSession(id: string): Promise<ApiResult<void>>;
  revokeOtherSessions(): Promise<ApiResult<void>>;
  keys(): Promise<ApiResult<readonly KeyView[]>>;
  /**
   * A label another unexpired key of the user carries, compared after NFC and
   * case folding, is auth_key_label_taken; an empty one is auth_bad_request
   * with reason label_empty.
   */
  createKey(r: NewKeyRequest): Promise<ApiResult<KeyCreatedResponse>>;
  revokeKey(id: number): Promise<ApiResult<void>>;
  /** key lists the users any key in that key's lineage acted on (GET /users?key=). */
  adminUsers(o?: { readonly key?: number }): Promise<ApiResult<readonly UserView[]>>;
  adminCreateUser(r: NewUserRequest): Promise<ApiResult<UserView>>;
  adminUpdateUser(id: number, r: UserUpdateRequest): Promise<ApiResult<UserView>>;
  adminDeleteUser(id: number): Promise<ApiResult<void>>;
  adminIssueRecovery(id: number, r: TTLRequest): Promise<ApiResult<TokenResponse>>;
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
    setupPassword: (r) => json("POST", p("/setup/password"), parseSignedInResponse, { body: r }),
    setupPasskeyBegin: (r) =>
      json("POST", p("/setup/passkey/begin"), parseCeremonyResponse, { body: r }),
    setupPasskeyFinish: (c, cred) =>
      json("POST", p("/setup/passkey/finish"), parseSignedInResponse, finish(c, cred)),
    loginPassword: (r) => json("POST", p("/login/password"), parseSignedInResponse, { body: r }),
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
    oidcPending: () => json("GET", p("/oidc/pending"), parsePendingLinkResponse),
    oidcLinkPending: () => json("POST", p("/oidc/link"), parseMeResponse),
    oidcUnlink: () => empty("DELETE", p("/oidc/link")),
    recoveryStart: (r) => json("POST", p("/recovery"), parseRecoveryResponse, { body: r }),
    recoveryPassword: (r) => empty("POST", p("/recovery/password"), r),
    recoveryPasskeyBegin: () => json("POST", p("/recovery/passkey/begin"), parseCeremonyResponse),
    recoveryPasskeyFinish: (c, cred, flags) =>
      f.requestRaw<undefined>(
        "POST",
        p(
          `/recovery/passkey/finish${query({
            keep_sessions: flags.keepSessions ? "true" : undefined,
            keep_keys: flags.keepKeys ? "true" : undefined,
          })}`,
        ),
        { ...finish(c, cred), ignoreBody: true },
      ),
    inviteAcceptPassword: (r) =>
      json("POST", p("/invite/password"), parseSignedInResponse, { body: r }),
    me: () => json("GET", p("/me"), parseMeResponse),
    updateProfile: (r) => json("PUT", p("/profile"), parseMeResponse, { body: r }),
    reenableMethod: (m) => empty("POST", p(`/methods/${seg(m)}/reenable`)),
    stepUpPassword: (r) => empty("POST", p("/stepup/password"), r),
    stepUpPasskeyBegin: () => json("POST", p("/stepup/passkey/begin"), parseCeremonyResponse),
    stepUpPasskeyFinish: (c, cred) =>
      f.requestRaw<undefined>("POST", p("/stepup/passkey/finish"), {
        ...finish(c, cred),
        ignoreBody: true,
      }),
    setPassword: (r) => empty("PUT", p("/password"), r),
    removePassword: (r) => empty("DELETE", p("/password"), r),
    passkeys: () => json("GET", p("/passkeys"), passkeyList),
    passkeyRegisterBegin: () => json("POST", p("/passkeys/begin"), parseCeremonyResponse),
    passkeyRegisterFinish: (c, cred) =>
      json("POST", p("/passkeys/finish"), parsePasskeyView, finish(c, cred)),
    renamePasskey: (id, r) => empty("PUT", p(`/passkeys/${String(id)}`), r),
    removePasskey: (id) => empty("DELETE", p(`/passkeys/${String(id)}`)),
    webauthnSignals: () => json("GET", p("/webauthn/signals"), parseWebAuthnSignals),
    sessions: () => json("GET", p("/sessions"), sessionList),
    renameSession: (id, r) => empty("PUT", p(`/sessions/${seg(id)}`), r),
    revokeSession: (id) => empty("DELETE", p(`/sessions/${seg(id)}`)),
    revokeOtherSessions: () => empty("POST", p("/sessions/revoke-others")),
    keys: () => json("GET", p("/apikeys"), keyList),
    createKey: (r) => json("POST", p("/apikeys"), parseKeyCreatedResponse, { body: r }),
    revokeKey: (id) => empty("DELETE", p(`/apikeys/${String(id)}`)),
    adminUsers: (q) => json("GET", p(`/users${query({ key: num(q?.key) })}`), userList),
    adminCreateUser: (r) => json("POST", p("/users"), parseUserView, { body: r }),
    adminUpdateUser: (id, r) => json("PUT", p(`/users/${String(id)}`), parseUserView, { body: r }),
    adminDeleteUser: (id) => empty("DELETE", p(`/users/${String(id)}`)),
    adminIssueRecovery: (id, r) =>
      json("POST", p(`/users/${String(id)}/recovery`), parseTokenResponse, { body: r }),
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
