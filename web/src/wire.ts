import type { ApiErr } from "@cplieger/reactive/fetch";

/**
 * A validator: reads an untrusted JSON value and returns a fresh, narrowed copy, or undefined
 * when the value is not the type. It never throws.
 */
export type Validator<T> = (value: unknown) => T | undefined;

/** @internal Go's Role constants. */
export const ROLES = ["admin", "user"] as const;
/** @internal Go's Method constants. */
export const METHODS = ["password", "passkey", "oidc", "recovery", "api_key", "bypass"] as const;
/** @internal Go's TokenPurpose constants. */
export const TOKEN_PURPOSES = ["setup", "recovery", "invite"] as const;

// An open set (types.go: Method, Role, TokenPurpose): the server may send an app-defined
// value beside Go's constants, so a switch over one needs a default arm.
type Open<L extends readonly string[]> = L[number] | (string & {});
type Role = Open<typeof ROLES>;
type Method = Open<typeof METHODS>;
type TokenPurpose = Open<typeof TOKEN_PURPOSES>;

// Ties each field's optionality to the interface, so a field the interface marks optional
// cannot be declared required in its validator, or the reverse.
interface Field<V, O extends boolean> {
  readonly check: Validator<V>;
  readonly optional: O;
}
type Fields<T> = {
  readonly [K in keyof T]-?: Field<
    Exclude<T[K], undefined>,
    Pick<T, K> extends Required<Pick<T, K>> ? false : true
  >;
};

const req = <V>(check: Validator<V>): Field<V, false> => ({ check, optional: false });
const opt = <V>(check: Validator<V>): Field<V, true> => ({ check, optional: true });

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// strict refuses a key the type does not declare, as accesshttp's decoder does; a loose
// object (the browser's WebAuthn options) drops it instead.
function object<T>(fields: Fields<NoInfer<T>>, strict = true): Validator<T> {
  const spec: Readonly<Record<string, Field<unknown, boolean>>> = fields;
  const keys = Object.keys(spec);
  return (v) => {
    if (!isRecord(v)) {
      return undefined;
    }
    if (strict && Object.keys(v).some((k) => !Object.hasOwn(spec, k))) {
      return undefined;
    }
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      const f = spec[k];
      if (f === undefined) {
        return undefined;
      }
      if (!Object.hasOwn(v, k)) {
        if (f.optional) {
          continue;
        }
        return undefined;
      }
      const value = f.check(v[k]);
      if (value === undefined) {
        return undefined;
      }
      out[k] = value;
    }
    return out as T;
  };
}

/** @internal */
export function list<V>(check: Validator<V>): Validator<readonly V[]> {
  return (v) => {
    if (!Array.isArray(v)) {
      return undefined;
    }
    const out: V[] = [];
    for (const item of v as readonly unknown[]) {
      const value = check(item);
      if (value === undefined) {
        return undefined;
      }
      out.push(value);
    }
    return out;
  };
}

function oneOf<const L extends readonly string[]>(...values: L): Validator<L[number]> {
  const set: ReadonlySet<string> = new Set(values);
  return (v) => (typeof v === "string" && set.has(v) ? v : undefined);
}

const str: Validator<string> = (v) => (typeof v === "string" ? v : undefined);
const bool: Validator<boolean> = (v) => (typeof v === "boolean" ? v : undefined);
const int: Validator<number> = (v) =>
  typeof v === "number" && Number.isSafeInteger(v) ? v : undefined;
const count: Validator<number> = (v) => {
  const n = int(v);
  return n !== undefined && n >= 0 ? n : undefined;
};
// User, key and passkey IDs are positive and within Number.MAX_SAFE_INTEGER (contract rule 17).
const id: Validator<number> = (v) => {
  const n = int(v);
  return n !== undefined && n > 0 ? n : undefined;
};
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const time: Validator<string> = (v) =>
  typeof v === "string" && RFC3339.test(v) && !Number.isNaN(Date.parse(v)) ? v : undefined;
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const base64url: Validator<string> = (v) =>
  typeof v === "string" && BASE64URL.test(v) && v.length % 4 !== 1 ? v : undefined;
const nonEmpty: Validator<string> = (v) => (typeof v === "string" && v !== "" ? v : undefined);
const role: Validator<Role> = nonEmpty;
const method: Validator<Method> = nonEmpty;
const purpose: Validator<TokenPurpose> = nonEmpty;
const ids = list(id);
const strings = list(str);

// Requests.

export interface SetupPasswordRequest {
  readonly token?: string;
  readonly username: string;
  readonly password: string;
}
export const parseSetupPasswordRequest: Validator<SetupPasswordRequest> = object({
  token: opt(str),
  username: req(str),
  password: req(str),
});

export interface SetupPasskeyBeginRequest {
  readonly token?: string;
  readonly username: string;
}
export const parseSetupPasskeyBeginRequest: Validator<SetupPasskeyBeginRequest> = object({
  token: opt(str),
  username: req(str),
});

export interface LoginRequest {
  readonly username: string;
  readonly password: string;
}
export const parseLoginRequest: Validator<LoginRequest> = object({
  username: req(str),
  password: req(str),
});

export interface RedirectRequest {
  readonly redirect?: string;
}
export const parseRedirectRequest: Validator<RedirectRequest> = object({ redirect: opt(str) });

export interface TokenRequest {
  readonly token: string;
}
export const parseTokenRequest: Validator<TokenRequest> = object({ token: req(str) });

export interface RecoverPasswordRequest {
  readonly password: string;
  readonly keep_sessions?: boolean;
  readonly keep_keys?: boolean;
}
export const parseRecoverPasswordRequest: Validator<RecoverPasswordRequest> = object({
  password: req(str),
  keep_sessions: opt(bool),
  keep_keys: opt(bool),
});

export interface InviteAcceptRequest {
  readonly token: string;
  readonly username: string;
  readonly password: string;
}
export const parseInviteAcceptRequest: Validator<InviteAcceptRequest> = object({
  token: req(str),
  username: req(str),
  password: req(str),
});

export interface ProfileRequest {
  readonly display_name: string;
}
export const parseProfileRequest: Validator<ProfileRequest> = object({ display_name: req(str) });

export interface PasswordRequest {
  readonly password: string;
}
export const parsePasswordRequest: Validator<PasswordRequest> = object({ password: req(str) });

/** current_password is required when the user holds a password. */
export interface PasswordChangeRequest {
  readonly current_password?: string;
  readonly password: string;
}
export const parsePasswordChangeRequest: Validator<PasswordChangeRequest> = object({
  current_password: opt(str),
  password: req(str),
});

export interface PasswordRemoveRequest {
  readonly current_password: string;
}
export const parsePasswordRemoveRequest: Validator<PasswordRemoveRequest> = object({
  current_password: req(str),
});

export interface NameRequest {
  readonly name: string;
}
export const parseNameRequest: Validator<NameRequest> = object({ name: req(str) });

/** expires_in_days absent or 0 is a key that never expires. */
export interface NewKeyRequest {
  readonly label: string;
  readonly scopes: readonly string[];
  readonly expires_in_days?: number;
}
export const parseNewKeyRequest: Validator<NewKeyRequest> = object({
  label: req(str),
  scopes: req(strings),
  expires_in_days: opt(int),
});

/** Without a password the user has no sign-in method until a recovery link. */
export interface NewUserRequest {
  readonly username: string;
  readonly password?: string;
  readonly role: Role;
}
export const parseNewUserRequest: Validator<NewUserRequest> = object({
  username: req(str),
  password: opt(str),
  role: req(role),
});

export interface UserUpdateRequest {
  readonly role?: Role;
  readonly enabled?: boolean;
}
export const parseUserUpdateRequest: Validator<UserUpdateRequest> = object({
  role: opt(role),
  enabled: opt(bool),
});

/** hours absent or 0 is the default lifetime. */
export interface TTLRequest {
  readonly hours?: number;
}
export const parseTTLRequest: Validator<TTLRequest> = object({ hours: opt(int) });

export interface InviteRequest {
  readonly role: Role;
  readonly hours?: number;
}
export const parseInviteRequest: Validator<InviteRequest> = object({
  role: req(role),
  hours: opt(int),
});

// Responses.

export interface StateResponse {
  readonly setup_required: boolean;
  readonly password_login: boolean;
  readonly passkeys: boolean;
  readonly oidc: boolean;
}
export const parseStateResponse: Validator<StateResponse> = object({
  setup_required: req(bool),
  password_login: req(bool),
  passkeys: req(bool),
  oidc: req(bool),
});

export interface UserMethodsView {
  readonly password: boolean;
  readonly passkey_count: number;
}
export const parseUserMethodsView: Validator<UserMethodsView> = object({
  password: req(bool),
  passkey_count: req(count),
});

/** key_lineage and methods are set on the admin list only. */
export interface UserView {
  readonly id: number;
  readonly username: string;
  readonly display_name?: string;
  readonly role: Role;
  readonly enabled: boolean;
  readonly oidc_linked: boolean;
  readonly created_at: string;
  readonly key_lineage?: readonly number[];
  readonly methods?: UserMethodsView;
}
export const parseUserView: Validator<UserView> = object({
  id: req(id),
  username: req(str),
  display_name: opt(str),
  role: req(role),
  enabled: req(bool),
  oidc_linked: req(bool),
  created_at: req(time),
  key_lineage: opt(ids),
  methods: opt(parseUserMethodsView),
});

export interface SignedInResponse {
  readonly user: UserView;
  readonly session_id: string;
  readonly clone_warning?: boolean;
}
export const parseSignedInResponse: Validator<SignedInResponse> = object({
  user: req(parseUserView),
  session_id: req(str),
  clone_warning: opt(bool),
});

/** The WebAuthn options of a begin route, in the browser's JSON shape. */
export type CeremonyOptions =
  | { readonly publicKey: PublicKeyCredentialCreationOptionsJSON }
  | {
      readonly publicKey: PublicKeyCredentialRequestOptionsJSON;
      readonly mediation?: CredentialMediationRequirement;
    };

export interface CeremonyResponse {
  /** Sent back in the finish request's X-Auth-Ceremony header. */
  readonly ceremony: string;
  readonly public_key: CeremonyOptions;
}

const descriptor: Validator<PublicKeyCredentialDescriptorJSON> = object(
  { id: req(base64url), type: req(str), transports: opt(list(str)) as Field<string[], true> },
  false,
);
const descriptors = list(descriptor) as Validator<PublicKeyCredentialDescriptorJSON[]>;
const hints = strings as Validator<string[]>;

// An extension input accesshttp never sends is refused rather than passed through unchecked.
const absent: Field<never, true> = { check: () => undefined, optional: true };
const extensionInputs = object<AuthenticationExtensionsClientInputsJSON>(
  { appid: opt(str), credProps: opt(bool), largeBlob: absent, prf: absent },
  false,
);

const creationFields = object<PublicKeyCredentialCreationOptionsJSON>(
  {
    challenge: req(base64url),
    rp: req(object({ name: req(str), id: opt(str) }, false)),
    user: req(object({ id: req(base64url), name: req(str), displayName: req(str) }, false)),
    pubKeyCredParams: req(
      list(object({ alg: req(int), type: req(oneOf("public-key")) }, false)) as Validator<
        PublicKeyCredentialParameters[]
      >,
    ),
    authenticatorSelection: opt(
      object<AuthenticatorSelectionCriteria>(
        {
          authenticatorAttachment: opt(oneOf("cross-platform", "platform")),
          requireResidentKey: opt(bool),
          residentKey: opt(oneOf("discouraged", "preferred", "required")),
          userVerification: opt(oneOf("discouraged", "preferred", "required")),
        },
        false,
      ),
    ),
    attestation: opt(str),
    excludeCredentials: opt(descriptors),
    extensions: opt(extensionInputs),
    hints: opt(hints),
    timeout: opt(count),
  },
  false,
);

// accesshttp omits an empty pubKeyCredParams, which the browser API requires as a member.
const creationOptions: Validator<PublicKeyCredentialCreationOptionsJSON> = (v) =>
  isRecord(v) && !Object.hasOwn(v, "pubKeyCredParams")
    ? creationFields({ ...v, pubKeyCredParams: [] })
    : creationFields(v);

const requestOptions = object<PublicKeyCredentialRequestOptionsJSON>(
  {
    challenge: req(base64url),
    rpId: opt(str),
    userVerification: opt(str),
    allowCredentials: opt(descriptors),
    hints: opt(hints),
    timeout: opt(count),
    extensions: opt(extensionInputs),
  },
  false,
);

const mediation = oneOf("conditional", "optional", "required", "silent");

const ceremonyOptions: Validator<CeremonyOptions> = (v) => {
  if (!isRecord(v)) {
    return undefined;
  }
  const pk = v["publicKey"];
  if (isRecord(pk) && (Object.hasOwn(pk, "rp") || Object.hasOwn(pk, "user"))) {
    const publicKey = creationOptions(pk);
    return publicKey === undefined ? undefined : { publicKey };
  }
  const publicKey = requestOptions(pk);
  if (publicKey === undefined) {
    return undefined;
  }
  if (!Object.hasOwn(v, "mediation")) {
    return { publicKey };
  }
  const m = mediation(v["mediation"]);
  return m === undefined ? undefined : { publicKey, mediation: m };
};

export const parseCeremonyResponse: Validator<CeremonyResponse> = object({
  ceremony: req(str),
  public_key: req(ceremonyOptions),
});

export interface OIDCStartResponse {
  readonly url: string;
}
export const parseOIDCStartResponse: Validator<OIDCStartResponse> = object({ url: req(str) });

export interface PendingLinkResponse {
  readonly issuer: string;
  readonly username_hint?: string;
  readonly email?: string;
}
export const parsePendingLinkResponse: Validator<PendingLinkResponse> = object({
  issuer: req(str),
  username_hint: opt(str),
  email: opt(str),
});

export interface MethodLockView {
  readonly method: Method;
  readonly untrusted: boolean;
  readonly trusted: boolean;
}
export const parseMethodLockView: Validator<MethodLockView> = object({
  method: req(method),
  untrusted: req(bool),
  trusted: req(bool),
});

export interface MethodsView {
  readonly password: boolean;
  readonly passkey_count: number;
  readonly oidc_linked: boolean;
  readonly oidc_available: boolean;
  readonly passkeys_available: boolean;
  readonly password_login: boolean;
  readonly locks: readonly MethodLockView[];
}
export const parseMethodsView: Validator<MethodsView> = object({
  password: req(bool),
  passkey_count: req(count),
  oidc_linked: req(bool),
  oidc_available: req(bool),
  passkeys_available: req(bool),
  password_login: req(bool),
  locks: req(list(parseMethodLockView)),
});

export interface CurrentSessionView {
  readonly id: string;
  readonly method: Method;
  readonly auth_time: string;
  readonly idle_deadline: string;
  readonly absolute_deadline: string;
}
export const parseCurrentSessionView: Validator<CurrentSessionView> = object({
  id: req(str),
  method: req(method),
  auth_time: req(time),
  idle_deadline: req(time),
  absolute_deadline: req(time),
});

export interface MeResponse {
  readonly user: UserView;
  readonly methods: MethodsView;
  readonly can_link_oidc: boolean;
  readonly sso_governed: boolean;
  readonly session: CurrentSessionView;
}
export const parseMeResponse: Validator<MeResponse> = object({
  user: req(parseUserView),
  methods: req(parseMethodsView),
  can_link_oidc: req(bool),
  sso_governed: req(bool),
  session: req(parseCurrentSessionView),
});

export interface RecoveryResponse {
  readonly username: string;
  readonly methods: MethodsView;
}
export const parseRecoveryResponse: Validator<RecoveryResponse> = object({
  username: req(str),
  methods: req(parseMethodsView),
});

/** A passkey whose rp_id differs from the current RP's ID cannot sign in. */
export interface PasskeyView {
  readonly id: number;
  readonly name: string;
  readonly created_at: string;
  readonly last_used_at?: string;
  readonly backup_eligible: boolean;
  readonly backed_up: boolean;
  readonly clone_warning?: boolean;
  readonly rp_id: string;
}
export const parsePasskeyView: Validator<PasskeyView> = object({
  id: req(id),
  name: req(str),
  created_at: req(time),
  last_used_at: opt(time),
  backup_eligible: req(bool),
  backed_up: req(bool),
  clone_warning: opt(bool),
  rp_id: req(str),
});

export interface SessionView {
  readonly id: string;
  readonly label?: string;
  readonly user_agent?: string;
  readonly last_ip?: string;
  readonly method: Method;
  readonly created_at: string;
  readonly last_activity: string;
  readonly auth_time: string;
  readonly idle_deadline: string;
  readonly absolute_deadline: string;
  readonly current: boolean;
}
export const parseSessionView: Validator<SessionView> = object({
  id: req(str),
  label: opt(str),
  user_agent: opt(str),
  last_ip: opt(str),
  method: req(method),
  created_at: req(time),
  last_activity: req(time),
  auth_time: req(time),
  idle_deadline: req(time),
  absolute_deadline: req(time),
  current: req(bool),
});

/** owner is set on the admin list only. */
export interface KeyView {
  readonly id: number;
  readonly user_id: number;
  readonly owner?: string;
  readonly label: string;
  readonly prefix: string;
  readonly suffix: string;
  readonly scopes: readonly string[];
  readonly created_at: string;
  readonly expires_at?: string;
  readonly last_used_at?: string;
  readonly parent_key_id?: number;
}
export const parseKeyView: Validator<KeyView> = object({
  id: req(id),
  user_id: req(id),
  owner: opt(str),
  label: req(str),
  prefix: req(str),
  suffix: req(str),
  scopes: req(strings),
  created_at: req(time),
  expires_at: opt(time),
  last_used_at: opt(time),
  parent_key_id: opt(id),
});

/** key is the plaintext, shown once. */
export interface KeyCreatedResponse {
  readonly key: string;
  readonly details: KeyView;
}
export const parseKeyCreatedResponse: Validator<KeyCreatedResponse> = object({
  key: req(str),
  details: req(parseKeyView),
});

/** token is the plaintext, shown once. */
export interface TokenResponse {
  readonly token: string;
  readonly expires_at: string;
}
export const parseTokenResponse: Validator<TokenResponse> = object({
  token: req(str),
  expires_at: req(time),
});

/** One live invite or recovery token; it carries neither the token nor its hash. */
export interface TokenView {
  readonly purpose: TokenPurpose;
  readonly role?: Role;
  readonly subject?: number;
  readonly created_at: string;
  readonly expires_at: string;
  readonly issued_by_key?: number;
  readonly issuer_lineage?: readonly number[];
}
export const parseTokenView: Validator<TokenView> = object({
  purpose: req(purpose),
  role: opt(role),
  subject: opt(id),
  created_at: req(time),
  expires_at: req(time),
  issued_by_key: opt(id),
  issuer_lineage: opt(ids),
});

/** @internal Go's account.LogClasses(), in its order. */
export const LOG_CLASSES = ["change", "session"] as const;
type LogClass = (typeof LOG_CLASSES)[number];
const logClass = oneOf(...LOG_CLASSES);

/** Who made a logged change, with the display data its commit snapshotted. */
export interface LogActorView {
  readonly user_id?: number;
  readonly session_id?: string;
  readonly key_id?: number;
  readonly out_of_band?: string;
  readonly label?: string;
  readonly user_agent?: string;
  readonly key_suffix?: string;
}
export const parseLogActorView: Validator<LogActorView> = object({
  user_id: opt(id),
  session_id: opt(str),
  key_id: opt(id),
  out_of_band: opt(str),
  label: opt(str),
  user_agent: opt(str),
  key_suffix: opt(str),
});

/** at is when the entry was appended; occurred_at is the change's own time. */
export interface LogEntryView {
  readonly seq: number;
  readonly at: string;
  readonly occurred_at: string;
  readonly class: LogClass;
  readonly kind: string;
  readonly user_id?: number;
  readonly actor: LogActorView;
  readonly ip?: string;
  readonly session_ids?: readonly string[];
  readonly key_id?: number;
  readonly passkey_id?: number;
  readonly method?: Method;
  readonly role?: Role;
  readonly trusted?: boolean;
  readonly detail?: string;
}
export const parseLogEntryView: Validator<LogEntryView> = object({
  seq: req(id),
  at: req(time),
  occurred_at: req(time),
  class: req(logClass),
  kind: req(nonEmpty),
  user_id: opt(id),
  actor: req(parseLogActorView),
  ip: opt(str),
  session_ids: opt(strings),
  key_id: opt(id),
  passkey_id: opt(id),
  method: opt(method),
  role: opt(role),
  trusted: opt(bool),
  detail: opt(str),
});

/** evicted counts the entries the size limit removed, ever. */
export interface LogClassView {
  readonly class: LogClass;
  readonly count: number;
  readonly evicted: number;
}
export const parseLogClassView: Validator<LogClassView> = object({
  class: req(logClass),
  count: req(count),
  evicted: req(count),
});

/** One security-log page; classes holds one row per LogClass, in LOG_CLASSES order. */
export interface SecurityLogView {
  readonly entries: readonly LogEntryView[];
  readonly classes: readonly LogClassView[];
}
export const parseSecurityLogView: Validator<SecurityLogView> = object({
  entries: req(list(parseLogEntryView)),
  classes: req(list(parseLogClassView)),
});

/** The arguments of PublicKeyCredential's two signal methods, in their own shape. */
export interface WebAuthnSignals {
  readonly currentUserDetails: {
    readonly rpId: string;
    readonly userId: string;
    readonly name: string;
    readonly displayName: string;
  };
  readonly allAcceptedCredentials: {
    readonly rpId: string;
    readonly userId: string;
    readonly allAcceptedCredentialIds: readonly string[];
  };
}
export const parseWebAuthnSignals: Validator<WebAuthnSignals> = object({
  currentUserDetails: req(
    object({ rpId: req(str), userId: req(base64url), name: req(str), displayName: req(str) }),
  ),
  allAcceptedCredentials: req(
    object({
      rpId: req(str),
      userId: req(base64url),
      allAcceptedCredentialIds: req(list(base64url)),
    }),
  ),
});

// Error codes and reasons.

/** accesshttp.Codes(), in its order. @internal */
export const CODES = [
  "auth_required",
  "auth_session_expired",
  "auth_invalid_credentials",
  "auth_key_invalid",
  "auth_recent_auth_required",
  "auth_session_required",
  "auth_scope_required",
  "auth_forbidden",
  "auth_rate_limited",
  "auth_busy",
  "auth_unavailable",
  "auth_bad_request",
  "auth_body_too_large",
  "auth_username_invalid",
  "auth_username_taken",
  "auth_password_rejected",
  "auth_breach_check_unavailable",
  "auth_password_login_disabled",
  "auth_setup_complete",
  "auth_setup_token_required",
  "auth_token_invalid",
  "auth_last_method",
  "auth_identity_taken",
  "auth_already_linked",
  "auth_method_not_locked",
  "auth_cross_origin",
  "auth_duplicate_credential",
  "auth_unknown_scope",
  "auth_passkeys_unavailable",
  "auth_origin_refused",
  "auth_ceremony_invalid",
  "auth_not_discoverable",
  "auth_unknown_credential",
  "auth_assertion_failed",
  "auth_registration_failed",
  "auth_oidc_unavailable",
  "auth_oidc_failed",
  "auth_not_found",
  "auth_method_not_allowed",
] as const;

/** Every code accesshttp answers, as accesshttp.Codes() lists them. */
export type AuthCode = (typeof CODES)[number];

/** accesshttp.Reasons(), in its order. @internal */
export const REASONS = [
  "sso_governed",
  "ttl_too_long",
  "ttl_negative",
  "no_change",
  "expiry_invalid",
  "redirect_too_long",
  "current_password_required",
  "session_gone",
  "pending_too_large",
  "stale_authentication",
  "flow_invalid",
  "discovery_failed",
  "exchange_failed",
  "token_invalid",
  "nonce_mismatch",
  "no_username",
  "provisioning_disabled",
  "not_admitted",
  "username_invalid",
  "recovery",
  "reenable_needs_other_method",
  "trailing_data",
  "malformed_json",
  "content_type",
  "body",
  "unknown_field",
  "token_in_query",
  "too_short",
  "too_long",
  "contains_username",
  "contains_forbidden_word",
  "common",
  "breached",
  "out_of_band_only",
  "key_not_current",
  "admin_target",
  "scopes_not_subset",
  "expiry_after_parent",
  "lineage_too_deep",
  "permission_not_admin",
  "self_recovery",
  "other_user",
  "target_not_eligible",
  "not_principal",
  "unknown_operation",
  "not_enabled_user",
  "not_admin",
  "self_delete",
  "last_admin",
  "last_local_admin",
  "single_owner",
  "not_owner",
  "unknown_via",
  "via_with_actor",
  "empty",
  "disallowed_character",
  "label_disallowed_character",
  "label_too_long",
  "display_name_disallowed_character",
  "display_name_too_long",
  "log_limit",
  "log_range",
  "log_kind",
  "log_id",
  "malformed",
  "trailing_dot",
  "empty_label",
  "non_ascii",
  "no_origin",
  "insecure_scheme",
  "ip_host",
  "host_not_covered",
  "not_allowlisted",
] as const;

/**
 * Every fixed reason accesshttp answers, as accesshttp.Reasons() lists them. A reason with a
 * dynamic part (provider_error:<code>, a refused field or key name) is outside the union.
 */
export type AuthReason = (typeof REASONS)[number];

const codeSet: ReadonlySet<string> = new Set(CODES);
const reasonSet: ReadonlySet<string> = new Set(REASONS);

// A server code is lifted only from a real error response; fetch's own codes carry status 0,
// or a 2xx status for "decode", and must never read as a server's.
function fromServer(e: ApiErr): boolean {
  return e.status >= 400 && e.status <= 599;
}

/** Returns undefined for a code outside the union, so a newer server code is never mistaken for a known one. */
export function authCode(e: ApiErr): AuthCode | undefined {
  return fromServer(e) && e.code !== undefined ? knownCode(e.code) : undefined;
}

/** The code when it is in the union, else undefined. @internal */
export function knownCode(c: string): AuthCode | undefined {
  return codeSet.has(c) ? (c as AuthCode) : undefined;
}

/**
 * The error body's non-empty reason, known or not: what a caller tests for presence.
 * @internal
 */
export function errorReason(e: ApiErr): string | undefined {
  if (!fromServer(e) || !isRecord(e.body) || !Object.hasOwn(e.body, "reason")) {
    return undefined;
  }
  const r = e.body["reason"];
  return typeof r === "string" && r !== "" ? r : undefined;
}

/** Returns undefined for a reason outside the union, as authCode does for codes. */
export function authReason(e: ApiErr): AuthReason | undefined {
  const r = errorReason(e);
  return r !== undefined && reasonSet.has(r) ? (r as AuthReason) : undefined;
}
