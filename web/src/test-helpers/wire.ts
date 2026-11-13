/// <reference types="vite/client" />
import {
  parseCeremonyResponse,
  parseInviteAcceptRequest,
  parseInviteRequest,
  parseKeyCreatedResponse,
  parseKeyView,
  parseLoginRequest,
  parseMeResponse,
  parseNameRequest,
  parseNewKeyRequest,
  parseNewUserRequest,
  parseOIDCStartResponse,
  parsePasskeyView,
  parsePasswordChangeRequest,
  parsePasswordRemoveRequest,
  parsePasswordRequest,
  parsePendingLinkResponse,
  parseProfileRequest,
  parseRecoverPasswordRequest,
  parseRecoveryResponse,
  parseRedirectRequest,
  parseSecurityLogView,
  parseSessionView,
  parseSetupPasskeyBeginRequest,
  parseSetupPasswordRequest,
  parseSignedInResponse,
  parseStateResponse,
  parseTTLRequest,
  parseTokenRequest,
  parseTokenResponse,
  parseTokenView,
  parseUserUpdateRequest,
  parseUserView,
  parseWebAuthnSignals,
} from "../wire.js";
import type { Validator } from "../wire.js";

// Keyed by the Go type name the fixtures use (webauthn.Signals is "Signals"); wire.node.test.ts
// pins the keys against index.json in both directions.
export const validators: Readonly<Record<string, Validator<unknown>>> = {
  CeremonyResponse: parseCeremonyResponse,
  InviteAcceptRequest: parseInviteAcceptRequest,
  InviteRequest: parseInviteRequest,
  KeyCreatedResponse: parseKeyCreatedResponse,
  KeyView: parseKeyView,
  LoginRequest: parseLoginRequest,
  MeResponse: parseMeResponse,
  NameRequest: parseNameRequest,
  NewKeyRequest: parseNewKeyRequest,
  NewUserRequest: parseNewUserRequest,
  OIDCStartResponse: parseOIDCStartResponse,
  PasskeyView: parsePasskeyView,
  PasswordChangeRequest: parsePasswordChangeRequest,
  PasswordRemoveRequest: parsePasswordRemoveRequest,
  PasswordRequest: parsePasswordRequest,
  PendingLinkResponse: parsePendingLinkResponse,
  ProfileRequest: parseProfileRequest,
  RecoverPasswordRequest: parseRecoverPasswordRequest,
  RecoveryResponse: parseRecoveryResponse,
  RedirectRequest: parseRedirectRequest,
  SecurityLogView: parseSecurityLogView,
  SessionView: parseSessionView,
  SetupPasskeyBeginRequest: parseSetupPasskeyBeginRequest,
  SetupPasswordRequest: parseSetupPasswordRequest,
  Signals: parseWebAuthnSignals,
  SignedInResponse: parseSignedInResponse,
  StateResponse: parseStateResponse,
  TTLRequest: parseTTLRequest,
  TokenRequest: parseTokenRequest,
  TokenResponse: parseTokenResponse,
  TokenView: parseTokenView,
  UserUpdateRequest: parseUserUpdateRequest,
  UserView: parseUserView,
};

export function validatorFor(type: string): Validator<unknown> {
  if (!Object.hasOwn(validators, type)) {
    throw new Error(`no validator for wire type ${type}`);
  }
  const v = validators[type];
  if (v === undefined) {
    throw new Error(`no validator for wire type ${type}`);
  }
  return v;
}

const files = import.meta.glob<unknown>("../../testdata/wire/*.json", {
  eager: true,
  import: "default",
});

/** Every fixture, keyed by its file name without ".json" ("UserView", "NewUserRequest.noPassword"). */
export const fixtures: ReadonlyMap<string, unknown> = new Map(
  Object.entries(files).map(([path, value]) => [
    path.slice(path.lastIndexOf("/") + 1, -".json".length),
    value,
  ]),
);

export function fixture(name: string): unknown {
  if (!fixtures.has(name)) {
    throw new Error(`no fixture ${name}.json`);
  }
  return structuredClone(fixtures.get(name));
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function strings(name: string): readonly string[] {
  const v = fixture(name);
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
    throw new Error(`${name}.json is not a list of strings`);
  }
  return v;
}

export const index = strings("index");
export const codes = strings("codes");
export const reasons = strings("reasons");

/** queries.json: route name to the sorted query keys its Query struct declares. */
export const queries: ReadonlyMap<string, readonly string[]> = (() => {
  const v = fixture("queries");
  if (!isObject(v)) {
    throw new Error("queries.json is not an object");
  }
  return new Map(
    Object.entries(v).map(([k, keys]) => {
      if (!Array.isArray(keys) || !keys.every((x) => typeof x === "string")) {
        throw new Error(`queries.json ${k} is not a list of strings`);
      }
      return [k, keys];
    }),
  );
})();

export interface WireField {
  readonly name: string;
  readonly optional: boolean;
  /** The Go constants of the field's named string type. */
  readonly values?: readonly string[];
  /** The type also takes values outside its constants (app-defined). */
  readonly open: boolean;
  /** The fields of a struct-typed field, or of each element of a struct-list field. */
  readonly fields?: readonly WireField[];
}

function wireFields(at: string, fields: unknown): WireField[] {
  if (!Array.isArray(fields)) {
    throw new Error(`types.json ${at} is not a list`);
  }
  return fields.map((f: unknown) => {
    if (!isObject(f) || typeof f["name"] !== "string") {
      throw new Error(`types.json ${at} has a field without a name`);
    }
    const values = f["values"];
    if (
      values !== undefined &&
      (!Array.isArray(values) || !values.every((x: unknown) => typeof x === "string"))
    ) {
      throw new Error(`types.json ${at}.${f["name"]} has values that are not strings`);
    }
    if (f["open"] !== undefined && f["open"] !== true) {
      throw new Error(`types.json ${at}.${f["name"]} has an open marker that is not true`);
    }
    if (f["open"] === true && values === undefined) {
      throw new Error(`types.json ${at}.${f["name"]} has an open marker without values`);
    }
    return {
      name: f["name"],
      optional: f["optional"] === true,
      open: f["open"] === true,
      ...(values === undefined ? {} : { values }),
      ...(f["fields"] === undefined
        ? {}
        : { fields: wireFields(`${at}.${f["name"]}`, f["fields"]) }),
    };
  });
}

/** types.json: each index.json type's JSON fields, optional where Go may omit it. */
export const types: ReadonlyMap<string, readonly WireField[]> = (() => {
  const v = fixture("types");
  if (!isObject(v)) {
    throw new Error("types.json is not an object");
  }
  return new Map(Object.entries(v).map(([type, fields]) => [type, wireFields(type, fields)]));
})();

export interface WireRoute {
  readonly name: string;
  readonly method: string;
  readonly path: string;
  readonly kind: "json" | "redirect";
  readonly request: string | null;
  readonly response: string | null;
  readonly array: boolean;
}

/** routes.json: accesshttp's route table, paths under {prefix} or {oidcPrefix}. */
export const routes: readonly WireRoute[] = (() => {
  const v = fixture("routes");
  if (!Array.isArray(v)) {
    throw new Error("routes.json is not a list");
  }
  return v.map((r: unknown): WireRoute => {
    const nullableString = (x: unknown): x is string | null => x === null || typeof x === "string";
    if (
      !isObject(r) ||
      typeof r["name"] !== "string" ||
      typeof r["method"] !== "string" ||
      typeof r["path"] !== "string" ||
      (r["kind"] !== "json" && r["kind"] !== "redirect") ||
      !nullableString(r["request"]) ||
      !nullableString(r["response"]) ||
      typeof r["array"] !== "boolean"
    ) {
      throw new Error(`routes.json has a malformed row: ${JSON.stringify(r)}`);
    }
    return {
      name: r["name"],
      method: r["method"],
      path: r["path"],
      kind: r["kind"],
      request: r["request"],
      response: r["response"],
      array: r["array"],
    };
  });
})();
