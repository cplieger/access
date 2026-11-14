import type { ApiErr } from "@cplieger/reactive/fetch";
import { describe, expect, it } from "vitest";
import {
  codes,
  fixture,
  fixtures,
  index,
  isObject,
  reasons,
  types,
  validatorFor,
  validators,
} from "./test-helpers/wire.js";
import type { WireField } from "./test-helpers/wire.js";
import {
  CODES,
  LOG_CLASSES,
  METHODS,
  REASONS,
  ROLES,
  TOKEN_PURPOSES,
  authCode,
  authReason,
  errorReason,
  parseCeremonyResponse,
  parseKeyView,
  parseSecurityLogView,
  parseUserView,
} from "./wire.js";

const META = new Set(["index", "codes", "reasons", "queries", "types", "routes"]);

function typeOf(name: string): string {
  const dot = name.indexOf(".");
  return dot === -1 ? name : name.slice(0, dot);
}

function fieldsOf(type: string): readonly WireField[] {
  const f = types.get(type);
  if (f === undefined) {
    throw new Error(`types.json has no ${type}`);
  }
  return f;
}

function without(v: unknown, key: string): Record<string, unknown> {
  if (!isObject(v)) {
    throw new Error("fixture is not an object");
  }
  const { [key]: _dropped, ...rest } = v;
  return rest;
}

// Every path to a JSON object below v, except inside public_key, whose WebAuthn options are
// the browser's shape and drop an unknown member rather than refuse it.
function objectPaths(v: unknown, at: readonly (string | number)[] = []): (string | number)[][] {
  if (Array.isArray(v)) {
    return v.flatMap((x: unknown, i) => objectPaths(x, [...at, i]));
  }
  if (!isObject(v)) {
    return [];
  }
  return [
    [...at],
    ...Object.entries(v).flatMap(([k, x]) =>
      k === "public_key" ? [] : objectPaths(x, [...at, k]),
    ),
  ];
}

function withExtra(v: unknown, path: readonly (string | number)[]): unknown {
  const copy: unknown = structuredClone(v);
  let target: unknown = copy;
  for (const step of path) {
    target = (target as Record<string | number, unknown>)[step];
  }
  (target as Record<string, unknown>)["unexpected"] = 1;
  return copy;
}

interface FieldSite {
  readonly path: readonly (string | number)[];
  readonly optional: boolean;
}

// Every field types.json lists for v, at any depth, by its path in v; a list field's rows
// apply to each of its elements.
function fieldSites(
  rows: readonly WireField[],
  v: unknown,
  at: readonly (string | number)[] = [],
): FieldSite[] {
  if (!isObject(v)) {
    return [];
  }
  return rows.flatMap((row) => {
    const path = [...at, row.name];
    const x = v[row.name];
    const fields = row.fields;
    const below =
      fields === undefined
        ? []
        : Array.isArray(x)
          ? x.flatMap((e: unknown, i) => fieldSites(fields, e, [...path, i]))
          : fieldSites(fields, x, path);
    return [{ path, optional: row.optional }, ...below];
  });
}

function withoutAt(v: unknown, path: readonly (string | number)[]): unknown {
  const copy: unknown = structuredClone(v);
  let target = copy as Record<string | number, unknown>;
  for (const step of path.slice(0, -1)) {
    target = target[step] as Record<string | number, unknown>;
  }
  Reflect.deleteProperty(target, path[path.length - 1] as string | number);
  return copy;
}

function err(status: number, code?: string, body?: unknown): ApiErr {
  return {
    ok: false,
    status,
    error: "x",
    ...(code === undefined ? {} : { code }),
    ...(body === undefined ? {} : { body }),
  };
}

describe("wire fixtures", () => {
  it("has one validator per Go wire type, and a type for every fixture", () => {
    expect(Object.keys(validators).sort()).toEqual([...index].sort());
    expect([...types.keys()].sort()).toEqual([...index].sort());
    for (const name of fixtures.keys()) {
      if (!META.has(name)) {
        expect(index, `${name}.json`).toContain(typeOf(name));
      }
    }
    expect(() => validatorFor("constructor")).toThrow("no validator");
  });

  it.each([...index])("%s: the fixture decodes to an equal, fresh value", (type) => {
    const f = fixture(type);
    const out = validatorFor(type)(f);
    expect(out).toEqual(f);
    expect(out).not.toBe(f);
  });

  it.each([...index])("%s: the fixture sets exactly the fields Go declares", (type) => {
    const f = fixture(type);
    expect(isObject(f)).toBe(true);
    expect(Object.keys(f as object).sort()).toEqual(
      fieldsOf(type)
        .map((x) => x.name)
        .sort(),
    );
  });

  it.each([...index])("%s: an unknown field is refused at every level", (type) => {
    const f = fixture(type);
    const paths = objectPaths(f);
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      expect(validatorFor(type)(withExtra(f, path)), path.join(".")).toBeUndefined();
    }
  });

  it.each([...index])(
    "%s: a missing required field at any depth is refused, a missing optional one is not",
    (type) => {
      const f = fixture(type);
      const sites = fieldSites(fieldsOf(type), f);
      expect(sites.length).toBeGreaterThanOrEqual(fieldsOf(type).length);
      for (const { path, optional } of sites) {
        const out = validatorFor(type)(withoutAt(f, path));
        if (optional) {
          expect(out, path.join(".")).toEqual(withoutAt(f, path));
        } else {
          expect(out, path.join(".")).toBeUndefined();
        }
      }
    },
  );

  const variants = [...fixtures.keys()].filter((n) => !META.has(n) && n.includes("."));

  it("has the four absent-optional variants", () => {
    expect(variants.sort()).toEqual([
      "NewUserRequest.noPassword",
      "PasswordChangeRequest.noCurrent",
      "SetupPasskeyBeginRequest.noToken",
      "SetupPasswordRequest.noToken",
    ]);
  });

  it.each(variants)(
    "%s validates, omits only optional fields, and needs its required ones",
    (name) => {
      const type = typeOf(name);
      const f = fixture(name);
      expect(validatorFor(type)(f)).toEqual(f);
      const present = new Set(Object.keys(f as object));
      for (const { name: field, optional } of fieldsOf(type)) {
        if (!present.has(field)) {
          expect(optional, field).toBe(true);
        } else if (!optional) {
          expect(validatorFor(type)(without(f, field)), field).toBeUndefined();
        }
      }
    },
  );

  it.each(["SetupPasswordRequest.noToken", "PasswordChangeRequest.noCurrent"])(
    "%s without password is refused",
    (name) => {
      expect(validatorFor(typeOf(name))(without(fixture(name), "password"))).toBeUndefined();
    },
  );

  it("refuses a NewUserRequest whose password is not a string", () => {
    const f = { ...(fixture("NewUserRequest.noPassword") as object), password: 7 };
    expect(validatorFor("NewUserRequest")(f)).toBeUndefined();
  });
});

interface EnumSite {
  readonly path: readonly (string | number)[];
  // The types.json row's path: path without list indexes.
  readonly row: string;
  readonly values: readonly string[];
  readonly open: boolean;
}

// Every field of v that types.json gives a value set, at any depth, by its path in v.
function enumSites(
  rows: readonly WireField[],
  v: unknown,
  at: readonly (string | number)[] = [],
): EnumSite[] {
  if (!isObject(v)) {
    return [];
  }
  return rows.flatMap((row) => {
    const x = v[row.name];
    const path = [...at, row.name];
    const here =
      row.values === undefined
        ? []
        : [{ path, row: rowOf(path), values: row.values, open: row.open }];
    const fields = row.fields;
    if (fields === undefined) {
      return here;
    }
    const below = Array.isArray(x)
      ? x.flatMap((e: unknown, i) => enumSites(fields, e, [...path, i]))
      : enumSites(fields, x, path);
    return [...here, ...below];
  });
}

function rowOf(path: readonly (string | number)[]): string {
  return path.filter((p) => typeof p === "string").join(".");
}

// Every types.json row with a value set, at any depth.
function enumRows(rows: readonly WireField[], at = ""): string[] {
  return rows.flatMap((row) => {
    const here = at === "" ? row.name : `${at}.${row.name}`;
    return [...(row.values === undefined ? [] : [here]), ...enumRows(row.fields ?? [], here)];
  });
}

function withValue(v: unknown, path: readonly (string | number)[], value: unknown): unknown {
  const copy: unknown = structuredClone(v);
  let target = copy as Record<string | number, unknown>;
  for (const step of path.slice(0, -1)) {
    target = target[step] as Record<string | number, unknown>;
  }
  target[path[path.length - 1] as string | number] = value;
  return copy;
}

describe("value sets", () => {
  const sites = new Map(index.map((t) => [t, enumSites(fieldsOf(t), fixture(t))]));
  const known: readonly (readonly string[])[] = [ROLES, METHODS, TOKEN_PURPOSES, LOG_CLASSES];

  it.each(index)("%s: a fixture reaches every value set types.json lists", (type) => {
    const reached = new Set((sites.get(type) ?? []).map((x) => x.row));
    expect(enumRows(fieldsOf(type)).filter((row) => !reached.has(row))).toEqual([]);
  });

  it("each value set is one of wire.ts's constant lists, and each list is a value set", () => {
    const sets = [...sites.values()].flat().map((x) => x.values);
    expect(sets.length).toBeGreaterThan(0);
    for (const values of sets) {
      expect(known, values.join(",")).toContainEqual(values);
    }
    for (const list of known) {
      expect(sets, list.join(",")).toContainEqual(list);
    }
  });

  const typed = index.filter((t) => (sites.get(t) ?? []).length > 0);

  it.each(typed)(
    "%s: each enum field takes Go's values, and an unknown one exactly when open",
    (type) => {
      const f = fixture(type);
      for (const { path, values, open } of sites.get(type) ?? []) {
        const at = path.join(".");
        for (const value of values) {
          const v = withValue(f, path, value);
          expect(validatorFor(type)(v), `${at} = ${value}`).toEqual(v);
        }
        const v = withValue(f, path, "app_defined");
        expect(validatorFor(type)(v), `${at} = app_defined, open ${open}`).toEqual(
          open ? v : undefined,
        );
        for (const value of ["", 0, null, ["admin"]]) {
          expect(
            validatorFor(type)(withValue(f, path, value)),
            `${at} = ${JSON.stringify(value)}`,
          ).toBeUndefined();
        }
      }
    },
  );
});

describe("field narrowing", () => {
  const user = fixture("UserView") as Record<string, unknown>;

  it.each([0, -1, 1.5, 2 ** 53, "7", null])("refuses the user ID %s", (id) => {
    expect(parseUserView({ ...user, id })).toBeUndefined();
  });

  it.each(["2026-01-02", "2026-01-02 03:04:05Z", "2026-13-02T03:04:05Z", 0])(
    "refuses the time %s",
    (created_at) => {
      expect(parseUserView({ ...user, created_at })).toBeUndefined();
    },
  );

  it("accepts fractional seconds and an offset", () => {
    const created_at = "2026-01-02T03:04:05.123456789+02:00";
    expect(parseUserView({ ...user, created_at })).toEqual({ ...user, created_at });
  });

  it("narrows every array element", () => {
    expect(parseUserView({ ...user, key_lineage: [3, "5"] })).toBeUndefined();
    expect(parseUserView({ ...user, key_lineage: {} })).toBeUndefined();
    const key = fixture("KeyView") as Record<string, unknown>;
    expect(parseKeyView({ ...key, scopes: ["read", 1] })).toBeUndefined();
  });

  it("reads a key's previous_until and refuses one that is not a time", () => {
    const key = fixture("KeyView") as Record<string, unknown>;
    expect(parseKeyView(key)?.previous_until).toBe(key["previous_until"]);
    expect(parseKeyView({ ...key, previous_until: "soon" })).toBeUndefined();
  });

  it("reads only own fields", () => {
    const inherited = Object.assign(Object.create({ name: "x" }) as object, {});
    expect(validatorFor("NameRequest")(inherited)).toBeUndefined();
  });

  it.each([null, [], "x", 1, true, undefined])("refuses %s as an object", (v) => {
    for (const type of index) {
      expect(validatorFor(type)(v), type).toBeUndefined();
    }
  });
});

describe("SecurityLogView", () => {
  const page = fixture("SecurityLogView") as Record<string, unknown>;

  it("LOG_CLASSES is each class value set types.json lists, in order", () => {
    const sets = enumSites(fieldsOf("SecurityLogView"), page)
      .filter((x) => x.path[x.path.length - 1] === "class")
      .map((x) => x.values);
    expect(sets.length).toBeGreaterThanOrEqual(2);
    for (const values of sets) {
      expect(values).toEqual([...LOG_CLASSES]);
    }
  });

  it("takes an empty page", () => {
    const empty = { ...page, entries: [] };
    expect(parseSecurityLogView(empty)).toEqual(empty);
  });

  it.each(["entries", "classes"])("refuses %s as null", (key) => {
    expect(parseSecurityLogView({ ...page, [key]: null })).toBeUndefined();
  });

  it.each([0, -1, 1.5, 2 ** 53, "42"])("refuses the entry seq %s", (seq) => {
    const entry = (page["entries"] as Record<string, unknown>[])[0];
    expect(parseSecurityLogView({ ...page, entries: [{ ...entry, seq }] })).toBeUndefined();
  });

  it.each([-1, 1.5, 2 ** 53])("refuses the class count or evicted %s", (n) => {
    const classes = page["classes"] as Record<string, unknown>[];
    for (const key of ["count", "evicted"]) {
      const v = { ...page, classes: [{ ...classes[0], [key]: n }, ...classes.slice(1)] };
      expect(parseSecurityLogView(v), key).toBeUndefined();
    }
  });
});

describe("CeremonyResponse.public_key", () => {
  const creation = {
    publicKey: {
      challenge: "Y2hhbGxlbmdl",
      rp: { name: "App", id: "app.example.com" },
      user: { id: "aGFuZGxl", name: "alice", displayName: "Alice" },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      excludeCredentials: [{ id: "Y3JlZA", type: "public-key", transports: ["internal"] }],
      extensions: { credProps: true },
      timeout: 60000,
    },
  };

  it("narrows creation options", () => {
    expect(parseCeremonyResponse({ ceremony: "c", public_key: creation })).toEqual({
      ceremony: "c",
      public_key: creation,
    });
  });

  it("fills an omitted pubKeyCredParams with an empty list", () => {
    const { pubKeyCredParams: _p, ...rest } = creation.publicKey;
    const out = parseCeremonyResponse({ ceremony: "c", public_key: { publicKey: rest } });
    expect(out?.public_key.publicKey).toEqual({ ...rest, pubKeyCredParams: [] });
  });

  it("drops an option member it does not know", () => {
    const publicKey = { ...creation.publicKey, futureOption: 1 };
    const out = parseCeremonyResponse({ ceremony: "c", public_key: { publicKey } });
    expect(out?.public_key).toEqual(creation);
  });

  it.each([
    ["a non-base64url challenge", { challenge: "a+b/" }],
    ["an impossible base64url length", { challenge: "abcde" }],
    ["a user without an id", { user: { name: "a", displayName: "A" } }],
    [
      "an algorithm that is not an integer",
      { pubKeyCredParams: [{ alg: "-7", type: "public-key" }] },
    ],
    ["a credential type other than public-key", { pubKeyCredParams: [{ alg: -7, type: "x" }] }],
    [
      "a resident-key value outside the spec",
      { authenticatorSelection: { residentKey: "always" } },
    ],
    ["a largeBlob extension", { extensions: { largeBlob: { support: "required" } } }],
    ["a prf extension", { extensions: { prf: {} } }],
    ["a negative timeout", { timeout: -1 }],
  ])("refuses creation options with %s", (_name, change) => {
    const publicKey = { ...creation.publicKey, ...change };
    expect(parseCeremonyResponse({ ceremony: "c", public_key: { publicKey } })).toBeUndefined();
  });

  it.each(["optional", "conditional"])("keeps request options with mediation %s", (mediation) => {
    const public_key = { publicKey: { challenge: "Y2g", allowCredentials: [] }, mediation };
    expect(parseCeremonyResponse({ ceremony: "c", public_key })).toEqual({
      ceremony: "c",
      public_key,
    });
  });

  it.each(["immediate", 1, null])("refuses the mediation %s", (mediation) => {
    const public_key = { publicKey: { challenge: "Y2g" }, mediation };
    expect(parseCeremonyResponse({ ceremony: "c", public_key })).toBeUndefined();
  });

  it("refuses a missing publicKey", () => {
    expect(parseCeremonyResponse({ ceremony: "c", public_key: {} })).toBeUndefined();
    expect(parseCeremonyResponse({ ceremony: "c", public_key: [] })).toBeUndefined();
  });
});

describe("AuthCode", () => {
  it("is codes.json, in access.Codes() order", () => {
    expect([...CODES]).toEqual(codes);
  });

  it.each([...codes])("lifts %s from a server error", (code) => {
    expect(authCode(err(400, code))).toBe(code);
  });

  it.each(["constructor", "toString", "__proto__", "hasOwnProperty", "auth_newer_code", ""])(
    "gives undefined for %s",
    (code) => {
      expect(authCode(err(400, code))).toBeUndefined();
    },
  );

  it("gives undefined for the fetch instance's own failures", () => {
    expect(authCode(err(0, "auth_required"))).toBeUndefined();
    expect(authCode(err(200, "auth_required"))).toBeUndefined();
    expect(authCode(err(600, "auth_required"))).toBeUndefined();
    expect(authCode(err(401))).toBeUndefined();
  });
});

describe("AuthReason", () => {
  it("is reasons.json, in accesshttp.Reasons() order", () => {
    expect([...REASONS]).toEqual(reasons);
  });

  it.each([...reasons])("lifts %s from a server error body", (reason) => {
    expect(authReason(err(400, "auth_bad_request", { code: "auth_bad_request", reason }))).toBe(
      reason,
    );
  });

  it("reads an open reason as present but not known", () => {
    const e = err(400, "auth_oidc_failed", { reason: "provider_error:access_denied" });
    expect(errorReason(e)).toBe("provider_error:access_denied");
    expect(authReason(e)).toBeUndefined();
  });

  it.each([
    ["status 0", err(0, undefined, { reason: "session_gone" })],
    ["a 2xx decode failure", err(200, "decode", { reason: "session_gone" })],
    ["no body", err(401, "auth_session_expired")],
    ["a body that is a list", err(401, "auth_session_expired", ["session_gone"])],
    ["an empty reason", err(403, "auth_recent_auth_required", { reason: "" })],
    ["a reason that is not a string", err(403, "auth_recent_auth_required", { reason: 1 })],
    [
      "an inherited reason",
      err(403, "auth_recent_auth_required", Object.create({ reason: "session_gone" }) as object),
    ],
  ])("gives undefined for %s", (_name, e) => {
    expect(errorReason(e)).toBeUndefined();
    expect(authReason(e)).toBeUndefined();
  });

  it("gives undefined for an inherited name", () => {
    expect(authReason(err(400, "auth_bad_request", { reason: "constructor" }))).toBeUndefined();
    expect(errorReason(err(400, "auth_bad_request", { reason: "constructor" }))).toBe(
      "constructor",
    );
  });
});
