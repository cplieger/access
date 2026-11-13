import { readOIDCReturn } from "./oidc.js";

const PREFIX = "@cplieger/access:continue:";
const NONCE = /^[A-Za-z0-9_-]{22}$/;

function storage(): Storage | undefined {
  try {
    return (globalThis as { readonly sessionStorage?: Storage }).sessionStorage;
  } catch {
    // The getter itself throws SecurityError where storage is blocked
    // (https://html.spec.whatwg.org/multipage/webstorage.html#dom-sessionstorage).
    return undefined;
  }
}

function nonce(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...b))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Undefined for an entry this module did not write.
function entry(raw: string | null): { readonly exp: number; readonly v: unknown } | undefined {
  if (raw === null) {
    return undefined;
  }
  let e: unknown;
  try {
    e = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!isRecord(e) || typeof e["exp"] !== "number" || !Object.hasOwn(e, "v")) {
    return undefined;
  }
  return { exp: e["exp"], v: e["v"] };
}

function dropExpired(s: Storage, now: number): void {
  const keys: string[] = [];
  for (let i = 0; i < s.length; i++) {
    const k = s.key(i);
    if (k?.startsWith(PREFIX) === true) {
      keys.push(k);
    }
  }
  for (const k of keys) {
    const e = entry(s.getItem(k));
    if (e === undefined || now > e.exp) {
      s.removeItem(k);
    }
  }
}

/** The same-origin half of an OIDC step-up's continuation, kept per tab in sessionStorage. */
export const continuation: {
  /**
   * Stores value (JSON-serialisable) under a fresh 128-bit base64url nonce for at most
   * maxAgeMs, and returns the nonce, which the app puts in its startOIDC redirect as
   * continue=<nonce>. Throws, storing nothing, unless maxAgeMs is a finite number greater than
   * 0 and JSON.stringify can serialise value.
   */
  put(value: unknown, maxAgeMs: number): string;
  /**
   * Reads search (location.search). Returns the stored value once, only when the oidc marker
   * is stepped_up and continue names a known, unspent, unexpired nonce; otherwise undefined.
   * Every call that names a nonce spends it, whatever it returns, and drops every expired
   * entry.
   */
  take(search: string): unknown;
} = {
  put(value, maxAgeMs) {
    if (!(Number.isFinite(maxAgeMs) && maxAgeMs > 0)) {
      throw new RangeError("continuation.put: maxAgeMs must be a finite number above 0");
    }
    if ((JSON.stringify(value) as string | undefined) === undefined) {
      throw new TypeError("continuation.put: value has no JSON form");
    }
    const record = JSON.stringify({ v: value, exp: Date.now() + maxAgeMs });
    const s = storage();
    if (s === undefined) {
      throw new Error("continuation.put: sessionStorage is unavailable");
    }
    const n = nonce();
    s.setItem(PREFIX + n, record);
    return n;
  },

  take(search) {
    const s = storage();
    if (s === undefined) {
      return undefined;
    }
    const now = Date.now();
    const named = new URLSearchParams(search).getAll("continue");
    const found = named.map((n) => {
      const k = PREFIX + n;
      const e = entry(s.getItem(k));
      s.removeItem(k);
      return e;
    });
    dropExpired(s, now);
    const [only] = named;
    const [e] = found;
    if (
      named.length !== 1 ||
      only === undefined ||
      !NONCE.test(only) ||
      e === undefined ||
      now > e.exp ||
      readOIDCReturn(search).kind !== "stepped_up"
    ) {
      return undefined;
    }
    return e.v;
  },
};

function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

function decode(s: string): string | undefined {
  try {
    return decodeURIComponent(s);
  } catch {
    return undefined;
  }
}

/**
 * Reads name from location.hash's key=value pairs, removes every pair named name with
 * history.replaceState (and the "#" when none is left), and returns the value when name
 * appears exactly once and its value is non-empty and at most maxBytes UTF-8 bytes; otherwise
 * undefined. The pairs are removed in every case, so no token stays in the URL or in this
 * history entry; an entry the browser recorded elsewhere before the call is out of its reach.
 */
export function takeFragmentToken(name: string, maxBytes = 512): string | undefined {
  const hash = globalThis.location.hash;
  if (hash.length <= 1) {
    return undefined;
  }
  const pairs = hash.slice(1).split("&");
  const values: (string | undefined)[] = [];
  const kept: string[] = [];
  for (const p of pairs) {
    const eq = p.indexOf("=");
    const key = eq === -1 ? p : p.slice(0, eq);
    if (decode(key) === name) {
      values.push(eq === -1 ? "" : decode(p.slice(eq + 1)));
    } else {
      kept.push(p);
    }
  }
  if (values.length === 0) {
    return undefined;
  }
  const { pathname, search } = globalThis.location;
  history.replaceState(
    history.state,
    "",
    pathname + search + (kept.length === 0 ? "" : `#${kept.join("&")}`),
  );
  const [v] = values;
  return values.length === 1 && v !== undefined && v !== "" && utf8Length(v) <= maxBytes
    ? v
    : undefined;
}
