import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { continuation, takeFragmentToken } from "./continuation.js";
import { RecordingStorage } from "./test-helpers/storage.js";

const PREFIX = "@cplieger/access:continue:";
const FOREIGN = "app:draft";
const T0 = new Date("2026-03-01T10:00:00Z").getTime();

let store: RecordingStorage;
let localTouched: string[];

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  store = new RecordingStorage();
  store.items.set(FOREIGN, "the app's own value");
  vi.stubGlobal("sessionStorage", store);
  localTouched = [];
  vi.stubGlobal(
    "localStorage",
    new Proxy({}, { get: (_t, k) => (localTouched.push(String(k)), undefined) }),
  );
});

afterEach(() => {
  vi.useRealTimers();
  expect(localTouched).toEqual([]);
  expect(store.keysUsed.filter((k) => !k.startsWith(PREFIX))).toEqual([]);
  expect(store.items.get(FOREIGN)).toBe("the app's own value");
});

const back = (nonce: string): string => `?continue=${nonce}&oidc=stepped_up`;
const stored = (): string[] => [...store.items.keys()].filter((k) => k.startsWith(PREFIX));

describe("continuation", () => {
  it("hands a value back once after a stepped_up return", () => {
    const value = { action: "revoke-others", args: [1, "a"] };
    const n = continuation.put(value, 60_000);
    expect(store.items.has(PREFIX + n)).toBe(true);
    expect(continuation.take(back(n))).toEqual(value);
    expect(continuation.take(back(n))).toBeUndefined();
    expect(stored()).toEqual([]);
  });

  it("reads the nonce wherever it sits in the query", () => {
    const n = continuation.put("x", 60_000);
    expect(continuation.take(`?oidc=stepped_up&tab=security&continue=${n}`)).toBe("x");
  });

  const refused: readonly (readonly [string, (n: string) => string])[] = [
    ["oidc=linked", (n) => `?continue=${n}&oidc=linked`],
    ["an auth_error", (n) => `?continue=${n}&auth_error=auth_oidc_failed`],
    ["an auth_error beside stepped_up", (n) => `${back(n)}&auth_error=auth_oidc_failed`],
    ["no marker", (n) => `?continue=${n}`],
    ["a repeated continue", (n) => `${back(n)}&continue=${n}`],
  ];
  for (const [what, search] of refused) {
    it(`gives undefined for ${what} and spends the nonce`, () => {
      const n = continuation.put("x", 60_000);
      expect(continuation.take(search(n))).toBeUndefined();
      expect(store.items.has(PREFIX + n)).toBe(false);
      expect(continuation.take(back(n))).toBeUndefined();
    });
  }

  it("gives undefined for an unknown or malformed nonce and leaves no entry for it", () => {
    const live = continuation.put("x", 60_000);
    const unknown = "A".repeat(22);
    expect(continuation.take(back(unknown))).toBeUndefined();
    store.items.set(`${PREFIX}short`, JSON.stringify({ v: "planted", exp: T0 + 60_000 }));
    expect(continuation.take(back("short"))).toBeUndefined();
    expect(stored()).toEqual([PREFIX + live]);
  });

  it("keeps an entry for exactly maxAgeMs and no longer", () => {
    const a = continuation.put("a", 1000);
    const b = continuation.put("b", 1000);
    vi.setSystemTime(T0 + 1000);
    expect(continuation.take(back(a))).toBe("a");
    vi.setSystemTime(T0 + 1001);
    expect(continuation.take(back(b))).toBeUndefined();
    expect(stored()).toEqual([]);
  });

  it("drops the expired entries of other nonces and keeps the live ones", () => {
    const old = continuation.put("old", 1000);
    vi.setSystemTime(T0 + 500);
    const live = continuation.put("live", 60_000);
    const spent = continuation.put("spent", 60_000);
    store.items.set(`${PREFIX}junk`, "not json");
    vi.setSystemTime(T0 + 2000);
    expect(continuation.take(back(spent))).toBe("spent");
    expect(stored()).toEqual([PREFIX + live]);
    expect(store.items.has(PREFIX + old)).toBe(false);
  });

  it("drops expired entries on a take that names no nonce", () => {
    continuation.put("old", 1000);
    vi.setSystemTime(T0 + 2000);
    expect(continuation.take("?oidc=stepped_up")).toBeUndefined();
    expect(stored()).toEqual([]);
  });

  it("makes distinct 22-character base64url nonces", () => {
    const a = continuation.put(1, 1000);
    const b = continuation.put(2, 1000);
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(b).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(a).not.toBe(b);
  });

  for (const [what, value] of [
    ["a BigInt", 1n],
    ["undefined", undefined],
    ["a function", () => 1],
  ] as const) {
    it(`throws for ${what} and stores nothing`, () => {
      expect(() => continuation.put(value, 1000)).toThrow(TypeError);
      expect(stored()).toEqual([]);
    });
  }

  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
    it(`throws for a maxAgeMs of ${String(bad)} and stores nothing`, () => {
      expect(() => continuation.put("x", bad)).toThrow(RangeError);
      expect(stored()).toEqual([]);
    });
  }

  it("takes nothing, and put throws, where sessionStorage is blocked", () => {
    // stubGlobal first, so the original descriptor is restored after the test.
    vi.stubGlobal("sessionStorage", undefined);
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      get: () => {
        throw new DOMException("blocked", "SecurityError");
      },
    });
    expect(continuation.take(back("A".repeat(22)))).toBeUndefined();
    expect(() => continuation.put("x", 1000)).toThrow(Error);
  });
});

describe("takeFragmentToken", () => {
  const original = location.pathname + location.search + location.hash;
  let replace: ReturnType<typeof vi.spyOn>;
  const at = (url: string): void => {
    history.replaceState(history.state, "", url);
    replace = vi.spyOn(history, "replaceState");
    replace.mockClear();
  };

  afterEach(() => {
    replace.mockRestore();
    history.replaceState(history.state, "", original);
  });

  it("returns the token and leaves the URL with no #", () => {
    at("/setup?x=1#token=abc");
    expect(takeFragmentToken("token")).toBe("abc");
    expect(location.hash).toBe("");
    expect(location.href.endsWith("/setup?x=1")).toBe(true);
    expect(replace).toHaveBeenCalledOnce();
  });

  it("keeps the other pairs", () => {
    at("/setup#a=1&token=abc&b=2");
    expect(takeFragmentToken("token")).toBe("abc");
    expect(location.hash).toBe("#a=1&b=2");
  });

  it("bounds the token in UTF-8 bytes and removes an oversize one", () => {
    at(`/r#token=${"a".repeat(512)}`);
    expect(takeFragmentToken("token")).toBe("a".repeat(512));
    at(`/r#token=${"a".repeat(513)}`);
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(location.hash).toBe("");
    at(`/r#token=${"%C3%A9".repeat(257)}`);
    expect(takeFragmentToken("token")).toBeUndefined();
    at(`/r#token=${"%C3%A9".repeat(2)}`);
    expect(takeFragmentToken("token", 4)).toBe("éé");
    at(`/r#token=${"%C3%A9".repeat(3)}`);
    expect(takeFragmentToken("token", 4)).toBeUndefined();
  });

  it("returns undefined and calls no replaceState for an absent name", () => {
    at("/r#a=1");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(replace).not.toHaveBeenCalled();
    at("/r");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(replace).not.toHaveBeenCalled();
  });

  it("removes an empty value and returns undefined", () => {
    at("/r#token=&a=1");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(location.hash).toBe("#a=1");
    at("/r#token");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(location.hash).toBe("");
  });

  it("refuses a repeated name and removes every copy", () => {
    at("/r#token=a&token=b");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(location.hash).toBe("");
  });

  it("refuses a value that does not decode, and removes it", () => {
    at("/r#token=%E0%A4%A");
    expect(takeFragmentToken("token")).toBeUndefined();
    expect(location.hash).toBe("");
  });

  it("decodes the value and keeps a +", () => {
    at("/r#token=a%2Fb+c");
    expect(takeFragmentToken("token")).toBe("a/b+c");
  });

  it("leaves no token in the history entry", () => {
    at("/invite?step=2#token=s3cret");
    const state: unknown = history.state;
    takeFragmentToken("token");
    const [, , url] = replace.mock.calls[0] ?? [];
    expect(String(url)).not.toContain("s3cret");
    expect(location.href).not.toContain("s3cret");
    expect(history.state).toBe(state);
  });
});
