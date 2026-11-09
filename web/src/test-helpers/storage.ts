import { afterEach, beforeEach, expect, vi } from "vitest";

function trap(name: string, touched: string[]): unknown {
  return new Proxy(
    {},
    {
      get: (_t, k) => {
        touched.push(`${name}.${String(k)}`);
        return undefined;
      },
      set: (_t, k) => {
        touched.push(`${name}.${String(k)}=`);
        return true;
      },
    },
  );
}

/**
 * Replaces sessionStorage and localStorage with traps for every test of the calling file, and
 * fails a test after which either was read or written: only continuation.ts may use storage.
 */
export function forbidStorage(): void {
  let touched: string[] = [];
  beforeEach(() => {
    touched = [];
    vi.stubGlobal("sessionStorage", trap("sessionStorage", touched));
    vi.stubGlobal("localStorage", trap("localStorage", touched));
  });
  afterEach(() => {
    expect(touched, "storage touched outside continuation.ts").toEqual([]);
  });
}

/** A sessionStorage stand-in recording every key the code reads, writes or removes. */
export class RecordingStorage implements Storage {
  readonly items = new Map<string, string>();
  readonly keysUsed: string[] = [];

  get length(): number {
    return this.items.size;
  }
  key(i: number): string | null {
    return [...this.items.keys()][i] ?? null;
  }
  getItem(k: string): string | null {
    this.keysUsed.push(k);
    return this.items.get(k) ?? null;
  }
  setItem(k: string, v: string): void {
    this.keysUsed.push(k);
    this.items.set(k, v);
  }
  removeItem(k: string): void {
    this.keysUsed.push(k);
    this.items.delete(k);
  }
  clear(): void {
    throw new Error("clear() would drop every key, the app's own included");
  }
  [name: string]: unknown;
}
