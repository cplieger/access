import { effect } from "@cplieger/reactive/signal";
import { afterEach, describe, expect, it, vi } from "vitest";
import { shownOnce } from "./secret.js";
import { forbidStorage } from "./test-helpers/storage.js";

forbidStorage();

afterEach(() => {
  vi.useRealTimers();
});

describe("shownOnce", () => {
  it("holds the plaintext until dismissed, then null for good", () => {
    const s = shownOnce("ak_secret");
    expect(s.value.value).toBe("ak_secret");
    s.dismiss();
    expect(s.value.value).toBeNull();
    s.dismiss();
    expect(s.value.peek()).toBeNull();
  });

  it("clears on pagehide", () => {
    const s = shownOnce("ak_secret");
    globalThis.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
    expect(s.value.value).toBeNull();
  });

  it("clears after clearAfterMs and not before", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const s = shownOnce("ak_secret", { clearAfterMs: 1000 });
    vi.advanceTimersByTime(999);
    expect(s.value.value).toBe("ak_secret");
    vi.advanceTimersByTime(1);
    expect(s.value.value).toBeNull();
  });

  it("keeps the value with no clearAfterMs however long it waits", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const s = shownOnce("ak_secret");
    vi.advanceTimersByTime(24 * 60 * 60 * 1000);
    expect(s.value.value).toBe("ak_secret");
  });

  it("stops listening and timing once dismissed", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const remove = vi.spyOn(globalThis, "removeEventListener");
    const s = shownOnce("ak_secret", { clearAfterMs: 1000 });
    s.dismiss();
    expect(remove).toHaveBeenCalledWith("pagehide", expect.any(Function));
    expect(vi.getTimerCount()).toBe(0);
  });

  it("notifies a reader that tracks the value", () => {
    const s = shownOnce("ak_secret");
    const seen: (string | null)[] = [];
    const stop = effect(() => {
      seen.push(s.value.value);
    });
    s.dismiss();
    stop();
    expect(seen).toEqual(["ak_secret", null]);
  });

  it("offers no way to write the value back", () => {
    const s = shownOnce("ak_secret");
    expect(() => {
      (s.value as { value: string | null }).value = "other";
    }).toThrow(TypeError);
    expect(s.value.value).toBe("ak_secret");
  });

  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
    it(`throws for a clearAfterMs of ${String(bad)}`, () => {
      const add = vi.spyOn(globalThis, "addEventListener");
      expect(() => shownOnce("ak_secret", { clearAfterMs: bad })).toThrow(RangeError);
      expect(add).not.toHaveBeenCalled();
    });
  }
});
