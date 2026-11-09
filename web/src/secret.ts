import { signal } from "@cplieger/reactive/signal";
import type { ReadonlySignal } from "@cplieger/reactive/signal";

/** A secret shown to the user once, such as a new API key or a recovery link. */
export interface ShownOnce {
  /** The plaintext until it is cleared, then null for good. */
  readonly value: ReadonlySignal<string | null>;
  /** Clears the value now; later calls do nothing. */
  dismiss(): void;
}

/**
 * Holds plaintext for display and clears it on dismiss, on the page's pagehide (so a page
 * restored from the back-forward cache shows nothing), and after clearAfterMs when given.
 * Throws unless clearAfterMs, when given, is a finite number greater than 0.
 */
export function shownOnce(plaintext: string, o?: { readonly clearAfterMs?: number }): ShownOnce {
  const after = o?.clearAfterMs;
  if (after !== undefined && !(Number.isFinite(after) && after > 0)) {
    throw new RangeError(`shownOnce: clearAfterMs must be a finite number above 0, got ${after}`);
  }
  const value = signal<string | null>(plaintext);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const dismiss = (): void => {
    clearTimeout(timer);
    globalThis.removeEventListener("pagehide", dismiss);
    value.value = null;
  };
  globalThis.addEventListener("pagehide", dismiss);
  if (after !== undefined) {
    timer = setTimeout(dismiss, after);
  }
  return {
    value: {
      get value() {
        return value.value;
      },
      peek: () => value.peek(),
    },
    dismiss,
  };
}
