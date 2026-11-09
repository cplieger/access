import type { ApiResult } from "@cplieger/reactive/fetch";
import { signal } from "@cplieger/reactive/signal";
import type { ReadonlySignal } from "@cplieger/reactive/signal";
import type { AuthClient } from "./client.js";
import type { SessionView } from "./wire.js";

/** The signed-in user's device list and the calls that change it. */
export interface SessionsModel {
  /** Empty until the first successful refresh. */
  readonly sessions: ReadonlySignal<readonly SessionView[]>;
  /** Replaces the list with the server's; a refusal leaves the list as it was. */
  refresh(): Promise<ApiResult<void>>;
  revoke(id: string): Promise<ApiResult<void>>;
  revokeOthers(): Promise<ApiResult<void>>;
  /** An empty label clears the session's label. */
  rename(id: string, label: string): Promise<ApiResult<void>>;
}

/**
 * A device-list model over c. Each change applies to the list only after the server accepts
 * it, by the rule the server applied, so the list needs no refresh after a change.
 */
export function createSessionsModel(c: AuthClient): SessionsModel {
  const list = signal<readonly SessionView[]>([]);
  const after = async (
    call: Promise<ApiResult<void>>,
    apply: (s: readonly SessionView[]) => readonly SessionView[],
  ): Promise<ApiResult<void>> => {
    const res = await call;
    if (res.ok) {
      list.value = apply(list.peek());
    }
    return res;
  };
  return {
    sessions: {
      get value() {
        return list.value;
      },
      peek: () => list.peek(),
    },
    refresh: async () => {
      const res = await c.sessions();
      if (!res.ok) {
        return res;
      }
      list.value = res.data;
      return { ...res, data: undefined };
    },
    revoke: (id) => after(c.revokeSession(id), (s) => s.filter((x) => x.id !== id)),
    revokeOthers: () => after(c.revokeOtherSessions(), (s) => s.filter((x) => x.current)),
    rename: (id, label) =>
      after(c.renameSession(id, { name: label }), (s) =>
        s.map((x) => {
          if (x.id !== id) {
            return x;
          }
          const { label: _old, ...rest } = x;
          return label === "" ? rest : { ...rest, label };
        }),
      ),
  };
}
