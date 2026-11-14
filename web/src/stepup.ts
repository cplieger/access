import type { ApiErr, ApiResult } from "@cplieger/reactive/fetch";
import type { AuthClient } from "./client.js";
import { assign } from "./navigate.js";
import { startOIDC } from "./oidc.js";
import { stepUpWithPasskey } from "./webauthn.js";
import type { StepUpOutcome } from "./webauthn.js";
import { authCode, errorReason } from "./wire.js";
import type { MeResponse } from "./wire.js";

/** Asks the user how to re-authenticate, given the methods the account holds. */
export type StepUpPrompt = (
  methods: MeResponse["methods"],
) => Promise<"password" | "passkey" | "oidc" | "cancel">;

export interface StepUpOptions {
  readonly prompt: StepUpPrompt;
  /** The user's current password, or null when the user cancels. */
  readonly password: () => Promise<string | null>;
  /**
   * Where an OIDC step-up returns: the app's own relative path, at most 512 bytes, in which
   * the app encodes what to continue. Default location.pathname + location.search, or
   * location.pathname, or "/", the first that fits 512 bytes counted in UTF-8.
   */
  readonly redirect?: string;
  /** Default location.assign. */
  readonly navigate?: (url: string) => void;
  /**
   * Runs a fresh sign-in for a refusal with reason sign_in_again, which a plain session gets
   * in place of a step-up; true when the user signed in. Unset: the refusal is returned as
   * done.
   */
  readonly signInAgain?: () => Promise<boolean>;
}

export type StepUpResult<T> =
  /** The action's own result, after at most one retry. */
  | { readonly kind: "done"; readonly result: ApiResult<T> }
  | { readonly kind: "cancelled" }
  | {
      readonly kind: "step-up-failed";
      readonly error: ApiErr | Exclude<StepUpOutcome, { kind: "stepped-up" }>;
    }
  /** OIDC: the page is leaving; nothing was retried. */
  | { readonly kind: "redirecting" };

const MAX_REDIRECT_BYTES = 512;

function fits(path: string): boolean {
  return new TextEncoder().encode(path).length <= MAX_REDIRECT_BYTES;
}

function defaultRedirect(): string {
  const { pathname, search } = globalThis.location;
  if (fits(pathname + search)) {
    return pathname + search;
  }
  return fits(pathname) ? pathname : "/";
}

/**
 * Runs action; on an auth_recent_auth_required refusal with no reason, asks prompt for a
 * method, re-authenticates and retries action once. On sign_in_again it never prompts: it runs
 * signInAgain and retries once on true, answers cancelled on false, and with no signInAgain
 * returns the refusal as done. Any other reason is returned as done. The OIDC branch navigates
 * away and never re-runs action. Keeps nothing in browser storage.
 */
export async function withStepUp<T>(
  c: AuthClient,
  action: () => Promise<ApiResult<T>>,
  o: StepUpOptions,
): Promise<StepUpResult<T>> {
  const first = await action();
  if (first.ok || authCode(first) !== "auth_recent_auth_required") {
    return { kind: "done", result: first };
  }
  const retry = async (): Promise<StepUpResult<T>> => ({ kind: "done", result: await action() });
  const reason = errorReason(first);
  if (reason === "sign_in_again" && o.signInAgain !== undefined) {
    return (await o.signInAgain()) ? retry() : { kind: "cancelled" };
  }
  if (reason !== undefined) {
    return { kind: "done", result: first };
  }
  const me = await c.me();
  if (!me.ok) {
    return { kind: "step-up-failed", error: me };
  }
  const choice = await o.prompt(me.data.methods);
  switch (choice) {
    case "cancel":
      return { kind: "cancelled" };
    case "password": {
      const password = await o.password();
      if (password === null) {
        return { kind: "cancelled" };
      }
      const res = await c.stepUpPassword({ password });
      return res.ok ? retry() : { kind: "step-up-failed", error: res };
    }
    case "passkey": {
      const out = await stepUpWithPasskey(c);
      switch (out.kind) {
        case "stepped-up":
          return retry();
        case "cancelled":
          return { kind: "cancelled" };
        default:
          return { kind: "step-up-failed", error: out };
      }
    }
    case "oidc": {
      const res = await startOIDC(c, "stepup", o.redirect ?? defaultRedirect());
      if (!res.ok) {
        return { kind: "step-up-failed", error: res };
      }
      (o.navigate ?? assign)(res.data.url);
      return { kind: "redirecting" };
    }
  }
}
