import type { ApiResult } from "@cplieger/reactive/fetch";
import type { AuthClient } from "./client.js";
import { knownCode } from "./wire.js";
import type { AuthCode, MeResponse, OIDCStartResponse, PendingLinkResponse } from "./wire.js";

/**
 * The URL that starts an OIDC sign-in, for a plain navigation or a link: GET
 * {oidcPrefix}/start/signin, with redirect, the app's relative return path, when given. The
 * server lands on "/" for a redirect it refuses.
 */
export function oidcSignInURL(c: AuthClient, redirect?: string): string {
  const start = `${c.oidcPrefix}/start/signin`;
  return redirect === undefined || redirect === ""
    ? start
    : `${start}?${new URLSearchParams({ redirect }).toString()}`;
}

/**
 * Link and step-up POST same-origin first, then navigate to the returned URL. redirect is the
 * app's relative return path, at most 512 bytes (oidc.MaxRedirectBytes); the server refuses a
 * longer one.
 */
export function startOIDC(
  c: AuthClient,
  intent: "link" | "stepup",
  redirect?: string,
): Promise<ApiResult<OIDCStartResponse>> {
  const r = redirect === undefined ? {} : { redirect };
  return intent === "link" ? c.oidcStartLink(r) : c.oidcStartStepUp(r);
}

export type OIDCReturn =
  | { readonly kind: "none" }
  | { readonly kind: "not_linked" }
  | { readonly kind: "linked" }
  | { readonly kind: "stepped_up" }
  | { readonly kind: "error"; readonly code: AuthCode | undefined };

/**
 * Reads the callback's markers from search (location.search). An auth_error outside the
 * AuthCode union gives code undefined, and an auth_error beside an oidc marker is the error.
 * A marker is a hint any link can carry: the page never dispatches on it without the user's
 * click, and a lasting continuation is bound to same-origin state, continuation.put's nonce,
 * never to URL arguments alone.
 */
export function readOIDCReturn(search: string): OIDCReturn {
  const q = new URLSearchParams(search);
  const errors = q.getAll("auth_error");
  if (errors.length > 0) {
    const only = errors.length === 1 ? errors[0] : undefined;
    return { kind: "error", code: only === undefined ? undefined : knownCode(only) };
  }
  const markers = q.getAll("oidc");
  if (markers.length !== 1) {
    return { kind: "none" };
  }
  switch (markers[0]) {
    case "not_linked":
      return { kind: "not_linked" };
    case "linked":
      return { kind: "linked" };
    case "stepped_up":
      return { kind: "stepped_up" };
    default:
      return { kind: "none" };
  }
}

/** The IdP identity a not-linked OIDC sign-in left in its pending-link cookie. */
export function pendingLink(c: AuthClient): Promise<ApiResult<PendingLinkResponse>> {
  return c.oidcPending();
}

/** Links the pending IdP identity to the signed-in user and returns the updated user. */
export function completePendingLink(c: AuthClient): Promise<ApiResult<MeResponse>> {
  return c.oidcLinkPending();
}
