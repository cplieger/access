# @cplieger/access

`@cplieger/access` is the browser half of [cplieger/access](https://github.com/cplieger/access): a typed client for the JSON routes the Go package `accesshttp` serves, with the passkey ceremonies, OIDC redirects and step-up flow those routes expect. Every response is validated against the server's wire types before your code sees it.

## Install

```sh
npm install @cplieger/access @cplieger/reactive@dev
```

The package ships TypeScript source as ES modules. `@cplieger/reactive` 2.x, from 2.4, is a peer dependency: the client makes its requests through your `@cplieger/reactive/fetch` instance, so your base URL, credentials mode and error hook apply to every call, and the models that `createSessionsModel` and `shownOnce` return are `@cplieger/reactive/signal` signals, so read them from effects made with that same package.

## Usage

Create one client with the same prefixes you gave `accesshttp.Config`:

```ts
import { createFetch } from "@cplieger/reactive/fetch";
import { createAuthClient, signInWithPasskey, withStepUp } from "@cplieger/access";

const auth = createAuthClient({
  fetch: createFetch({ credentials: "same-origin" }),
  prefix: "/api/auth",
  oidcPrefix: "/api/auth/oidc",
});

const res = await auth.loginPassword({ username, password });
if (!res.ok) {
  // authCode(res) and authReason(res) give the stable code and reason to branch on
}

const passkey = await signInWithPasskey(auth);
if (passkey.kind === "signed-in") {
  // passkey.result is the SignedInResponse
}
```

Every call returns an `ApiResult`: `ok` with the decoded `data`, or the refusal. `authCode` and `authReason` read the refusal's code and reason as the `AuthCode` and `AuthReason` unions, which mirror the server's `access.Codes()` and `accesshttp.Reasons()`.

`withStepUp` runs an action that needs a recent sign-in. On an `auth_recent_auth_required` refusal with no reason, it asks your `prompt` which method to use, re-authenticates with it and retries the action once. A refusal that carries a reason, such as `reenable_needs_other_method`, is returned as it is, because a step-up cannot cure it:

```ts
const out = await withStepUp(auth, () => auth.setPassword(change), {
  prompt: async (methods) => askUser(methods), // "password", "passkey", "oidc" or "cancel"
  password: async () => askForCurrentPassword(), // null when the user cancels
});
```

The OIDC branch navigates to the identity provider and never returns to the action, so the app continues from its own redirect path.

## What it exports

- `createAuthClient` returns an `AuthClient` with one method per route, such as `me`, `loginPassword`, `sessions` and `createKey`. `adminSecurityLog` reads a page of the [security log](https://github.com/cplieger/access/blob/main/docs/security-log.md) with its per-class counts, newest first, or oldest first when `oldestFirst` is set; `after` and `before` are bounds only.
- `signInWithPasskey`, `registerPasskey`, `setupWithPasskey`, `stepUpWithPasskey` and `recoverWithPasskey` run the WebAuthn ceremonies. `passkeySupport` reports what the browser offers, and `sendSignals` keeps the credential manager's passkey list in step with the server.
- `oidcSignInURL`, `startOIDC`, `readOIDCReturn`, `pendingLink` and `completePendingLink` handle the OIDC sign-in, link and step-up redirects.
- `withStepUp` retries an action after a step-up, and `createSessionsModel` keeps a reactive list of the user's sessions.
- `shownOnce` holds a key or link shown once and clears it, `storePasswordCredential` offers the password to the browser's password manager, and `continuation` and `takeFragmentToken` carry state and a one-time token across a redirect.
- A `parse*` validator and a type for every JSON body the routes accept or return (the query structs are built by the client methods), `authCode`, `authReason`, `AuthCode` and `AuthReason`.

## Compatibility

The client speaks the v1.0.0 wire. It needs a server built on `github.com/cplieger/access` at v1.0.0 or later, with `accesshttp` serving the routes. The Go module and this package version separately, and a later release states its own floor here.

## License

Apache-2.0. See [LICENSE](LICENSE).
