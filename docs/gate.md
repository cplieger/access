# Guarding your own routes

The `access/gate` package guards the routes of your own app with an `access.Authenticator`. You describe every route in one table, each row with its class, and give one handler per row. The gate answers every refusal through your `access.ErrorWriter`, with the same codes and the same `WWW-Authenticate` challenge as the auth routes. It imports only `access` and the standard library, so an app that guards an API links no passkey or OIDC code.

```go
g, err := gate.New(gate.Config{Authenticator: authn, Errors: writeError}, []gate.Route{
	{Name: "me", Method: http.MethodGet, Path: "/api/me", Class: gate.Session},
	{Name: "notify", Method: http.MethodPost, Path: "/api/notify", Class: gate.Key, Scope: "notify"},
}, map[string]http.Handler{"me": me, "notify": notify})
```

`New` returns an error, and never panics, for a table it cannot serve exactly:

- a nil `Authenticator` or `Errors`;
- an empty or repeated `Name`;
- a `Method` other than GET, POST, PUT, PATCH or DELETE;
- a `Path` that does not start with `/`, is not clean, names a host, ends in `/`, or holds `{$}` anywhere but the root row `/{$}`;
- two rows with one method and path, or patterns `http.ServeMux` refuses to register together;
- a `Scope` on a `Public` or `Session` row, none on a `Scoped` row, or one that is not a single [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750#section-3) scope-token (printable ASCII other than space, `"` and `\`);
- `Passive` on a `Public` row;
- a row with no handler, or a handler with no row.

The gate serves its rows and nothing else. A route with no row cannot be reached through it.

## The classes

Every class but `Public` runs `Authenticator.Authenticate`, under `access.Passive` when the row sets `Passive`, so a polling route verifies a session without counting as activity. No principal passes a class implicitly: the bypass principal and a custom verifier's principal pass only where `Allow` admits them.

| Class | Admits | Refuses |
| --- | --- | --- |
| `Public` | every request, with nothing read | nothing. A revoked or unknown credential reaches it as no credential does |
| `Session` | a full session | anything else: 403 `auth_session_required` |
| `Key` | an API key, and when the row has a `Scope`, one `Allow` admits | a principal that is not an API key, a custom verifier's included: 403 `auth_key_required`, before `Allow` runs. A key `Allow` refuses: 403 `auth_scope_required` |
| `Scoped` | a principal `Allow` admits | an API key: 403 `auth_scope_required`. Any other principal: 403 `auth_forbidden` |

`Config.Allow` decides a `Scoped` row and a `Key` row with a `Scope`, for sessions and keys alike, so a scope lattice or a role cap is yours to write. Left nil, it admits a full session, and an API key holding the row's scope. The gate never compares scopes itself.

Every authenticating row also answers a credential `Authenticate` refuses, mapped by `access.ErrorFor`: 401 `auth_required` with no credential, `auth_session_expired` for a session cookie whose session is gone, `auth_key_invalid` for a refused API key, `auth_invalid_credentials` for any other refused credential, and 403 `auth_session_required` for a recovery-session cookie. A store failure is 503 `auth_unavailable` with `Retry-After: 5`, logged at WARN. An error `ErrorFor` does not map, which only a custom verifier returns, is 503 `auth_unavailable` too, logged at ERROR, and when it carries the request's own ended context it is the client walking away, logged at DEBUG. The gate writes these lines to `Config.Logger`, which is `slog.Default()` when nil. It does not use the `Authenticator`'s `Logger`, so pass the same logger to both. The handler never runs for a refused request.

API keys are read from the `Authorization: Bearer` header only.

A `Session` or `Scoped` row whose method is not GET checks the request with Go's `http.CrossOriginProtection` first, as every unsafe auth route does, and refuses a cross-site browser request with 403 `auth_cross_origin`. A client sending a Bearer key sends no `Sec-Fetch-Site` or `Origin` header, so it passes. A `Key` row admits no session, so it needs no check.

An admitted request runs its handler with the principal in its context: `gate.Principal(r.Context())` returns it, and reports false on a `Public` row.

## A cookie and a key on one request

`Authenticate` reads the session cookie first, so a request carrying both a session cookie and a Bearer key is the session's. A `Key` row refuses it with `auth_key_required`. A browser tool that tests a key with `fetch` sends the page's cookie along unless it sets `credentials: "omit"`.

## Matching

The gate registers each row on its own `http.ServeMux` as `METHOD PATH`, so the precedence between rows is ServeMux's: `GET /files/upload` wins over `GET /files/{name}`, and `POST /files/upload` is its own row. A GET row also answers HEAD. The gate then answers, in order:

1. A path that is not canonical, such as `//x` or `/a/./b`, gets 404 `auth_not_found` with no `Location`, so ServeMux's redirect never runs.
2. A request a row matches is served by that row.
3. A path some row has under another method gets 405 `auth_method_not_allowed`, with `Allow` listing those methods, and `HEAD` beside `GET`.
4. Anything else gets 404 `auth_not_found`.

Every refusal goes through your `ErrorWriter`, with `Cache-Control: no-store`. The gate never answers with ServeMux's own 307, 405 or text body.

## Mounting

The gate is not your top mux. Mount it on your own `http.ServeMux` beside the auth routes, at as many patterns as you like, with no prefix stripped: a row's `Path` is the full request path. One gate mounted at `/api/` and at `/metrics` serves both sets of rows from one table. Your shell page, static files and health check stay on your own mux.

```go
mux.Handle("/api/", g)
mux.Handle("/metrics", g)
```

Mount the gate on patterns with no method. Under a method-qualified pattern such as `GET /metrics`, your mux answers a POST with its own text 405 before the gate runs, where the gate would answer `auth_method_not_allowed` through your `ErrorWriter`.

Your mux cleans a path before the gate sees it. A non-canonical path under the mount, such as `/api//items`, and the bare prefix `/api` for an `/api/` mount, get your mux's 307 to the cleaned path. The target is canonical and goes through the gate again, and a redirect grants nothing. The gate's own 404 for a non-canonical path applies when it is mounted where nothing cleans the path first, such as behind `http.StripPrefix` under another router.

The gate never serves the auth routes, so nothing authenticates an auth route twice, and it does not touch first-user setup.

## The codes

`gate.Codes(route)` lists every code a row can answer, in `access.Codes()` order, and `gate.MountCodes()` what the gate answers outside any row, which is `auth_not_found`. Your app's error union is every row's `Codes` and `MountCodes()`.

- Every row: `auth_method_not_allowed`.
- Every row but `Public`: `auth_required`, `auth_session_expired`, `auth_invalid_credentials`, `auth_key_invalid`, `auth_session_required` and `auth_unavailable`.
- `Session`: `auth_cross_origin` when its method is not GET.
- `Key`: `auth_key_required`, and `auth_scope_required` with a `Scope`.
- `Scoped`: `auth_scope_required` and `auth_forbidden`, and `auth_cross_origin` when its method is not GET.

## The challenge

Before your `ErrorWriter` runs, the gate calls `Authenticator.Challenge` with the code and the row's scope, so every 401 carries a `WWW-Authenticate` header, where `R` is `Config.Realm`:

- `auth_key_invalid`: `Bearer realm="R", error="invalid_token"`, the only answer that tells a client to discard its token;
- `auth_scope_required`: `Bearer realm="R", error="insufficient_scope", scope="S"`, naming the row's scope;
- every other 401, and `auth_key_required`: `Bearer realm="R"`, as [RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750#section-3) gives a request that carries no Bearer token.

Your `ErrorWriter` adds any header of its own, such as a `Link` to your API description.

## The audit

Set `Config.Audit` to receive one `access.AuditEvent` for each refusal of a presented credential. It is called synchronously, before your `ErrorWriter` runs, so a limiter of failed attempts by client can count from it. The gate itself does not rate-limit: a 256-bit key cannot be guessed.

`gate.failure` is a 401 for a credential that was presented. Its `Reason` is one of:

| Reason | The credential |
| --- | --- |
| `key_unknown` | a Bearer value no stored key has as either secret |
| `key_expired` | an API key at or past its `ExpiresAt` |
| `key_retired` | a rotated key's previous secret, once its overlap has ended or the new secret has been used |
| `account_disabled` | a key or session whose owner is missing or disabled |
| `session_expired` | a session cookie past its idle or absolute limit |
| `session_unknown` | a session cookie no stored session has |
| `credential_invalid` | a credential your custom verifier refused |

`key_retired` lasts until the store clears the previous secret, which the account sweep does once it can no longer verify, or until the key is rotated again. After that the old secret is `key_unknown`. `key_expired` is also the reason `account` refuses to rotate an expired key with, since both name the same fact.

`gate.forbidden` is a 403. Its `Reason` is `session_required`, `key_required`, `scope_required` or `forbidden` for a principal the row's class refuses, `recovery_session` for a recovery-session cookie, and `cross_origin` for a cross-site request.

On both kinds, `Method` is `access.MethodAPIKey` for a Bearer key, your custom verifier's own method for its principal, the bypass method for the bypass principal, and empty for a session cookie. `KeyID` and `UserID` are set when the gate knows them, and `IP` is the client address `Authenticator.ClientAddr` resolves.

A request with no credential (`auth_required`) and a 503 send no event, so a store outage never counts as failed sign-ins.

The reason is for your records only. A client sees `auth_key_invalid` or `auth_session_expired` with an empty `Reason`, and an unknown key, an expired key and a retired previous secret get byte-identical answers, so a refusal never tells a key holder which keys exist.
