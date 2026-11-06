# Configuration

This page lists every field of `access.Config`, the session cookie settings, `access.HasherConfig`, the rate limiter, `oidc.Config`, `account.Config`, `account.Rules` and `accesshttp.Config`, each with its zero-value default. Read it when you wire the library into your service.

Every setting is a field of a configuration struct or a function argument. The library reads no environment variables, keeps every setting on the value you construct and does nothing when it is imported.

## Authenticator configuration

`New(store, cfg)` takes an `access.Config` with these fields.

| Field | What it sets | Default |
| --- | --- | --- |
| `Logger` | The `*slog.Logger` for warnings and debug lines | `slog.Default()` |
| `Cookie` | The session cookie, described below | the zero `CookieConfig`, which behaves as `DefaultCookieConfig()` |
| `IdleTimeout` | How long a session may sit unused | 1h |
| `AbsTimeout` | How long a session may live at most | 24h |
| `ActivityThrottle` | Writes an API key's last use once the stored one is this old, and a session's activity once the stored one is as old as the lesser of this and half that session's idle limit | `0`, a write on every request |
| `TimeoutSource` | Reads the two timeouts from a callback on every verification, for settings you reload at run time | _(unset)_ |
| `Unauthorized` | Replaces the response `RequireAuth` writes for a request that is not signed in, and receives the error | _(unset)_ |
| `Verifier` | Adds your own `CredentialVerifier` between the session cookie and the API key | _(unset)_ |
| `ClientAddr` | Your resolver for the client's address, behind `Authenticator.ClientAddr` and each session's last IP | the socket peer, with no proxy trusted |
| `Bypass` | A development hook that grants a synthetic admin user while it returns true | _(unset)_ |

`New` returns an error for a configuration that cannot work. That is a timeout or throttle below zero, an activity throttle at or above the idle timeout, or a cookie configuration that `CookieConfig.Validate` refuses. `New` also refuses a nil store, and a `Verifier` that holds a nil pointer, map, slice, func or chan; a nil `Verifier` means none.

The activity throttle exists to cut store writes. An API key's last use is written once the stored time is `d` old. A session's activity is written once the stored time is one window old. That window is the lesser of `d` and half the session's idle limit, which the session's own `IdleCap` and the 15-minute limit of a recovery session can lower, so a session in use never expires between two writes. The window runs from the time the store holds, so it holds across restarts, and requests that arrive together as a window ends may each write once. A failed write leaves the stored time old, so the next request tries it again. A failed write logs a warning at most once a minute for sessions and once a minute for keys. The next warning after that minute carries `suppressed`, the count of failures held back, when there were any. The stored last-activity time lags real activity by up to that window, which is why the throttle must stay below the idle timeout.

With `TimeoutSource`, a value at or below zero from the callback falls back to the matching static field. The same cap on the throttle window applies to the idle timeout the callback returns.

By default `RequireAuth` answers 503 with `Retry-After: 5` when the store fails (`ErrAuthBackend`). Every other refusal gets a 401 with `WWW-Authenticate: Bearer` and a JSON body whose `code` is `auth_session_expired` for a session cookie whose session has expired or is gone, and `auth_required` otherwise. It never redirects. An `Unauthorized` hook replaces the answer and receives the error, so it can redirect browsers itself with `IsBrowserRequest`.

The `Verifier` runs after the session cookie and before the API-key verifier, which refuses every Bearer value it cannot find. A verifier for another Bearer credential answers `ok` false and a nil error for every value that is not its own. Its principal may carry a user your app made up with no stored row. That user must be non-nil and enabled, the `Method` must be non-empty, and the `Authenticator` never looks the user up in the store.

Without `ClientAddr`, no peer is treated as a proxy. The address is the connection's peer, with an IPv4-mapped IPv6 address unmapped, and `UntrustedForwarding` is true when the request carries `Forwarded`, `X-Forwarded-For` or `X-Real-IP`, which the default ignores.

`Bypass` logs one info line when `New` installs it. It logs a warning on each request that finds the hook on after a request that found it off, the first request included. The synthetic user's ID is 0, which no stored user has. Keep it off in production.

## Session cookie

`CookieConfig` holds the cookie's attributes. Declare the configuration your deployment needs instead of relying on a default, so the posture is visible where you call `New`.

| Field | What it sets | Default |
| --- | --- | --- |
| `Name` | The base cookie name, without the `__Host-` prefix | `auth_session` |
| `Posture` | The prefix and Secure flag strategy, in the next table | `PostureSecure` |
| `Path` | The cookie's Path attribute | `/` |
| `Domain` | The cookie's Domain attribute | _(unset)_ |
| `SameSite` | The cookie's SameSite attribute: Lax or Strict | `http.SameSiteLaxMode` |
| `HTTPS` | Tells whether a request arrived over HTTPS, under `PosturePerRequest`, where it is required. Pass `access.RequestIsHTTPS` | _(nil)_ |
| `Persistent` | Tells whether a cookie set on a request may outlive the browser session. When it answers false, a cookie that would have a lifetime carries neither `Max-Age` nor `Expires`, so it ends with the browser session | _(nil: always persistent)_ |

```go
cfg := access.CookieConfig{
	Name:     "my_session",
	Posture:  access.PostureSecure,
	Path:     "/",
	Domain:   "", // must stay empty under a __Host- posture
	SameSite: http.SameSiteLaxMode,
}
authenticator, err := access.New(myStore, access.Config{Cookie: cfg})
if err != nil {
	log.Fatalf("access: %v", err) // CookieConfig.Validate refused cfg
}
```

| Posture | Behavior |
| --- | --- |
| `PostureSecure` | The default. The `__Host-` prefix with Secure, HttpOnly and SameSite=Lax, for any HTTPS deployment, self-signed certificates included |
| `PostureInsecureLAN` | For plain-HTTP access by address and port on a LAN or a Docker network. The bare name without Secure, chosen only explicitly |
| `PosturePerRequest` | Over HTTPS, as `HTTPS` reports it, the `__Host-` prefix with Secure. Over plain HTTP, the bare name without Secure |

`PosturePerRequest` suits one instance that serves both plain-HTTP LAN traffic and HTTPS traffic through a proxy.

Every posture except `PostureInsecureLAN` uses the `__Host-` prefix. Under those, `Domain` must stay empty and `Path` must be `/`, because browsers silently drop a `__Host-` cookie that breaks either rule. `Validate` refuses such a configuration. It also refuses a posture other than the three above, a name, domain or path that `http.Cookie.Valid` refuses, a path that does not start with `/` or is longer than 1024 bytes, a `SameSite` other than unset (which means Lax), Lax or Strict, and a nil `HTTPS` under `PosturePerRequest`. It refuses a `Name` that starts with `__Secure-`, `__Host-` or `__Http-` in any letter case, because browsers drop such a cookie when it is sent without Secure. Browsers also drop a cookie whose name and value together pass 4096 bytes; `Validate` never sees the value, so keep the name short.

`RequestIsHTTPS` reports a request as HTTPS when it carries TLS or when the first token of `X-Forwarded-Proto` is `https`, from any peer. It never downgrades: a client that forges `https` only makes its own browser refuse the Secure cookie. Do not pass a predicate that trusts `X-Forwarded-Proto` only from listed proxies, because behind a TLS proxy you did not list it answers false and the cookie loses Secure.

`SetCookie` always sets HttpOnly and also sends `Cache-Control: no-store`. `ClearCookie` expires the cookie, also when `Persistent` answers false. `ReadCookie` reads the name that fits the request, and only when the request carries exactly one cookie of that name.

`Derive(suffix, sameSite)` returns the configuration of a companion cookie named `<Name>_<suffix>`, with the same posture, path, domain and `HTTPS`, and a nil `Persistent`. The suffix must match `^[a-z_]{1,16}$`, and `sameSite` must be unset (Lax), Lax or Strict. Any other value panics.

## Password hasher

`NewHasher(access.HasherConfig{})` uses `DefaultArgon2Params()`: 19456 KiB of memory, 2 iterations, 1 thread, a 16-byte salt and a 32-byte key. Each hash is a PHC string such as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`, held as an `access.Hash`.

Every derivation draws on a `HashBudget`, which bounds the memory Argon2 may hold at once. `HashCost(params)` is one derivation's share, 19 MiB at the defaults. With a nil `HasherConfig.Budget`, each hasher gets a private budget of four shares. Build one budget per process and pass it to every hasher, so they share one bound:

```go
budget, err := access.NewHashBudget(256 << 20) // four 64 MiB derivations at a time
if err != nil {
	log.Fatal(err)
}
hasher, err := access.NewHasher(access.HasherConfig{
	Params: access.Argon2Params{
		Memory: 65536, Iterations: 3, Parallelism: 2,
		SaltLength: 16, KeyLength: 32,
	},
	Budget: budget,
	Wait:   time.Second,
})
if err != nil {
	log.Fatal(err) // a parameter is out of bounds, or the budget cannot hold one derivation
}
hash, err := hasher.Hash(ctx, "my-secure-password")
ok, needsRehash, err := hasher.Verify(ctx, "my-secure-password", hash)
```

When the budget has no room, `Hash`, `Verify` and `Reserve` wait for it. They return `ErrHashBusy` once the budget wait ends, 2 s by default, or once the context ends. A stored hash costlier than the hasher's parameters then waits for its own cost, and only the budget wait bounds that second wait. Once `Verify` holds its first share, it runs to completion even if the context ends. A stored hash costlier than the whole budget returns `ErrHashInvalid`.

`Verify` against the zero `Hash`, a malformed hash or an out-of-bounds one still derives once at the hasher's parameters and reports `ok=false`. An unknown username therefore costs what a wrong password does.

`Argon2Params.Validate`, and so `NewHasher`, refuses parameters outside these bounds:

- memory of at most 4 GiB;
- memory of at least [OWASP's Argon2id minimum](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) for the iterations: 47104 KiB at 1 iteration, 19456 KiB at 2, 12288 KiB at 3, 9216 KiB at 4, and 7168 KiB at 5 or more;
- iterations from 1 to 100, and parallelism from 1 to 16;
- a salt and a key of 16 to 64 bytes each.

A stored hash outside the same bounds, or not in canonical PHC form, never matches. `NewHasher` also refuses a negative wait and a budget smaller than `HashCost(params)` with `ErrHashBudgetTooSmall`. Passwords are NFC-normalised before hashing and verifying.

`needsRehash`, and `NeedsRehash`, report a hash made with other parameters, so you can rehash the password at the user's next sign-in.

## Rate limiter

`ratelimit.DefaultConfig()` returns the rates and bounds below. Each rate is a limit per sliding window, per key: the limiter bounds the failed attempts, and the begin-route requests, each key makes in a window. Its windows live in memory, so a restart clears them.

| Field | Default | Bounds |
| --- | --- | --- |
| `IP` | 10 per 15m | failed attempts per IP key |
| `Account` | 100 per 1h | failures from untrusted clients per account |
| `Device` | 10 per 1h | failures per account and device cookie |
| `Request` | 60 per 1m | requests on an anonymous begin route per IP key |
| `IPv6Prefix` | 64 | the IPv6 prefix one IP key covers, 48 to 128 |
| `MaxEntries` | 10000 | the keys, and so the memory, each dimension tracks |
| `Prune` | 5m | how often windows with no live entry are dropped, and the eviction warning's interval |
| `Devices` | none | the `*access.Sealer` that seals device cookies, required |
| `Logger` | `slog.Default()` | where the eviction warning goes |

`New` refuses a limit or window at or below zero, an `IPv6Prefix` outside 48 to 128, a `MaxEntries` or `Prune` at or below zero, and a nil `Devices`. The error is a `*ConfigError` naming the field, and it matches `ErrConfigInvalid`.

`IPKey` keys an IPv4 address by all 32 bits and an IPv6 address by its first `IPv6Prefix` bits. A 4in6 address keys as its IPv4 address, and the zero address is one shared "unknown" key. `AccountKey` keys a username by its `access.NormalizeUsername` form, so `admin`, `ADMIN` and `ａｄｍｉｎ` are one account. A username that `NormalizeUsername` refuses keys by its first 256 bytes, apart from every accepted name. Every stored account key is a fixed-size digest, so the limiter's retained state does not grow with username length.

`Attempt` checks and reserves a slot in every window that applies, under one lock, so concurrent attempts never pass a limit. The IP window applies unless `Attempt.OmitIP` is set, which `account` sets for a password step-up and for the current-password check of `SetPassword` and `RemovePassword`. A browser with a valid device cookie for the account counts against its own device bucket, and any other client against the account's untrusted bucket. A full window refuses with `*RefusedError`, which matches `ErrRefused` and names the `Dimension` that waits longest and the exact `RetryAfter`.

The reservation counts as a failure until it is settled, so an abandoned one still counts:

- `Succeed` removes its own entries, clears the account's device bucket for a trusted browser, else its untrusted bucket, and returns a fresh device cookie. It leaves other accounts' failures in the IP window.
- `Fail` settles it as the failure it already counts.
- `Cancel` removes it without crediting a success, for a refusal before the password was checked.

Only the first of the three acts. `Request` counts one request on an anonymous begin route against the IP key's request window.

Set the device cookie `Succeed` returns for 180 days, and pass the browser's cookie back in `Attempt.Device`. The device protocol follows OWASP's [device cookies](https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies): locking an account for untrusted clients leaves the owner's trusted browsers working. With a `Devices` sealer over persisted keys, that trust survives a restart. With `access.NewEphemeralSealer()`, a restart makes every browser untrusted until it signs in again. After a sign-in that ran no `Attempt`, such as a passkey or OIDC sign-in, `DeviceCookie` returns the cookie to set, and it keeps the device of a valid cookie the browser presented.

Each dimension keeps at most `MaxEntries` keys, which bounds the limiter's memory. Keys are ordered by when each was last used. An admitted attempt or request counts one entry under every key it checks, and marks each as used. A refused one counts nothing, starts tracking no new key and evicts none. It only marks as used the keys it checks that the limiter already tracks. A key's limit is exact while it is among its dimension's `MaxEntries` most recently used keys. A new key past that is never refused for capacity. It evicts the least recently used key whatever its count, and that key starts over. A key that keeps trying is evicted last: it is forgotten only when a new key arrives after `MaxEntries - 1` other keys have been used since its last attempt.

Past those keys, the limiter bounds no spray of new keys. What bounds one depends on the route:

- Password attempts on an account (`PasswordLogin`, `StepUpPassword`, and the current-password check of `SetPassword` and `RemovePassword`). The durable failure cap, `account.FailureCap`, locks the password for a name and trust context after 100 consecutive failures, so a spray gets at most 100 consecutive guesses at each account in each context. Every password hash draws on the `access.HashBudget`, which bounds how many hashes run at once.
- Attempts with no account (`SetupWithPassword`, `AcceptInvitePassword` and `StartRecovery`). Nothing beyond the IP limit bounds their rate. Those that hash a password draw on the `access.HashBudget`.
- Begin routes that hold a passkey ceremony (`SetupPasskeyBegin` and `PasskeyLoginBegin`). The pending-ceremony cache holds at most `account.Config.MaxPending` entries and evicts the oldest first. That bounds memory, not the request rate.
- The OIDC sign-in start and callback. `account.Service.AdmitOIDC` charges the IP request limit on both before `oidc.Provider.Finish` and `OIDCComplete` run, and nothing beyond that limit bounds their rate. A callback without a flow cookie that `Begin` sealed fails when the cookie is opened, before any call to the identity provider.

Once per `Prune` interval, each dimension that evicted keys at their limit logs one warning with their count, after the limiter's locks are released. The prune goroutine stops when the context given to `New` ends, after logging the warnings its last interval had not yet logged. `Shutdown` stops it and blocks until it has exited, or until the context given to `Shutdown` ends.

## OIDC provider

`oidc.NewProvider(ctx, cfg)` takes an `oidc.Config`, runs discovery and refuses a discovery document whose authorization, token or JWKS endpoint is not an absolute `https` URL. Plain `http` is accepted only on a loopback host while the issuer is itself a loopback `http` URL.

| Field | What it sets | Default |
| --- | --- | --- |
| `IssuerURL` | The identity provider's issuer | required |
| `ClientID`, `ClientSecret` | The client registration; the secret is an `access.Secret` | required |
| `RedirectURL` | The callback URL registered with the provider | required |
| `Scopes` | The requested scopes, which must include `openid` | `openid`, `profile` and `email` |
| `HTTPClient` | The client for discovery, JWKS and token calls. The provider uses a copy, wraps its transport to refuse a body over 1 MiB, and refuses a negative timeout | a client with a 10 s timeout |
| `FlowSealer` | The `*access.Sealer` for the flow cookie | a new ephemeral sealer per provider |
| `Now` | The clock for the flow cookie and the ID token's expiry | `time.Now` |

An ephemeral `FlowSealer` means a flow begun under one provider cannot finish under a rebuilt one. An app that rebuilds its provider when its settings change passes one sealer that outlives them. The flow cookie lives 10 minutes, the return path is at most 512 bytes, and a step-up accepts 60 s of `auth_time` skew. [OIDC sign-in](oidc.md) explains the flow.

## Account service

`account.New(ctx, cfg)` takes an `account.Config`. It refuses a nil `Store`, `Policy`, `Authenticator`, `Hasher`, `Limiter` or `Rules`, a `FailureKey` that is not 32 bytes, two equal non-empty scopes, a negative `CleanupInterval` or `MaxPending`, and a `Rules()` value that `Rules.Validate` refuses or whose breach mode has no `Breach` client.

| Field | What it sets | Default |
| --- | --- | --- |
| `Store` | Your `account.Store` ([Implementing the store](storage.md)) | required |
| `Policy` | Who may do what: `RolePolicy{}`, `SingleOwnerPolicy{}` or your own | required |
| `Authenticator` | The `*access.Authenticator` whose cookie and timeouts `account` reads; it keeps no copy | required |
| `Hasher` | The `*access.Hasher` for every password | required |
| `Limiter` | The `*ratelimit.Limiter` every attempt goes through | required |
| `Rules` | A function returning the app's `Rules`, read once per operation | required |
| `FailureKey` | The 32-byte HMAC key that names failure records. Persist it beside the device-cookie key ring: a new key resets every count and clears every lock, with no event | required |
| `RP` | A function returning the passkey relying party | nil: passkeys off |
| `OIDC` | A function returning the OIDC provider | nil: OIDC off |
| `OnEvent` | Receives every event after its commit, in the committing goroutine. It must not block | nil: none |
| `Breach` | The HTTP client for the breached-password check | nil: required only when `Rules.Breach` is not `BreachOff` |
| `AdminScope` | The key scope that lets an admin's key list users and every user's keys, and revoke any key | empty: session only |
| `ManageUsersScope` | The key scope that lets a key manage `RoleUser` accounts, described below | empty: session only, under recent sign-in |
| `CreateKeysScope` | The key scope that lets a key mint keys for its own user, described below | empty: session only, under recent sign-in |
| `CleanupInterval` | How often expired sessions, tokens, pending ceremonies and stale failure records are swept | 5m |
| `MaxPending` | The most pending WebAuthn ceremonies held, oldest evicted first | 10000 |
| `Logger` | The `*slog.Logger` | `slog.Default()` at each call |
| `Now` | The clock | `time.Now` |

`RP` and `OIDC` are read on every operation, so an app that swaps its provider at run time does so by returning the new value. A provider swapped in mid-flow fails that flow closed.

`RolePolicy` has two fields. `KeepLocalAdmin` refuses removing, demoting, disabling or migrating to single sign-on the last enabled admin who holds a password. `KeysAdminOnly` lets only admins mint keys for themselves; by default any enabled user may. `SingleOwnerPolicy` keeps one user, the one setup creates, and refuses every change to the user set.

### Rules

`account.Rules` is your policy as data. `Config.Rules` is read once per operation, so a reloaded value applies from the next operation on. The zero value of every field is its default.

| Field | What it sets | Default |
| --- | --- | --- |
| `SetupTokenRequired` | Whether a first-user setup from a client needs a setup token | nil: always |
| `MethodUsable` | Whether a held method can sign the user in now under your own rules, ANDed into the last-method guard and `Service.UsableMethods` ([Your own rules inside the transaction](storage.md#your-own-rules-inside-the-transaction)) | nil: every held method is usable |
| `SessionCaps` | Per-session idle and absolute limits for a new session; a positive value lowers that limit for the session's life | nil: no cap |
| `KeyPrefix` | The prefix of every minted key's plaintext | empty |
| `ForbiddenWords` | Words refused in a password, beside the username | none |
| `Scopes` | The key-scope vocabulary; `CreateAPIKey` refuses any other scope | none |
| `Provisioning` | Just-in-time account creation on an OIDC sign-in with no linked account | off |
| `RecentAuth` | How recent a sign-in or step-up must be for a sensitive operation; below 1m is invalid | 10m |
| `Breach` | The breached-password check: `BreachOff`, `BreachFailOpen` or `BreachFailClosed` | `BreachOff` |
| `MaxSessionsPerUser` | The most sessions per user; a new one past it ends the user's least recently active | 0: unlimited |
| `DisablePasswordLogin` | Refuses password sign-in and step-up | false: allowed |
| `SSOGoverned` | Makes linking an OIDC identity remove the password and passkeys; only recovery restores a local method | false |
| `RevokeKeysOnCredentialChange` | Deletes the user's API keys when the password is set or changed or an OIDC identity is linked | false |

An app may refuse a sign-in method in its own gate before `account` sees the attempt. `Rules` has no sign-in hook for that, and `MethodUsable` keeps the last-method guard from counting a method the app refuses.

### Key permissions

`ManageUsersScope` and `CreateKeysScope` are empty by default, and a key holds either only when the admin grants that scope when creating it. No other scope implies them, full access included.

- A `ManageUsersScope` key creates, updates and deletes `RoleUser` accounts, invites `RoleUser` accounts and issues recovery for `RoleUser` accounts. It never reaches an admin account: it cannot create, promote, invite, recover, disable or delete one.
- A `CreateKeysScope` key mints keys for its own user only. Each key it mints carries a subset of its scopes and expires no later than it does, so a key can pass on a permission only when it holds it.
- The invite and recovery links a key issues expire no later than the key and are re-checked against it when used.
- A key's expiry needs no cleanup: its descendant keys and every link they issued expire no later than it does, and every use refuses an expired key or link.
- Revoking a key revokes every key minted below it and deletes their unused invite and recovery links, in one transaction.
- The accounts the key or any key below it created, invited or took over through recovery stay, with their credentials. Each is attributed by an append-only record that carries the acting key's whole lineage, which `Service.Users` with `UserFilter.AttributedToKey` (`GET /users?key=`) filters by any key in that lineage, a revoked one included. Review and disable those accounts after revoking a leaked key.
- A key's lineage holds at most `account.MaxKeyLineage` IDs, 8: a root key and seven generations of keys minted by keys. Minting below a full lineage is refused with the reason `lineage_too_deep`.

Every key-authorized write re-reads the key and its owner inside its own transaction, so a key revoked or expired, or an owner disabled, deleted or demoted, authorises nothing that commits after the change. Leaving both scopes empty keeps all of these operations session-only under a recent sign-in.

## HTTP handlers

`accesshttp.New(cfg)` takes an `accesshttp.Config` and refuses a nil `Account` or `Errors`.

| Field | What it sets | Default |
| --- | --- | --- |
| `Account` | The `*account.Service`, which also supplies the cookie and timeouts | required |
| `Errors` | Your `ErrorWriter`, which renders every refusal | required |
| `Audit` | Receives the request-level outcomes that change no state | nil: none |
| `Prefix` | The path every route not under `OIDCPrefix` starts with, such as `/api/auth` | empty |
| `OIDCPrefix` | The prefix of the OIDC start and callback routes | empty |
| `SignInPath` | Where the OIDC callback sends a browser on any outcome other than success | empty |
| `PendingSealer` | The `*access.Sealer` for the pending-link cookie | an ephemeral sealer, so a restart drops a pending link |
| `Logger` | The `*slog.Logger` | `slog.Default()` at each call |

`Handler.Routes()` returns every route as a `Descriptor` and an `http.Handler`. accesshttp registers nothing itself: mount the routes on your own mux, behind your own gate. You may mount any subset, and no route depends on another being mounted. An unmounted pending-link pair leaves only an unread 10-minute cookie. Each handler applies its own class guard, its own body cap on a route that reads a body, and, on an unsafe (non-GET) method, its own cross-origin protection. Your gate adds to them and never replaces them.

accesshttp writes no error body itself. Every refusal reaches your `ErrorWriter` as an `accesshttp.Error`, with `Cache-Control` and, when `RetryAfter` is set, `Retry-After` already on the response. Render it in your own envelope:

- `Status` is the HTTP status, and `Code` is the stable code a client branches on.
- `Reason` is a stable sub-reason a client may branch on, such as `label_too_long`.
- `Detail` is safe to show and never holds a secret or a raw cause.
- `Err` is for your log only. Never send it.

`accesshttp.Codes()` returns every code accesshttp answers, and each route's `Descriptor.Codes` lists the subset that route can answer, in the same order. `accesshttp.Reasons()` returns every fixed `Reason`, each once. Two families stay open and are not listed: `provider_error:` followed by the identity provider's error code on `auth_oidc_failed`, and, on `auth_bad_request`, the name of the body field, path value or query key that was refused. A client that labels each code and reason can check its table against both lists.
