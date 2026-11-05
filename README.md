# access

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/access.svg)](https://pkg.go.dev/github.com/cplieger/access) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/access)](https://github.com/cplieger/access/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/access/badges/mutation.json)](https://github.com/cplieger/access/issues?q=label%3Agremlins-tracker)

access gives your Go web service its login building blocks: Argon2id passwords, passkeys, OIDC sign-in, sessions and API keys. You write the HTTP handlers and the storage.

It replaces the hashing, token, cookie and passkey code you would otherwise assemble around `net/http`. It reads no environment variables, and every setting lives on the value you construct. It needs Go 1.27 or later and is licensed under Apache-2.0. It has six direct dependencies at run time: `golang.org/x/crypto`, `golang.org/x/oauth2`, `golang.org/x/sync`, `golang.org/x/text`, `go-webauthn/webauthn` and `coreos/go-oidc`.

## Why use it

access is built for a Go service that owns its login pages and database.

- Passwords hash with Argon2id at OWASP's parameters, under a memory budget, which one `HashBudget` shared through `HasherConfig.Budget` makes process-wide. Verifying against the zero `Hash` evens out login timing for an unknown username.
- Your store keeps only the SHA-256 hash of each 256-bit random session token. The cookie holds only the token, so it needs no encryption or signing.
- Passkey ceremonies check each browser origin against the relying-party ID, and the API exposes no go-webauthn type.
- OIDC sign-in sends a PKCE S256 challenge and checks the ID token's nonce.
- Secrets are compared in constant time.
- You implement only the storage interfaces for the features you use, and `accesstest` is an in-memory test store.

Consider [Authboss](https://github.com/aarondl/authboss) if you want ready-made registration, recovery and two-factor flows with HTML or JSON views. Consider [Ory Kratos](https://github.com/ory/kratos) if you want identity as a separate server with login, recovery and multi-factor flows over HTTP APIs.

## Install

```sh
go get github.com/cplieger/access@latest
```

## Usage

An `Authenticator` guards a route. Its store is your implementation of `access.AuthenticatorStore`, and this example uses the in-memory test store instead.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
)

func main() {
	store := accesstest.NewMemStore() // use your database-backed store here

	authn, err := access.New(store, access.Config{
		IdleTimeout: time.Hour,
		AbsTimeout:  24 * time.Hour,
		Cookie:      access.DefaultCookieConfig(),
	})
	if err != nil {
		log.Fatal(err) // the cookie or timeout settings cannot work
	}

	http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		p, ok := authn.RequireAuth(w, r)
		if !ok {
			return // RequireAuth has already answered
		}
		fmt.Fprintln(w, p.User.Username)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`RequireAuth` returns the request's `Principal`, which names the user, the method that authenticated it, and the session or key behind it. It reads the session cookie first, then a verifier you add as `Config.Verifier`, then an `Authorization: Bearer` API key. A request it refuses gets a 401 JSON body, or a 503 when the store fails, and `Config.Unauthorized` replaces that answer.

Signing in is your handler. This one checks a password and starts a session. Here `store` implements `account.Store`, `hasher` is your `*access.Hasher`, and `cookie` is the `CookieConfig` you pass as `Config.Cookie`.

```go
func signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, err := access.NormalizeUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	user, found, err := store.UserByUsername(ctx, name)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	var hash access.Hash // the zero Hash costs the same work for an unknown username
	if found {
		hash = user.PasswordHash
	}
	ok, _, err := hasher.Verify(ctx, r.FormValue("password"), hash)
	if errors.Is(err, access.ErrHashBusy) {
		http.Error(w, "try again shortly", http.StatusServiceUnavailable)
		return
	}
	if err != nil || !ok || !found || !user.Enabled {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	token, tokenHash := access.GenerateSessionToken()
	now := time.Now()
	err = store.CreateSession(ctx, &access.Session{
		TokenHash: tokenHash, UserID: user.ID, AuthMethod: access.MethodPassword,
		CreatedAt: now, LastActivity: now,
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	cookie.SetCookie(w, r, token.Reveal(), 0)
	http.Redirect(w, r, access.ValidateRedirectURI(r.FormValue("next")), http.StatusSeeOther)
}
```

The `ratelimit` package limits failed sign-ins per IP address, per account and per trusted device. Its limits are exact for the `MaxEntries` keys each dimension used most recently. Past that, `MaxEntries` bounds its memory, not a spray of new keys, and the [rate limiter](docs/configuration.md#rate-limiter) section names what bounds each route. Admit each attempt before you check the password, then settle it. `sealer` is an `*access.Sealer` over keys you persist, so trusted devices survive a restart, and `deviceCookie` is the value of the device cookie the browser sent, if any:

```go
cfg := ratelimit.DefaultConfig()
cfg.Devices = sealer
rl, err := ratelimit.New(ctx, cfg)
if err != nil {
	log.Fatal(err)
}
defer func() {
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rl.Shutdown(sctx); err != nil {
		log.Printf("ratelimit shutdown: %v", err)
	}
}()

res, err := rl.Attempt(ratelimit.Attempt{
	IP:      ratelimit.IPKey(clientAddr),
	Account: ratelimit.AccountKey(username),
	Device:  access.NewSecret(deviceCookie),
})
var refused *ratelimit.RefusedError
if errors.As(err, &refused) {
	return fmt.Errorf("too many attempts, retry in %s", refused.RetryAfter)
}
if !passwordOK {
	res.Fail() // the attempt stays counted
	return errSignInFailed
}
device := res.Succeed() // clears this account's failures for this device, or its untrusted count
// set device.Reveal() as the device cookie, for 180 days
```

## API

- `NewHasher`, `Hasher.Hash`, `Hasher.Verify` and `NewHashBudget` hash passwords within a memory budget. `ValidatePasswordLength`, `ValidatePasswordContext`, `ValidatePasswordCommon` and `CheckBreachedPassword` check them.
- `NormalizeUsername` maps a username to one canonical form, so `Müller` and `MÜLLER` sign in to the same account.
- `GenerateSessionToken` and `GenerateOpaqueToken` make tokens, the second one for password-reset and email-verification links. `VerifyOpaqueToken` checks the second one, and `ValidateSession` checks a session's timeouts.
- `CookieConfig` sets, reads and clears the session cookie. `GenerateAPIKey` and `VerifyAPIKey` handle API keys.
- `New` builds the `Authenticator`. `HasRole`, `ValidateRedirectURI`, `CanDisableMethod` and `IsBrowserRequest` are the checks around it.
- The `account` package's `Store` is the storage interface you implement, and its package documentation states the contract every store keeps.
- The `webauthn` package runs passkey ceremonies, `oidc` runs OIDC sign-in, `ratelimit` limits failed logins, and `accesstest` is an in-memory store for tests.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/access).

## Security

access hardens the building blocks, and the security of your service depends on how you wire them.

- Each password hash has its own random salt. Password hashes, API keys and opaque tokens are compared in constant time.
- The default cookie carries the `__Host-` prefix with the Secure, HttpOnly and SameSite=Lax attributes. With that prefix, leave `Domain` empty and `Path` at `/`, because `New` refuses any other value.
- API keys are read from the `Authorization: Bearer` header only, never from a URL query parameter.
- Fuzz targets cover password hashes and password checks, cookie settings, API keys, opaque tokens, redirect paths, OIDC settings, the rate limiter, and WebAuthn origins and stored credentials.
- `Config.Bypass` grants a synthetic admin user to every request while its callback returns true. Keep it off in production.
- When hosts you do not control share your relying-party domain, set `RPConfig.Origins` to your own origin. [Passkeys](docs/webauthn.md#narrowing-the-policy-with-origins) explains why.
- Three rules stay with you. Guard every protected route with `RequireAuth`, match your [cookie settings](docs/configuration.md#session-cookie) to where TLS ends, and return a copy of each record your store looks up. [Implementing the store](docs/storage.md) explains the last rule.
- The cryptography has had no independent third-party audit.

Report a vulnerability privately through the [security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md), not in a public issue.

## Unsupported by design

These are left out on purpose. [Non-goals](docs/non-goals.md) gives the reason for each and what to use instead.

- HTTP handlers, because they depend on your web framework.
- A CSRF token, because Go's `http.CrossOriginProtection` refuses cross-origin state-changing requests without needing one.
- OIDC token refresh, a registry of several providers, back-channel logout and the userinfo endpoint.
- WebAuthn metadata-service verification, attestation conveyance, filtering authenticators by AAGUID, and the passkey well-known endpoints.
- Role hierarchies and permission sets. Each user has one role, and `HasRole` passes when it matches the role a route needs or when the user is an admin.
- Cookie encryption and signing, because the cookie holds only a random token.

The library has no TOTP or SMS second factor. A custom `CredentialVerifier` passed as `Config.Verifier` can add one.

## Documentation

- [Configuration](docs/configuration.md) lists every setting and default, the cookie postures and the rate limiter's limits.
- [Passwords, sessions and tokens](docs/primitives.md) covers each building block in detail.
- [Implementing the store](docs/storage.md) lists the storage interfaces and the rules a store must follow.
- [Passkeys](docs/webauthn.md) explains how ceremonies check origins and what registration requires.
- [OIDC sign-in](docs/oidc.md) explains the sealed flow cookie, the link and step-up checks and the limits on outbound calls.
- [Non-goals](docs/non-goals.md) gives the reason for each feature left out.

## Contributing

Issues and pull requests are welcome. The [shared contributing rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) apply.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI assistance. The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
