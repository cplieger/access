# access

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/access.svg)](https://pkg.go.dev/github.com/cplieger/access) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/access)](https://github.com/cplieger/access/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/access/badges/mutation.json)](https://github.com/cplieger/access/issues?q=label%3Agremlins-tracker)

access gives your Go web service its sign-in: Argon2id passwords, passkeys, authenticator-app codes, OIDC sign-in, sessions, API keys and invites, served as JSON routes you mount on your own mux, with a typed browser client. You write the storage and the pages.

It reads no environment variables, and every setting lives on the value you construct. It is licensed under Apache-2.0. It has five direct dependencies at run time: `github.com/cplieger/go/keylock`, `golang.org/x/crypto`, `golang.org/x/oauth2`, `golang.org/x/sync` and `golang.org/x/text`.

## Why use it

access is built for a Go service that owns its login pages and its database.

- Every sign-in path, password, passkey, OIDC, invite, self-registration and first-user setup, runs through one admission path, which checks the rate limits before any password is hashed.
- Passwords hash with Argon2id at OWASP's parameters. When every `Hasher` is given the same `HashBudget`, that bound is process-wide. With no `HashBudget`, each `Hasher` has its own budget of four derivations. An unknown username costs the same work as a wrong password.
- Repeated wrong passwords lock the method durably: after 100 consecutive failures for one account, method and trust context, that method is locked in that context until the user, signed in another way, re-enables it. A browser that signed in before keeps its own context, so a stranger's guesses do not lock the account's holder out.
- Your store keeps only the SHA-256 hash of each 256-bit random session token. The session cookie holds only the token, and the cookies that carry state are sealed with AES-256-GCM.
- A password sign-in from a user with an authenticator app asks for its code or a passkey before any session exists, and under `RequireSecondFactor` every password sign-in proves or binds a second factor. A recovery code or an admin's single-use temporary password lets a person back in.
- Passkey ceremonies accept only your exact origin by default.
- OIDC sign-in sends a PKCE S256 challenge, checks the ID token's nonce and keeps the flow in a sealed cookie, with nothing stored on the server.
- API keys can carry scopes, and two permissions you grant explicitly let a key manage regular users or mint narrower keys, each act attributed to the key's whole lineage. A key rotates to a new secret in place, and its old secret keeps working through a short overlap.
- Every credential is an `access.Secret` or an `access.Hash`, which print as redacted wherever they are logged.
- Sign-ins and credential, key, role and account changes append a security-log entry in the same transaction that makes the change, so the change and its record commit together, and the next failure-record sweep records each lock. The [security log](docs/security-log.md) lists what it leaves out, such as renames and failed attempts.

Consider [Authboss](https://github.com/aarondl/authboss) if you want ready-made registration and recovery flows with HTML views. Consider [Ory Kratos](https://github.com/ory/kratos) if you want identity as a separate server.

## Packages

| Package | What it does |
| --- | --- |
| `access` | The building blocks: the `Authenticator` that verifies a request, the refusal codes, the password hasher, session and API-key tokens, cookies, `Secret`, `Hash` and `Sealer` |
| `access/gate` | Guards your own routes: one table of routes, each with the class of caller it admits, answered through your error writer. It needs nothing of passkeys or OIDC |
| `account` | Sign-in, sessions, passkeys, OIDC, keys, invites, the user set and the [security log](docs/security-log.md), run over your `account.Store` |
| `accesshttp` | Every `account` operation as a JSON route with a descriptor, for your own mux |
| `ratelimit` | Per-IP, per-account and per-device limits on failed attempts, with trusted-device cookies |
| `totp` | Authenticator-app codes, RFC 6238 |
| `webauthn` | Passkey ceremonies |
| `oidc` | OpenID Connect sign-in, link, step-up and invite acceptance |
| `accesstest` | An in-memory store, the store contract suite, a test identity provider and a software passkey |
| [`@cplieger/access`](web/README.md) | The browser client for `accesshttp`'s routes |

## Install

```sh
go get github.com/cplieger/access@latest
```

For the browser client:

```sh
npm install @cplieger/access @cplieger/reactive@dev
```

## Usage

This service mounts every route under `/api/auth` and guards one route of its own. It uses the in-memory test store; yours is your implementation of `account.Store`.

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/accesshttp"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/gate"
	"github.com/cplieger/access/ratelimit"
)

func main() {
	ctx := context.Background()
	store := accesstest.NewMemStore() // use your database-backed account.Store here

	authn, err := access.New(store, access.Config{
		IdleTimeout: time.Hour,
		AbsTimeout:  24 * time.Hour,
		Cookie:      access.DefaultCookieConfig(),
	})
	if err != nil {
		log.Fatal(err)
	}
	hasher, err := access.NewHasher(access.HasherConfig{})
	if err != nil {
		log.Fatal(err)
	}
	devices, err := access.NewSealer(loadKey("device.key")) // persisted, so trusted browsers survive a restart
	if err != nil {
		log.Fatal(err)
	}
	limits := ratelimit.DefaultConfig()
	limits.Devices = devices
	limiter, err := ratelimit.New(ctx, limits)
	if err != nil {
		log.Fatal(err)
	}

	svc, err := account.New(ctx, account.Config{
		Store:         store,
		Policy:        account.RolePolicy{},
		Authenticator: authn,
		Hasher:        hasher,
		Limiter:       limiter,
		Rules:         func() account.Rules { return account.Rules{} },
		FailureKey:    loadKey("failure.key"),
	})
	if err != nil {
		log.Fatal(err)
	}

	routes, err := accesshttp.New(accesshttp.Config{
		Account:    svc,
		Errors:     writeError,
		Prefix:     "/api/auth",
		OIDCPrefix: "/api/auth/oidc",
		SignInPath: "/login",
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, rt := range routes.Routes() {
		mux.Handle(rt.Method+" "+rt.Path, rt.Handler)
	}
	app, err := gate.New(gate.Config{Authenticator: authn, Errors: writeError},
		[]gate.Route{{Name: "me", Method: http.MethodGet, Path: "/api/me", Class: gate.Session}},
		map[string]http.Handler{"me": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := gate.Principal(r.Context()) // the session the gate admitted
			_ = json.NewEncoder(w).Encode(map[string]string{"user": p.User.Username})
		})})
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/api/", app)
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", mux))
}

// writeError renders every refusal in the app's own JSON envelope.
func writeError(w http.ResponseWriter, _ *http.Request, e access.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": string(e.Code), "reason": e.Reason, "detail": e.Detail})
}

// loadKey reads a 32-byte key the app generated once with access.GenerateSealerKey.
func loadKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return b
}
```

The service ends TLS itself, so the default resolver reads each request as secure. Behind a TLS proxy, set `Config.ClientAddr` instead ([Authenticator configuration](docs/configuration.md#authenticator-configuration)): under the default `PostureSecure`, a request your resolver reads as plain HTTP is refused, and [Plain HTTP](docs/plain-http.md) explains the posture that serves one.

The gate serves `/api/me` to a signed-in session only, and answers every other request under `/api/` itself. The handler reads the request's `Principal`, which names the user, the method that authenticated it, and the session or key behind it. The `Authenticator` reads the session cookie first, then a verifier you add as `Config.Verifier`, then an `Authorization: Bearer` API key. [Guarding your own routes](docs/gate.md) explains the route classes, the codes and how to mount the gate.

Neither `accesshttp` nor the gate writes an error body itself: every refusal reaches your `ErrorWriter` as an `access.Error` with a stable `Code` and `Reason`, so the envelope is yours. You may mount any subset of the auth routes. [Configuration](docs/configuration.md#http-handlers) explains both.

## API

- `access`: `New` builds the `Authenticator` that returns a `Principal`, with the refusal types `Error`, `Code` and `ErrorWriter`, the `Hasher`, the token generators, `Secret`, `Hash` and `Sealer`.
- `access/gate`: `New` builds a `Gate` from a `Config` and a table of `Route` values, `Principal` reads the admitted caller, and `Codes` and `MountCodes` list the codes a route can answer.
- `account`: `New` builds the `Service` that runs every operation over your `Store`, and `Actor` names who performs each operation.
- `accesshttp`: `New` builds the `Handler` whose `Route` values carry each operation, and the request and view types are its wire format.
- `ratelimit`, `oidc`, `webauthn` and `totp`: the `Limiter`, the `Provider` with its `Flow`, the `RelyingParty` with its ceremony functions, and `Match` with the secret and URI helpers.
- `accesstest`: `MemStore`, the `IdP` fake and `StoreContract`.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/access).

## The limits on guessing

- The rate limiter counts failed attempts per IP address, per account and per trusted device. Its limits are exact for the `MaxEntries` keys each dimension used most recently, 10,000 by default. Past that, `MaxEntries` bounds its memory, not a spray of new keys, and the [rate limiter](docs/configuration.md#rate-limiter) section names what bounds each route.
- The durable failure cap bounds what such a spray gets: at most 100 consecutive password guesses at each account in each trust context, counted in your store before the password is checked, so a restart does not reset it.
- These are the library's own bounds. It makes no claim of conformance to a password-guessing standard.

## Security

access hardens the building blocks, and the security of your service depends on how you wire them.

- Each password hash has its own random salt. Password hashes, API keys and tokens are compared in constant time.
- The default cookie carries the `__Host-` prefix with the Secure, HttpOnly and SameSite=Lax attributes, `Path=/` and no `Domain`, on every request.
- API keys are read from the `Authorization: Bearer` header only, never from a URL query parameter.
- Every unsafe-method route applies Go's `http.CrossOriginProtection` itself, whatever your own middleware does.
- `Config.Bypass` grants a synthetic admin user, whose ID is 0 and names no stored user, to every request while its callback returns true. `account` refuses every write made under it. Keep it off in production.
- When hosts you do not control share your relying-party domain, keep the default exact origin. [Passkeys](docs/webauthn.md#the-origin-policy) explains `AllowSubdomains` and `Origins`.
- Three rules stay with you. Guard every route of your own with `access/gate`, set `ClientAddr.Secure` from where TLS ends ([Authenticator configuration](docs/configuration.md#authenticator-configuration)), and keep the store contract. [Implementing the store](docs/storage.md) states the contract, and `accesstest.StoreContract` checks it.
- Fuzz targets cover password hashes and checks, cookie settings, API keys, opaque tokens, sealed values, redirect paths, the JSON body decoder, OIDC claims, ID tokens, discovery documents and key sets, the rate limiter, TOTP codes and URIs, temporary-password and recovery-code input, and WebAuthn origins, stored credentials, and registration and sign-in responses.
- The cryptography has had no independent third-party audit.

Report a vulnerability privately through the [security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md), not in a public issue.

## Unsupported by design

These are left out on purpose. [Non-goals](docs/non-goals.md) gives the reason for each and what to use instead.

- Several processes over one store. Every read-check-write decision runs inside one store transaction, but the rate limiter's windows, the pending passkey ceremonies and the pending sign-ins and enrolments live in the process, so run one process per store.
- Page rendering. The browser client renders nothing.
- A CSRF token, because Go's `http.CrossOriginProtection` refuses cross-origin state-changing requests without needing one.
- OIDC token refresh, a registry of several providers, back-channel logout and the userinfo endpoint.
- WebAuthn metadata-service verification, attestation conveyance, filtering authenticators by AAGUID, and the passkey well-known endpoints.
- Role hierarchies and permission sets. Each user has one role, and `HasRole` passes when it matches the role a route needs or when the user is an admin.
- Encrypting or signing the session cookie, because it holds only a random token.
- SMS and email codes, and recovery by an emailed link. The library stores no phone number or address.

## Documentation

- [Guarding your own routes](docs/gate.md) explains the gate's route classes, matching, codes, challenge and audit events.
- [Configuration](docs/configuration.md) lists every setting and default, the cookie postures, the rate limiter's limits, the key permissions and the HTTP handlers' error contract.
- [Plain HTTP](docs/plain-http.md) lists what a request without TLS may do under each cookie posture, and what binding a session to its transport protects.
- [Passwords, sessions and tokens](docs/primitives.md) covers each building block in detail.
- [Implementing the store](docs/storage.md) explains the transaction boundary, the store contract and what each write costs.
- [The security log](docs/security-log.md) lists what is logged, how long it is kept, and who can read it.
- [Passkeys](docs/webauthn.md) explains how ceremonies check origins and what registration requires.
- [OIDC sign-in](docs/oidc.md) explains the sealed flow cookie, the link, step-up and invite checks and the limits on outbound calls.
- [Second factors and temporary passwords](docs/totp.md) covers authenticator apps, the recovery code and an admin's ways to let a person back in.
- [Identity and single sign-on](docs/identity.md) explains owners, the SSO mode, linking and offboarding.
- [Migrating from auth v6](docs/migration-v7.md) lists every change and its replacement.
- [Non-goals](docs/non-goals.md) gives the reason for each feature left out.

## Contributing

Issues and pull requests are welcome. The [shared contributing rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) apply.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI assistance. The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
