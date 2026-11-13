# Passwords, sessions and tokens

This page explains each building block of the root package and of the `oidc` package. For each one it says what it does, what it returns and the rule a caller must keep. Read it when you write the handlers around them. Signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/access), and the defaults are on the [Configuration](configuration.md) page.

## Secrets and hashes

Every plaintext credential the library hands you is an `access.Secret`, and every stored credential hash is an `access.Hash`. Every way of printing either one, the `fmt` verbs, `slog`, `encoding/json` and reflection-based printers included, shows `[redacted]` or masked bytes, so neither leaks into a log by accident. Only `Reveal()` returns the text: call it at the boundary where the value leaves your process, a cookie, a response body or a store column. `NewSecret` and `NewHash` wrap a string you decoded yourself.

`==` does not compile on either type. Compare hashes with `Hash.Equal`, which runs in constant time, and key an in-memory map on `Hash.Key()`. Neither type has a JSON or text decoder, so a struct holding one cannot be filled from untrusted JSON by accident.

## Sealed cookies

`access.Sealer` seals short payloads with AES-256-GCM under a ring of 1 to 4 keys of `SealerKeySize` bytes. The first key seals and every key opens, so you rotate by putting the new key first and keeping the old one second until every cookie it sealed has expired. `GenerateSealerKey` returns a new key to persist, and `NewSealer` builds the ring from your persisted keys. `NewEphemeralSealer` uses one random key that nobody else holds, so what it sealed cannot be opened after a restart. Each `Seal` binds a purpose and an expiry, and `Open` refuses a payload sealed for another purpose or past its expiry.

The OIDC flow cookie, the pending-link cookie and the trusted-device cookie are sealed this way. Pass a sealer over persisted keys where a restart should keep them working: `ratelimit.Config.Devices` requires one.

## Passwords

`Hasher.Hash` hashes a password with Argon2id and returns its PHC string as an `access.Hash`. `Hasher.Verify` checks a password against a stored hash and also reports whether the hash was made with other parameters, and `Hasher.NeedsRehash` reports that alone. `Hash` and `Verify` wait for room in the hasher's `HashBudget`, which bounds the memory all Argon2 work sharing it holds at once, and return `ErrHashBusy` when none comes in time.

When the username does not exist, verify the password against the zero `access.Hash`. That derives once at the hasher's parameters and fails, so an unknown username takes as long to refuse as a wrong password.

`ValidatePasswordLength` requires at least 15 characters and allows 128 at most, counted in runes after Unicode NFC normalization. A refused password returns a `*PasswordError` whose `Reason` is `too_short` or `too_long`, with the bounds in `Min` and `Max`.

`ValidatePasswordContext` refuses a password that is a forbidden word or the username, or a simple variant of one: the word with digits, spaces or punctuation around it, or the word repeated. It compares the whole password after the NFC normalization `Hasher` applies and case folding, so every Unicode spelling of the same characters gets the same answer. A password that only contains the word is accepted, as is the word wrapped in symbols such as emoji. The username counts when it has four characters or more. A word or username made only of digits, spaces and punctuation refuses only a password equal to it. A refusal is a `*PasswordError` with `Reason` `contains_forbidden_word` or `contains_username`. Its zero `PasswordContext` checks nothing at all, so fill every field the account has.

`ValidatePasswordCommon` refuses a password on the package's built-in list of common passwords, with a `*PasswordError` whose `Reason` is `common`. The list holds the most frequent passwords of 15 characters or more from [SecLists](https://github.com/danielmiessler/SecLists) (MIT), and the comparison runs after NFC normalization and case folding, so neither case nor Unicode spelling changes the answer. It ships inside the package and reads nothing over the network; the copy names the SecLists commit it came from and is regenerated with `go generate`.

`CheckBreachedPassword` asks the Have I Been Pwned Passwords API whether a password appears in a breach. It sends only the first five characters of the SHA-1 hash of the password's NFC form, the k-anonymity range request, so two spellings of the same characters get the same answer. It never logs and never follows a redirect. When it gets no answer, because the client is nil, the request times out or fails, the status is not 200 or the body is over 2 MiB, it returns an error wrapping `ErrBreachCheckUnavailable` whose text names the cause. When your context was cancelled or its deadline passed, the error also wraps `context.Canceled` or `context.DeadlineExceeded`, so `errors.Is` tells a walk-away from an unavailable service. Your policy decides whether to accept the password.

## Usernames

`NormalizeUsername` decides whether two usernames are the same account. It applies the `UsernameCaseMapped` profile of the PRECIS IdentifierClass from RFC 8265, a standard rule for comparing usernames.

- Case folds across the whole of Unicode, so `Müller` and `MÜLLER` are one account.
- Nothing is transliterated, so `straße` and `strasse` stay two accounts.
- A username containing a space is refused. The characters `.`, `-` and `_` are allowed.
- An empty result returns `ErrUsernameEmpty`, and a refused character returns `ErrUsernameInvalid`.
- It sets no length limit and does not refuse a name that looks like another account's name in a different script. Both policies are yours.

Apply it on both sides of the comparison. Apply it to the key of your unique-username index, and again to the login input before the lookup.

## Sessions

`GenerateSessionToken` returns a 256-bit random token and its SHA-256 hash, with no error. Put the token in the cookie and store only the hash. `SessionHash` turns the cookie value back into the hash you look up.

`ValidateSession` checks a session against a `SessionTimeouts` value holding the idle and absolute timeouts. A recovery session gets at most 15 minutes of each, and a session's own `IdleCap` and `AbsoluteCap` lower them further. `SessionDeadlines` returns the two instants after which the session expires. Fill both timeouts. A zero field expires every session, so a mistake locks users out instead of letting them in.

The session verifier inside `Authenticator` refuses a session whose user is disabled or missing, and a session past its idle or absolute deadline, which `ValidateSession` decides. A store failure is `ErrAuthBackend`, which `RequireAuth` answers with a 503. A recovery session signs in only on a request whose context carries `AllowRecoverySession`.

## One-time tokens

`GenerateOpaqueToken` returns a random token and its SHA-256 hash, for password-reset and email-verification links. Send the token to the user and store the hash. `VerifyOpaqueToken` checks a token against the stored hash and its expiry time, and returns `ErrTokenInvalid` or `ErrTokenExpired`.

## API keys

`GenerateAPIKey` returns a `GeneratedKey`. Its `Plaintext` is the key, your prefix in front of 256 random bits, held as an `access.Secret`. Its `Hash` is the key's SHA-256 hash as an `access.Hash`. `DisplayPrefix` and `DisplaySuffix` are the first 8 and last 4 bytes of the key, for display. The prefix can be up to 16 ASCII letters, digits and underscores, so the display parts are ASCII too. Any other prefix returns `ErrInvalidKeyPrefix`. Store the hash and show the key once.

`VerifyAPIKey` hashes a key, looks it up in your store, compares the stored hash in constant time and checks the expiry. A missing or mismatched key returns `ErrInvalidAPIKey`, and so does a store that reports a match with no key. A key with an `ExpiresAt` is refused from that instant on, and `ExpiresAt` left at its zero value means the key never expires.

The `Authenticator` reads an API key from an `Authorization: Bearer` header only, with the scheme matched in any case. A key in a URL query parameter ends up in server logs and browser history, CWE-598, so it is never accepted. A key it cannot use is refused with `ErrInvalidCredential`, whose `*InvalidCredentialError` carries nothing of the value presented. When the store found the key, the error names it by its `KeyID`: an expired key, or a key whose owner is missing or disabled. It accepts only a value `GenerateAPIKey` could have returned: a valid prefix, then 64 lowercase hex characters. Any other Bearer value is refused without a store lookup. A use records the key's last use through `TouchAPIKey` once the stored last use is an activity-throttle window old.

## Guards

`Authenticator.Authenticate` returns the request's `Principal`. It runs the session verifier, the `Config.Verifier` verifier if you set one, then the API-key verifier, and returns the first principal granted. A verifier error matching `ErrUnauthenticated` means a credential was presented but is no longer usable. The chain continues, and that error is the result if nothing later grants. `ErrInvalidCredential`, a refused credential, and `ErrAuthBackend`, a store failure, stop the chain. A principal whose user is missing or disabled, or whose `Method` is empty, is refused with `ErrInvalidCredential`. The principal's `User` and `Scopes` are copies, so a handler may change them without reaching another request. `RequireAuth` does the same and writes the refusal for you.

`ErrorFor` maps an error `Authenticate` returned to the `access.Error` the library answers it with: no credential is `auth_required`, a session cookie whose session is gone `auth_session_expired`, a refused key `auth_key_invalid`, any other refused credential `auth_invalid_credentials`, a recovery session `auth_session_required`, and a store failure 503 `auth_unavailable` with a five-second `RetryAfter`. Its `Reason` is always empty, so the answer never says which keys or sessions exist. It reports false for any other error. `NewError` builds the `Error` for any code in `Codes()`, with the status, detail and `RetryAfter` of the code table, for an app that answers a refusal of its own in the same envelope. `Authenticator.Challenge` sets the `WWW-Authenticate` header for a refusal's code before your `ErrorWriter` runs: `error="invalid_token"` only for a refused API key, `error="insufficient_scope"` with the scope for a key that lacks one, the bare `Bearer realm="R"` for every other 401, and nothing for any other code. The realm is `Config.Realm`.

`Principal.IsSession` is true only for a full session from the built-in session verifier, so a custom verifier cannot pose as one. `RequireRecentAuth` passes only such a principal whose `AuthTime` is within the age you give and not in the future. `Authenticator.ClientAddr` returns the `Config.ClientAddr` resolver's answer for a request. Its `Via` says how the request reached you, `IP()` is the client's address, and `ClientKnown()` reports whether that address is the client itself, as [the configuration page](configuration.md#authenticator-configuration) describes.

A principal's `IdleDeadline` and `AbsoluteDeadline` are when it lapses. A session's come from its timeouts and caps, and a key's `AbsoluteDeadline` is its `ExpiresAt`. Wrap a request's context with `Passive` to verify it without counting it as session activity, for polling and presence requests. `Authenticator.Recheck` checks a principal again for a long-lived connection, returns its current deadlines and writes nothing.

`HasRole` checks a user's role. The two roles are `RoleUser` and `RoleAdmin`, and an admin passes every role check.

`ValidateRedirectURI` returns the path you pass when it is a safe relative path of 2048 bytes or fewer with no ASCII control character anywhere, its fragment included, and `/` for anything else. Pass the `next` value from a sign-in form through it before you redirect, and write the result as the `Location` header yourself, with each byte of 0x80 or above percent-escaped as `%XX`, since a `Location` holds ASCII only: `http.Redirect` escapes those bytes but also cleans dot segments inside a fragment, so `/settings#/../../admin` would land on `/admin`.

`CanDisableMethod` reports whether a user keeps at least one way to sign in after you turn one off. It takes a `MethodAvailability` value that describes what remains after the change: the password, the OIDC link and the passkeys other than the one you remove. A user with two passkeys can remove one of them. If you pass a count that includes the passkey being removed, that passkey counts as remaining. The zero value refuses every change.

`IsBrowserRequest` reports a request whose `Accept` header contains `text/html` and that carries no `Authorization` header.

## OIDC sign-in

The `oidc` package signs a user in with an OpenID Connect provider, on [coreos/go-oidc](https://github.com/coreos/go-oidc). `Provider.Begin` seals the flow into a cookie and `Provider.Finish` completes it on the callback, so nothing is stored on the server. The [OIDC sign-in](oidc.md) page explains the flow, the link and step-up checks and the outbound-call bounds.
