# OIDC sign-in

The `oidc` package signs a user in with an OpenID Connect provider. It verifies the provider's ID tokens with its own code on Go's standard library, and uses `golang.org/x/oauth2` for the code exchange and PKCE. This page explains how a flow travels from start to callback, what the provider must prove for a link or a step-up, which tokens and keys it accepts, and how outbound calls are bounded. Read it before you wire the start and callback routes yourself. The `accesshttp` package wires them for you.

## The provider

`oidc.NewProvider` takes an `oidc.Config`, runs discovery and fetches the provider's key set. `Config.Validate` requires a client ID and an `https` issuer and redirect URL. It also accepts `http` on a loopback host, such as a local test provider. `Scopes` defaults to `openid`, `profile` and `email`, and a list you set must include `openid`.

Discovery reads the issuer with one trailing `/` removed, followed by `/.well-known/openid-configuration`, so an issuer such as `https://tenant.auth0.com/` works. The document's `issuer` must equal `Config.IssuerURL` exactly, trailing slash included.

`NewProvider` fails with `ErrDiscovery` in each of these cases, and the error never names a URL:

- the document or the key set cannot be fetched, redirects, or answers with a status other than 200
- the document's `issuer` is another issuer
- the document's `authorization_endpoint`, `token_endpoint` or `jwks_uri` is not an absolute `https` URL with a host and no user information. The error names the field. A loopback `http` endpoint is accepted only while the issuer is itself a loopback `http` URL.
- the document's `id_token_signing_alg_values_supported` shares no algorithm with the table below. When the field is absent, the provider's set is `RS256`, the OpenID Connect default.
- the key set holds no usable key

`Config.Logger` receives the key set's warnings, described in "The key cache". When it is nil, each warning goes to `slog.Default()` as it is at that moment.

A `Provider` does not change after `NewProvider` returns. When the settings change, build a new one and swap the pointer.

## The flow cookie

`Provider.Begin` seals the flow's state, nonce and PKCE verifier into one cookie, with what the flow is for. It returns the URL to send the browser to, and nothing is stored on the server. The cookie's name comes from your session cookie config through `session.Derive("oidc", http.SameSiteLaxMode)`, so it never collides with the session cookie. `Begin` and `Finish` always use its secure name, `__Host-<Name>_oidc` with Secure, because every OIDC route needs a secure request under both postures: over plain HTTP the browser drops the cookie and the flow fails closed. It is `HttpOnly` and expires after 10 minutes. It is `SameSite=Lax`, because the provider sends the browser back with a cross-site navigation.

`Config.FlowSealer` seals the cookie. When you leave it nil, each `Provider` gets its own ephemeral sealer, and a flow begun under one provider value cannot finish under a rebuilt one. If you rebuild providers while flows are in flight, pass one sealer that outlives them.

`NewProvider` sizes the cookie before discovery. It refuses with `ErrConfigInvalid` a configuration whose largest flow the sealer refuses as too large, which also matches `access.ErrSealTooLarge`. It also refuses a configuration whose largest sealed flow plus the longest flow-cookie name a valid session cookie config gives passes 4096 bytes, the most a browser keeps. A long issuer, client ID or redirect URL is what pushes a flow past these limits, so `Begin` never refuses a flow for its size.

`Begin` refuses each of these before it sets any cookie:

- a `Redirect` longer than `MaxRedirectBytes`, which is 512, with `ErrRedirectTooLong`
- a session cookie config that fails `Validate`, with `ErrConfigInvalid`
- a `BeginRequest` whose intent is unknown, or whose session ID and user ID do not fit its intent, with `ErrFlowInvalid`. A sign-in carries neither, and a link or step-up needs both, with a positive user ID.
- a link or step-up request whose `Sec-Fetch-Site` header is present and is not `same-origin`, with `ErrFlowInvalid`

The redirect goes through `access.ValidateRedirectURI`, so an unsafe path becomes `/`.

## The callback

Decode the callback's query once and pass its `state`, `code` and `error` values to `Provider.Finish` as an `oidc.Callback`. `Finish` never reads the request URL. A session cookie config that fails `Validate` is `ErrConfigInvalid`, with no cookie set. Past that check, `Finish` reads and clears the flow cookie on every outcome, then takes these steps:

1. It opens the cookie. A cookie that is missing, forged, expired or duplicated fails with `ErrFlowInvalid`, and so does one sealed by a provider with another issuer, client ID or redirect URL.
2. It compares the state, and only then reads the provider's error. That error becomes a `*ProviderError` whose `Code` is one of the RFC 6749 codes or `other`. The `error_description` is never read.
3. It exchanges the code with the PKCE verifier. A failure is `ErrExchange`.
4. It verifies the ID token's signature, as "Parsing a token" describes, then checks its claims, as "The ID-token claims" describes. A refused token is `ErrTokenInvalid`, a nonce that differs from the sealed one is `ErrNonceMismatch`, and a link or step-up without fresh authentication is `ErrStaleAuthentication`.

An error from step 2 on comes with the opened `Flow`, so you can send the browser back to the page the flow began on. Before that, the `Flow` is zero.

## Linking and step-up

A link adds a sign-in method to an account and a step-up proves the user again. Both need proof that the user signed in at the provider just now, rather than a silent single sign-on answer. For `IntentLink` and `IntentStepUp`, `Begin` sends both `max_age=0` and `prompt=login`. `Finish` then requires an `auth_time` claim no earlier than 60 seconds before the flow began, and a missing or older one is `ErrStaleAuthentication`.

Providers honour different parameters, which is why both are sent. Authentik 2026.8.3 ignores `max_age=0` and honours `prompt=login`. On Authentik the forced sign-in comes from `prompt=login`, and the `auth_time` check proves that it happened.

## Outbound calls

Discovery, the key-set fetch and the token exchange all use `Config.HTTPClient`, or a default client when it is nil. The provider works on a copy, so your client is never changed. The copy differs from yours in two ways:

- A zero `Timeout` becomes 10 seconds. A negative one is refused.
- The transport is wrapped so that a response body past 1 MiB is refused, whether or not the response declares its length.

`Jar` and the transport's own dialer and TLS settings stay as you set them. A transport you pass that guards against server-side request forgery still sees every request.

Discovery and the key-set fetch follow no redirect, and they never call your `CheckRedirect`. A redirect, or any answer other than 200, is a failed fetch whose body is never read. Every key-set request sends `Cache-Control: no-cache`, so a caching proxy cannot serve a stale set. The token exchange keeps your `CheckRedirect`.

## Accepted algorithms

A token's header names one algorithm. The key that verifies it must be of that algorithm's key type and curve, and a key that carries its own `alg` must name that algorithm.

| `alg` | Key | Hash | Signature |
| --- | --- | --- | --- |
| `RS256`, `RS384`, `RS512` | RSA | SHA-256, SHA-384, SHA-512 | RSASSA-PKCS1-v1_5, as long as the modulus |
| `PS256`, `PS384`, `PS512` | RSA | SHA-256, SHA-384, SHA-512 | RSASSA-PSS with a salt the size of the hash, as long as the modulus |
| `ES256`, `ES384`, `ES512` | EC on P-256, P-384, P-521 | SHA-256, SHA-384, SHA-512 | `R` and `S` side by side, exactly 64, 96 or 132 bytes, never DER |
| `EdDSA` or `Ed25519` | OKP on Ed25519 | none | 64 bytes |

`EdDSA` and `Ed25519` name the same algorithm, so either header verifies under a key that names the other. Every other name, `none` and every `HS256`, `HS384` and `HS512` included, is refused, because a client secret is not a signing key here. The provider's set is the document's `id_token_signing_alg_values_supported` intersected with this table.

## Keys

`NewProvider` fetches the provider's JSON Web Key Set from `jwks_uri` and judges each key once. The rows apply in order, and the first that matches decides.

| The key | Result |
| --- | --- |
| an `RSA`, `EC` or `OKP` key that carries a private member: `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k` or `priv` | the whole set is refused |
| more than 100 keys, or an entry of `keys` that is not an object | the whole set is refused |
| a key type or curve outside the table above, such as `oct`, Ed448, X25519 or secp256k1 | skipped |
| a required member that is missing or of the wrong type | skipped |
| `use` present and not `sig`, or `key_ops` present and without `verify` | skipped |
| `alg` present and not an algorithm of the table, or one of another key type | skipped |
| RSA with a modulus under 2048 or over 4096 bits, an even exponent, or one below 3 or above 2^31 minus 1 | skipped |
| RSA whose modulus has the fingerprint of the Infineon key generator flaw, CVE-2017-15361, whose private key can be recovered | skipped |
| EC whose `x` or `y` is not exactly 32, 48 or 66 bytes for its curve, or whose point is not on the curve | skipped |
| Ed25519 whose `x` is not 32 bytes, or encodes one of the curve's eight small-order points, under which one signature verifies any message | skipped |
| any other key | usable |

A key with no `use` and no `key_ops` is usable. A refused set, or one left with no usable key, fails `NewProvider`.

## Parsing a token

`Finish` checks the ID token in this order, and each refusal is `ErrTokenInvalid`:

1. The token is at most 64 KiB, holds only base64url characters and exactly two `.` separators. A five-part JWE is refused here.
2. Each part decodes as unpadded base64url with no stray bits, so only one encoding of a signature passes.
3. The header is a JSON object. `alg` is a required string, and `kid` an optional string. `crit` is refused in any form, `[]` and `null` included. A `typ`, when present, is `JWT` or `application/jwt`, in any case. `jku`, `jwk`, `x5u` and `x5c` are ignored, so a key is never taken from a token.
4. The header's `alg` is in the provider's set, before any key is chosen.
5. The candidate keys are the usable keys that fit the `alg` and, when the header has a `kid`, carry that `kid`. A key fits when it is of the algorithm's key type and curve and, when it carries an `alg`, names that algorithm. Each is tried in turn. A token without a `kid` tries every key that fits.
6. When no candidate verifies the signature, the key set is fetched again once, as "The key cache" describes, and the result after that is final.
7. The payload, decoded only now, is a JSON object.

Every JSON document the package reads, the header, the payload, the key set and the discovery document, must be valid UTF-8 with no duplicate member name at any depth, unread members included. Member names match case-sensitively.

## The ID-token claims

A required claim that is missing, or a claim of the wrong type, refuses the token before any claim is compared.

| Claim | Required | Rule |
| --- | --- | --- |
| `iss` | yes | a string equal to `Config.IssuerURL`, with the Google exception below |
| `sub` | yes | 1 to 255 ASCII characters with no control character |
| `aud` | yes | a string, or a non-empty array of strings, each equal to your client ID |
| `azp` | no | a string equal to your client ID |
| `exp` | yes | a time, and now is before it plus 5 minutes |
| `iat` | yes | a time no later than now plus 5 minutes |
| `nbf` | no | a time no later than now plus 5 minutes |
| `nonce` | yes | a string equal to the sealed nonce |
| `auth_time` | for a link and a step-up | a time no earlier than 60 seconds before the flow began |
| `email`, `preferred_username`, `name` | no | a string |
| `email_verified` | no | a boolean, or the string `"true"` or `"false"` |

A time is a JSON number of seconds from 0 to 253402300799, the last second of the year 9999. Now is `Config.Now()`. A `null` reads as absent on `nbf`, `auth_time`, `email`, `email_verified`, `preferred_username` and `name`, and as the wrong type on every other claim the table names. A missing, `null` or non-string `nonce` is `ErrTokenInvalid`, and a different string is `ErrNonceMismatch`. Any other claim is never type-checked and stays in `Claims.Raw`. `at_hash` is not checked, because the access token is never used.

Google documents two forms of its ID tokens' `iss`. With `Config.IssuerURL` exactly `https://accounts.google.com`, a token whose `iss` is `accounts.google.com` is accepted too. `Claims.Identity.Issuer` is always `Config.IssuerURL`, so both forms give one identity.

## The key cache

The key set read at `NewProvider` is cached and used until a fetch replaces it. A fetch happens in two cases:

- A token no cached key verifies fetches the set again and tries it once more. A provider's new key therefore verifies as soon as the provider publishes it.
- A token that verifies from a set older than 24 hours starts a fetch in the background, and that sign-in does not wait for it.

Fetches share one gate, which allows at most one attempt every 60 seconds of `Config.Now()`, whatever starts it and whatever its result. The fetch at `NewProvider` does not count, so a key that rotates seconds after start verifies at once. A key that rotates within a minute of an earlier attempt verifies once the minute has passed, and `Finish` answers `ErrTokenInvalid` meanwhile. A clock that steps back opens the gate and the 24-hour age at once.

Every sign-in waiting for a fetch shares one request, and none can cancel it. Each waiter still returns when its own request's context ends. Nothing runs in the background once a fetch ends, so a `Provider` has no `Close`.

A failed fetch keeps the last good set and logs a warning on `Config.Logger`. A set that holds no usable key counts as a failed fetch. The fetch also logs a warning when two keys share a `kid` and fit one algorithm, and both are tried.

A key the provider retires keeps verifying from the cache until the first successful fetch after the set is 24 hours old, or an earlier fetch for an unknown key.

## Provisioning and usernames

`Provisioning` decides whether an identity with no account may get one, and its zero value is off. With `Claim` set, `Admit` admits a token whose claim holds one of `AllowedValues`, as a string or in an array of strings. `Validate` refuses a `Claim` without `AllowedValues`, `AllowedValues` without a `Claim`, and a `Role` other than empty, `access.RoleUser` or `access.RoleAdmin`.

`UsernameCandidate` proposes a username. It takes `preferred_username` when present, or else the email when `email_verified` is true, and normalises it with `access.NormalizeUsername`. It returns `ErrNoUsername` when neither applies. When the chosen value does not normalise, it returns a `*UsernameError` naming the claim.

## Changes from earlier versions

Earlier versions verified tokens with `coreos/go-oidc`, and these behaviours changed:

- `NewProvider` also fails when the key set cannot be fetched or holds no usable key, and when the provider's algorithms share nothing with the table above.
- A provider that signs outside the table, with `HS256` or EdDSA on Ed448, while it lists an accepted algorithm, now fails at `Finish` with `ErrTokenInvalid`.
- `exp` gains 5 minutes of grace. An `iat` more than 5 minutes ahead, a missing `iat` or `exp`, and an empty `aud` array are now refused. `nbf` keeps its 5 minutes.
- A `sub` that is not 1 to 255 ASCII characters is refused. A provider set to send a username as `sub`, such as Authentik's mode based on the user's username, can produce one.
- A token with no `nonce`, or a `null` one, now fails with `ErrTokenInvalid` where it failed with `ErrNonceMismatch`. Both are refused on every intent.
- Discovery and key-set redirects are refused, and a status other than 200 is a failed fetch.
- PS256, PS384 and PS512 accept only a salt the size of the hash, where any salt length passed before.
- A key set that holds a key access cannot use, such as an `oct` key or a malformed RSA, EC or Ed25519 key, now verifies with that key skipped, where it failed the whole set before.
- An RSA key with a modulus under 2048 bits is now skipped (RFC 7518 §3.3). A provider that signs only with one fails `NewProvider` with `ErrDiscovery`, so rotate it to a key of 2048 bits or more.
- An RSA key with the CVE-2017-15361 fingerprint, and an Ed25519 key of small order, are now skipped.
- A key whose `alg` names another algorithm than the token's header no longer verifies it, where any key of the right type did before (RFC 8725 §3.1). Publish the key with the algorithm the provider signs with, or without an `alg`.
- An ID token over 64 KiB is refused with `ErrTokenInvalid`.
- A token under an unknown key fetches the key set at most once a minute, where every such token fetched it before. A key a provider serves late verifies once the minute has passed, and `Finish` answers `ErrTokenInvalid` meanwhile.
- A header `kid` of `""` is a key ID and matches only a key whose `kid` is `""`, where every key was tried before.
- A Google user's two `iss` forms are one identity. An identity stored with `Issuer` set to `accounts.google.com` no longer matches. That user signs in as new, unless you rewrite the stored issuer to `https://accounts.google.com`.
- A header `kid` or `typ` of `null`, a `typ` other than `JWT` or `application/jwt`, and a `crit` header in any form are refused.
- A header or payload with a duplicate member name or invalid UTF-8 at any depth is refused, a custom claim included.
- A retired key verifies from the cache until the first successful fetch after the set is 24 hours old, or an earlier fetch for an unknown key. A failed fetch keeps it.

These stay as they were:

- the discovery URL for an issuer with a trailing slash
- Google's `iss` without a scheme
- a token without a `kid`, tried against every key that fits, and a shared `kid`, tried across its keys
- `null` read as absent on `nbf`, `auth_time`, `email`, `email_verified`, `preferred_username` and `name`
- no type check on any claim the claim table does not name

The tests check the package against RFC 7515, 7517, 7518, 7519 and 8037, OpenID Connect Core 1.0 and Discovery 1.0, with their published examples and the Wycheproof test vectors. `THIRD_PARTY_NOTICES.md` credits the copied test data and the list of primes the CVE-2017-15361 check takes from the ROCA detector.
