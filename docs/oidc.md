# OIDC sign-in

The `oidc` package signs a user in with an OpenID Connect provider, on [coreos/go-oidc](https://github.com/coreos/go-oidc). This page explains how a flow travels from start to callback, what the provider must prove for a link or a step-up, and how outbound calls are bounded. Read it before you wire the start and callback routes yourself. The `accesshttp` package wires them for you.

## The provider

`oidc.NewProvider` takes an `oidc.Config` and runs discovery. `Config.Validate` requires a client ID and an `https` issuer and redirect URL. It also accepts `http` on a loopback host, such as a local test provider. `Scopes` defaults to `openid`, `profile` and `email`, and a list you set must include `openid`.

Discovery fails with `ErrDiscovery` when the document's `authorization_endpoint`, `token_endpoint` or `jwks_uri` is not an absolute `https` URL with a host and no user information. The error names the field. A loopback `http` endpoint is accepted only while the issuer is itself a loopback `http` URL.

A `Provider` does not change after `NewProvider` returns. When the settings change, build a new one and swap the pointer.

## The flow cookie

`Provider.Begin` seals the flow's state, nonce and PKCE verifier into one cookie, with what the flow is for. It returns the URL to send the browser to, and nothing is stored on the server. The cookie's name comes from your session cookie config through `session.Derive("oidc", http.SameSiteLaxMode)`, so it follows the session cookie's posture and never collides with it. It is `HttpOnly` and expires after 10 minutes. It is `SameSite=Lax`, because the provider sends the browser back with a cross-site navigation.

`Config.FlowSealer` seals the cookie. When you leave it nil, each `Provider` gets its own ephemeral sealer, and a flow begun under one provider value cannot finish under a rebuilt one. If you rebuild providers while flows are in flight, pass one sealer that outlives them.

`Begin` refuses each of these before it sets any cookie:

- a `Redirect` longer than `MaxRedirectBytes`, which is 512, with `ErrRedirectTooLong`
- a session cookie config that fails `Validate`, with `ErrConfigInvalid`
- a `BeginRequest` whose intent is unknown, or whose session ID and user ID do not fit its intent, with `ErrFlowInvalid`. A sign-in carries neither, and a link or step-up needs both, with a positive user ID.
- a link or step-up request whose `Sec-Fetch-Site` header is present and is not `same-origin`, with `ErrFlowInvalid`
- a flow that the sealer refuses as too large, with `ErrConfigInvalid`, which also matches `access.ErrSealTooLarge`
- a flow cookie whose name and value together pass 4096 bytes, the most a browser keeps, with `ErrConfigInvalid`

The redirect goes through `access.ValidateRedirectURI`, so an unsafe path becomes `/`.

## The callback

Decode the callback's query once and pass its `state`, `code` and `error` values to `Provider.Finish` as an `oidc.Callback`. `Finish` never reads the request URL. It reads and clears the flow cookie on every outcome, then takes these steps:

1. It opens the cookie. A cookie that is missing, forged, expired or duplicated fails with `ErrFlowInvalid`, and so does one sealed by a provider with another issuer, client ID or redirect URL.
2. It compares the state, and only then reads the provider's error. That error becomes a `*ProviderError` whose `Code` is one of the RFC 6749 codes or `other`. The `error_description` is never read.
3. It exchanges the code with the PKCE verifier. A failure is `ErrExchange`.
4. It verifies the ID token's signature, issuer and expiry. The only audience must be your client ID, and a present `azp` must equal it. An empty subject fails with `ErrTokenInvalid`, and another nonce with `ErrNonceMismatch`.

An error from step 2 on comes with the opened `Flow`, so you can send the browser back to the page the flow began on. Before that, the `Flow` is zero.

## Linking and step-up

A link adds a sign-in method to an account and a step-up proves the user again. Both need proof that the user signed in at the provider just now, rather than a silent single sign-on answer. For `IntentLink` and `IntentStepUp`, `Begin` sends both `max_age=0` and `prompt=login`. `Finish` then requires an `auth_time` claim no earlier than 60 seconds before the flow began, and a missing or older one is `ErrStaleAuthentication`.

Providers honour different parameters, which is why both are sent. Authentik 2026.8.3 ignores `max_age=0` and honours `prompt=login`. On Authentik the forced sign-in comes from `prompt=login`, and the `auth_time` check proves that it happened.

## Outbound calls

Discovery, the key-set fetch and the token exchange all use `Config.HTTPClient`, or a default client when it is nil. The provider works on a copy, so your client is never changed. The copy differs from yours in two ways:

- A zero `Timeout` becomes 10 seconds. A negative one is refused.
- The transport is wrapped so that a response body past 1 MiB is refused, whether or not the response declares its length.

`CheckRedirect`, `Jar` and the transport's own dialer and TLS settings stay as you set them. A transport you pass that guards against server-side request forgery still sees every request.

## Provisioning and usernames

`Provisioning` decides whether an identity with no account may get one, and its zero value is off. With `Claim` set, `Admit` admits a token whose claim holds one of `AllowedValues`, as a string or in an array of strings. `Validate` refuses a `Claim` without `AllowedValues`, `AllowedValues` without a `Claim`, and a `Role` other than empty, `access.RoleUser` or `access.RoleAdmin`.

`UsernameCandidate` proposes a username. It takes `preferred_username` when present, or else the email when `email_verified` is true, and normalises it with `access.NormalizeUsername`. It returns `ErrNoUsername` when neither applies. When the chosen value does not normalise, it returns a `*UsernameError` naming the claim.
