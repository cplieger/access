# Passkeys

The `webauthn` package runs passkey registration and sign-in, on [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn). This page explains how a ceremony checks the browser's origin, what registration requires and which errors you can branch on. Read it before you write the passkey handlers.

No go-webauthn type appears in this package's exported API, so your code runs a ceremony without importing go-webauthn.

## The relying party

`webauthn.New` takes an `RPConfig` with an `ID`, a `DisplayName`, and optionally `Origins` or `AllowSubdomains`, and returns a `*RelyingParty`. `ID()` reports the relying-party ID it was built with.

`ValidateRPID` decides whether a value can be a relying-party ID. It accepts a lowercase domain name with no scheme, port or path. It refuses an IP address, and a single label other than `localhost`. Every refusal matches `ErrIllegalRPID`. `New` refuses an empty ID, and an illegal one with the same `ErrIllegalRPID` error.

## The origin a ceremony expects

A ceremony expects the origin it was begun at. Parse the request's `Origin` header with `ParseOrigin` and pass the result to the `Begin` call. The response is then verified against exactly that scheme, host and port by go-webauthn's own comparison, so you never list the expected origins in advance.

`ParseOrigin` refuses rather than repairs. It folds ASCII case and drops a default port, because the comparison does the same. It refuses a trailing dot, an empty label and a non-ASCII host, each with its own `OriginRejection`. It refuses a path other than `/`, a query, a fragment, user information and any scheme other than `http` or `https` as malformed. The error is an `*OriginError`.

A ceremony that carries no bound origin fails at the finish step with `ErrCeremonyUnbound`.

## The origin policy

`CheckOrigin` runs at every `Begin` call. It applies the host rule first, then the origin set.

The host rule:

- The scheme must be `https`, or `http` for `localhost`, the specification's exception.
- The host must be a domain, never an IP address, equal to the relying-party ID or a subdomain of it. The subdomain test requires the separating dot, so `evilexample.com` is not under `example.com`.
- The port is carried into the bound origin, so a response declaring another port fails at the finish step.

The origin set, which an origin that passes the host rule must also be in:

- By default, with `Origins` empty and `AllowSubdomains` false, only the relying party's exact origin: `https://<ID>` on the default port, plus `http://localhost` when the ID is `localhost`. A sibling host under the ID, or the ID on another port, is refused with `RejectNotAllowlisted`. The [WebAuthn specification](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) recommends restricting origins this way.
- `Origins` replaces that set with your exact list, described below.
- `AllowSubdomains` widens it to every subdomain and port of the ID. Use it only when every host under the ID is yours, because any of them that can run script can then start a ceremony for your accounts.

## Listing origins with Origins

Set `RPConfig.Origins` when your service answers on an origin other than `https://<ID>`, such as a subdomain, a non-default port behind a proxy, or several hosts. An origin must then pass the host rule and also equal one listed origin on scheme, host and port, compared in `ParseOrigin`'s form. A miss is `RejectNotAllowlisted`.

`New` parses every entry. When an entry is not a usable origin, or the host rule would refuse it, `New` refuses the relying party with an `*OriginsError` that names the entry, its index and the reason, so a list never widens the host rule. `New` also refuses `Origins` and `AllowSubdomains` set together.

## Running a ceremony

`NewUser` wraps an `access.User` and its stored passkeys. `BeginRegistration`, `BeginLogin` and `BeginConditionalLogin` each take the browser origin as their last argument. `BeginConditionalLogin` is the autofill form of sign-in, called conditional mediation.

Each `Begin` call returns two values. `CredentialCreation` or `CredentialAssertion` holds the options for the browser, restating the WebAuthn dictionaries of sections 5.4 and 5.5, and serializes exactly as the browser expects. `Ceremony` is an opaque handle you keep between the two halves. Evict it from your ceremony store at `Ceremony.Expires()`, so the deadline the authenticator received and the one your store enforces stay the same.

`FinishRegistration` returns an `access.PasskeyCredential` ready to store. Set its `Name` first with `PasskeyFriendlyName`. It names a known passkey provider from its AAGUID, such as `Chrome on Mac`, numbered from the second passkey of that provider (`Chrome on Mac 2`), and numbers every other passkey, from `Passkey 1`. It never repeats one of the user's existing names.

The provider names come from the [passkey authenticator AAGUID list](https://github.com/passkeydeveloper/passkey-authenticator-aaguids), which the passkey developer community maintains. The package ships a copy, adds three authenticators the list lacks, and reads nothing over the network. Dependency-update pull requests refresh the copy, and each copy names the commit of the list it came from. `AuthenticatorName` returns the name for an AAGUID, and `false` when the AAGUID is unknown.

`CompleteLogin` finishes a sign-in against your `webauthn.Store`. It resolves the account from the user handle, verifies the assertion and writes the new sign count and flags. Account status and session creation stay yours, so check `User.Enabled` before you create the session.

## What registration requires

Registration asks for a discoverable credential with user verification. It offers the three ML-DSA post-quantum algorithms ahead of EdDSA, ES256 and RS256, so an authenticator that supports one creates a post-quantum credential, and every other authenticator still registers on a classical algorithm.

`FinishRegistration` returns `ErrNotDiscoverable` when the client reports that the new credential is not discoverable, because only a discoverable credential can complete `BeginLogin`. An authenticator that reports nothing is accepted. The check reads the client extension results, so forward them from the browser for it to work.

## Errors you can branch on

- `ErrUnknownCredential` reports a sign-in with a passkey you deleted on the server. Use it to tell the client to forget that passkey. It replaces go-webauthn's own error rather than wrapping it, so the upstream type is not reachable through it.
- `ErrNotDiscoverable` reports a registration that cannot be used to sign in.
- `ErrCeremonyUnbound` reports a ceremony with no bound origin.
- `*OriginError` reports a refused origin, and its `Reason` field names why.

## Keeping the credential manager in step

`NewSignals(rpID, user)` builds the WebAuthn Signal API payloads a client sends to keep a password manager's passkey list in step with the server. An empty accepted-credential list tells the credential manager to remove every passkey for the account, so it always serializes as `[]` and never as `null`.
