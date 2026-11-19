# Passkeys

The `webauthn` package runs passkey registration, sign-in and step-up. It is a [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) relying party written on Go's standard library, its CBOR decoder and COSE key parser included. This page explains how a ceremony checks the browser's origin, what registration and sign-in check, where access departs from the specification, and which errors you can branch on. Read it before you write the passkey handlers.

## The relying party

`webauthn.New` takes an `RPConfig` with an `ID`, a `DisplayName`, and optionally `Origins` or `AllowSubdomains`, and returns a `*RelyingParty`. `ID()` reports the relying-party ID it was built with.

`ValidateRPID` decides whether a value can be a relying-party ID, a valid domain in the [WHATWG URL](https://url.spec.whatwg.org/#valid-domain) sense spelled in lowercase:

- at most 253 bytes, with no scheme, port, path, query or fragment, and not an IP address;
- labels of 1 to 63 lowercase letters, digits and hyphens, none starting or ending with a hyphen, and none with hyphens in both its third and fourth places unless it starts with `xn--`, so `ab--cd.example` and `exa_mple.com` are refused;
- a last label that is not a number, so `example.123`, `example.0x1` and `example.0x` are refused, since a browser reads each as an IPv4 address;
- a single label only as `localhost`.

An `xn--` label is accepted as written and not decoded, the one place access admits more than WHATWG's strict rule; a wrong one fails at the browser. Every refusal matches `ErrIllegalRPID` and states its reason. `New` refuses an empty ID, and an illegal one with the same `ErrIllegalRPID` error.

## The origin a ceremony expects

A ceremony expects the origin it was begun at. Parse the request's `Origin` header with `ParseOrigin` and pass the result to the `Begin` call. The `origin` member of the response's client data must then equal that origin's serialization, `Origin.String()`, byte for byte, so you never list the expected origins in advance. A response made at another origin is refused, even one your origin policy also admits.

`ParseOrigin` refuses rather than repairs. It folds ASCII case and drops a default port, as a browser does when it serializes an origin, so `String()` is the form the client data carries. It refuses a trailing dot, an empty label and a non-ASCII host, each with its own `OriginRejection`.

It refuses as malformed a host that is neither a hostname nor an IP address. A hostname is dot-separated labels of letters, digits, `-` and `_`, and its last label is not a number, because a browser reads such a host as an IPv4 address. An IP address has no zone and is spelled as a browser serializes it, so `[::ffff:102:304]` is accepted and `[::ffff:1.2.3.4]` is refused. An invalid port, a path other than `/`, a query, a fragment, user information and any scheme other than `http` or `https` are malformed too. The error is an `*OriginError`.

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

`NewUser` wraps an `access.User` and its stored passkeys. `BeginRegistration`, `BeginLogin`, `BeginConditionalLogin` and `BeginReauthentication` each take the browser origin as their last argument. `BeginConditionalLogin` is the autofill form of sign-in, called conditional mediation. `BeginReauthentication` is the step-up form: it asks the signed-in user for one of their own passkeys, and refuses a user who holds none.

Each `Begin` call returns two values. `CredentialCreation` or `CredentialAssertion` holds the options for the browser, restating the WebAuthn dictionaries of sections 5.4 and 5.5, and serializes exactly as the browser expects. `Ceremony` is an opaque handle you keep between the two halves. It holds a 32-byte random challenge, the origin, the user handle and, for a step-up, the user's credential IDs, and only the finish of its own kind accepts it. Evict it from your ceremony store at `Ceremony.Expires()`, five minutes after `Begin`, so the deadline the authenticator received and the one your store enforces stay the same. `BeginRegistration` and `BeginReauthentication` refuse a user handle outside 1 to 64 bytes.

`FinishRegistration` returns an `access.PasskeyCredential` ready to store. Set its `Name` first with `PasskeyFriendlyName`. It names a known passkey provider from its AAGUID, such as `Chrome on Mac`, numbered from the second passkey of that provider (`Chrome on Mac 2`), and numbers every other passkey, from `Passkey 1`. It never repeats one of the user's existing names.

The provider names come from the [passkey authenticator AAGUID list](https://github.com/passkeydeveloper/passkey-authenticator-aaguids), which the passkey developer community maintains. The package ships a copy, adds three authenticators the list lacks, and reads nothing over the network. A monthly job proposes a pull request when the list changes, and each copy names the commit of the list it came from. `AuthenticatorName` returns the name for an AAGUID, and `false` when the AAGUID is unknown.

`CompleteLogin` finishes a sign-in against your `webauthn.Store`, and `CompleteReauthentication` a step-up for the user you pass, holding the passkeys stored now. Each verifies the assertion and records the custody through `RecordAssertion`, which must, in one atomic step, keep the larger of the stored and the new sign count, OR the clone warnings, and store the new flags and time. `account` implements it for you; a custom `webauthn.Store` must keep that contract, or two concurrent sign-ins can lower the count or clear a warning. Account status and session creation stay yours, so check `User.Enabled` before you create the session.

## The algorithms offered

Registration offers these COSE algorithms, in this order, so an authenticator that supports a post-quantum one creates a post-quantum credential and every other one still registers on a classical algorithm:

| Algorithm | COSE `alg` | Key |
| --- | --- | --- |
| ML-DSA-44 | -48 | AKP, RFC 9964 |
| ML-DSA-65 | -49 | AKP, RFC 9964 |
| ML-DSA-87 | -50 | AKP, RFC 9964 |
| EdDSA, Ed25519 only | -8 | OKP, RFC 9053 |
| ES256, P-256 | -7 | EC2, RFC 9053 |
| RS256, a modulus of 2048 to 4096 bits | -257 | RSA, RFC 8812 |

A credential key on any other algorithm or curve is refused. The fully specified identifiers of RFC 9864, -19 (Ed25519) and -9 (ESP256), are not offered: authenticators send -8 and -7. Each key must hold exactly its algorithm's COSE labels, as section 6.5.1 requires, so a key carrying a private member or any other extra label is refused. An EC2 key must be an uncompressed point on the curve.

## What registration checks

`FinishRegistration` follows the registration steps of WebAuthn section 7.1:

- the ceremony came from `BeginRegistration` for the finishing user and has not expired;
- the response is at most 64 KiB, its `rawId` is 1 to 1023 bytes of unpadded base64url, and its `id` is exactly that encoding of `rawId`;
- the client data has the type `webauthn.create`, the ceremony's challenge and its origin, and reports no cross-origin frame;
- the authenticator data names the relying-party ID's hash, reports the user present and verified, and attests a credential whose ID is `rawId` and whose key is one of the algorithms above. A backup state without backup eligibility is refused, here and at sign-in;
- the attestation is `none` or self attestation, `packed` with no certificate chain and a signature by the new credential's own key. Every other format, and `packed` with a certificate chain, is refused. No attestation is trusted and no metadata service is consulted: under the default conveyance the browser sends `none` or self attestation;
- a credential the client's `credProps` output reports as not discoverable is `ErrNotDiscoverable`.

Registration asks for a discoverable credential, sending `residentKey: "required"` and, for older clients that read only the earlier member, `requireResidentKey: true`, and it requires user verification. An authenticator that reports no `credProps` output is accepted, and the check reads the client extension results, so forward them from the browser for it to work.

The record keeps the credential ID, the key's bytes as received, the 16-byte AAGUID from the authenticator data, the sign count, the flags octet, the transports and the attachment. Up to 8 transports are kept, each 1 to 32 bytes with no comma; an attachment other than `platform` or `cross-platform` is stored empty. Under WebAuthn Level 3 the browser no longer zeroes the AAGUID under `none` conveyance, but nothing attests it. Your store's `CreatePasskey` refuses a credential ID already registered to any user.

## What sign-in checks

`CompleteLogin` and `CompleteReauthentication` follow the assertion steps of WebAuthn section 7.2:

- the ceremony is of the finishing call's kind and has not expired, and a step-up's ceremony was begun for the user passed in;
- a sign-in's `userHandle` is required, names the account, and that account holds the credential `rawId` names; a step-up's credential is one the ceremony allowed and the user still holds. Anything else is `ErrUnknownCredential`. A step-up's `userHandle`, when sent, must be the user's;
- the client data has the type `webauthn.get`, the ceremony's challenge and its origin;
- the authenticator data names the relying-party ID's hash, reports the user present and verified, attests no new credential, and reports the same backup eligibility as the stored flags octet, so a store that dropped the octet fails here;
- the signature verifies under the stored key, parsed again by the rules above at every sign-in;
- a sign count that does not rise, when either count is non-zero, sets `LoginResult.CloneWarning`, and the stored warning stays set.

## Strict response checks

Each response is read so that it has one meaning:

- JSON member names match exactly, case included, a duplicate member at any level is refused, and so is invalid UTF-8. Members access does not read are ignored, because the response forms grow. The client data is at most 4 KiB, and a leading byte order mark is dropped before it is parsed.
- The challenge must be the unpadded base64url of the ceremony's challenge, compared in constant time, so a padded or standard-alphabet copy is refused. `rawId`, `id` and `userHandle` must be unpadded too. The other binary members, the client data, the attestation object, the authenticator data and the signature, are accepted with trailing `=` padding, which some clients send.
- CBOR is read by a bounded decoder: a declared length past the input is refused before anything is allocated, and so are indefinite lengths, tags, integers outside the signed 64-bit range (`int64`), map keys other than integers and text, duplicate map keys, invalid UTF-8, more than 4 levels of nesting, more than 256 items, and more than 64 KiB. Anything left over after the attestation object, the authenticator data or the credential key is refused.

## Where access departs from the specification

- **CBOR's canonical form.** WebAuthn section 2.4 says a relying party SHOULD refuse CBOR not in the CTAP2 canonical form, shortest integers and lengths with map keys in length-first order. access refuses duplicate map keys, the other half of that rule, but does not check the encoding's form: it stores and verifies the bytes as received and compares decoded values, so a loose encoding still has one reading, and refusing it would refuse a working authenticator.
- **RSA's leading zero.** RFC 8230 section 4 forbids a leading zero byte in an RSA key's modulus or exponent. access reads each as the integer it encodes and accepts the zero, for the same reason.
- **Extension outputs.** WebAuthn sections 7.1 and 7.2 allow a relying party to ignore client extension outputs it did not request, or to refuse the response. access reads only `credProps.rk` at registration and ignores every other output, at registration and at sign-in. Authenticator extension outputs are checked to be well-formed CBOR and not read.

## Errors you can branch on

- `ErrUnknownCredential` reports a sign-in with a passkey you deleted on the server, or one the account does not hold. Use it to tell the client to forget that passkey. It wraps nothing.
- `ErrNotDiscoverable` reports a registration that cannot be used to sign in.
- `ErrCeremonyUnbound` reports a `Ceremony` that no `Begin` function returned, such as the zero value.
- `ErrResponseTooLarge` reports a response over `MaxResponseBytes`, 64 KiB.
- `*OriginError` reports a refused origin, and its `Reason` field names why.
- A store failure in the lookup or the custody write matches `access.ErrAuthBackend`.

## Keeping the credential manager in step

`NewSignals(rpID, user)` builds the WebAuthn Signal API payloads a client sends to keep a password manager's passkey list in step with the server. An empty accepted-credential list tells the credential manager to remove every passkey for the account, so it always serializes as `[]` and never as `null`.
