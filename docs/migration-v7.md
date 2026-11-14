# Migrating from auth v6

access changes the API of every package of auth v6, so a v6 caller does not compile against it unchanged. This page lists what was removed, renamed or changed, and what replaces each, for a developer moving a service from `github.com/cplieger/auth/v6`. Two packages are new: `account`, which runs sign-in, sessions, keys and the user set over your store, and `accesshttp`, which serves those operations as HTTP routes you mount yourself. Every symbol in them is new.

Change every import from `github.com/cplieger/auth/v6` to `github.com/cplieger/access`. The root package `auth` is now `access`, and `authtest` is now `accesstest`.

## Construction takes config structs

Functional options are gone. Each constructor takes one struct whose zero values are the defaults ([Configuration](configuration.md) lists every field).

| auth v6 | access |
| --- | --- |
| `New(store, opts...)` and `Option` | `New(store, access.Config{...})`. `New` refuses a nil store and a `Verifier` holding a nil value |
| `WithLogger`, `WithIdleTimeout`, `WithAbsTimeout`, `WithActivityThrottle`, `WithTimeoutSource` | `Config.Logger`, `IdleTimeout`, `AbsTimeout`, `ActivityThrottle`, `TimeoutSource`. The throttle also covers API-key touches |
| `WithUnauthorizedResponse(func(w, r))` and `WithLoginPath` | none. `access/gate` answers a refused request through your `ErrorWriter`, which can redirect a browser itself with `IsBrowserRequest` |
| `WithVerifiers([]CredentialVerifier)` | `Config.Verifier`, one verifier run between the session cookie and the API key |
| `WithBypass` | `Config.Bypass` |
| `WithCookie` | `Config.Cookie` |
| `NewSessionVerifier`, `NewAPIKeyVerifier`, `SessionVerifier`, `APIKeyVerifier` and their store interfaces | built inside `New` from its `Config`; the store side is `AuthenticatorStore` |
| `NewHasher(params, opts...)`, `HasherOption` | `NewHasher(access.HasherConfig{Params, Budget, Wait})` |
| `WithPepper` | none |
| `oidc.NewProvider(ctx, cfg, opts...)`, `oidc.Config = auth.OIDCConfig` | `oidc.NewProvider(ctx, oidc.Config{...})` with its own struct. `RedirectURI` is renamed `RedirectURL`, `ClientSecret` is an `access.Secret`, and `HTTPClient`, `FlowSealer` and `Now` are fields |
| `oidc.ValidateConfig(cfg)` | `oidc.Config.Validate()` |
| `ratelimit.New(ctx, cfg) *RateLimiter` | `ratelimit.New(ctx, cfg) (*Limiter, error)`. `Config.Devices`, the device-cookie sealer, is required |

## Secrets and hashes are their own types

Every plaintext credential is an `access.Secret` and every stored hash an `access.Hash`. Both print as redacted, neither compiles under `==`, and neither has a JSON or text decoder. Call `Reveal()` where the value leaves your process, and wrap a string you decoded with `NewSecret` or `NewHash`. Compare hashes with `Hash.Equal` and key a map on `Hash.Key()`.

| auth v6 | access |
| --- | --- |
| `User.PasswordHash`, `Session.TokenHash`, `Key.KeyHash` as `string` | `access.Hash` |
| `GenerateSessionToken`, `SessionHash`, `APIKeyHash` | the hash is an `access.Hash`, and `GenerateSessionToken`'s token an `access.Secret` |
| `GenerateOpaqueToken`, `VerifyOpaqueToken` | `GenerateOpaqueToken() (access.Secret, access.Hash)`; `VerifyOpaqueToken` takes the stored `access.Hash` |
| `GenerateAPIKey(prefix)` returning four strings | `GenerateAPIKey(prefix) (GeneratedKey, error)`, with `Plaintext` an `access.Secret` and `Hash` an `access.Hash` |
| `SessionReader.SessionByHash`, `APIKeyReader.APIKeyByHash` | take an `access.Hash` |

## Authentication returns a Principal

| auth v6 | access |
| --- | --- |
| `Authenticate` returning the user and the session hash | returns a `Principal`: the user, the method, the session or key behind it, its scopes and its deadlines |
| `RequireAuth` | `access/gate`, which guards a table of your routes and answers each refusal through your `ErrorWriter` ([Guarding your own routes](gate.md)); for a route you guard yourself, `Authenticate` and `ErrorFor` |
| `CredentialVerifier.Verify` | returns `(Principal, bool, error)`. `ok` false with a nil error means "not my credential". An error wrapping `ErrUnauthenticated` lets the chain continue |
| `ErrUnauthenticated` for every refusal | only "no usable credential". A presented key that is refused, or whose user is missing or disabled, returns `ErrInvalidCredential` with an `*InvalidCredentialError`, which names the key's ID when the store found the key |
| `HeaderXAPIKey`, the `X-Api-Key` header | `Authorization: Bearer` only |
| `AuthenticatorStore` | adds `APIKeyToucher`; activity takes a `SessionActivity` |
| `SessionActivityUpdater.UpdateSessionActivity(ctx, hash, now)` | `(ctx, access.Hash, SessionActivity)`. An older or equal time writes nothing |

New in the root package: `Principal`, `Rechecker`, `Authenticator.Recheck`, `RequireRecentAuth`, `Passive`, `AllowRecoverySession`, `ErrAuthBackend`, `ErrInvalidCredential`, `MethodAPIKey`, `MethodBypass`, `MethodRecovery`, `SessionKind`, `SessionRef`, `RecoverySessionLifetime`, `OIDCIdentity`, `OneTimeToken`, `TokenPurpose`, `KeyAttribution`, `Sealer`, `ClientAddr`, `Config.ClientAddr`, `RequestIsHTTPS` and `CookieConfig.Derive`. `Via` is new too, with its constants `ViaUnknown`, `ViaDirect`, `ViaUntrustedForwarding`, `ViaProxy` and `ViaProxyNoClient`.

The refusal vocabulary is in the root package as well, so an app that guards its own routes imports neither `accesshttp` nor the passkey and OIDC packages behind it: `Code`, every `Code…` constant and `Codes`, `Error`, `ErrorWriter`, `AuditEvent`, `NewError`, `ErrorFor`, and `Authenticator.Challenge` with its `Config.Realm`. A service built on an earlier access dev tag renames `accesshttp.Code…`, `accesshttp.Codes`, `accesshttp.Error`, `accesshttp.ErrorWriter` and `accesshttp.AuditEvent` to these `access.` names. The wire strings are unchanged. A service built on an earlier dev tag also replaces `Authenticator.RequireAuth` with `access/gate`, and drops `Config.Unauthorized`, which is gone with it. Every 401 the auth routes answer now carries a `WWW-Authenticate` challenge, and `account.New` and `Rules.Validate` refuse a key scope that is not one RFC 6750 scope-token (printable ASCII other than space, `"` and `\`). Two codes are new: 403 `auth_key_required`, a gate `Key` row reached without an API key, and 409 `auth_key_label_taken`, a key label the owner's keys already carry.

## Records

| auth v6 | access |
| --- | --- |
| `User.OIDCSub`, `User.OIDCIssuer` | `User.OIDC`, an `access.OIDCIdentity` |
| `Session.OIDCExpiry` | none; a session lives by your idle and absolute timeouts |
| `Session.IPAddress` | `Session.LastIP` |
| `Session` | gains `ID`, `AuthTime`, `Kind`, `UserAgent`, `Label`, `IssuedByKey`, `IdleCap` and `AbsoluteCap`; its JSON tags are dropped |
| `Key` | gains `Scopes`, `LastUsedAt` and `LineageIDs`, and the `ParentKeyID()` method, the key that minted it |
| `PasskeyCredential` | gains `LastUsedAt` |
| `PasskeyFlags` | `PasskeyLoginUpdate` and `DecodePasskeyFlags` |
| `OIDCConfig` | `oidc.Config` |

## Passwords

| auth v6 | access |
| --- | --- |
| `HashPassword`, `VerifyPassword`, `NeedsRehash` (functions) | `Hasher` methods |
| `Hasher.Hash(pw) string` | `Hash(ctx, pw) (access.Hash, error)` |
| `Hasher.Verify(pw, enc) (bool, error)` | `Verify(ctx, pw, enc) (ok, needsRehash bool, err error)` |
| `DummyHash` | `Hasher.Verify(ctx, pw, access.Hash{})`, which costs the same work |
| `ValidateSoloPasswordLength`, `PasswordMinLengthSolo` | `ValidatePasswordLength`, `PasswordMinLength` |
| `ValidateMultiFactorPasswordLength`, `PasswordMinLengthMultiFactor` | `ValidatePasswordLength` |
| `ValidatePasswordContext` | compares the whole password, and returns a `*PasswordError` |
| `CheckBreachedPassword` | returns an error on every failure, never logs, and treats a nil client as an error |
| `Argon2Params.Validate` | adds upper bounds and OWASP's minimum Argon2id table as the floor |

Every derivation now draws on a `HashBudget` (`NewHashBudget`, `HashCost`, `ErrHashBusy`, `ErrHashBudgetTooSmall`).

## Tokens, cookies and checks

| auth v6 | access |
| --- | --- |
| `CSRFToken`, `VerifyCSRFToken` | [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection) |
| `RotateSessionToken` | `account` rotates sessions through `SessionStore.RotateSession` |
| `ValidateSession` | has no OIDC expiry arm, and applies the recovery lifetime and a session's own caps through `SessionDeadlines` |
| `CookieConfig.TrustForwardedHeaders` | `CookieConfig.HTTPS` with `RequestIsHTTPS` |
| `PostureForceSecure` | `PostureSecure` |
| `CookieConfig.Validate`, `ReadCookie` | `Validate` applies `http.Cookie.Valid` and refuses `SameSite=None`; a duplicated cookie reads as no session |
| `CookieConfig.SetCookie` | drops a positive `maxAge` when `Persistent` answers false for the request |
| `ValidateRedirectURI` | returns `/` for input over 2048 bytes or holding an ASCII control character, in the fragment too |
| `IsBrowserRequest` | any `Authorization` header means a non-browser request |
| `CanDisableMethod` | the `MethodAvailability` you pass is what remains after the removal, so a user with two passkeys can remove one |
| `VerifyAPIKey` | a store that reports a match with no key returns `ErrInvalidAPIKey` |

## The store

The store interfaces move to `account`, and the store contract changes ([Implementing the store](storage.md)).

| auth v6 | access |
| --- | --- |
| `UserStore`, `SessionPersister`, `PasskeyStore`, `KeyStore` | `account.UserStore`, `account.SessionStore`, `account.PasskeyStore`, `account.KeyStore`, grouped in `account.Store` with `Update` and `account.Tx` |
| `UserStore.UserByEmail` | none |
| `UserStore.UserByOIDCSub` | `account.UserStore.UserByOIDC(ctx, access.OIDCIdentity)` |
| `UserByUsername`, `CreateUser`, `UpdateUser` normalising usernames | the store compares bytes exactly, because `account` normalises. Remove any `NormalizeUsername` call from your store |
| `CreateUser`, `UpdateUser` errors | `account.ErrUsernameTaken`, `account.ErrOIDCIdentityTaken` and `account.ErrNotFound` |
| `DeleteUser` | cascades, in one transaction, to the user's sessions, passkeys, keys, tokens and key attributions |
| `CreatePasskey` | refuses a credential ID registered to any user with `account.ErrDuplicateCredential` |
| `PasskeyByCredentialID`, `PasskeyCountForUser` | `ErrDuplicateCredential` from `CreatePasskey`; `len(PasskeysByUserID(...))` |
| `UpdatePasskeyAfterLogin(ctx, credID, signCount, flags)` | `(ctx, userID, credID, access.PasskeyLoginUpdate)`, scoped to the user |
| `DeleteUserSessions(ctx, userID, exceptHash)` | `(ctx, userID, exceptID) ([]string, error)` |
| `DeleteSession(ctx, hash)` | `DeleteSession(ctx, access.SessionRef)` and `DeleteSessionByHash(ctx, access.Hash)` |
| `CleanupExpiredSessions(ctx, now, timeouts) (int64, error)` | `account.Sweeper.CleanupExpiredSessions(ctx, now, timeouts, limit) ([]access.SessionRef, error)`, returning the refs it deleted |
| `CreateAPIKey` | appends the ID it assigns to `Key.LineageIDs` |
| `OIDCStateStore`, `OIDCState`, `OIDCNonce`, `OIDCCodeVerifier` | none; the OIDC flow travels in a sealed cookie |

New roles: `account.FailureStore` for the durable failure cap, `account.AttributionStore` for key attribution and `account.LogStore` for the security log.

Key rotation adds to the key store, under contract rule 23 ([Key secrets](storage.md#key-secrets)). A store built on an earlier access dev tag adds these:

- `access.Key` gains `PreviousHash` and `PreviousUntil`, and `APIKeyByHash` finds a key by its `KeyHash` or its non-zero `PreviousHash`, so the store indexes both.
- `TouchAPIKey(ctx, keyID, at)` becomes `TouchAPIKey(ctx, keyID, hash, at)`, on `access.APIKeyToucher` and `account.KeyStore`, and writes only when the stored `KeyHash` equals `hash`.
- `account.KeyStore` gains `UpdateAPIKeySecret(ctx, access.KeyRef, access.KeySecret)`, which writes the new secret and zeroes `LastUsedAt` in one write, and `UpdateAPIKeyLabel(ctx, access.KeyRef, label)`.
- `account.Sweeper` gains `ClearRetiredAPIKeySecrets(ctx, now, limit) (int, error)`.

`Service.AllAPIKeys(ctx, a)` and `Service.RevokeAnyAPIKey(ctx, a, id)` take an `account.Actor` in place of an `access.Principal`. Pass `account.As(p)` for a request's principal, or `account.OutOfBand(channel)` for an admin socket or a CLI. Both answer `ErrServiceClosed` after `Shutdown` for every actor, and `ErrSessionRequired` for the zero `Actor`. A key principal's authority is re-read in the operation's transaction, so a revoked or expired key gets a `*PolicyError` with `ReasonKeyNotCurrent` from `AllAPIKeys` as well. The built-in policies allow `OpManageAllKeys` to an out-of-band actor, and an app's own `Policy` now receives it with one.

## The security log

`account` keeps an append-only [security log](security-log.md), written in the same `Update` as each change it records.

- `account.Tx` embeds the new role `account.LogStore`, so every store implements its four methods: `AppendLog`, `ListLog`, `PruneLog` and `LogStats`, under contract rule 22 ([Implementing the store](storage.md#the-security-log)).
- `access.Principal.IP` holds the client address of the request `Authenticate` verified, for every principal it returns, the bypass principal included. `Recheck` copies it into the principal it returns, and a principal built elsewhere holds the zero address.
- `Service.AppendLog` appends an app's own entry, and `Service.SecurityLog` reads the log, which `accesshttp` serves as `GET {Prefix}/security-log`.

Code written against an earlier development release, one that predates the security log, also changes here:

| Before | Now |
| --- | --- |
| `account.Event` | gains `Seq`, the `Seq` of the event's log entry (0 for `EventSessionsExpired`), and `Role`, the role of an `EventRoleChanged`, `EventUserCreated` or `EventInviteIssued` |
| `CreateInvite` reporting no event | reports the new `EventInviteIssued`, with the invite's role |
| first-user setup reporting `EventSignedIn` only | reports `EventUserCreated` with the admin role, then `EventSignedIn` |
| `EventSessionRotated` | removed. Nothing sent it: each rotation is reported by the event of the operation that rotates, whose `SessionIDs` name the session |
| `account.Tx` without `LogStore` | embeds `LogStore`, so a store without the four methods no longer compiles |

## Tokens and display text in account

`account.Service.CreateInvite` and `IssueRecovery` return an `account.IssuedToken{Plaintext, ExpiresAt}` in place of an `access.Secret`. `ExpiresAt` is the stored expiry, which an API key's own `ExpiresAt` caps when a key issues the token, so the expiry you show is the one the token has. `accesshttp` copies it into `TokenResponse.ExpiresAt`.

A label (a key or session label, or a passkey name) or a display name that is too long, or that holds a disallowed character, returns an `*account.TextError{Field, Reason}` before any write. A disallowed character is invalid UTF-8, a control, a bidi control or a line separator. `Field` is `label` or `display_name`, and `Reason` is `empty`, `too_long` or `disallowed_character`; `account.TextErrors()` lists the pairs an operation returns. `accesshttp` answers it with 400 `auth_bad_request` and the `Reason` `<field>_<reason>`, for example `label_too_long`, never with a 500.

A key label is required and unique per owner. `CreateAPIKey` refuses an empty label with `TextError{label, empty}` (wire reason `label_empty`), and a label one of the owner's unexpired keys already carries, compared after NFC normalisation and Unicode case folding, with `account.ErrKeyLabelTaken`, answered 409 `auth_key_label_taken`. An expired key's label is free again. A full session renames one of its own keys with `account.Service.RenameAPIKey`, served as `authKeyRename` (`PUT /apikeys/{id}`, a `NameRequest` body, `client.renameKey` in `@cplieger/access`): the new label meets the same rule, the key's own label aside, and another user's key or a missing one is `ErrNotFound`. A rename logs no event. The rule applies when a key is created or renamed: keys already stored with an empty or a repeated label stay as they are, addressable by ID, and a store adds no unique index.

## ratelimit

| auth v6 | access |
| --- | --- |
| `Checker`, `RateLimiter` | `*Limiter` |
| `Allow`, `Record`, `Reset` | `Attempt`, settled with `Reservation.Succeed`, `Fail` or `Cancel`; `Request` for begin routes; `DeviceCookie` |
| `ClientIP`, `Username` as string keys | `IPKey(netip.Addr)` and `AccountKey(string)` |
| `Config{IPLimit, IPWindow, AcctLimit, AcctWindow, PruneInterval, MaxEntries}` | `Config{IP, Account, Device, Request, IPv6Prefix, MaxEntries, Prune, Devices, Logger}` |
| `DefaultConfig` | returns the new `Config`, with `Devices` left for you to set |

`Attempt.OmitIP` leaves the IP dimension out of an attempt, for a password check on a request that is already signed in.

## webauthn

| auth v6 | access |
| --- | --- |
| `RPConfig` accepting every subdomain by default | accepts only the relying party's exact origin by default. `AllowSubdomains` restores the auth v6 behaviour ([Passkeys](webauthn.md#the-origin-policy)) |
| `FinishRegistration(..., *http.Request)` | `(..., io.Reader)`, capped at `MaxResponseBytes` (64 KiB) |
| `CompleteLogin(..., *http.Request) (*auth.User, error)` | `(..., io.Reader) (LoginResult, error)` |
| `Store.UpdatePasskeyAfterLogin` | scoped to the user, with `access.PasskeyLoginUpdate` |
| `KnownAAGUIDs` | `AuthenticatorName` |
| `ErrUnknownCredential` | now also returned on the discoverable path |

New: `ErrResponseTooLarge`, `LoginResult`, `BeginReauthentication` and `CompleteReauthentication`.

## oidc

| auth v6 | access |
| --- | --- |
| `Provider.AuthorizationURL`, `Provider.Exchange` | `Provider.Begin` and `Provider.Finish` with an `oidc.Callback` |
| `GenerateState`, `GeneratePKCE` and the `State`, `Nonce`, `CodeChallenge`, `Code`, `CodeVerifier` types | none; `Begin` and `Finish` handle them |
| `Claims.Subject`, `Claims.Issuer` and its JSON tags | `Claims.Identity`, an `access.OIDCIdentity`; `Claims` gains `AuthTime`, `Raw` and `Strings` |
| `ResolveUser` | `Provisioning.Admit` and `UsernameCandidate`, which `account` composes |
| a discovery document with `http` endpoints | refused with `ErrDiscovery` unless the issuer is a loopback `http` URL |

New: `Provider.Issuer`, `BeginRequest`, the `Intent` constants, `Flow`, `MaxRedirectBytes`, `Provisioning`, `ProviderError`, `UsernameError`, `ErrFlowInvalid`, `ErrStaleAuthentication`, `ErrRedirectTooLong`, `ErrProvisioningDisabled` and `ErrNotAdmitted`.

## accesstest

| auth v6 | access |
| --- | --- |
| `MemStore` | implements `account.Store`, `Update` included, and copies on every read and write |
| `MemStore.AddUser`, `AddSession`, `AddAPIKey` | the `account.Store` methods `CreateUser`, `CreateSession` and `CreateAPIKey` |
| `AuthenticatorStoreContractSuite` | `accesstest.StoreContract(t, newStore, accesstest.ContractConfig{...})`, which checks every store contract rule |

New: `DurabilityFaults`, `NewIdP` with `IdP` and `IdPOptions`, an in-process OIDC provider for tests, and `NewPasskeyDevice`, a software passkey.
