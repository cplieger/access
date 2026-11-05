# Implementing the store

access stores nothing itself. This page lists the interfaces your storage layer implements and the rules each one must follow, for the developer writing that layer. Method signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/access).

## The interfaces

A store implements `account.Store`: the roles `UserStore`, `SessionStore`, `PasskeyStore`, `KeyStore`, `TokenStore`, `AttributionStore` and `FailureStore`, grouped as `account.Tx` inside `Store.Update`, plus the `Sweeper` cleanups. The `account` package documentation states the contract rules every store keeps.

`access.New` takes an `AuthenticatorStore`, the read side it needs. That is session lookup and activity updates, user lookup by ID, API-key lookup by hash, and `TouchAPIKey`, which records a key's last use. An activity update or a touch for a session or key that does not exist writes nothing and returns nil, and so does one older than or equal to the stored time. `webauthn.CompleteLogin` takes a `webauthn.Store`, which an `account.Store` already satisfies.

## Rules every lookup follows

A lookup by key returns `(value, found, err)`. Absence is `found == false` with a nil error, never a nil value with a nil error, and never an error. A list method is a search instead, and an empty slice with a nil error is its correct answer.

A lookup returns a value the caller owns. Never hand back a pointer to state the store keeps changing. Never keep reading a pointer the caller passed to a write method after the method returns. The library reads a returned session after the lookup, while another request may update the same session. A shared pointer there is a data race that no lock inside the store can fix. A store that scans each query into a fresh value meets this rule already. An in-memory or caching store must copy.

## Usernames

`account` passes `NormalizeUsername` output to `CreateUser`, `UpdateUser` and `UserByUsername`. The store indexes and compares those bytes exactly and never normalises again. A store that called `NormalizeUsername` itself drops the call.

## WebAuthn handles and passkey flags

`User.WebAuthnHandle` is the value an authenticator stores to identify the account. Set it with `GenerateWebAuthnHandle`, 64 random bytes, when you create the account, and never change it, because every registered passkey is bound to it. Persist it and index it, because a discoverable login arrives carrying only the handle.

`UserByWebAuthnHandle` must answer the same way for an unknown handle and a malformed one. A different answer would let someone who is not signed in probe which handles exist.

`PasskeyCredential.RawFlags` is required, and it is the only flag field the library reads. The four booleans beside it are a decoded view for display. A store that drops the octet restores each passkey with every flag false. Every login with a synced passkey then fails, because the stored backup-eligible flag no longer matches what the authenticator reports. A store that kept only the booleans can rebuild the octet. User presence is bit 0, user verification bit 2, backup eligibility bit 3 and backup state bit 4.

## Sessions

`CleanupExpiredSessions` deletes at most `limit` of the sessions `ValidateSession` refuses and returns the ref of each one it deleted. `account` never passes a zero `SessionTimeouts` or a `limit` below 1, and a store may refuse either.

## The test store

`accesstest.NewMemStore` returns an in-memory `account.Store` for your tests. Every read returns a copy and every write stores one, so a test can change what it receives without touching the store. It is meant for tests only.

```go
store := accesstest.NewMemStore()
err := store.CreateUser(ctx, &access.User{Username: "test", Role: access.RoleUser, Enabled: true})
```
