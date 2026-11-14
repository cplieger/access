# Implementing the store

access stores nothing itself. This page is for the developer writing the storage layer: the interfaces it implements, the transaction boundary, the 22 contract rules and what each costs. The [`account` package documentation](https://pkg.go.dev/github.com/cplieger/access/account) owns the rules' exact wording, and `accesstest.StoreContract` tests every one of them. Where this page and the package documentation differ, the package documentation is right. Method signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/access).

## The interfaces

A store implements `account.Store`: the roles `UserStore`, `SessionStore`, `PasskeyStore`, `KeyStore`, `TokenStore`, `AttributionStore`, `FailureStore` and `LogStore`, grouped as `account.Tx` inside `Store.Update`, plus the `Sweeper` cleanups the background sweep calls.

`access.New` takes an `AuthenticatorStore`, the read side it needs: session lookup and activity updates, user lookup by ID, API-key lookup by hash, and `TouchAPIKey`, which records the last use of a key's current secret. `webauthn.CompleteLogin` takes a `webauthn.Store`. An `account.Store` satisfies both.

## The transaction boundary

Every `account` operation that changes more than one record runs wholly inside one `Store.Update`, so a backend error or a crash leaves the whole old state or the whole new state. The slow steps (Argon2, the breach check, the identity provider exchange, WebAuthn verification) run before `Update`, and the callback re-reads every record it decides on.

What your store must give that callback:

- Two `Update`s never interleave, and a single-call write outside `Update` is ordered against them. A last-admin, last-method or user-count check inside one callback is then race-free with no lock in the app.
- An `Update` commits every record it touches as one unit. A store that spreads records over several files publishes one `Update` with one atomic step: every file written into a new generation directory and published by one rename of a pointer, or every record kept in one file. Two renames in sequence break the rule, because a crash between them leaves half the writes durable.
- The store may run a callback more than once, as bbolt's `db.Batch` does. `account` rebuilds its results, events and log entries on each run and emits nothing until `Update` returns nil, so only the last run's writes may remain.
- The callback uses only its `tx`. Calling the store from inside it can deadlock on a single-writer backend such as bbolt, and `account` never does it. A `Tx` is not kept after the callback returns.

### Your own rules inside the transaction

`Rules.MethodUsable` receives the transaction the last-method count reads: the removal's own `Update` when the guard decides, the store itself for `RemovePassword`'s check before its `Update`, and the caller's `tx` in `Service.UsableMethods`. A store-backed app may type-assert that `tx` to its own transaction type and read its in-transaction view of its own settings. `MethodUsable` must not block, and must not call the store outside `tx`.

`Config.OIDC()` and `Config.RP()` are read as published, not from the store. An app whose identity provider or relying party is a store record folds that record into `MethodUsable`. Before the app saves a settings change that could leave a user with no sign-in method (password sign-in off, the provider removed, the relying-party ID moved), it can call `Service.UsableMethods` inside its own `Update` with the new values in an `account.MethodState`, and refuse the change when a user would be left with nothing.

## The contract rules

Each rule below is one line of the package documentation's numbered list. `accesstest.StoreContract` runs a case per rule against your store.

1. **Absence.** A lookup by key returns `(value, found, err)`. Absence is `found == false` with a nil error, never a nil value with a nil error and never an error. A list is a search, and an empty slice with a nil error is its correct empty answer.
2. **Ownership.** A lookup returns values the caller owns, deep copies of every slice and pointer field included, and a write never keeps a pointer or slice it was given. The library reads a returned session while another request may update the same one, and a shared pointer there is a data race no lock inside the store can fix. A store that scans each query into a fresh value meets this already. An in-memory or caching store must copy.
3. **Canonical usernames.** `account` passes `access.NormalizeUsername` output to `CreateUser`, `UpdateUser` and `UserByUsername`. The store indexes and compares those bytes exactly and never normalises again.
4. **Uniqueness.** Usernames, OIDC identities, WebAuthn handles, credential IDs across all users, key hashes, session hashes and IDs, and token hashes are each unique, refused with the sentinel the package documentation names. A key's `KeyHash` and its non-zero `PreviousHash` share one index (rule 23).
5. **Atomicity.** `RotateSession`, `ConsumeOneTimeToken` and `CreateInitialUser` are linearisable, `CreatePasskey`'s uniqueness holds under concurrent inserts, and `DeleteUser`'s cascade is one transaction. Inside `Update`, an error or a panic leaves no write visible and a nil return makes every write visible at once and durably.
6. **Scoping.** A user-scoped operation whose owner does not match affects nothing and reports `ErrNotFound`, as for an absent row, so there is no ownership oracle. A zero or partial ref matches nothing. `UpdateAPIKeySecret` and `UpdateAPIKeyLabel` are scoped by their `access.KeyRef`, inside an `Update` too.
7. **Expiry at consume.** `ConsumeOneTimeToken` refuses an expired token at the call, not only in a sweep, and `LiveOneTimeTokens` never lists one.
8. **Flags.** `UpdatePasskeyAfterLogin` writes the flags octet, the derived booleans, the sign count, the clone warning and `LastUsedAt` together. A stored credential always carries `RawFlags` (see [passkey flags](#webauthn-handles-and-passkey-flags)).
9. **Handle probing.** `UserByWebAuthnHandle` answers an unknown handle and a malformed one the same way.
10. **Durability.** A write or an `Update` returns nil only once its new state is durable. On an error `account` treats the operation as not done, answers a backend error and fires no event. A medium that can publish before it confirms durability, such as a file store whose directory sync fails after its rename, returns an error there.
11. **Time.** Stored `time.Time` values round-trip to at least millisecond precision.
12. **Errors.** Caller faults use only the `account` sentinels. Everything else is a backend error, and `context.Canceled` and `context.DeadlineExceeded` pass through wrapped.
13. **Concurrency.** The store is safe for concurrent use, and no goroutine outlives a call.
14. **Cleanup.** See [Sessions](#sessions) and [Key secrets](#key-secrets).
15. **Failure records.** `PutAuthFailure` upserts, `DeleteAuthFailures` and `PruneAuthFailures` remove exactly what they name, `UnreportedLocks` returns exactly the records whose `Unreported` is set, and a record's `Name` is opaque. The store's prune and `account`'s admission together bound the records held. The bound starts at 2 × users records of user names plus 2 × `account.MaxUntrustedCounts` (20,000) records of other names. It adds the records of users deleted since the last sweep. It also adds at most one trusted record per counted method for each user deleted within the 180-day device-cookie lifetime.
16. **Reads never wait on a write's fsync or rename.** A read sees the last committed state. A file store publishes snapshots through an atomic pointer and holds its writer mutex only among writers. bbolt meets this, except while a commit grows the file past its memory mapping.
17. **IDs and lineage.** See [IDs and key lineage](#ids-and-key-lineage).
18. **Context.** Every store call receives the context of the caller it serves, unchanged except for added values, so a store may read a value the app put on a request's context. The background sweep serves no caller and runs on the service context.
19. **Writes to an absent row.** `UpdateSessionActivity`, `TouchAPIKey` and `UpdatePasskeyAfterLogin` never create a row. The first two write nothing and return nil, and the third returns `ErrNotFound`. A verification that read a session just before it was revoked or rotated can therefore never bring it back.
20. **Fidelity.** Every exported field of every record reads back as it was written, apart from what the store assigns, and a persistent store keeps that across a close and a reopen. `accesstest.ContractConfig.Reopen` lets the contract check the reopen.
21. **Activity never moves backwards.** `UpdateSessionActivity` stores `LastActivity` and `LastIP` only when the new time is after the stored one, and `TouchAPIKey` does the same for `LastUsedAt`, writing only when the stored `KeyHash` equals the hash it carries. `RotateSession` keeps the stored `LastActivity` and `LastIP` when the stored `LastActivity` is after `Next`'s, in the same conditional write, so no activity write lowers either. `UpdateAPIKeySecret` alone sets `LastUsedAt` to zero, in the same atomic write as the new `KeyHash`, because after a rotation `LastUsedAt` records only the new secret's use. Two requests can reach the store in the reverse order of their clocks, and a late, older write would otherwise move a session's idle deadline back. Implement it as one conditional update (`UPDATE … WHERE last_activity < ?`, or a compare inside the write transaction or writer mutex), never as a read followed by a separate write.
22. **The security log.** See [The security log](#the-security-log).
23. **Key secrets.** See [Key secrets](#key-secrets).

## The security log

`LogStore` keeps the [security log](security-log.md). Its four methods are on `Tx`, so `account` appends each entry in the same `Update` as the change it records. Rule 22 in the [`account` package documentation](https://pkg.go.dev/github.com/cplieger/access/account) owns the exact wording. In short:

- **Order.** `AppendLog` assigns `Event.Seq` a positive integer no larger than 2^53 − 1, in commit order. A reader that sees an entry already sees every committed entry with a smaller `Seq`. Being larger than every entry committed before it is not enough for a store whose `Update`s run concurrently under serializable isolation: two writers could take 5 and 6 and commit 6 first, and a reader catching up from 6 would never see 5. Assign `Seq` under the lock that orders your commits, such as bbolt's single writer transaction or a file store's writer mutex. A store whose writers commit concurrently assigns it at commit, in commit order.
- **Never reused.** A `Seq` is never given to two committed entries, after any prune and across a close and a reopen included. A rolled-back or re-run `Update` may use up numbers that no entry keeps, so gaps are allowed. Keep a counter that commits with the entry and that nothing lowers, as for [IDs](#ids-and-key-lineage).
- **One unit with its change.** An entry commits and rolls back with its `Update`, and a re-run callback leaves only its last run's entries. A stored entry reads back with every field as written, `Event.SessionIDs` and `IP` included, and reads return deep copies.
- **Reads.** `ListLog` returns exactly the committed entries in its open `Seq` range, in the order asked, at most `Limit`. `ListLog` and `LogStats` never wait on a write, as rule 16 asks of every read.
- **Pruning.** `PruneLog` removes entries of one class only, lowest `Seq` first, never more than `Limit`, and returns the count. A `LogPrune` sets exactly one criterion: `Keep`, the cap, removes the entries beyond the class's newest `Keep`, and `Before`, the age, removes the entries appended before that time. Refuse a prune with both set or neither, because the criterion is what tells a removal by the cap from a removal by age.
- **The eviction counter.** Each class keeps a durable `Evicted` counter. A `Keep` prune adds the number it removed, in the same `Update`, and nothing else changes it: a `Before` prune leaves it alone, a rolled-back `Update` leaves it as it was, and it survives a close and a reopen. `LogStats` returns each class that has ever held an entry, with its committed `Count` and `Evicted`.
- **Nothing else removes an entry.** No other method changes or removes one, and `DeleteUser`'s cascade keeps the user's entries.
- **Durable.** Keep the log with the durability of your users and keys. A store that resets derived data on a format change classifies its log records as durable, never derived. The library names no table, bucket or file of yours, so your reset policy names your own log table.

## Hashes

Every hash the store keeps or looks up by is an `access.Hash`: password hashes, session, key and token hashes, and the expected hash of a session rotation. Persist and index `h.Reveal()` on disk, rebuild the value with `access.NewHash(stored)` when you read it, and treat two hashes as the same key exactly when their texts are equal. An index held in memory keys on `h.Key()`, the comparable `access.HashKey`, so no map key holds a hash text. `Hash` has no decoder, its JSON encoding is only the redacted rendering, and the record fields carry `json:"-"`, so map each field by hand rather than encoding a record with `encoding/json`.

## Usernames

`account` passes `NormalizeUsername` output to the store (rule 3). A store that called `NormalizeUsername` itself drops the call.

## WebAuthn handles and passkey flags

`User.WebAuthnHandle` is the value an authenticator stores to identify the account. Set it with `GenerateWebAuthnHandle` when you create the account and never change it, because every registered passkey is bound to it. Persist and index it, because a discoverable login arrives carrying only the handle. `UserByWebAuthnHandle` answers an unknown and a malformed handle alike (rule 9), so someone who is not signed in cannot probe which handles exist.

`PasskeyCredential.RawFlags` is required, and it is the only flag field the library reads. The four booleans beside it are a decoded view for display. A store that drops the octet restores each passkey with every flag false, and every login with a synced passkey then fails, because the stored backup-eligible flag no longer matches what the authenticator reports. A store that kept only the booleans can rebuild the octet: user presence is bit 0, user verification bit 2, backup eligibility bit 3 and backup state bit 4.

## Sessions

`CleanupExpiredSessions` deletes at most `limit` of the sessions `access.ValidateSession` refuses at `now`, in one atomic step, and returns exactly the `access.SessionRef` of each session it deleted, none twice. `account` groups each call's refs into one `EventSessionsExpired` per user, in ascending `UserID`, each event's session IDs sorted. A ref the store did not delete, or a deleted session it does not return, reaches the app's listeners as a wrong event. Call `access.ValidateSession` or `access.SessionDeadlines` instead of restating the timeout rule. A store whose commit may re-run its batch builds the result afresh on each run and returns only the last run's. A call that returns fewer than `limit` refs has left no session `access.ValidateSession` refuses at `now`, because the sweep stops calling at that answer. A call that returns an error is treated as having deleted nothing, and `account` emits nothing for it. `account` never passes a zero `SessionTimeouts` or a `limit` below 1, and a store may refuse either.

## Key secrets

A key rotation replaces a key's secret and keeps its ID, label, scopes, expiry, lineage and owner. The superseded secret keeps working for a bounded overlap, until the new secret's first use or until `Key.PreviousUntil`, whichever comes first. The store holds both secrets, and rule 23 in the [`account` package documentation](https://pkg.go.dev/github.com/cplieger/access/account) owns the exact wording:

- **Two hashes, one index.** `Key.PreviousHash` is the secret the last rotation superseded, zero when none, and `Key.PreviousUntil` is the overlap's bound. `APIKeyByHash` finds a key by its `KeyHash` or by its non-zero `PreviousHash`, so index both. A zero hash finds nothing.
- **The rotation write.** `Tx.UpdateAPIKeySecret(ctx, ref, s)` writes the five fields of `access.KeySecret` (`KeyHash`, `KeyPrefix`, `KeySuffix`, `PreviousHash` and `PreviousUntil`) and zeroes `LastUsedAt`, in one atomic write. The hash it supersedes as `PreviousHash` leaves the index in that write, so after rotations A to B to C only B and C find the key. A ref no key of `ref.UserID` has is `ErrNotFound` (rule 6). Only `account`'s rotation calls it, inside the `Update` that read the key.
- **The conditional touch.** `TouchAPIKey(ctx, keyID, hash, at)` writes `LastUsedAt` only when the stored `KeyHash` equals `hash` and `at` is after the stored value. A touch sampled before a rotation carries the old hash and writes nothing, so it can never end the new secret's overlap.
- **The sweep.** `Sweeper.ClearRetiredAPIKeySecrets(ctx, now, limit)` zeroes `PreviousHash` and `PreviousUntil`, in one atomic step, on at most `limit` keys whose previous secret no longer verifies: `PreviousHash` set, and `PreviousUntil` not after `now` or `LastUsedAt` non-zero. It returns how many it cleared and never writes `KeyHash`. Evaluate the predicate in the write itself (`UPDATE … WHERE …`, or a compare under the writer mutex), never from a list read before it: a key rotated again between the read and the write would lose its new previous secret. The sweep calls it in batches of `account.MaxSweepBatch` and stops at a count below `limit`.
- **Deletes.** `DeleteAPIKey`, `DeleteUserAPIKeys` and `DeleteUser`'s cascade remove both hashes with the key.
- **Labels.** `Tx.UpdateAPIKeyLabel(ctx, ref, label)` writes the label and nothing else, scoped by `ref` like the rotation write. `account` checks that a label is unique among its owner's unexpired keys when it creates or renames the key, inside the same `Update`. Do not add a unique index on the label: a store from before that rule may hold two keys with one label, or a key with an empty label, and each stays listed, readable and revocable by its ID.

## IDs and key lineage

A store assigns `User.ID`, `Key.ID`, `PasskeyCredential.ID` and `KeyAttribution.ID` as positive integers no larger than 2^53 − 1, so every ID survives a JSON number in a browser.

A user or key ID, once assigned, is never assigned again for the life of the store, after its row's deletion and across restarts included. Key lineage paths, attribution records and the issuer fields of sessions and tokens outlive the keys they name, so a reused ID would let a later key stand in for a revoked one. Keep a counter that a delete never lowers and that commits with the row. bbolt's per-bucket `NextSequence` does this, because the sequence commits with the row and only `SetSequence` lowers it. An allocator that takes the highest live ID plus one, or the lowest free ID, fails the contract: delete the newest key, and its ID goes to the next one.

`CreateAPIKey` appends the ID it assigns to the `Key.LineageIDs` it was given, so a stored key's path ends with its own ID. Key attributions are append-only: each new `KeyAttribution.ID` is larger than every one before it, so ascending ID is append order whatever the clock says. A store never updates an attribution and deletes one only in `DeleteUser`'s cascade. An attribution path names a key that may since have been deleted, for the life of the store, which is what lets `Service.Users` with `UserFilter.AttributedToKey` (accesshttp's `GET /users?key=`) find the accounts a revoked key created.

## Write cost

Every password attempt commits its failure count before the password is verified, so each attempt costs one durable `Update`. Two consequences follow for a store author.

- A hash permit is held, idle, through that count's commit. On bbolt under `db.Batch` the commit waits up to the 10 ms default batch delay (`go.etcd.io/bbolt@v1.5.0/db.go:198`), plus the fsync.
- A store that rewrites one whole file on every commit pays for its size. A JSON file store holding rule 15's bound of failure records is about 2.8 MB, so attempts spaced just past one publish each cost one publish, about 100 MB/s of rewrites. A whole-file store must group concurrent `Update`s into shared commits.

The library half, measured on `accesstest.MemStore` and on a fault store that groups concurrent `Update`s behind a 10 ms window:

```sh
go test -run '^$' -bench 'BenchmarkCountCommit|BenchmarkPruneAtBound' -benchtime 20x ./account/
```

Measured on an Intel Core i5-13500 limited to 4 of its 20 logical CPUs (`GOMAXPROCS=4`), Linux 6.12, go1.27.2, on a shared host, with the hasher at OWASP's cheapest Argon2id row (m = 7168 KiB, t = 5, p = 1) and a budget of four derivations:

| Benchmark | Time per op | Time in `Update` | Commits per attempt |
| --- | --- | --- | --- |
| `CountCommit`, ungrouped, 1 caller | 17.6 ms | 0.08 % | 1.00 |
| `CountCommit`, ungrouped, 16 callers | 11.4 ms | 0.09 % | 1.00 |
| `CountCommit`, grouped, 1 caller | 38.8 ms | 27 % | 1.00 |
| `CountCommit`, grouped, 16 callers | 21.0 ms | 4.7 % | 0.65 |
| `PruneAtBound`, 1,000 users | 54.7 ms per sweep | | |

In memory the count commit is under 0.1 % of an attempt, which the derivation dominates. Behind a 10 ms batch window a lone caller waits out the whole window, and concurrent callers share commits. `PruneAtBound` is one failure-sweep `Update` over rule 15's bound for 1,000 users. Your store's own figures depend on its medium, so measure them with your store in place of `MemStore`.

### Security-log writes

Every logged `Update` adds one `AppendLog` per entry and one `Keep` prune for each class it appended to, which trims the class back to its cap. A no-op trim is the common case, so keep a count and a `Seq`-ordered index per class: the trim then costs O(removed), and O(1) when it removes nothing, never a scan of the class. The background sweep adds a `Before` prune per class each `CleanupInterval`, in `Update`s that each remove at most `account.MaxSweepBatch` (1000) entries.

A change entry with its actor's label and user agent and an IPv6 address is about 420 bytes of compact JSON. At the default caps of 10,000 entries per class, a class of such entries is about 4.2 MB. A store that rewrites one whole file on every commit pays that on every write, sign-in counts included, so set `LogMaxChanges` and `LogMaxSessions` lower: 1,000 per class is about 0.42 MB.

## The test store

`accesstest.NewMemStore` returns an in-memory `account.Store` for your tests. Every read returns a copy and every write stores one, so a test can change what it receives without touching the store. It is meant for tests only.

```go
store := accesstest.NewMemStore()
err := store.CreateUser(ctx, &access.User{Username: "test", Role: access.RoleUser, Enabled: true})
```

Run `accesstest.StoreContract` against your own store to check every rule above.
