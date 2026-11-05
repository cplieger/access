// Package account defines the store SPI: the role interfaces a store
// implements, the [Tx] that groups them inside one [Store.Update], the
// [Sweeper] the background sweep calls, and the contract every store keeps.
// accesstest.StoreContract tests each rule below.
//
// # Hashes
//
// Every hash the SPI carries, as a record field (User.PasswordHash,
// Session.TokenHash, Key.KeyHash, OneTimeToken.Hash, Rotation.ExpectHash) or
// as a by-hash key, is an [access.Hash], and so are the by-hash parameters of
// the root roles ([access.SessionReader], [access.SessionActivityUpdater],
// [access.APIKeyReader]). A store persists and indexes h.Reveal() when it
// writes, rebuilds the field with access.NewHash(stored) when it reads, and
// treats two hashes as the same key exactly when their texts are equal,
// which is what [access.Hash.Equal] reports. An index held in memory keys on
// h.Key(), the comparable [access.HashKey], so no map key holds a hash text
// and no store defines a comparable form of its own. A store maps each
// field explicitly and never encodes a record through encoding/json: the
// record fields carry `json:"-"`, and Hash has no decoder.
//
// # Transactions
//
// Every account operation that changes more than one record runs wholly
// inside one Update, so a backend error or a crash leaves the whole old
// state or the whole new state. Slow steps (Argon2, the breach call, the
// identity provider exchange, WebAuthn verification) run before Update, and
// the callback re-reads what it decides on, so a check made before the slow
// step is never trusted.
//
// Two Updates never interleave, and a single-call write outside Update is
// ordered against them, so a read-check-write inside one callback (last
// admin, last method, user count) is race-free without an in-process lock.
// The callback resets, then fills, its local results and events on each
// run, so a re-run under a grouped commit reports and emits nothing twice,
// and no event is emitted until Update returns nil.
//
// An Update commits every record set it touches as one unit. A store that
// spreads its records over several files must still publish one Update
// with one atomic step: every file written into a new generation directory
// and published by one rename of a pointer, or every record kept in one
// file. Two renames in sequence do not meet the rule, because a fault or a
// crash between them leaves half the writes durable.
//
// The callback uses only its tx. Calling the Store from inside it can
// deadlock (bbolt's single writer), and account never does. A Tx is not
// retained.
//
// # Contract rules
//
//  1. Absence. A by-key lookup reports absence through found with a nil
//     error, never through a nil value with a nil error, and never through
//     an error. A list is a search: an empty slice with a nil error is its
//     correct empty answer.
//  2. Ownership. A lookup returns values the caller owns: deep copies of
//     User.WebAuthnHandle, Key.Scopes, Key.LineageIDs,
//     KeyAttribution.KeyLineage, PasskeyCredential's byte slices, and every
//     other reference field. A write never retains a pointer or slice it was
//     given.
//  3. Canonical usernames. account passes [access.NormalizeUsername] output to
//     CreateUser, UpdateUser and UserByUsername. The store indexes and
//     compares those bytes exactly, and never normalises again.
//  4. Uniqueness. Username ([ErrUsernameTaken]); a non-zero OIDCIdentity
//     ([ErrOIDCIdentityTaken]); WebAuthnHandle; credential ID across all
//     users ([ErrDuplicateCredential]); key hash; session hash and session
//     ID; token hash. Two hashes are the same key exactly when Hash.Equal
//     holds, and a hash read back is Equal to the one written.
//  5. Atomicity. RotateSession, ConsumeOneTimeToken and CreateInitialUser
//     are each linearisable: concurrent calls on the same key give exactly
//     one success. CreatePasskey's uniqueness holds under concurrent
//     inserts. DeleteUser's cascade (sessions, passkeys, keys, tokens whose
//     Subject is the user, and the user's key attributions) is one
//     transaction. A failed single-call write leaves no partial state. In
//     Update, a callback returning an error, or panicking, leaves no write
//     visible; a nil return makes every write visible at once and durably;
//     concurrent Updates are serialisable, also when the store groups them
//     into one commit; a read inside the callback sees the callback's own
//     earlier writes. A callback the store re-runs leaves only its last
//     run's writes. The same rules hold when the callback's writes are
//     single-call writes through tx. A store with a durable medium groups
//     concurrently pending Updates into shared durable commits.
//  6. Scoping. User-scoped operations affect nothing when the owner does
//     not match, and they report [ErrNotFound] as for an absent row, so
//     there is no ownership oracle. The operations: DeletePasskey,
//     RenamePasskey, UpdatePasskeyAfterLogin, DeleteSession,
//     UpdateSessionLabel, DeleteAPIKey and RotateSession. A zero or partial
//     ref ([access.PasskeyRef], [access.KeyRef], [access.SessionRef]) matches
//     nothing. DeleteOneTimeTokensIssuedBy removes exactly the tokens whose
//     IssuedByKey it lists, and an empty list or a 0 matches nothing.
//  7. Expiry at consume. ConsumeOneTimeToken refuses an expired token at
//     the call, not only in a sweep, and LiveOneTimeTokens never lists a
//     token whose ExpiresAt is not after now.
//  8. Flags. UpdatePasskeyAfterLogin writes the octet, the derived booleans
//     ([access.DecodePasskeyFlags]), the sign count, the clone warning and
//     LastUsedAt together. A stored credential always carries RawFlags.
//  9. Handle probing. UserByWebAuthnHandle answers an unknown handle and a
//     malformed one the same way.
//  10. Durability. A write or an Update returns nil only when its new state
//     is durable in the store's medium. On an error account treats the
//     operation as not done: it answers [access.ErrAuthBackend] and fires no
//     event, and it holds no state that could diverge, because every record
//     it decides on lives in the store. A medium that can publish before it
//     confirms durability (a file store whose directory sync fails after its
//     rename) therefore returns an error there; how that store then stays
//     consistent, for example by fencing writes until a durable rewrite, is
//     its own business. bbolt's db.Update reports durability with its
//     commit.
//  11. Time. Stored time.Time values round-trip to at least millisecond
//     precision.
//  12. Errors. Caller faults use only the sentinels of this package.
//     Everything else is a backend error. context.Canceled and
//     context.DeadlineExceeded pass through wrapped.
//  13. Concurrency. Safe for concurrent use by many goroutines. No goroutine
//     outlives a call.
//  14. Cleanup. CleanupExpiredSessions deletes exactly the sessions for
//     which access.ValidateSession(s, timeouts, now) fails: past idle or
//     absolute, a SessionRecovery session past min(timeouts,
//     access.RecoverySessionLifetime), and a session past its own IdleCap or
//     AbsoluteCap. A store calls [access.ValidateSession] (or
//     [access.SessionDeadlines]) rather than restating the rule. account
//     passes the timeouts the verifier enforces, and never a zero
//     SessionTimeouts; a store may refuse one. A call deletes at most limit
//     such sessions, in one atomic step (rule 5), and returns exactly the
//     access.SessionRef of each session it deleted, none twice and no other,
//     so across calls that return nil, a close and a reopen included, the
//     refs returned are exactly the rows those calls removed; a session
//     created, rotated or touched concurrently is named only if that call
//     deleted it. A store whose call can run more than once before it
//     returns (a grouped commit that re-runs its batch, as bbolt's db.Batch
//     may) builds the result afresh on each run and returns only the last
//     run's, so a re-run never names a session twice. A call returning
//     fewer than limit refs left no session ValidateSession refuses at now.
//     account never passes a limit below 1; a store may refuse one. A call
//     that returns an error is treated as having deleted nothing, and
//     account emits nothing for it (rules 5 and 10).
//  15. Failure records. AuthFailure reports absence through found (rule 1).
//     PutAuthFailure upserts one record, and DeleteAuthFailures removes the
//     listed methods' records of one name in both trust contexts, skipping
//     absent ones. A Name is opaque: the store indexes it and derives
//     nothing from it. PruneAuthFailures(keep) leaves exactly the records
//     whose Name is in keep and reports how many it removed.
//     UnreportedLocks returns exactly the records with Unreported set. The
//     bound, which the store's prune and account's admission make together:
//     at any time the store holds at most 2 × len(users) records of user
//     names (one counted method, two trust contexts), plus 2 × 20,000
//     records of other names, plus the records of users deleted since the
//     last sweep, plus at most one trusted record per counted method for
//     each user deleted within the device-cookie lifetime (180 days), whose
//     old cookie can recreate it.
//  16. Reads never wait across a write's fsync or rename. A read sees the
//     last committed state and never blocks on an in-progress Update or
//     single-call write. bbolt's read transactions give this, except that a
//     commit growing the file past its mapping remaps under db.mmaplock,
//     which new read transactions wait out (go.etcd.io/bbolt@v1.5.0
//     db.go:457 and db.go:801); that is file growth, which an attacker
//     steers only up to rule 15's bound. A file store publishes snapshots
//     through an atomic pointer and holds its writer mutex only among
//     writers. Without the rule a cheap read stalls during a commit, and
//     whatever triggers a commit becomes observable.
//  17. IDs and lineage. A store assigns User.ID, Key.ID,
//     PasskeyCredential.ID and KeyAttribution.ID as positive integers no
//     larger than 2^53 − 1, so every ID survives a JSON number in the
//     browser. A User.ID or Key.ID the store has assigned is never assigned
//     again, to a user or a key respectively, for the life of the store,
//     after that row's deletion and across restarts included. Each
//     KeyAttribution.ID is larger than every one assigned before it, so
//     ascending ID is append order whatever the clock says. CreateAPIKey
//     appends the ID it assigns to the LineageIDs it was given, so a stored
//     key's path ends with its own ID. Key.LineageIDs,
//     KeyAttribution.KeyLineage, Session.IssuedByKey and
//     OneTimeToken.IssuedByKey outlive the keys they name, and account
//     refuses an issuer it cannot find, so a reused ID would let a later key
//     stand in for a revoked one. bbolt's per-bucket NextSequence keeps the
//     rule, because the sequence commits with the row and only SetSequence
//     lowers it; an allocator that takes the highest live ID plus one, or
//     the lowest free one, breaks it, and such a store keeps a high-water
//     mark instead, which a delete never lowers and which commits with the
//     row. Session.ID is the 128-bit hex string account mints.
//  18. Context. A store call receives the context of the caller it serves,
//     unchanged except for added values. Every call made while an account
//     operation or a request runs receives that caller's context: every
//     read, every Update and every Tx call inside it, CreateSession,
//     RotateSession and the counted attempt's failure write included, and
//     the Authenticator's SessionByHash, UpdateSessionActivity, UserByID,
//     APIKeyByHash and TouchAPIKey. The background sweep serves no
//     caller and runs on the service context. A store never detaches or
//     replaces the context it receives, so in any call made for a request
//     it may read a value the app put on that request's context.
//  19. Writes to an absent row. UpdateSessionActivity, TouchAPIKey and
//     UpdatePasskeyAfterLogin never create a row. For a hash or ID that
//     names nothing, UpdateSessionActivity and TouchAPIKey write nothing and
//     return nil; UpdatePasskeyAfterLogin returns ErrNotFound (rule 6). A
//     verification that read a session just before it was revoked or
//     rotated can therefore never bring it back.
//  20. Fidelity. Every exported field of every record a store keeps
//     (User, Session, PasskeyCredential, Key, OneTimeToken, KeyAttribution,
//     [FailureCount], and the structs they embed or hold, OIDCIdentity and
//     [FailureRef]) reads back as it was written, apart from what the store
//     assigns (IDs, the LineageIDs append of rule 17). The record fields
//     carry `json:"-"` and Hash has no codec, so every store maps every
//     field by hand. A persistent store keeps the same fidelity across a
//     close and a reopen of its medium.
//  21. Activity never moves backwards. UpdateSessionActivity stores act.At
//     as LastActivity, and act.IP as LastIP, only when act.At is after the
//     stored LastActivity, comparing and writing in one atomic step; an
//     older or equal At writes nothing, LastIP included, and returns nil.
//     LastIP therefore always belongs to the newest LastActivity; UserAgent
//     is set at creation and no activity write touches it. TouchAPIKey does
//     the same for LastUsedAt, and RotateSession keeps the stored
//     LastActivity and LastIP when the stored LastActivity is after Next's,
//     so no write path lowers either. Two verified requests can reach the
//     store in the reverse order of their clocks: without the rule a late,
//     older write would move a session's idle deadline back. A store
//     implements it as a conditional update (UPDATE … WHERE last_activity <
//     ?, or a compare inside its write transaction or writer mutex), never
//     as a read followed by a separate write.
package account
