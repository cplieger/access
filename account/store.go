package account

import (
	"context"
	"time"

	"github.com/cplieger/access"
)

// UserStore holds the user records.
type UserStore interface {
	// CreateUser assigns user.ID. Errors: ErrUsernameTaken, ErrOIDCIdentityTaken.
	CreateUser(ctx context.Context, user *access.User) error
	// CreateInitialUser creates user only while no user exists, atomically;
	// otherwise ErrSetupComplete.
	CreateInitialUser(ctx context.Context, user *access.User) error
	UserByID(ctx context.Context, id int64) (user *access.User, found bool, err error)
	UserByUsername(ctx context.Context, canonical string) (user *access.User, found bool, err error)
	UserByOIDC(ctx context.Context, id access.OIDCIdentity) (user *access.User, found bool, err error)
	UserByWebAuthnHandle(ctx context.Context, handle []byte) (user *access.User, found bool, err error)
	ListUsers(ctx context.Context) ([]access.User, error)
	// UpdateUser errors: ErrNotFound, ErrUsernameTaken, ErrOIDCIdentityTaken.
	UpdateUser(ctx context.Context, user *access.User) error
	// DeleteUser removes the user and, in the same transaction, every
	// session, passkey, key and token whose Subject is the user, and every
	// KeyAttribution whose UserID is the user. ErrNotFound when no user has id.
	DeleteUser(ctx context.Context, id int64) error
	UserCount(ctx context.Context) (int, error)
}

// SessionStore holds the session records.
type SessionStore interface {
	CreateSession(ctx context.Context, sess *access.Session) error
	SessionByHash(ctx context.Context, tokenHash access.Hash) (sess *access.Session, found bool, err error)
	SessionsByUserID(ctx context.Context, userID int64) ([]access.Session, error)
	// UpdateSessionActivity changes an existing session only; for a hash
	// no session has, it writes nothing and returns nil (rule 19). It
	// stores act's LastActivity and LastIP only when act.At is after the
	// stored LastActivity, atomically; an older or equal At writes nothing,
	// LastIP included, and returns nil (rule 21).
	UpdateSessionActivity(ctx context.Context, tokenHash access.Hash, act access.SessionActivity) error
	// RotateSession writes rot.Next over the session (rot.UserID, rot.ID),
	// atomically; Next keeps that ID and user, and the stored LastActivity
	// and LastIP stay when the stored LastActivity is after Next's (rule 21).
	// ErrNotFound when no session of that user has that ID, or when
	// ExpectHash is non-zero and not Equal to the session's TokenHash.
	RotateSession(ctx context.Context, rot Rotation) error
	UpdateSessionLabel(ctx context.Context, ref access.SessionRef, label string) error
	DeleteSession(ctx context.Context, ref access.SessionRef) error
	DeleteSessionByHash(ctx context.Context, tokenHash access.Hash) error // idempotent
	// DeleteUserSessions removes every session of userID but exceptID and
	// returns the IDs it removed.
	DeleteUserSessions(ctx context.Context, userID int64, exceptID string) ([]string, error)
}

// Rotation is one [SessionStore.RotateSession] call.
type Rotation struct {
	ID         string
	ExpectHash access.Hash `json:"-"` // optional compare-and-swap on the current hash
	// Next is the session after rotation; account copies it from the
	// current session and changes only the fields the operation names.
	Next   access.Session
	UserID int64
}

// PasskeyStore holds the passkey credentials.
type PasskeyStore interface {
	// CreatePasskey assigns cred.ID and refuses a credential ID registered
	// to any user with ErrDuplicateCredential (WebAuthn L3 §7.1 step 26).
	CreatePasskey(ctx context.Context, cred *access.PasskeyCredential) error
	PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error
	RenamePasskey(ctx context.Context, ref access.PasskeyRef, name string) error
	DeletePasskey(ctx context.Context, ref access.PasskeyRef) error
	// DeleteUserPasskeys returns the IDs it removed.
	DeleteUserPasskeys(ctx context.Context, userID int64) ([]int64, error)
}

// KeyStore holds the API keys.
type KeyStore interface {
	// CreateAPIKey assigns key.ID and appends it to key.LineageIDs, which
	// account sets to the minting key's path, or leaves empty for a key a
	// session or an out-of-band actor mints (rule 17).
	CreateAPIKey(ctx context.Context, key *access.Key) error
	APIKeyByHash(ctx context.Context, hash access.Hash) (key *access.Key, found bool, err error)
	ListAPIKeysByUserID(ctx context.Context, userID int64) ([]access.Key, error)
	ListAPIKeys(ctx context.Context) ([]access.Key, error) // every user's
	DeleteAPIKey(ctx context.Context, ref access.KeyRef) error
	DeleteUserAPIKeys(ctx context.Context, userID int64) ([]int64, error) // the IDs removed
	// TouchAPIKey sets LastUsedAt to at only when at is after the stored
	// value, atomically; an older or equal at, or an unknown key, writes
	// nothing and returns nil (rules 19 and 21).
	TouchAPIKey(ctx context.Context, keyID int64, at time.Time) error
}

// TokenStore holds the one-time tokens.
type TokenStore interface {
	CreateOneTimeToken(ctx context.Context, tok access.OneTimeToken) error
	OneTimeTokenByHash(ctx context.Context, hash access.Hash) (tok access.OneTimeToken, found bool, err error)
	// ConsumeOneTimeToken reads and deletes in one step. An expired token is
	// deleted and reported as not found.
	ConsumeOneTimeToken(ctx context.Context, hash access.Hash, now time.Time) (tok access.OneTimeToken, found bool, err error)
	DeleteOneTimeTokens(ctx context.Context, purpose access.TokenPurpose, subject int64) (int, error)
	// LiveOneTimeTokens returns every token whose Purpose is in purposes
	// and whose ExpiresAt is after now, in any order.
	LiveOneTimeTokens(ctx context.Context, purposes []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error)
	// DeleteOneTimeTokensIssuedBy removes every token whose IssuedByKey is
	// in keyIDs, of any purpose and subject, and never one whose
	// IssuedByKey is 0.
	DeleteOneTimeTokensIssuedBy(ctx context.Context, keyIDs []int64) (int, error)
}

// AttributionStore holds the append-only key attribution records. It has
// no update and no delete: a record goes only with its user, in
// [UserStore.DeleteUser]'s cascade.
type AttributionStore interface {
	// CreateKeyAttribution assigns a.ID, larger than every ID it assigned
	// before (rule 17), and stores a copy.
	CreateKeyAttribution(ctx context.Context, a *access.KeyAttribution) error
	// ListKeyAttributions returns every record, in ascending ID order.
	ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error)
}

// FailureRef names one failure record.
type FailureRef struct {
	// Name is the hex HMAC-SHA256, under the service's failure key, of the
	// canonical typed username, whether or not a user has that name. The
	// name itself is never stored.
	Name    string
	Method  access.Method
	Trusted bool // the attempts carried a valid device cookie for that account
}

// FailureCount is one record: consecutive failed attempts, counted before
// verification, for one (name, method, trust context).
type FailureCount struct {
	LockedAt time.Time // set with Locked; the time the lock was reached
	FailureRef
	Count  int
	Locked bool // Count reached the failure cap; stays set until recovery or re-enable
	// Unreported is set with Locked; the sweep reports the lock when Name
	// is a user's and clears it.
	Unreported bool
}

// FailureStore holds the failure records.
type FailureStore interface {
	AuthFailure(ctx context.Context, ref FailureRef) (f FailureCount, found bool, err error)
	PutAuthFailure(ctx context.Context, f FailureCount) error // upsert
	// UnreportedLocks returns every record whose Unreported is set.
	UnreportedLocks(ctx context.Context) ([]FailureCount, error)
	// DeleteAuthFailures removes name's records for each listed method, in
	// both trust contexts; an absent record is skipped.
	DeleteAuthFailures(ctx context.Context, name string, methods []access.Method) error
	// PruneAuthFailures removes every record whose Name is not in keep and
	// returns how many it removed.
	PruneAuthFailures(ctx context.Context, keep []string) (int64, error)
}

// LogStore holds the append-only security log ([LogEntry]). It has no
// update; entries leave only through PruneLog.
type LogStore interface {
	// AppendLog assigns e.Event.Seq and stores a deep copy (rule 22).
	AppendLog(ctx context.Context, e *LogEntry) error
	// ListLog returns the entries with r.AfterSeq < Seq, and Seq <
	// r.BeforeSeq when r.BeforeSeq is non-zero, in ascending Seq, or
	// descending when r.Descending, at most r.Limit of them (rule 22).
	ListLog(ctx context.Context, r LogRange) ([]LogEntry, error)
	// PruneLog removes entries of p.Class, lowest Seq first: with p.Keep
	// set, each beyond the newest p.Keep of that class, adding the number
	// removed to the class's Evicted; with p.Before set, each with At
	// before p.Before. Exactly one of the two is set, else it returns an
	// error. It removes at most p.Limit and returns how many (rule 22).
	PruneLog(ctx context.Context, p LogPrune) (int, error)
	// LogStats returns one LogClassStats per class that has ever held an
	// entry, in [LogClasses] order (rule 22).
	LogStats(ctx context.Context) ([]LogClassStats, error)
}

// LogClassStats is one class's entry count and cap evictions.
type LogClassStats struct {
	Class   LogClass
	Count   int    // entries the class holds now
	Evicted uint64 // entries Keep prunes have removed, ever; never lowered
}

// LogRange is one [LogStore.ListLog] call: an open Seq range, 0 BeforeSeq
// being unbounded.
type LogRange struct {
	AfterSeq, BeforeSeq uint64
	Limit               int
	Descending          bool
}

// LogPrune is one [LogStore.PruneLog] call, with exactly one of Keep (a
// positive cap) and Before (a non-zero age bound) set.
type LogPrune struct {
	Before time.Time
	Class  LogClass
	Keep   int
	Limit  int
}

// Tx is the view of the store inside one transaction. It is valid only
// until the Update callback returns.
type Tx interface {
	UserStore
	SessionStore
	PasskeyStore
	KeyStore
	TokenStore
	AttributionStore
	FailureStore
	LogStore
}

// Sweeper holds the two expiry cleanups the background sweep calls, each a
// single-call write outside Update. They are not on Tx: inside a
// transaction, "exactly the refs it deleted, in one atomic step" cannot
// hold, since the Update may roll back or run again.
type Sweeper interface {
	// CleanupExpiredSessions deletes, in one atomic step, at most limit of
	// the sessions access.ValidateSession refuses at now under timeouts, and
	// returns the ref of each session it deleted; fewer than limit refs
	// means none such is left (rule 14). A store may refuse a limit below 1
	// or a zero timeouts with an error.
	CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error)
	// CleanupExpiredOneTimeTokens deletes every token whose ExpiresAt is not
	// after now and returns how many it deleted.
	CleanupExpiredOneTimeTokens(ctx context.Context, now time.Time) (int64, error)
}

// Store is everything account reads and writes.
type Store interface {
	Tx
	Sweeper
	// Update runs fn in one serialisable read-write transaction. fn's nil
	// return commits every write durably and at once; an error or a panic
	// discards every write, and a panic is re-raised after the rollback.
	// A store with a durable medium serves concurrently pending Updates
	// with one durable commit (bbolt db.Batch, a file store's group commit),
	// so a burst of counted sign-ins costs one publish, not one each; fn may
	// then run more than once, and only its last run's writes count (rule 5).
	Update(ctx context.Context, fn func(tx Tx) error) error
}
