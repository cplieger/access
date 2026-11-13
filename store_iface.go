package access

import (
	"context"
	"time"
)

// The read roles below keep the store contract of the account package's
// documentation: absence travels as found, and a lookup returns a value the
// caller owns. Ownership makes concurrent verification of one session safe:
// the session verifier reads the returned session while a sibling
// verification may be calling UpdateSessionActivity, so a store returning an
// alias it mutates races.

// SessionReader finds session data by token hash.
type SessionReader interface {
	SessionByHash(ctx context.Context, tokenHash Hash) (sess *Session, found bool, err error)
}

// SessionActivityUpdater writes an active verified request's activity back
// to its session. For a hash no session has, it writes nothing and returns
// nil. It stores act's LastActivity and LastIP only when act.At is after the
// stored LastActivity, atomically; an older or equal At writes nothing,
// LastIP included, and returns nil.
type SessionActivityUpdater interface {
	UpdateSessionActivity(ctx context.Context, tokenHash Hash, act SessionActivity) error
}

// --- User storage ---

// UserReader retrieves user records for authentication.
type UserReader interface {
	UserByID(ctx context.Context, id int64) (user *User, found bool, err error)
}

// --- API Key storage ---

// APIKeyReader validates API keys (looked up by hash).
type APIKeyReader interface {
	// APIKeyByHash finds the key whose KeyHash, or whose non-zero
	// PreviousHash, equals hash; a zero hash finds nothing.
	APIKeyByHash(ctx context.Context, hash Hash) (key *Key, found bool, err error)
}

// APIKeyToucher records a use of a key's current secret as its LastUsedAt.
type APIKeyToucher interface {
	// TouchAPIKey sets LastUsedAt to at only when the stored KeyHash equals
	// hash and at is after the stored LastUsedAt, comparing and writing in
	// one atomic step. Otherwise, an ID no key has included, it writes
	// nothing and returns nil, so a touch sampled before a rotation, which
	// carries the superseded hash, never ends the new overlap.
	TouchAPIKey(ctx context.Context, keyID int64, hash Hash, at time.Time) error
}
