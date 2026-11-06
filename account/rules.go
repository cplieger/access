package account

import (
	"context"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
)

// BreachMode is what a password set does with the breached-password check.
type BreachMode int

const (
	// BreachOff runs no breach check.
	BreachOff BreachMode = iota
	// BreachFailOpen refuses a breached password and accepts one the check
	// could not judge, logging one WARN; a caller whose context ended gets
	// that context's error instead.
	BreachFailOpen
	// BreachFailClosed refuses a breached password, and one the check could
	// not judge with ErrBreachCheckUnavailable.
	BreachFailClosed
)

// Rules is the app's policy as data. Config.Rules is read once per
// operation, so a reloaded value applies from the next operation on.
//
// An app may refuse a sign-in method in its own gate before account sees
// the attempt; Rules has no sign-in hook for it, and MethodUsable keeps the
// last-method guard from counting such a method.
type Rules struct {
	// SetupTokenRequired reports whether a setup from c needs a token. It
	// gets the request context and the resolved client with its
	// provenance. Nil means always.
	SetupTokenRequired func(ctx context.Context, c Client) bool
	// MethodUsable reports whether m can sign u in now under the app's own
	// rules; the last-method guard and UsableMethods AND it into every
	// method they count. tx is what the count reads: a removal's own Update
	// when it decides, the Store for RemovePassword's pre-check, the
	// caller's tx in UsableMethods. An app may type-assert tx to its own
	// transaction type; MethodUsable must not block or call the Store
	// outside tx. The guard reads Config.RP() and Config.OIDC() as
	// published. Nil means every held method is usable.
	MethodUsable func(ctx context.Context, tx Tx, u *access.User, m access.Method) bool
	// SessionCaps returns per-session limits for a session about to be
	// created for c, read once at creation. A positive value caps that
	// limit for the session's whole life (Session.IdleCap,
	// Session.AbsoluteCap; kept on rotation); zero or less, or a nil func,
	// means no cap.
	SessionCaps func(ctx context.Context, c Client) (idle, absolute time.Duration)
	// KeyPrefix starts every minted key's plaintext; see access.GenerateAPIKey.
	KeyPrefix string
	// ForbiddenWords join the username in the password context check.
	ForbiddenWords []string
	// Scopes is the key-scope vocabulary; CreateAPIKey refuses any other.
	Scopes []string
	// Provisioning gates just-in-time creation on an OIDC sign-in with no
	// linked account. The zero value is off.
	Provisioning oidc.Provisioning
	// RecentAuth is how recent a sign-in or step-up must be for an
	// operation that requires recent authentication. Zero means 10m; a
	// value below 1m is invalid.
	RecentAuth time.Duration
	// Breach is the breached-password check's mode; the zero value is off.
	Breach BreachMode
	// MaxSessionsPerUser bounds each user's sessions; creating one past it
	// ends the user's least recently active. Zero is unlimited.
	MaxSessionsPerUser int
	// DisablePasswordLogin refuses password sign-in and step-up with
	// ErrPasswordLoginDisabled. The zero value allows them.
	DisablePasswordLogin bool
	// SSOGoverned makes an OIDC link migrate the account: the password and
	// passkeys are removed, and only recovery restores a local method. A
	// full session of a user with a linked identity may not then set a
	// password or enrol a passkey (ErrSSOGoverned); unlinked users are
	// unaffected.
	SSOGoverned bool
	// RevokeKeysOnCredentialChange deletes the user's API keys when the
	// password is set or changed or an OIDC identity is linked. Disable and
	// delete always delete keys, whatever this says.
	RevokeKeysOnCredentialChange bool
}

// MethodState is the configuration UsableMethods counts under, in place of
// the published Config.Rules(), Config.RP() and Config.OIDC(), so an app
// can check values before it publishes them.
type MethodState struct {
	// RPID is the relying party ID a counted passkey is registered under;
	// empty means passkeys are off.
	RPID string
	// OIDCIssuer is the issuer a counted OIDC link carries; empty means
	// OIDC is off.
	OIDCIssuer string
	Rules      Rules
}

const (
	// MaxUsernameLength is the longest username, in runes after
	// access.NormalizeUsername, that any creation path accepts.
	MaxUsernameLength = 64
	// FailureCap is the consecutive-failure count, per (name, method) and
	// trust context, at which the method locks for that context.
	FailureCap = 100
	// MaxUntrustedCounts is how many untrusted attempts the whole process
	// counts between two failure-record prunes; spending it wakes a prune,
	// and untrusted counted attempts are refused until it commits.
	MaxUntrustedCounts = 10000
	// MaxKeyLineage is the most IDs a Key.LineageIDs holds: a root and seven
	// generations of keys minted by keys. Minting below a key whose path is
	// full is *PolicyError{Reason: "lineage_too_deep"}.
	MaxKeyLineage = 8
	// MaxSweepBatch is the most sessions one CleanupExpiredSessions call
	// deletes, and so the most IDs one call's EventSessionsExpired events
	// carry together; the sweep calls again within the tick until a call
	// returns fewer.
	MaxSweepBatch = 1000
)

const (
	defaultRecentAuth = 10 * time.Minute
	minRecentAuth     = time.Minute
)

// Validate checks every bounded field, KeyPrefix and Provisioning. The error is a
// *RulesError naming the field, which matches ErrRulesInvalid.
func (r Rules) Validate() error { //nolint:gocritic // hugeParam: Rules is the value Config.Rules returns
	switch {
	case r.RecentAuth != 0 && r.RecentAuth < minRecentAuth:
		return &RulesError{Field: "RecentAuth", Reason: "below 1m"}
	case r.Breach < BreachOff || r.Breach > BreachFailClosed:
		return &RulesError{Field: "Breach", Reason: "unknown mode"}
	case r.MaxSessionsPerUser < 0:
		return &RulesError{Field: "MaxSessionsPerUser", Reason: "negative"}
	}
	if err := access.ValidateKeyPrefix(r.KeyPrefix); err != nil {
		return &RulesError{Field: "KeyPrefix", Reason: err.Error(), Err: err}
	}
	if err := r.Provisioning.Validate(); err != nil {
		return &RulesError{Field: "Provisioning", Reason: err.Error(), Err: err}
	}
	return nil
}

// withDefaults returns r with each zero field that has a default set to it.
func (r Rules) withDefaults() Rules { //nolint:gocritic // hugeParam: Rules is the value Config.Rules returns
	if r.RecentAuth == 0 {
		r.RecentAuth = defaultRecentAuth
	}
	return r
}
