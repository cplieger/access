package access

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"
)

// Principal is the outcome of authenticating one request.
type Principal struct {
	// AuthTime is the session's last primary sign-in or step-up; session
	// principals only.
	AuthTime time.Time
	// IdleDeadline and AbsoluteDeadline are when this principal lapses if
	// nothing else happens. A session's are its [SessionDeadlines]; a key's
	// AbsoluteDeadline is its non-zero ExpiresAt and its IdleDeadline zero;
	// both are zero for a key with no expiry and for every other principal.
	// A stream ends itself at the earlier non-zero one without a store read.
	IdleDeadline     time.Time
	AbsoluteDeadline time.Time
	// IP is the client address of the request Authenticate verified,
	// Recheck's input's for a rechecked principal; zero for a principal
	// built elsewhere.
	IP   netip.Addr
	User *User
	// credential is the looked-up session or key hash, for Recheck and
	// rotation.
	credential Hash
	Method     Method
	// SessionID and SessionKind name the session; session principals only.
	SessionID   string
	SessionKind SessionKind
	// Scopes are a key's or a custom verifier's scopes; nil for sessions.
	Scopes []string
	// KeyID is the authenticating key; MethodAPIKey only.
	KeyID int64
	// source is set only by the built-in session and API-key verifiers, so a
	// custom verifier that fills SessionID and AuthTime, or Method and KeyID,
	// cannot pass IsSession, IsRecoverySession, RequireRecentAuth or IsAPIKey.
	source principalSource
}

// principalSource is which verifier produced a Principal. Its zero value is
// a custom verifier or the bypass, so a Principal built outside this package
// carries no built-in provenance.
type principalSource uint8

const (
	sourceExternal principalSource = iota
	sourceSession
	sourceAPIKey
)

// HasScope reports whether scope is among p's Scopes.
func (p Principal) HasScope(scope string) bool { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	return slices.Contains(p.Scopes, scope)
}

// SessionTokenHash returns the stored hash of the session that produced p,
// or the zero Hash for any other principal.
func (p Principal) SessionTokenHash() Hash { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	if p.source != sourceSession {
		return Hash{}
	}
	return p.credential
}

// IsSession reports a principal the built-in session verifier produced from
// a full session ([SessionFull]). Keys, custom verifiers and the bypass never
// pass it.
func (p Principal) IsSession() bool { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	return p.source == sourceSession && p.SessionKind == SessionFull
}

// IsRecoverySession reports a principal the built-in session verifier
// produced from a [SessionRecovery] session.
func (p Principal) IsRecoverySession() bool { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	return p.source == sourceSession && p.SessionKind == SessionRecovery
}

// IsAPIKey reports a principal the built-in API-key verifier produced. A
// custom verifier's principal never passes it, whatever its Method and
// KeyID.
func (p Principal) IsAPIKey() bool { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	return p.source == sourceAPIKey
}

// LogValue emits the method, the user's ID, the session ID and kind, the key
// ID and the scopes; never the credential hash.
func (p Principal) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies it to a Principal value too
	attrs := []slog.Attr{slog.String("method", string(p.Method))}
	if p.User != nil {
		attrs = append(attrs, slog.Int64("user_id", p.User.ID))
	}
	return slog.GroupValue(append(attrs,
		slog.String("session_id", p.SessionID),
		slog.String("session_kind", string(p.SessionKind)),
		slog.Int64("key_id", p.KeyID),
		slog.Any("scopes", p.Scopes),
	)...)
}

// RequireRecentAuth returns nil only for a principal for which IsSession is
// true and whose AuthTime is within maxAge of now and not after it; every
// other principal, a custom verifier's included, gets [ErrRecentAuthRequired].
// An AuthTime after now is refused on purpose: this gate guards a sensitive
// operation, a job apart from session validity, and fails closed where it
// cannot place the proof of a recent sign-in.
func RequireRecentAuth(p Principal, maxAge time.Duration, now time.Time) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if !p.IsSession() || p.AuthTime.Before(now.Add(-maxAge)) || p.AuthTime.After(now) {
		return ErrRecentAuthRequired
	}
	return nil
}

type (
	passiveKey       struct{}
	allowRecoveryKey struct{}
)

// Passive marks a request whose verification must not count as session
// activity: presence receipts, polling, stream reconnects. The session is
// still fully verified; only the activity write is skipped.
func Passive(ctx context.Context) context.Context {
	return context.WithValue(ctx, passiveKey{}, true)
}

// IsPassive reports whether ctx carries [Passive].
func IsPassive(ctx context.Context) bool {
	v, _ := ctx.Value(passiveKey{}).(bool)
	return v
}

// AllowRecoverySession marks a request on which a [SessionRecovery]
// principal may authenticate. Every other request refuses it.
func AllowRecoverySession(ctx context.Context) context.Context {
	return context.WithValue(ctx, allowRecoveryKey{}, true)
}

func allowsRecoverySession(ctx context.Context) bool {
	v, _ := ctx.Value(allowRecoveryKey{}).(bool)
	return v
}
