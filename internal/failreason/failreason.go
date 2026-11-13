// Package failreason carries why a refusal happened beside the public
// sentinel a client sees, so an audit event can name it, or accesshttp an
// error body, while every caller's errors.Is and error text stay the
// sentinel's.
package failreason

import "errors"

const (
	// MethodLocked is a password attempt on a record already locked by the
	// failure cap; the client still sees ErrInvalidCredentials.
	MethodLocked = "method_locked"
	// ReenableNeedsOtherMethod is ReenableMethod refused for a session that
	// signed in with the method being re-enabled.
	ReenableNeedsOtherMethod = "reenable_needs_other_method"

	// KeyUnknown is a Bearer value no stored key has as either secret. The
	// verifiers' reasons are audit-only: the client sees the sentinel, so a
	// refusal never tells a key holder which keys exist.
	KeyUnknown = "key_unknown"
	// KeyExpired is a key at or past its ExpiresAt.
	KeyExpired = "key_expired"
	// KeyRetired is a rotated key's previous secret once it no longer
	// verifies.
	KeyRetired = "key_retired"
	// AccountDisabled is a credential whose owner is missing or disabled.
	AccountDisabled = "account_disabled"
	// SessionExpired is a session cookie past its idle or absolute limit.
	SessionExpired = "session_expired"
	// SessionUnknown is a session cookie no stored session has.
	SessionUnknown = "session_unknown"
	// CredentialInvalid is a custom verifier's refusal.
	CredentialInvalid = "credential_invalid" //nolint:gosec // G101: a refusal reason, not a credential
)

type reasoned struct {
	err    error
	reason string
}

func (r *reasoned) Error() string { return r.err.Error() }
func (r *reasoned) Unwrap() error { return r.err }

// Wrap returns err carrying reason. The result matches err under errors.Is
// and has err's Error text.
func Wrap(err error, reason string) error { return &reasoned{err: err, reason: reason} }

// Of returns the reason err carries, or "" for none.
func Of(err error) string {
	if r, ok := errors.AsType[*reasoned](err); ok {
		return r.reason
	}
	return ""
}
