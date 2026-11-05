package access

import "errors"

// Errors of authentication. A verifier's or the [Authenticator]'s refusal
// carries one of the first three; the rest are details or the answers of
// [RequireRecentAuth] and [Authenticator.Recheck].
var (
	// ErrUnauthenticated means no usable credential. It is bare when none
	// was presented, and wraps [ErrSessionExpired] or [ErrSessionNotFound]
	// when the only one was a session cookie whose session is gone.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrInvalidCredential means a credential was presented and refused.
	// The error is an [*InvalidCredentialError] naming why.
	ErrInvalidCredential = errors.New("access: invalid credential")
	// ErrAuthBackend means a store failed while authenticating; the error
	// wraps the store's.
	ErrAuthBackend = errors.New("access: authentication backend failed")
	// ErrRecentAuthRequired is [RequireRecentAuth]'s refusal.
	ErrRecentAuthRequired = errors.New("access: recent authentication required")
	// ErrNotRecheckable is the answer for a principal no verifier can
	// re-validate.
	ErrNotRecheckable = errors.New("access: principal cannot be rechecked")
	// ErrAccountDisabled is the detail for a credential whose user is
	// missing or disabled.
	ErrAccountDisabled = errors.New("access: account disabled")
	// ErrRestrictedSession is the detail for a recovery session presented
	// on a request that does not allow one (see [AllowRecoverySession]).
	ErrRestrictedSession = errors.New("access: restricted session")
)

// InvalidCredentialError is the detail of [ErrInvalidCredential]; the error
// matches both ErrInvalidCredential and Err.
type InvalidCredentialError struct {
	// Err is [ErrInvalidAPIKey], [ErrAccountDisabled] or
	// [ErrRestrictedSession], or nil for a granted principal refused only
	// for an empty Method.
	Err error
	// Method is the refused credential's: [MethodAPIKey] for an API key, a
	// recovery session's AuthMethod, the granted principal's own Method for
	// a refused grant.
	Method Method
	// KeyID is the ID of the stored key a refused API key named, set only
	// when the store found it (expired, owner missing or disabled) and zero
	// otherwise, so a refusal carries no byte of a presented value.
	KeyID int64
}

func (e *InvalidCredentialError) Error() string {
	msg := ErrInvalidCredential.Error()
	if e.Method != "" {
		msg += " (" + string(e.Method) + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns [ErrInvalidCredential] and Err, when set.
func (e *InvalidCredentialError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrInvalidCredential}
	}
	return []error{ErrInvalidCredential, e.Err}
}
