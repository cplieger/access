// Package failreason carries why a refusal happened beside the public
// sentinel a client sees, so accesshttp can audit it or name it in an error
// body while every caller's errors.Is and error text stay the sentinel's.
package failreason

import "errors"

const (
	// MethodLocked is a password attempt on a record already locked by the
	// failure cap; the client still sees ErrInvalidCredentials.
	MethodLocked = "method_locked"
	// ReenableNeedsOtherMethod is ReenableMethod refused for a session that
	// signed in with the method being re-enabled.
	ReenableNeedsOtherMethod = "reenable_needs_other_method"
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
