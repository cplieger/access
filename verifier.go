package access

import (
	"context"
	"net/http"
)

// CredentialVerifier resolves one credential type. ok true with a nil error
// grants p. ok false with a nil error means "not my credential", and p is
// ignored. A non-nil error decides whatever ok says: one matching
// [ErrUnauthenticated] means "presented but unusable" (expired, revoked), so
// the chain continues and that error is the result if nothing later grants;
// any other stops the chain: [ErrInvalidCredential] for a refused
// credential, [ErrAuthBackend] for a store failure.
type CredentialVerifier interface {
	Verify(ctx context.Context, r *http.Request) (p Principal, ok bool, err error)
}

// Rechecker re-validates a principal for a long-lived connection without
// writing activity. ok false with a nil error means "not a principal I
// produced", which [Authenticator.Recheck] answers as [ErrNotRecheckable]; a
// non-nil error is the re-validation's refusal.
type Rechecker interface {
	Recheck(ctx context.Context, p Principal) (q Principal, ok bool, err error)
}
