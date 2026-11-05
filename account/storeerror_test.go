package account_test

import (
	"errors"
	"testing"

	"github.com/cplieger/access"
)

// TestStoreErrorAfterApply runs every writing operation over an Update that
// publishes its writes and then errs (rule 10): the operation answers
// ErrAuthBackend, emits nothing, and makes no write of its own after it.
func TestStoreErrorAfterApply(t *testing.T) {
	t.Parallel()
	for _, op := range operations() {
		if op.readOnly || op.direct {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			mark := len(w.events.all())
			w.fs.resetRecord()
			w.fs.failAfterApply()
			if err := call.run(t.Context()); !errors.Is(err, access.ErrAuthBackend) {
				t.Errorf("%s over an Update that errs after applying = %v, want ErrAuthBackend", op.name, err)
			}
			if n := len(w.events.all()) - mark; n != 0 {
				t.Errorf("%s emitted %d events", op.name, n)
			}
			failed := 0
			for i, c := range w.fs.recorded() {
				if c.name == "Update" {
					if failed != 0 {
						t.Errorf("%s ran Update %d after the failed one", op.name, c.update)
					}
					failed = c.update
					continue
				}
				if failed != 0 && c.update != failed && isWrite(c.name) {
					t.Errorf("%s made write %s (call %d) after the failed Update", op.name, c.name, i)
				}
			}
			if failed == 0 {
				t.Errorf("%s ran no Update", op.name)
			}
		})
	}
}

// isWrite reports whether a recorded store call writes.
func isWrite(name string) bool {
	switch name {
	case "UserByID", "UserByUsername", "UserByOIDC", "UserByWebAuthnHandle", "ListUsers", "UserCount",
		"SessionByHash", "SessionsByUserID", "PasskeysByUserID", "APIKeyByHash", "ListAPIKeysByUserID",
		"ListAPIKeys", "OneTimeTokenByHash", "LiveOneTimeTokens", "ListKeyAttributions", "AuthFailure",
		"UnreportedLocks":
		return false
	}
	return true
}
