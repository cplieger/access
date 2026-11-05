package account_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// TestUpdateProfileViewReadRollsBack holds UpdateProfile's view to its
// Update: a store error reading it answers ErrAuthBackend with the stored
// name as it was.
func TestUpdateProfileViewReadRollsBack(t *testing.T) {
	t.Parallel()
	var armed atomic.Bool
	f := newFixture(t, options{edit: func(c *account.Config) { c.Store = passkeyReadsFail{c.Store, &armed} }})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	if _, err := f.svc.UpdateProfile(t.Context(), pr, "Before"); err != nil {
		t.Fatalf("UpdateProfile = %v", err)
	}
	armed.Store(true)
	_, err := f.svc.UpdateProfile(t.Context(), pr, "After")
	armed.Store(false)
	if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errFault) {
		t.Fatalf("UpdateProfile with the view read failing = %v, want ErrAuthBackend wrapping the fault", err)
	}
	if got := storedUser(t, f.mem, u.ID).DisplayName; got != "Before" {
		t.Errorf("stored display name = %q, want %q: the update must roll back", got, "Before")
	}
}
