package account_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// passkeyReadsFail is a Store whose PasskeysByUserID fails inside an
// Update once armed; a single call outside one still succeeds, so a view
// read after the Update would not fail.
type passkeyReadsFail struct {
	account.Store
	armed *atomic.Bool
}

func (s passkeyReadsFail) Update(ctx context.Context, fn func(account.Tx) error) error {
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(passkeyReadsFailTx{tx, s.armed}) })
}

type passkeyReadsFailTx struct {
	account.Tx
	armed *atomic.Bool
}

func (t passkeyReadsFailTx) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if t.armed.Load() {
		return nil, errFault
	}
	return t.Tx.PasskeysByUserID(ctx, userID)
}

// TestLinkPendingViewReadRollsBack holds LinkPendingOIDC's view to its
// Update: a store error reading it answers ErrAuthBackend with the link,
// the session's token and the events as they were.
func TestLinkPendingViewReadRollsBack(t *testing.T) {
	t.Parallel()
	var armed atomic.Bool
	f := newPendingFixture(t, pwOptions{edit: func(c *account.Config) { c.Store = passkeyReadsFail{c.Store, &armed} }})
	pr, old := f.signedInVia(t, f.u, access.MethodPassword)
	events := len(f.events.all())
	armed.Store(true)
	is, view, err := f.svc.LinkPendingOIDC(t.Context(), pr, f.pending)
	armed.Store(false)
	if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errFault) || !is.Token.IsZero() || view.User != nil {
		t.Fatalf("LinkPendingOIDC = %+v, %+v, %v; want ErrAuthBackend and nothing issued", is, view, err)
	}
	if got := storedUser(t, f.mem, f.u.ID).OIDC; !got.IsZero() {
		t.Errorf("stored link = %+v, want none: the link must roll back", got)
	}
	if _, err := f.authenticate(t.Context(), old); err != nil {
		t.Errorf("the pre-link token no longer authenticates (%v): the rotation must roll back", err)
	}
	if n := len(f.events.all()); n != events {
		t.Errorf("%d events fired on a rolled-back link", n-events)
	}
}
