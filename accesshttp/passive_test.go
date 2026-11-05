package accesshttp

import (
	"context"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// activityCounting is an env whose store counts UpdateSessionActivity calls.
func activityCounting(writes *atomic.Int64) envOptions {
	return envOptions{store: func(m *accesstest.MemStore) account.Store {
		cs := &countingStore{seen: func(_ context.Context, call string, _ bool) {
			if call == "UpdateSessionActivity" {
				writes.Add(1)
			}
		}}
		cs.wrap(m)
		return cs
	}}
}

// TestPassiveRoutes is §1.2's passive verification through accesshttp: GET
// /state, /me and /oidc/pending, sent a session whose activity write is
// due on every request, write none, while a session route that is not
// passive writes one.
func TestPassiveRoutes(t *testing.T) {
	var passive []string
	for _, rt := range newEnv(t, envOptions{}).h.Routes() {
		if rt.Passive {
			passive = append(passive, rt.Name)
		}
	}
	if want := []string{"authState", "authOIDCPending", "authMe"}; !slices.Equal(passive, want) {
		t.Errorf("passive routes %v, want %v", passive, want)
	}
	for _, tc := range []struct {
		name   string
		writes int64
	}{
		{name: "authState"},
		{name: "authOIDCPending"},
		{name: "authMe"},
		{name: "authSessions", writes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes atomic.Int64
			e := newEnv(t, activityCounting(&writes))
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			e.createUser(t, "alice", access.RoleUser)
			r := request(e.route(t, tc.name), "", e.sessionCookie(t, "alice"), e.pendingCookie(t, pendingPayload{Issuer: testIssuer, Subject: "pending-subject"}))
			writes.Store(0)
			if w := do(e.route(t, tc.name), r); w.Code != http.StatusOK {
				t.Fatalf("status %d, errors %+v, want 200", w.Code, e.errs.all())
			}
			if n := writes.Load(); n != tc.writes {
				t.Errorf("%d activity writes, want %d", n, tc.writes)
			}
		})
	}
}
