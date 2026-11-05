package account_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// TestDirectSessionDelete deletes a session through the store, outside
// account, after a ceremony or flow on it began: none of them can finish.
func TestDirectSessionDelete(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		begin func(t *testing.T, w *opWorld, p access.Principal) func(ctx context.Context) error
		name  string
	}{
		{name: "passkey_step_up", begin: func(t *testing.T, w *opWorld, p access.Principal) func(context.Context) error {
			pc, err := w.svc.StepUpPasskeyBegin(t.Context(), p, w.origin)
			if err != nil {
				t.Fatalf("StepUpPasskeyBegin = %v", err)
			}
			body := w.devs[w.alice.ID].Assert(browserJSON(t, pc.Assertion))
			return func(ctx context.Context) error {
				_, err := w.svc.StepUpPasskeyFinish(ctx, localClient, p, pc.ID, bytes.NewReader(body))
				return err
			}
		}},
		{name: "oidc_link", begin: func(t *testing.T, w *opWorld, p access.Principal) func(context.Context) error {
			flow, claims := w.rig.sessionFlow(t, oidc.IntentLink, w.alice, p.SessionID)
			return func(ctx context.Context) error {
				_, err := w.svc.OIDCComplete(ctx, localClient, flow, claims)
				return err
			}
		}},
		{name: "oidc_step_up", begin: func(t *testing.T, w *opWorld, p access.Principal) func(context.Context) error {
			linkIdentity(t, w.mem, storedUser(t, w.mem, w.alice.ID), w.rig.identity())
			flow, claims := w.rig.sessionFlow(t, oidc.IntentStepUp, w.alice, p.SessionID)
			return func(ctx context.Context) error {
				_, err := w.svc.OIDCComplete(ctx, localClient, flow, claims)
				return err
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{})
			p := w.recent(t, w.alice)
			finish := tc.begin(t, w, p)
			linked := storedUser(t, w.mem, w.alice.ID).OIDC
			if err := w.mem.DeleteSessionByHash(t.Context(), p.SessionTokenHash()); err != nil {
				t.Fatalf("DeleteSessionByHash: %v", err)
			}
			mark := len(w.events.all())
			if err := finish(t.Context()); !errors.Is(err, account.ErrSessionGone) {
				t.Errorf("%s on a session deleted outside account = %v, want ErrSessionGone", tc.name, err)
			}
			if ids := sessionIDsOf(t, w.fixture, w.alice.ID); len(ids) != 1 {
				t.Errorf("alice's sessions = %v, want only the enrolment's: the deleted one came back", ids)
			}
			if got := storedUser(t, w.mem, w.alice.ID).OIDC; got != linked {
				t.Errorf("alice's link = %+v, want %+v unchanged", got, linked)
			}
			if evs := w.events.all()[mark:]; len(evs) != 0 {
				t.Errorf("%d events fired, first %s", len(evs), evs[0].Kind)
			}
		})
	}
}
