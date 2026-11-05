package account_test

import (
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

func TestRotationKeepsSession(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rotate func(t *testing.T, p *pkFixture, rig *oidcRig, pr access.Principal) (account.Issued, error)
		name   string
		stepUp access.Method // the method a step-up records; empty for any other rotation
	}{
		{name: "password_step_up", stepUp: access.MethodPassword, rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			return p.stepUp(t.Context(), localClient, pr, goodPassword)
		}},
		{name: "passkey_step_up", stepUp: access.MethodPasskey, rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			dev := accesstest.NewPasskeyDevice(t)
			p.enrol(t, pr.User, dev)
			return p.stepUpPasskey(t, localClient, pr, dev)
		}},
		{name: "set_password", rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			return p.setPassword(t.Context(), pr, goodPassword, newPassword)
		}},
		{name: "passkey_enrolment", rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			reg, err := p.register(t, pr, accesstest.NewPasskeyDevice(t))
			return reg.Issued, err
		}},
		{name: "oidc_step_up", stepUp: access.MethodOIDC, rotate: func(t *testing.T, p *pkFixture, rig *oidcRig, pr access.Principal) (account.Issued, error) {
			linkIdentity(t, p.mem, storedUser(t, p.mem, pr.User.ID), rig.identity())
			flow, claims := rig.sessionFlow(t, oidc.IntentStepUp, pr.User, pr.SessionID)
			out, err := p.svc.OIDCComplete(t.Context(), localClient, flow, claims)
			return out.Issued, err
		}},
		{name: "oidc_link", rotate: func(t *testing.T, p *pkFixture, rig *oidcRig, pr access.Principal) (account.Issued, error) {
			flow, claims := rig.sessionFlow(t, oidc.IntentLink, pr.User, pr.SessionID)
			out, err := p.svc.OIDCComplete(t.Context(), localClient, flow, claims)
			return out.Issued, err
		}},
		{name: "oidc_pending_link", rotate: func(t *testing.T, p *pkFixture, rig *oidcRig, pr access.Principal) (account.Issued, error) {
			is, _, err := p.svc.LinkPendingOIDC(t.Context(), pr, account.PendingLink{Identity: rig.identity()})
			return is, err
		}},
		{name: "password_removal", rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			p.enrol(t, pr.User, accesstest.NewPasskeyDevice(t))
			return p.svc.RemovePassword(t.Context(), localClient, pr, access.NewSecret(goodPassword))
		}},
		{name: "key_minting", rotate: func(t *testing.T, p *pkFixture, _ *oidcRig, pr access.Principal) (account.Issued, error) {
			created, err := p.svc.CreateAPIKey(t.Context(), account.As(pr), pr.User.ID, account.NewKey{Label: "ci"})
			return created.Issued, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rig := newOIDCRig(t, accesstest.IdPOptions{})
			p := newPK(t, pwOptions{edit: rig.withOIDC})
			u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			now := time.Now().Truncate(time.Second)
			sess := &access.Session{
				ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPasskey,
				CreatedAt: now.Add(-3 * time.Hour), LastActivity: now, AuthTime: now.Add(-5 * time.Minute),
				UserAgent: "test-agent", Label: "laptop", LastIP: "192.0.2.7",
				IdleCap: 30 * time.Minute, AbsoluteCap: 12 * time.Hour,
			}
			pr, _ := p.principalOf(t, sess)
			before := storedSession(t, p.mem, u.ID, sess.ID)
			start := time.Now()
			is, err := tc.rotate(t, p, rig, pr)
			if err != nil {
				t.Fatalf("rotation = %v", err)
			}
			after := storedSession(t, p.mem, u.ID, sess.ID)
			if !after.TokenHash.Equal(access.SessionHash(is.Token.Reveal())) || after.TokenHash.Equal(before.TokenHash) {
				t.Error("the stored token hash is not the issued token's, or did not change")
			}
			kept := after
			if tc.stepUp != "" {
				if after.AuthMethod != tc.stepUp || after.AuthTime.Before(start) {
					t.Errorf("AuthMethod %q, AuthTime %v; want %q and a time from the step-up on", after.AuthMethod, after.AuthTime, tc.stepUp)
				}
				kept.AuthTime, kept.AuthMethod = before.AuthTime, before.AuthMethod
			}
			if !reflect.DeepEqual(withoutToken(kept), withoutToken(before)) {
				t.Errorf("rotated session = %+v, want %+v apart from its token and a step-up's AuthTime and AuthMethod", after, before)
			}
			if after.IdleCap != 30*time.Minute || after.AbsoluteCap != 12*time.Hour {
				t.Errorf("caps after the rotation = %v and %v, want 30m and 12h kept", after.IdleCap, after.AbsoluteCap)
			}
			if !reflect.DeepEqual(withoutToken(is.Session), withoutToken(after)) || !is.Session.TokenHash.Equal(after.TokenHash) {
				t.Errorf("Issued.Session = %+v, want the stored %+v", is.Session, after)
			}
		})
	}
}

// withoutToken is s with no TokenHash, whose masked form differs between
// two reads of one hash; compare hashes with Hash.Equal.
func withoutToken(s access.Session) access.Session {
	s.TokenHash = access.Hash{}
	return s
}

// TestRotateRacingRevoke races a step-up's rotation of a session against
// RevokeSession of it, in both serial orders and concurrently: afterwards
// no token of that session authenticates and the store holds none.
func TestRotateRacingRevoke(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*pwFixture, access.Principal, access.Secret, access.Principal) {
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		target, token := p.signedInVia(t, u, access.MethodPassword)
		other, _ := p.signedInVia(t, u, access.MethodPassword)
		return p, target, token, other
	}
	dead := func(t *testing.T, p *pwFixture, target access.Principal, tokens ...access.Secret) {
		t.Helper()
		for _, tok := range tokens {
			if tok.IsZero() {
				continue
			}
			if _, err := p.authenticate(t.Context(), tok); err == nil {
				t.Error("a token of the revoked session still authenticates")
			}
		}
		if slices.Contains(sessionIDsOf(t, p.fixture, target.User.ID), target.SessionID) {
			t.Error("the revoked session is still stored")
		}
	}
	t.Run("revoke_first", func(t *testing.T) {
		t.Parallel()
		p, target, token, other := setup(t)
		if err := p.svc.RevokeSession(t.Context(), other, target.SessionID); err != nil {
			t.Fatalf("RevokeSession = %v", err)
		}
		is, err := p.stepUp(t.Context(), localClient, target, goodPassword)
		if !errors.Is(err, account.ErrSessionGone) {
			t.Errorf("a step-up of the revoked session = %v, want ErrSessionGone", err)
		}
		dead(t, p, target, token, is.Token)
	})
	t.Run("rotate_first", func(t *testing.T) {
		t.Parallel()
		p, target, token, other := setup(t)
		is, err := p.stepUp(t.Context(), localClient, target, goodPassword)
		if err != nil {
			t.Fatalf("StepUpPassword = %v", err)
		}
		if err := p.svc.RevokeSession(t.Context(), other, target.SessionID); err != nil {
			t.Fatalf("RevokeSession of the rotated session = %v", err)
		}
		dead(t, p, target, token, is.Token)
	})
	t.Run("concurrent", func(t *testing.T) {
		t.Parallel()
		for range 20 {
			p, target, token, other := setup(t)
			var (
				wg       sync.WaitGroup
				is       account.Issued
				rotErr   error
				revokErr error
			)
			wg.Go(func() { is, rotErr = p.stepUp(t.Context(), localClient, target, goodPassword) })
			wg.Go(func() { revokErr = p.svc.RevokeSession(t.Context(), other, target.SessionID) })
			wg.Wait()
			if revokErr != nil {
				t.Fatalf("RevokeSession = %v", revokErr)
			}
			if rotErr != nil && !errors.Is(rotErr, account.ErrSessionGone) {
				t.Fatalf("StepUpPassword = %v, want success or ErrSessionGone", rotErr)
			}
			dead(t, p, target, token, is.Token)
		}
	})
}
