package account_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// noSetupToken is a setup rule that asks no client for a token.
func noSetupToken() account.Rules {
	return account.Rules{SetupTokenRequired: func(context.Context, account.Client) bool { return false }}
}

// setupToken issues a setup token out of band.
func setupToken(t testing.TB, svc *account.Service) access.Secret {
	t.Helper()
	tok, err := svc.IssueSetupToken(t.Context(), account.OutOfBand("cli"), 0)
	if err != nil {
		t.Fatalf("IssueSetupToken: %v", err)
	}
	return tok
}

// beginSetup begins a passkey setup for owner and returns the ceremony's ID
// and dev's attestation for it.
func (p *pkFixture) beginSetup(t testing.TB, token access.Secret, dev *accesstest.PasskeyDevice) (string, []byte) {
	t.Helper()
	pc, err := p.svc.SetupPasskeyBegin(t.Context(), localClient, account.SetupPasskey{Token: token, Username: "Owner", Origin: p.origin})
	if err != nil {
		t.Fatalf("SetupPasskeyBegin: %v", err)
	}
	return pc.ID, dev.Register(browserJSON(t, pc.Creation))
}

func TestPasskeySetup(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rules func() account.Rules
		name  string
		token bool
	}{
		{name: "tokened", token: true},
		{name: "tokenless", rules: noSetupToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newPK(t, pwOptions{rules: tc.rules})
			var tok access.Secret
			if tc.token {
				tok = setupToken(t, p.svc)
			}
			dev := accesstest.NewPasskeyDevice(t)
			id, body := p.beginSetup(t, tok, dev)
			if n, err := p.mem.UserCount(t.Context()); err != nil || n != 0 {
				t.Fatalf("users after the begin = %d, %v; want none", n, err)
			}
			in, err := p.svc.SetupPasskeyFinish(t.Context(), localClient, id, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("SetupPasskeyFinish = %v", err)
			}
			u := storedUser(t, p.mem, in.User.ID)
			if u.Username != "owner" || u.Role != access.RoleAdmin || !u.Enabled || !u.PasswordHash.IsZero() {
				t.Errorf("created user = %+v, want an enabled admin owner with no password", u)
			}
			pks := passkeysOf(t, p.mem, u.ID)
			if len(pks) != 1 || pks[0].RPID != rpID || pks[0].Name != "Passkey 1" {
				t.Errorf("the owner's passkeys = %+v, want one named Passkey 1 under %s", pks, rpID)
			}
			sess := storedSession(t, p.mem, u.ID, in.Session.ID)
			if sess.AuthMethod != access.MethodPasskey || sess.Kind != access.SessionFull || in.DeviceCookie.IsZero() {
				t.Errorf("session %q %v, device cookie set %t; want a full passkey session and a cookie", sess.AuthMethod, sess.Kind, !in.DeviceCookie.IsZero())
			}
			if tc.token {
				if _, found, err := p.mem.OneTimeTokenByHash(t.Context(), access.NewHash(access.HexSHA256(tok.Reveal()))); err != nil || found {
					t.Errorf("the setup token is still stored (%v), want it spent", err)
				}
			}
			if signed := eventsOf(p.events, account.EventSignedIn); len(signed) != 1 || signed[0].Method != access.MethodPasskey || signed[0].UserID != u.ID {
				t.Errorf("EventSignedIn = %+v, want the owner's passkey sign-in", signed)
			}
			if again, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev); err != nil || again.User.ID != u.ID {
				t.Errorf("the owner's later passkey sign-in = %v, want it signed in", err)
			}
		})
	}
}

func TestPasskeySetupRefusals(t *testing.T) {
	t.Parallel()
	t.Run("begin", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		tok := setupToken(t, p.svc)
		other := access.NewSecret("not-the-setup-token")
		cases := []struct {
			want error
			name string
			in   account.SetupPasskey
		}{
			{name: "no_token", in: account.SetupPasskey{Username: "owner"}, want: account.ErrSetupTokenRequired},
			{name: "wrong_token", in: account.SetupPasskey{Token: other, Username: "owner"}, want: access.ErrTokenInvalid},
			{name: "empty_username", in: account.SetupPasskey{Token: tok, Username: ""}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tc.in.Origin = p.origin
				_, err := p.svc.SetupPasskeyBegin(t.Context(), localClient, tc.in)
				if tc.want == nil {
					if ue, ok := errors.AsType[*account.UsernameError](err); !ok || ue.Reason != "empty" {
						t.Errorf("SetupPasskeyBegin = %v, want *UsernameError{empty}", err)
					}
				} else if !errors.Is(err, tc.want) {
					t.Errorf("SetupPasskeyBegin = %v, want %v", err, tc.want)
				}
				if n := account.Pending(p.svc).Len(); n != 0 {
					t.Errorf("pending ceremonies = %d, want none after a refused begin", n)
				}
			})
		}
	})
	t.Run("begin_after_setup", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{rules: noSetupToken})
		mustUser(t, p.mem, "first", access.RoleAdmin)
		if _, err := p.svc.SetupPasskeyBegin(t.Context(), localClient, account.SetupPasskey{Username: "owner", Origin: p.origin}); !errors.Is(err, account.ErrSetupComplete) {
			t.Errorf("SetupPasskeyBegin with a user present = %v, want ErrSetupComplete", err)
		}
	})
	t.Run("token_spent_before_finish", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		tok := setupToken(t, p.svc)
		id, body := p.beginSetup(t, tok, accesstest.NewPasskeyDevice(t))
		if _, _, err := p.mem.ConsumeOneTimeToken(t.Context(), access.NewHash(access.HexSHA256(tok.Reveal())), time.Now()); err != nil {
			t.Fatalf("ConsumeOneTimeToken: %v", err)
		}
		if _, err := p.svc.SetupPasskeyFinish(t.Context(), localClient, id, bytes.NewReader(body)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("finish with the token spent = %v, want access.ErrTokenInvalid", err)
		}
		if n, _ := p.mem.UserCount(t.Context()); n != 0 {
			t.Errorf("users = %d, want none", n)
		}
	})
	t.Run("user_created_before_finish", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		tok := setupToken(t, p.svc)
		id, body := p.beginSetup(t, tok, accesstest.NewPasskeyDevice(t))
		first := &access.User{Username: "first", Role: access.RoleAdmin, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle()}
		if err := p.mem.CreateInitialUser(t.Context(), first); err != nil {
			t.Fatalf("CreateInitialUser: %v", err)
		}
		if _, err := p.svc.SetupPasskeyFinish(t.Context(), localClient, id, bytes.NewReader(body)); !errors.Is(err, account.ErrSetupComplete) {
			t.Errorf("finish after another setup won = %v, want ErrSetupComplete", err)
		}
		if n, _ := p.mem.UserCount(t.Context()); n != 1 {
			t.Errorf("users = %d, want only the winner", n)
		}
		if _, found, err := p.mem.OneTimeTokenByHash(t.Context(), access.NewHash(access.HexSHA256(tok.Reveal()))); err != nil || !found {
			t.Errorf("the setup token is gone (%v), want the rolled-back finish to leave it", err)
		}
		if n := len(passkeysOf(t, p.mem, first.ID)); n != 0 || len(eventsOf(p.events, account.EventSignedIn)) != 0 {
			t.Errorf("the refused finish stored %d passkeys or emitted a sign-in", n)
		}
	})
}
