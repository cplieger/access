package account_test

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

func TestMeLocks(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pr, _ := p.signedInVia(t, u, access.MethodPasskey)
	me, err := p.svc.Me(t.Context(), pr)
	if err != nil {
		t.Fatalf("Me = %v", err)
	}
	want := account.Methods{HasPassword: true, PasswordLogin: true}
	if !methodsEqual(me.Methods, want) || me.CanLinkOIDC || me.User == nil || me.User.ID != u.ID {
		t.Errorf("Me with no lock = %+v, want alice with a password, no passkey, no lock", me)
	}
	if err := p.mem.CreatePasskey(t.Context(), &access.PasskeyCredential{UserID: u.ID, CredentialID: []byte("cred-1"), Name: "key"}); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	p.failN(t, clientAt(1), "alice", account.FailureCap)
	untrusted, _ := record(t, p.mem, p.svc, "alice", false)
	if me, err = p.svc.Me(t.Context(), pr); err != nil {
		t.Fatalf("Me = %v", err)
	}
	want.PasskeyCount = 1
	want.Locks = []account.MethodLock{{Method: access.MethodPassword, Untrusted: true}}
	if !methodsEqual(me.Methods, want) {
		t.Errorf("Me.Methods with the untrusted context locked = %+v, want %+v", me.Methods, want)
	}
	seedLock(t, p.mem, p.svc, "alice", true, true)
	if me, err = p.svc.Me(t.Context(), pr); err != nil {
		t.Fatalf("Me = %v", err)
	}
	want.Locks = []account.MethodLock{{Method: access.MethodPassword, Untrusted: true, Trusted: true}}
	if !methodsEqual(me.Methods, want) {
		t.Errorf("Me.Methods with both contexts locked = %+v, want %+v", me.Methods, want)
	}
	if rec, _ := record(t, p.mem, p.svc, "alice", false); rec != untrusted {
		t.Errorf("record after Me = %+v, want %+v unchanged: Me writes nothing", rec, untrusted)
	}
	if got := p.events.all(); len(got) != 0 {
		t.Errorf("events = %v, want none", got)
	}
}

func TestMeMethods(t *testing.T) {
	t.Parallel()
	configured := func(provider *oidc.Provider) func(*account.Config) {
		return func(c *account.Config) {
			c.OIDC = func() *oidc.Provider { return provider }
			c.RP = func() *webauthn.RelyingParty { return &webauthn.RelyingParty{} }
		}
	}
	me := func(t *testing.T, f *fixture, u *access.User) account.Me {
		t.Helper()
		m, err := f.svc.Me(t.Context(), f.sessionPrincipal(t, u, access.SessionFull, time.Now()))
		if err != nil {
			t.Fatalf("Me = %v", err)
		}
		return m
	}
	t.Run("oidc_and_passkeys_on", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: configured(&oidc.Provider{})})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		m := me(t, f, u)
		if !m.Methods.OIDCAvailable || !m.Methods.PasskeysAvailable || m.Methods.OIDCLinked || !m.CanLinkOIDC {
			t.Errorf("Me of an unlinked user with OIDC and passkeys on = %+v, CanLinkOIDC %t; want both available, unlinked, linkable", m.Methods, m.CanLinkOIDC)
		}
		u.OIDC = access.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "alice-sub"}
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		m = me(t, f, u)
		if !m.Methods.OIDCLinked || !m.Methods.OIDCAvailable || m.CanLinkOIDC {
			t.Errorf("Me of a linked user = %+v, CanLinkOIDC %t; want linked, still available, not linkable", m.Methods, m.CanLinkOIDC)
		}
	})
	t.Run("oidc_resolves_nil", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: configured(nil)})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		m := me(t, f, u)
		if m.Methods.OIDCAvailable || m.CanLinkOIDC || !m.Methods.PasskeysAvailable {
			t.Errorf("Me with Config.OIDC resolving to nil = %+v, CanLinkOIDC %t; want OIDC unavailable, not linkable, passkeys on", m.Methods, m.CanLinkOIDC)
		}
	})
}

func TestMePasswordLoginDisabled(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{rules: func() account.Rules { return account.Rules{DisablePasswordLogin: true} }})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	me, err := f.svc.Me(t.Context(), f.sessionPrincipal(t, u, access.SessionFull, time.Now()))
	if err != nil {
		t.Fatalf("Me = %v", err)
	}
	if me.Methods.PasswordLogin || me.Methods.HasPassword {
		t.Errorf("Me.Methods = %+v, want PasswordLogin false under DisablePasswordLogin and no password", me.Methods)
	}
}

func TestMeRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	for name, pr := range map[string]access.Principal{
		"key":      f.keyPrincipal(t, u, "read"),
		"recovery": f.sessionPrincipal(t, u, access.SessionRecovery, time.Now()),
		"bypass":   f.bypassPrincipal(t),
	} {
		if _, err := f.svc.Me(t.Context(), pr); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("Me(%s) = %v, want ErrSessionRequired", name, err)
		}
	}
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	if err := f.mem.DeleteUser(t.Context(), u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := f.svc.Me(t.Context(), pr); !errors.Is(err, account.ErrSessionGone) {
		t.Errorf("Me for a user deleted since its principal = %v, want ErrSessionGone", err)
	}
}

func TestMeCurrentSessionCapped(t *testing.T) {
	t.Parallel()
	timeouts := access.SessionTimeouts{Idle: 7 * 24 * time.Hour, Absolute: 30 * 24 * time.Hour}
	f := newFixture(t, options{timeouts: func() access.SessionTimeouts { return timeouts }})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	now := time.Now()
	sess := &access.Session{
		ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPasskey,
		CreatedAt: now.Add(-2 * time.Hour), LastActivity: now, AuthTime: now.Add(-time.Hour),
		IdleCap: 30 * time.Minute, AbsoluteCap: 12 * time.Hour,
	}
	pr, _ := f.principalOf(t, sess)
	stored := storedSession(t, f.mem, u.ID, sess.ID)
	me, err := f.svc.Me(t.Context(), pr)
	if err != nil {
		t.Fatalf("Me = %v", err)
	}
	cur := me.Current
	if cur.ID != sess.ID || cur.Method != access.MethodPasskey || !cur.AuthTime.Equal(sess.AuthTime) {
		t.Errorf("Me.Current = %+v, want session %s by passkey at %v", cur, sess.ID, sess.AuthTime)
	}
	if want := stored.LastActivity.Add(30 * time.Minute); !cur.IdleDeadline.Equal(want) {
		t.Errorf("Me.Current.IdleDeadline = %v, want the 30m cap from the last activity, %v", cur.IdleDeadline, want)
	}
	if want := sess.CreatedAt.Add(12 * time.Hour); !cur.AbsoluteDeadline.Equal(want) {
		t.Errorf("Me.Current.AbsoluteDeadline = %v, want the 12h cap from creation, %v", cur.AbsoluteDeadline, want)
	}
}

// storedSession reads userID's session id from s.
func storedSession(t *testing.T, s account.Store, userID int64, id string) access.Session {
	t.Helper()
	sessions, err := s.SessionsByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("SessionsByUserID: %v", err)
	}
	i := slices.IndexFunc(sessions, func(s access.Session) bool { return s.ID == id })
	if i < 0 {
		t.Fatalf("session %s not stored", id)
	}
	return sessions[i]
}

func methodsEqual(a, b account.Methods) bool {
	return reflect.DeepEqual(a, b)
}
