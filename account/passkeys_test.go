package account_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// custodyFailing is a store whose post-login custody write fails.
type custodyFailing struct{ account.Store }

func (custodyFailing) UpdatePasskeyAfterLogin(context.Context, int64, []byte, access.PasskeyLoginUpdate) error {
	return errors.New("custody write failed")
}

func TestPasskeyCeremonies(t *testing.T) {
	t.Parallel()
	t.Run("registration", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		first, err := p.register(t, pr, accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("first registration = %v", err)
		}
		stored := passkeysOf(t, p.mem, u.ID)
		if len(stored) != 1 || stored[0].ID != first.Passkey.ID || stored[0].RPID != rpID || stored[0].UserID != u.ID {
			t.Fatalf("stored passkeys = %+v, want the one registered under %s for user %d", stored, rpID, u.ID)
		}
		if first.Passkey.Name != "Passkey 1" {
			t.Errorf("first name = %q, want Passkey 1 (an unknown authenticator is numbered)", first.Passkey.Name)
		}
		added := eventsOf(p.events, account.EventPasskeyAdded)
		if len(added) != 1 || added[0].PasskeyID != first.Passkey.ID || added[0].UserID != u.ID || added[0].Actor.SessionID != pr.SessionID {
			t.Errorf("EventPasskeyAdded = %+v, want one naming passkey %d, user %d and the session", added, first.Passkey.ID, u.ID)
		}
		second, err := p.register(t, p.principal(t, first.Issued.Token), accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("second registration from the rotated session = %v", err)
		}
		if second.Passkey.Name != "Passkey 2" {
			t.Errorf("second name = %q, want Passkey 2", second.Passkey.Name)
		}
	})
	t.Run("modal_sign_in", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		pc, err := p.svc.PasskeyLoginBegin(t.Context(), localClient, p.origin, account.LoginModal)
		if err != nil {
			t.Fatalf("PasskeyLoginBegin = %v", err)
		}
		if pc.Assertion == nil || pc.Assertion.Mediation != "" || pc.Creation != nil || len(pc.ID) != 64 {
			t.Fatalf("modal ceremony = %+v, want an assertion with no mediation and a 64-hex ID", pc)
		}
		in, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
		if err != nil {
			t.Fatalf("PasskeyLoginFinish = %v", err)
		}
		if in.User.ID != u.ID || in.Session.AuthMethod != access.MethodPasskey || in.Session.Kind != access.SessionFull || in.CloneWarning {
			t.Errorf("SignedIn = user %d, method %q, kind %v, clone %t; want alice's full passkey session", in.User.ID, in.Session.AuthMethod, in.Session.Kind, in.CloneWarning)
		}
		if got := p.principal(t, in.Token); got.User.ID != u.ID || got.SessionID != in.Session.ID {
			t.Errorf("the token authenticates user %d session %s, want %d %s", got.User.ID, got.SessionID, u.ID, in.Session.ID)
		}
		signed := eventsOf(p.events, account.EventSignedIn)
		if len(signed) != 1 || signed[0].Method != access.MethodPasskey || !slices.Equal(signed[0].SessionIDs, []string{in.Session.ID}) {
			t.Errorf("EventSignedIn = %+v, want one passkey sign-in naming the session", signed)
		}
	})
	t.Run("conditional_sign_in", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		pc, err := p.svc.PasskeyLoginBegin(t.Context(), localClient, p.origin, account.LoginConditional)
		if err != nil {
			t.Fatalf("PasskeyLoginBegin = %v", err)
		}
		if pc.Assertion.Mediation != webauthn.MediationConditional {
			t.Errorf("mediation = %q, want conditional", pc.Assertion.Mediation)
		}
		in, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
		if err != nil || in.User.ID != u.ID {
			t.Errorf("conditional sign-in = %v for user %v, want alice signed in", err, in.User)
		}
	})
	t.Run("unknown_mode", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		if _, err := p.svc.PasskeyLoginBegin(t.Context(), localClient, p.origin, account.LoginMode(7)); err == nil {
			t.Error("PasskeyLoginBegin(mode 7) = nil, want an error")
		}
		if n := account.Pending(p.svc).Len(); n != 0 {
			t.Errorf("pending ceremonies = %d, want none", n)
		}
	})
	t.Run("step_up", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		is, err := p.stepUpPasskey(t, localClient, pr, dev)
		if err != nil {
			t.Fatalf("passkey step-up = %v", err)
		}
		up := eventsOf(p.events, account.EventSteppedUp)
		if len(up) != 1 || up[0].Method != access.MethodPasskey || !slices.Equal(up[0].SessionIDs, []string{pr.SessionID}) || up[0].Actor.SessionID != pr.SessionID {
			t.Errorf("EventSteppedUp = %+v, want one passkey step-up of session %s", up, pr.SessionID)
		}
		if is.Session.AuthMethod != access.MethodPasskey {
			t.Errorf("stepped-up method = %q, want passkey", is.Session.AuthMethod)
		}
	})
	t.Run("unknown_credential_after_deletion", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		pk := p.enrol(t, u, dev)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		if err := p.svc.RemovePasskey(t.Context(), pr, pk.ID); err != nil {
			t.Fatalf("RemovePasskey = %v", err)
		}
		before := len(sessionsOf(t, p.mem, u.ID))
		if _, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev); !errors.Is(err, webauthn.ErrUnknownCredential) {
			t.Errorf("sign-in with the deleted passkey = %v, want webauthn.ErrUnknownCredential", err)
		}
		if after := len(sessionsOf(t, p.mem, u.ID)); after != before {
			t.Errorf("sessions %d after the refused sign-in, want %d", after, before)
		}
	})
	t.Run("duplicate_across_users", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		bob := passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, alice, dev)
		pr, _ := p.signedInVia(t, bob, access.MethodPassword)
		if _, err := p.register(t, pr, dev); !errors.Is(err, account.ErrDuplicateCredential) {
			t.Errorf("registering alice's credential for bob = %v, want ErrDuplicateCredential", err)
		}
		if n := len(passkeysOf(t, p.mem, bob.ID)); n != 0 {
			t.Errorf("bob holds %d passkeys, want none", n)
		}
		if got := storedSession(t, p.mem, bob.ID, pr.SessionID); !got.TokenHash.Equal(pr.SessionTokenHash()) {
			t.Error("the refused registration rotated bob's session")
		}
	})
	t.Run("clone_warning", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		first, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev)
		if err != nil || first.CloneWarning {
			t.Fatalf("first sign-in = %v, clone warning %t; want a clean sign-in", err, first.CloneWarning)
		}
		dev.SignCount = 0
		second, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev)
		if err != nil || !second.CloneWarning {
			t.Errorf("sign-in with a regressed counter = %v, clone warning %t; want a sign-in with the warning", err, second.CloneWarning)
		}
	})
	t.Run("custody_failure", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{edit: func(c *account.Config) { c.Store = custodyFailing{c.Store} }})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		before := len(sessionsOf(t, p.mem, u.ID))
		if _, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev); !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("sign-in whose custody write fails = %v, want access.ErrAuthBackend", err)
		}
		if after := len(sessionsOf(t, p.mem, u.ID)); after != before {
			t.Errorf("sessions %d after the failed sign-in, want %d", after, before)
		}
	})
	t.Run("disabled_user", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		cur := storedUser(t, p.mem, u.ID)
		cur.Enabled = false
		if err := p.mem.UpdateUser(t.Context(), cur); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		before := len(sessionsOf(t, p.mem, u.ID))
		if _, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("a disabled user's passkey sign-in = %v, want ErrInvalidCredentials", err)
		}
		if after := len(sessionsOf(t, p.mem, u.ID)); after != before || len(eventsOf(p.events, account.EventSignedIn)) != 0 {
			t.Errorf("sessions %d (want %d) and %d sign-in events after the refusal", after, before, len(eventsOf(p.events, account.EventSignedIn)))
		}
	})
}

func TestBeginRequestLimit(t *testing.T) {
	t.Parallel()
	limited := func(c *ratelimit.Config) { c.Request = ratelimit.Rate{Limit: 2, Window: time.Hour} }
	setup := func(ctx context.Context, p *pkFixture, c account.Client) error {
		_, err := p.svc.SetupPasskeyBegin(ctx, c, account.SetupPasskey{Username: "owner", Origin: p.origin})
		return err
	}
	login := func(ctx context.Context, p *pkFixture, c account.Client) error {
		_, err := p.svc.PasskeyLoginBegin(ctx, c, p.origin, account.LoginModal)
		return err
	}
	for name, begin := range map[string]func(context.Context, *pkFixture, account.Client) error{"login": login, "setup": setup} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPK(t, pwOptions{limiter: limited, rules: noSetupToken})
			for i := range 2 {
				if err := begin(t.Context(), p, localClient); err != nil {
					t.Fatalf("begin %d = %v, want admitted", i+1, err)
				}
			}
			if err := begin(t.Context(), p, localClient); !errors.Is(err, ratelimit.ErrRefused) {
				t.Errorf("third begin from one IP = %v, want *ratelimit.RefusedError", err)
			}
			if n := account.Pending(p.svc).Len(); n != 2 {
				t.Errorf("pending ceremonies = %d, want 2: the refused begin grew the cache", n)
			}
			if err := begin(t.Context(), p, clientAt(1)); err != nil {
				t.Errorf("a begin from another IP = %v, want admitted", err)
			}
		})
	}
}

func TestPasskeyCeremonyRefusals(t *testing.T) {
	t.Parallel()
	var offset atomic.Int64
	p := newPK(t, pwOptions{edit: func(c *account.Config) {
		c.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	}})
	alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	bob := passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
	dev := accesstest.NewPasskeyDevice(t)
	p.enrol(t, alice, dev)
	aliceP, _ := p.signedInVia(t, alice, access.MethodPassword)
	bobP, _ := p.signedInVia(t, bob, access.MethodPassword)
	loginID := func(t *testing.T) (string, []byte) {
		pc, err := p.svc.PasskeyLoginBegin(t.Context(), localClient, p.origin, account.LoginModal)
		if err != nil {
			t.Fatalf("PasskeyLoginBegin: %v", err)
		}
		return pc.ID, dev.Assert(browserJSON(t, pc.Assertion))
	}
	t.Run("unknown_id", func(t *testing.T) {
		if _, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, strings.Repeat("ab", 32), strings.NewReader("{}")); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("finish of an unknown ceremony = %v, want ErrCeremonyInvalid", err)
		}
	})
	t.Run("spent", func(t *testing.T) {
		id, body := loginID(t)
		if _, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, id, bytes.NewReader(body)); err != nil {
			t.Fatalf("first finish = %v", err)
		}
		if _, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, id, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("second finish = %v, want ErrCeremonyInvalid", err)
		}
	})
	t.Run("other_purpose", func(t *testing.T) {
		id, _ := loginID(t)
		if _, err := p.svc.PasskeyRegisterFinish(t.Context(), aliceP, id, strings.NewReader("{}")); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("registration finish of a login ceremony = %v, want ErrCeremonyInvalid", err)
		}
	})
	t.Run("another_users_ceremony", func(t *testing.T) {
		pc, err := p.svc.PasskeyRegisterBegin(t.Context(), aliceP, p.origin)
		if err != nil {
			t.Fatalf("PasskeyRegisterBegin: %v", err)
		}
		other := accesstest.NewPasskeyDevice(t)
		body := other.Register(browserJSON(t, pc.Creation))
		if _, err := p.svc.PasskeyRegisterFinish(t.Context(), bobP, pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("bob finishing alice's registration = %v, want ErrCeremonyInvalid", err)
		}
		if n := len(passkeysOf(t, p.mem, bob.ID)) + len(passkeysOf(t, p.mem, alice.ID)); n != 1 {
			t.Errorf("passkeys stored = %d, want alice's one", n)
		}
	})
	t.Run("expired", func(t *testing.T) {
		id, body := loginID(t)
		offset.Store(int64(webauthn.CeremonyTimeout))
		defer offset.Store(0)
		if _, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, id, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("finish at CeremonyTimeout = %v, want ErrCeremonyInvalid", err)
		}
	})
}

// TestCeremonyBeginRecordsItsUser pins what the finish calls' owner check
// compares against: each begin that is for a signed-in user leaves that user
// in its pending entry.
func TestCeremonyBeginRecordsItsUser(t *testing.T) {
	t.Parallel()
	w := newRecWorld(t, pwOptions{}, nil)
	session, _ := w.signedInVia(t, w.alice, access.MethodPassword)
	_, recovery := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
	for _, tc := range []struct {
		begin   func(t *testing.T) (account.PendingCeremony, error)
		name    string
		purpose account.PendingPurpose
	}{
		{name: "register", purpose: account.PurposeRegister, begin: func(t *testing.T) (account.PendingCeremony, error) {
			return w.svc.PasskeyRegisterBegin(t.Context(), session, w.origin)
		}},
		{name: "recovery", purpose: account.PurposeRecovery, begin: func(t *testing.T) (account.PendingCeremony, error) {
			return w.svc.RecoverPasskeyBegin(t.Context(), recovery, w.origin)
		}},
		{name: "step_up", purpose: account.PurposeStepUp, begin: func(t *testing.T) (account.PendingCeremony, error) {
			w.enrol(t, w.alice, accesstest.NewPasskeyDevice(t))
			return w.svc.StepUpPasskeyBegin(t.Context(), session, w.origin)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := tc.begin(t)
			if err != nil {
				t.Fatalf("begin = %v", err)
			}
			u, ok := account.Pending(w.svc).Take(pc.ID, tc.purpose, time.Now())
			if !ok || u.ID != w.alice.ID || u.Username != "alice" {
				t.Errorf("pending entry = user %d %q (found %t), want alice, user %d", u.ID, u.Username, ok, w.alice.ID)
			}
		})
	}
}

func TestPasskeysUnavailable(t *testing.T) {
	t.Parallel()
	// Request admits one call per IP and every op runs twice, so a begin
	// that charged before its nil-RP refusal answers the second call with a
	// *ratelimit.RefusedError. setup_begin runs on an empty store, where
	// its setup refusals pass.
	oneRequest := func(c *ratelimit.Config) { c.Request = ratelimit.Rate{Limit: 1, Window: time.Hour} }
	p := newPW(t, pwOptions{limiter: oneRequest})
	empty := newPW(t, pwOptions{limiter: oneRequest, rules: noSetupToken})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pr, _ := p.signedInVia(t, u, access.MethodPassword)
	origin, err := webauthn.ParseOrigin("https://" + rpID)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	body := func() *strings.Reader { return strings.NewReader("{}") }
	for name, op := range map[string]func() error{
		"login_begin": func() error {
			_, err := p.svc.PasskeyLoginBegin(t.Context(), localClient, origin, account.LoginModal)
			return err
		},
		"login_finish": func() error {
			_, err := p.svc.PasskeyLoginFinish(t.Context(), localClient, "x", body())
			return err
		},
		"setup_begin": func() error {
			_, err := empty.svc.SetupPasskeyBegin(t.Context(), localClient, account.SetupPasskey{Username: "owner", Origin: origin})
			return err
		},
		"setup_finish": func() error {
			_, err := p.svc.SetupPasskeyFinish(t.Context(), localClient, "x", body())
			return err
		},
		"register_begin": func() error {
			_, err := p.svc.PasskeyRegisterBegin(t.Context(), pr, origin)
			return err
		},
		"register_finish": func() error {
			_, err := p.svc.PasskeyRegisterFinish(t.Context(), pr, "x", body())
			return err
		},
		"step_up_begin": func() error {
			_, err := p.svc.StepUpPasskeyBegin(t.Context(), pr, origin)
			return err
		},
		"step_up_finish": func() error {
			_, err := p.svc.StepUpPasskeyFinish(t.Context(), localClient, pr, "x", body())
			return err
		},
		"signals": func() error {
			_, err := p.svc.WebAuthnSignals(t.Context(), pr)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			for call := range 2 {
				if err := op(); !errors.Is(err, account.ErrPasskeysUnavailable) {
					t.Errorf("%s call %d with no relying party = %v, want ErrPasskeysUnavailable", name, call+1, err)
				}
			}
		})
	}
}

func TestPasskeysWithoutRP(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	kept, gone := addPasskey(t, p.mem, u, rpID), addPasskey(t, p.mem, u, rpID)
	pr, _ := p.signedInVia(t, u, access.MethodPassword)
	t.Run("list", func(t *testing.T) {
		got, err := p.svc.Passkeys(t.Context(), pr)
		if err != nil || len(got) != 2 {
			t.Errorf("Passkeys with no relying party = %d passkeys, %v; want both", len(got), err)
		}
	})
	t.Run("rename", func(t *testing.T) {
		if err := p.svc.RenamePasskey(t.Context(), pr, kept.ID, "laptop"); err != nil {
			t.Fatalf("RenamePasskey with no relying party = %v", err)
		}
		for _, pk := range passkeysOf(t, p.mem, u.ID) {
			if pk.ID == kept.ID && pk.Name != "laptop" {
				t.Errorf("stored name %q, want laptop", pk.Name)
			}
		}
	})
	t.Run("remove", func(t *testing.T) {
		if err := p.svc.RemovePasskey(t.Context(), pr, gone.ID); err != nil {
			t.Fatalf("RemovePasskey with no relying party = %v", err)
		}
		if got := passkeysOf(t, p.mem, u.ID); len(got) != 1 || got[0].ID != kept.ID {
			t.Errorf("passkeys after the removal = %+v, want only %d", got, kept.ID)
		}
	})
}

func TestPasskeySessionPrecondition(t *testing.T) {
	t.Parallel()
	p := newPK(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pk := p.enrol(t, u, accesstest.NewPasskeyDevice(t))
	ops := map[string]func(access.Principal) error{
		"register_begin": func(pr access.Principal) error {
			_, err := p.svc.PasskeyRegisterBegin(t.Context(), pr, p.origin)
			return err
		},
		"step_up_begin": func(pr access.Principal) error {
			_, err := p.svc.StepUpPasskeyBegin(t.Context(), pr, p.origin)
			return err
		},
		"passkeys": func(pr access.Principal) error {
			_, err := p.svc.Passkeys(t.Context(), pr)
			return err
		},
		"rename": func(pr access.Principal) error { return p.svc.RenamePasskey(t.Context(), pr, pk.ID, "laptop") },
		"remove": func(pr access.Principal) error { return p.svc.RemovePasskey(t.Context(), pr, pk.ID+1000) },
		"signals": func(pr access.Principal) error {
			_, err := p.svc.WebAuthnSignals(t.Context(), pr)
			return err
		},
	}
	refused := map[string]access.Principal{
		"key":      p.keyPrincipal(t, u, "read"),
		"recovery": p.sessionPrincipal(t, u, access.SessionRecovery, time.Now()),
		"bypass":   p.bypassPrincipal(t),
	}
	for who, pr := range refused {
		for name, op := range ops {
			t.Run(who+"_"+name, func(t *testing.T) {
				if err := op(pr); !errors.Is(err, account.ErrSessionRequired) {
					t.Errorf("%s by a %s principal = %v, want ErrSessionRequired", name, who, err)
				}
			})
		}
	}
	stale := p.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour))
	for name, want := range map[string]error{
		"register_begin": access.ErrRecentAuthRequired, "remove": access.ErrRecentAuthRequired,
		"step_up_begin": nil, "passkeys": nil, "rename": nil, "signals": nil,
	} {
		t.Run("stale_"+name, func(t *testing.T) {
			if err := ops[name](stale); !errors.Is(err, want) || (want == nil && err != nil) {
				t.Errorf("%s by an hour-old session = %v, want %v", name, err, want)
			}
		})
	}
}

func TestPasskeyRegisterSSOGoverned(t *testing.T) {
	t.Parallel()
	governed := func() account.Rules { return account.Rules{SSOGoverned: true} }
	t.Run("linked", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{rules: governed})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		linkUser(t, p.mem, u, "https://idp.example")
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		if _, err := p.svc.PasskeyRegisterBegin(t.Context(), pr, p.origin); !errors.Is(err, account.ErrSSOGoverned) {
			t.Errorf("a linked user's registration under SSOGoverned = %v, want ErrSSOGoverned", err)
		}
	})
	t.Run("unlinked", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{rules: governed})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		if _, err := p.register(t, pr, accesstest.NewPasskeyDevice(t)); err != nil {
			t.Errorf("an unlinked user's registration under SSOGoverned = %v, want nil", err)
		}
	})
	t.Run("linked_during_ceremony", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{rules: governed})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		pc, err := p.svc.PasskeyRegisterBegin(t.Context(), pr, p.origin)
		if err != nil {
			t.Fatalf("PasskeyRegisterBegin = %v", err)
		}
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		linkUser(t, p.mem, storedUser(t, p.mem, u.ID), "https://idp.example")
		if _, err := p.svc.PasskeyRegisterFinish(t.Context(), pr, pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrSSOGoverned) {
			t.Errorf("finish after the user was linked = %v, want ErrSSOGoverned", err)
		}
		if n := len(passkeysOf(t, p.mem, u.ID)); n != 0 {
			t.Errorf("passkeys stored = %d, want none", n)
		}
		if got := storedSession(t, p.mem, u.ID, pr.SessionID); !got.TokenHash.Equal(pr.SessionTokenHash()) {
			t.Error("the refused finish rotated the session")
		}
	})
}

func TestRemovePasskeyLastUsable(t *testing.T) {
	t.Parallel()
	type env struct {
		p  *pkFixture
		u  *access.User
		pr access.Principal
	}
	setup := func(t *testing.T, rules account.Rules, password bool) env {
		p := newPK(t, pwOptions{rules: func() account.Rules { return rules }})
		var h *access.Hasher
		if password {
			h = p.hasher
		}
		u := passwordUser(t, p.mem, h, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		return env{p: p, u: u, pr: pr}
	}
	remove := func(t *testing.T, e env, id int64, want error) {
		t.Helper()
		before := passkeysOf(t, e.p.mem, e.u.ID)
		events := len(e.p.events.all())
		err := e.p.svc.RemovePasskey(t.Context(), e.pr, id)
		after := passkeysOf(t, e.p.mem, e.u.ID)
		if want != nil {
			if !errors.Is(err, want) {
				t.Errorf("RemovePasskey(%d) = %v, want %v", id, err, want)
			}
			if len(after) != len(before) || len(e.p.events.all()) != events {
				t.Errorf("a refused removal left %d of %d passkeys and emitted %d events", len(after), len(before), len(e.p.events.all())-events)
			}
			return
		}
		if err != nil {
			t.Errorf("RemovePasskey(%d) = %v, want nil", id, err)
		}
		if slices.ContainsFunc(after, func(k access.PasskeyCredential) bool { return k.ID == id }) || len(after) != len(before)-1 {
			t.Errorf("after removing %d the user holds %+v", id, after)
		}
		removed := eventsOf(e.p.events, account.EventPasskeyRemoved)
		if len(removed) == 0 || removed[len(removed)-1].PasskeyID != id || removed[len(removed)-1].UserID != e.u.ID {
			t.Errorf("EventPasskeyRemoved = %+v, want the last naming passkey %d of user %d", removed, id, e.u.ID)
		}
	}
	t.Run("password_and_passkey", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{}, true)
		remove(t, e, addPasskey(t, e.p.mem, e.u, rpID).ID, nil)
	})
	t.Run("password_and_passkey_login_disabled", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{DisablePasswordLogin: true}, true)
		remove(t, e, addPasskey(t, e.p.mem, e.u, rpID).ID, account.ErrLastMethod)
	})
	t.Run("two_usable_passkeys", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{}, false)
		first, second := addPasskey(t, e.p.mem, e.u, rpID), addPasskey(t, e.p.mem, e.u, rpID)
		remove(t, e, first.ID, nil)
		remove(t, e, second.ID, account.ErrLastMethod)
	})
	t.Run("usable_and_foreign", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{}, false)
		usable, foreign := addPasskey(t, e.p.mem, e.u, rpID), addPasskey(t, e.p.mem, e.u, foreignRP)
		remove(t, e, usable.ID, account.ErrLastMethod)
		remove(t, e, foreign.ID, nil)
	})
	t.Run("passkey_of_another_user", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{}, true)
		addPasskey(t, e.p.mem, e.u, rpID)
		bob := passwordUser(t, e.p.mem, e.p.hasher, "bob", goodPassword)
		bobs := addPasskey(t, e.p.mem, bob, rpID)
		remove(t, e, bobs.ID, account.ErrNotFound)
		if n := len(passkeysOf(t, e.p.mem, bob.ID)); n != 1 {
			t.Errorf("bob holds %d passkeys, want his one", n)
		}
	})
	t.Run("unknown_passkey_no_usable_method", func(t *testing.T) {
		t.Parallel()
		e := setup(t, account.Rules{}, false)
		foreign := addPasskey(t, e.p.mem, e.u, foreignRP)
		remove(t, e, foreign.ID+1000, account.ErrNotFound)
	})
}

func TestRenamePasskey(t *testing.T) {
	t.Parallel()
	p := newPK(t, pwOptions{})
	alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	bob := passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
	own := addPasskey(t, p.mem, alice, rpID)
	bobs := addPasskey(t, p.mem, bob, rpID)
	pr, _ := p.signedInVia(t, alice, access.MethodPassword)
	nameOf := func(u *access.User, id int64) string {
		for _, k := range passkeysOf(t, p.mem, u.ID) {
			if k.ID == id {
				return k.Name
			}
		}
		t.Fatalf("passkey %d not stored", id)
		return ""
	}
	cases := []struct {
		want   error
		reason string
		name   string
		label  string
		id     int64
	}{
		{name: "own_at_the_limit", id: own.ID, label: strings.Repeat("é", 128)},
		{name: "too_long", id: own.ID, label: strings.Repeat("é", 129), reason: "too_long"},
		{name: "line_break", id: own.ID, label: "lap\ntop", reason: "disallowed_character"},
		{name: "bidi_control", id: own.ID, label: "lap\u202etop", reason: "disallowed_character"},
		{name: "another_users", id: bobs.ID, label: "mine", want: account.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := nameOf(alice, own.ID)
			err := p.svc.RenamePasskey(t.Context(), pr, tc.id, tc.label)
			switch {
			case tc.reason != "":
				te, ok := errors.AsType[*account.TextError](err)
				if !ok || te.Field != "label" || te.Reason != tc.reason {
					t.Errorf("RenamePasskey(%q) = %v, want *TextError{label, %s}", tc.label, err, tc.reason)
				}
				if got := nameOf(alice, own.ID); got != before {
					t.Errorf("a refused rename stored %q", got)
				}
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Errorf("RenamePasskey = %v, want %v", err, tc.want)
				}
				if got := nameOf(bob, bobs.ID); got != bobs.Name {
					t.Errorf("bob's passkey is named %q, want %q", got, bobs.Name)
				}
			default:
				if err != nil || nameOf(alice, own.ID) != tc.label {
					t.Errorf("RenamePasskey = %v, stored %q; want %q", err, nameOf(alice, own.ID), tc.label)
				}
			}
		})
	}
}

func TestPasskeysAndSignals(t *testing.T) {
	t.Parallel()
	p := newPK(t, pwOptions{})
	alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	bob := passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
	usable := p.enrol(t, alice, accesstest.NewPasskeyDevice(t))
	foreign := addPasskey(t, p.mem, alice, foreignRP)
	addPasskey(t, p.mem, bob, rpID)
	pr, _ := p.signedInVia(t, alice, access.MethodPassword)
	listed, err := p.svc.Passkeys(t.Context(), pr)
	if err != nil {
		t.Fatalf("Passkeys = %v", err)
	}
	ids := make([]int64, len(listed))
	for i := range listed {
		ids[i] = listed[i].ID
	}
	slices.Sort(ids)
	if want := []int64{usable.ID, foreign.ID}; !slices.Equal(ids, want) {
		t.Errorf("Passkeys = %v, want alice's own %v", ids, want)
	}
	sig, err := p.svc.WebAuthnSignals(t.Context(), pr)
	if err != nil {
		t.Fatalf("WebAuthnSignals = %v", err)
	}
	acc := sig.AllAcceptedCredentials
	if acc.RPID != rpID || !bytes.Equal(acc.UserID, alice.WebAuthnHandle) || len(acc.AllAcceptedCredentialIDs) != 1 || !bytes.Equal(acc.AllAcceptedCredentialIDs[0], usable.CredentialID) {
		t.Errorf("allAcceptedCredentials = %+v, want only alice's passkey under %s", acc, rpID)
	}
	if cur := sig.CurrentUserDetails; cur.RPID != rpID || cur.Name != "alice" || !bytes.Equal(cur.UserID, alice.WebAuthnHandle) {
		t.Errorf("currentUserDetails = %+v, want alice under %s", cur, rpID)
	}
}

func TestStepUpPasskeyRefusals(t *testing.T) {
	t.Parallel()
	p := newPK(t, pwOptions{})
	alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	bob := passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
	t.Run("no_passkey", func(t *testing.T) {
		pr, _ := p.signedInVia(t, alice, access.MethodPassword)
		if _, err := p.svc.StepUpPasskeyBegin(t.Context(), pr, p.origin); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("a step-up for a user holding no passkey = %v, want ErrNotFound", err)
		}
	})
	t.Run("foreign_rp_only", func(t *testing.T) {
		carol := passwordUser(t, p.mem, p.hasher, "carol", goodPassword)
		addPasskey(t, p.mem, carol, foreignRP)
		pr, _ := p.signedInVia(t, carol, access.MethodPassword)
		before := account.Pending(p.svc).Len()
		if _, err := p.svc.StepUpPasskeyBegin(t.Context(), pr, p.origin); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("a step-up for a user holding only a passkey of another RP ID = %v, want ErrNotFound", err)
		}
		if n := account.Pending(p.svc).Len(); n != before {
			t.Errorf("pending ceremonies = %d, want %d: the refused begin grew the cache", n, before)
		}
	})
	t.Run("another_users_credential", func(t *testing.T) {
		p.enrol(t, alice, accesstest.NewPasskeyDevice(t))
		bobs := accesstest.NewPasskeyDevice(t)
		p.enrol(t, bob, bobs)
		pr, _ := p.signedInVia(t, alice, access.MethodPassword)
		if _, err := p.stepUpPasskey(t, localClient, pr, bobs); err == nil {
			t.Error("alice's step-up with bob's passkey = nil, want a refusal")
		}
		if got := storedSession(t, p.mem, alice.ID, pr.SessionID); !got.TokenHash.Equal(pr.SessionTokenHash()) || got.AuthMethod != access.MethodPassword {
			t.Error("the refused step-up rotated the session")
		}
	})
}

func TestPasskeyDeviceCookie(t *testing.T) {
	t.Parallel()
	// One failure fills a device's bucket, so a cookie whose device ID is
	// kept is refused at once and a fresh device is admitted.
	oneFailure := func(c *ratelimit.Config) { c.Device = ratelimit.Rate{Limit: 1, Window: time.Hour} }
	type env struct {
		p     *pkFixture
		u     *access.User
		dev   *accesstest.PasskeyDevice
		spent access.Secret // a device cookie of alice's whose bucket is full
	}
	setup := func(t *testing.T) env {
		p := newPK(t, pwOptions{limiter: oneFailure})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		p.enrol(t, u, dev)
		cookie := p.deviceCookie(t, localClient, "alice", goodPassword)
		c := localClient
		c.Device = cookie
		if _, err := p.login(t.Context(), c, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("wrong password on the device = %v", err)
		}
		if _, err := p.login(t.Context(), c, "alice", goodPassword); !errors.Is(err, ratelimit.ErrRefused) {
			t.Fatalf("a second attempt on the spent device = %v, want refused", err)
		}
		return env{p: p, u: u, dev: dev, spent: cookie}
	}
	// keeps reports whether cookie names the spent device: a password
	// attempt carrying it is refused by that device's bucket.
	keeps := func(t *testing.T, e env, cookie access.Secret) bool {
		t.Helper()
		if cookie.IsZero() {
			t.Fatal("no device cookie was returned")
		}
		c := localClient
		c.Device = cookie
		_, err := e.p.login(t.Context(), c, "alice", goodPassword)
		return errors.Is(err, ratelimit.ErrRefused)
	}
	t.Run("sign_in", func(t *testing.T) {
		t.Parallel()
		e := setup(t)
		c := localClient
		c.Device = e.spent
		in, err := e.p.signIn(t.Context(), t, c, account.LoginModal, e.dev)
		if err != nil {
			t.Fatalf("passkey sign-in = %v", err)
		}
		if !keeps(t, e, in.DeviceCookie) {
			t.Error("the sign-in's device cookie names a new device, want the presented one kept")
		}
	})
	t.Run("step_up", func(t *testing.T) {
		t.Parallel()
		e := setup(t)
		c := localClient
		c.Device = e.spent
		pr, _ := e.p.signedInVia(t, e.u, access.MethodPassword)
		is, err := e.p.stepUpPasskey(t, c, pr, e.dev)
		if err != nil {
			t.Fatalf("passkey step-up = %v", err)
		}
		if !keeps(t, e, is.DeviceCookie) {
			t.Error("the step-up's device cookie names a new device, want the presented one kept")
		}
	})
	t.Run("another_accounts_cookie", func(t *testing.T) {
		t.Parallel()
		e := setup(t)
		passwordUser(t, e.p.mem, e.p.hasher, "bob", goodPassword)
		c := localClient
		c.Device = e.p.deviceCookie(t, localClient, "bob", goodPassword)
		in, err := e.p.signIn(t.Context(), t, c, account.LoginModal, e.dev)
		if err != nil {
			t.Fatalf("passkey sign-in = %v", err)
		}
		if keeps(t, e, in.DeviceCookie) {
			t.Error("bob's cookie presented on alice's sign-in kept a spent device of alice's")
		}
	})
}

func TestPasskeySignInLeavesFailureRecords(t *testing.T) {
	t.Parallel()
	p := newPK(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	dev := accesstest.NewPasskeyDevice(t)
	p.enrol(t, u, dev)
	lockPassword(t, p.mem, p.svc, u, false)
	trusted := account.FailureCount{Name: account.FailureName(p.svc, u.Username), Method: access.MethodPassword, Trusted: true, Count: 3}
	if err := p.mem.PutAuthFailure(t.Context(), trusted); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
	beforeU, _ := record(t, p.mem, p.svc, "alice", false)
	beforeT, _ := record(t, p.mem, p.svc, "alice", true)
	in, err := p.signIn(t.Context(), t, localClient, account.LoginModal, dev)
	if err != nil {
		t.Fatalf("passkey sign-in = %v", err)
	}
	afterU, foundU := record(t, p.mem, p.svc, "alice", false)
	afterT, foundT := record(t, p.mem, p.svc, "alice", true)
	if !foundU || !afterU.Locked || afterU.Count != beforeU.Count || !afterU.LockedAt.Equal(beforeU.LockedAt) {
		t.Errorf("untrusted record after the passkey sign-in = %+v, want %+v unchanged", afterU, beforeU)
	}
	if !foundT || afterT.Count != beforeT.Count || afterT.Locked {
		t.Errorf("trusted record after the passkey sign-in = %+v, want %+v unchanged", afterT, beforeT)
	}
	if err := p.svc.ReenableMethod(t.Context(), p.principal(t, in.Token), access.MethodPassword); err != nil {
		t.Fatalf("ReenableMethod from the passkey session = %v", err)
	}
	if _, found := record(t, p.mem, p.svc, "alice", false); found {
		t.Error("the untrusted record survived the re-enable")
	}
	if len(eventsOf(p.events, account.EventMethodReenabled)) != 1 {
		t.Errorf("EventMethodReenabled = %d, want 1", len(eventsOf(p.events, account.EventMethodReenabled)))
	}
}
