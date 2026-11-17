package account_test

import (
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
	"github.com/cplieger/access/oidc"
)

// modeFixture is a Service with password, passkeys and OIDC wired, and an
// owner holding a password.
func modeFixture(t *testing.T, o pwOptions) (*oidcFixture, *access.User) {
	t.Helper()
	f := newOIDCFixture(t, rigFor(t, "subject-y"), o)
	return f, passwordOwner(t, f.pwFixture, "root")
}

// passwordOwner stores an owner holding goodPassword.
func passwordOwner(t *testing.T, p *pwFixture, name string) *access.User {
	t.Helper()
	u := passwordUser(t, p.mem, p.hasher, name, goodPassword)
	u.Role, u.Owner = access.RoleAdmin, true
	if err := p.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	return u
}

// linkedUser stores a non-owner holding goodPassword, linked to subject.
func linkedUser(t *testing.T, p *pwFixture, name, subject string) *access.User {
	t.Helper()
	u := passwordUser(t, p.mem, p.hasher, name, goodPassword)
	linkIdentity(t, p.mem, u, access.OIDCIdentity{Issuer: oidcIssuer, Subject: subject})
	return storedUser(t, p.mem, u.ID)
}

func storeMode(t *testing.T, s *accesstest.MemStore, mode account.SSOMode) {
	t.Helper()
	if err := s.SetSSOMode(t.Context(), mode); err != nil {
		t.Fatalf("SetSSOMode: %v", err)
	}
}

func modeOf(t *testing.T, s *accesstest.MemStore) (account.SSOMode, bool) {
	t.Helper()
	mode, set, err := s.SSOMode(t.Context())
	if err != nil {
		t.Fatalf("SSOMode: %v", err)
	}
	return mode, set
}

func reasonOf(err error) string {
	if pe, ok := errors.AsType[*account.PolicyError](err); ok {
		return pe.Reason
	}
	return ""
}

var socket = account.OutOfBand("admin-socket")

// The mode's wire names.
func TestSSOModeNames(t *testing.T) {
	t.Parallel()
	for mode, name := range map[account.SSOMode]account.SSOModeName{account.SSOAlongside: "alongside", account.SSOForLinked: "for_linked", account.SSOOnly: "only"} {
		if got := mode.Name(); got != name {
			t.Errorf("%d.Name() = %q, want %q", int(mode), got, name)
		}
		if got := mode.String(); got != string(name) {
			t.Errorf("%d.String() = %q, want %q", int(mode), got, name)
		}
		if got, ok := account.ParseSSOMode(name); !ok || got != mode {
			t.Errorf("ParseSSOMode(%q) = %v, %t; want %v", name, got, ok, mode)
		}
	}
	for _, name := range []account.SSOModeName{"", "Alongside", "for-linked", "3"} {
		if _, ok := account.ParseSSOMode(name); ok {
			t.Errorf("ParseSSOMode(%q) accepted", name)
		}
	}
	if got, name := account.SSOMode(3).String(), account.SSOMode(3).Name(); got != "SSOMode(3)" || name != "" {
		t.Errorf("SSOMode(3) = %q, name %q", got, name)
	}
}

// Who signs in locally under each mode.
func TestSSOModeLocalSignIn(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode           account.SSOMode
		linked, signIn bool
	}{
		{account.SSOAlongside, true, true},
		{account.SSOAlongside, false, true},
		{account.SSOForLinked, true, false},
		{account.SSOForLinked, false, true},
		{account.SSOOnly, true, false},
		{account.SSOOnly, false, false},
	} {
		t.Run(tc.mode.String()+map[bool]string{true: "_linked", false: "_unlinked"}[tc.linked], func(t *testing.T) {
			t.Parallel()
			f, root := modeFixture(t, pwOptions{})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			if tc.linked {
				linkIdentity(t, f.mem, u, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "alice"})
			}
			storeMode(t, f.mem, tc.mode)
			_, err := f.login(t.Context(), localClient, "alice", goodPassword)
			if (err == nil) != tc.signIn || (err != nil && !errors.Is(err, account.ErrInvalidCredentials)) {
				t.Errorf("alice's password sign-in = %v, want signed in %t, else ErrInvalidCredentials", err, tc.signIn)
			}
			if _, err := f.login(t.Context(), localClient, root.Username, goodPassword); err != nil {
				t.Errorf("the owner's password sign-in = %v, want nil: owners are exempt", err)
			}
		})
	}
}

// A refused local sign-in looks like a wrong password, for an
// owner's, a non-owner's and an unknown name, by error and failure count.
func TestSSOOnlyRefusalLooksLikeWrongPassword(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
	storeMode(t, f.mem, account.SSOOnly)
	_, right := f.login(t.Context(), localClient, "alice", goodPassword)
	_, wrong := f.login(t.Context(), localClient, "bob", wrongPassword)
	_, unknown := f.login(t.Context(), localClient, "nobody", goodPassword)
	_, ownerWrong := f.login(t.Context(), localClient, "root", wrongPassword)
	for name, err := range map[string]error{"right": right, "wrong": wrong, "unknown": unknown, "owner_wrong": ownerWrong} {
		if !errors.Is(err, account.ErrInvalidCredentials) || err.Error() != wrong.Error() {
			t.Errorf("%s = %v, want the wrong-password answer %v", name, err, wrong)
		}
	}
	if a, b := failuresOf(t, f.pwFixture, "alice"), failuresOf(t, f.pwFixture, "bob"); a != 1 || b != 1 {
		t.Errorf("failure counts alice %d, bob %d; want 1 each", a, b)
	}
	if n := len(sessionsOf(t, f.mem, storedByName(t, f.mem, "alice").ID)); n != 0 {
		t.Errorf("alice holds %d sessions", n)
	}
}

// failuresOf is the untrusted password failure count of name.
func failuresOf(t *testing.T, p *pwFixture, name string) int {
	t.Helper()
	rec, found, err := p.mem.AuthFailure(t.Context(), account.FailureRef{Name: account.FailureName(p.svc, name), Method: access.MethodPassword})
	if err != nil {
		t.Fatalf("AuthFailure: %v", err)
	}
	if !found {
		return 0
	}
	return rec.Count
}

func storedByName(t *testing.T, s *accesstest.MemStore, name string) *access.User {
	t.Helper()
	u, found, err := s.UserByUsername(t.Context(), name)
	if err != nil || !found {
		t.Fatalf("UserByUsername(%s) = %v, %t", name, err, found)
	}
	return u
}

// A discoverable passkey's user is known once its signature
// verifies, so a dormant passkey answers ErrInvalidCredentials after it.
func TestSSOModePasskeySignIn(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	dev := accesstest.NewPasskeyDevice(t)
	f.enrol(t, u, dev)
	linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "alice"})
	storeMode(t, f.mem, account.SSOForLinked)
	if _, err := f.signIn(t.Context(), t, localClient, account.LoginModal, dev); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("a linked non-owner's passkey sign-in under for_linked = %v, want ErrInvalidCredentials", err)
	}
	storeMode(t, f.mem, account.SSOAlongside)
	if _, err := f.signIn(t.Context(), t, localClient, account.LoginModal, dev); err != nil {
		t.Errorf("the same passkey under alongside = %v, want signed in", err)
	}
}

// A non-owner the mode keeps dormant
// adds no local method and steps up by none; Me says so; an owner is exempt.
func TestSSOModeSessionRefusals(t *testing.T) {
	t.Parallel()
	for _, owner := range []bool{false, true} {
		t.Run(map[bool]string{false: "non_owner", true: "owner"}[owner], func(t *testing.T) {
			t.Parallel()
			f, root := modeFixture(t, pwOptions{})
			u := linkedUser(t, f.pwFixture, "alice", "alice")
			if owner {
				u = root
				linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
			}
			dev := accesstest.NewPasskeyDevice(t)
			f.enrol(t, u, dev)
			storeMode(t, f.mem, account.SSOForLinked)
			pr, _ := f.signedInVia(t, u, access.MethodOIDC)
			want := func(err error) bool { return errors.Is(err, account.ErrSSOOnly) != owner }
			me, err := f.svc.Me(t.Context(), pr)
			if err != nil || me.SSOOnly == owner {
				t.Errorf("Me = SSOOnly %t, %v; want %t", me.SSOOnly, err, !owner)
			}
			if _, err := f.setPassword(t.Context(), pr, goodPassword, newPassword); !want(err) {
				t.Errorf("SetPassword = %v, want ErrSSOOnly %t", err, !owner)
			}
			pr, _ = f.signedInVia(t, u, access.MethodOIDC)
			if _, err := f.svc.PasskeyRegisterBegin(t.Context(), localClient, pr, f.origin, account.SecondFactorProof{}); !want(err) {
				t.Errorf("PasskeyRegisterBegin = %v, want ErrSSOOnly %t", err, !owner)
			}
			if _, err := f.stepUp(t.Context(), localClient, pr, goodPassword); !want(err) {
				t.Errorf("StepUpPassword = %v, want ErrSSOOnly %t", err, !owner)
			}
			pr, _ = f.signedInVia(t, u, access.MethodOIDC)
			if _, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin); !want(err) {
				t.Errorf("StepUpPasskeyBegin = %v, want ErrSSOOnly %t", err, !owner)
			}
		})
	}
}

// A ceremony begun before the mode changed is refused by its
// finish's own read of the mode.
func TestSSOModeCeremonyBegunBeforeChange(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	u := linkedUser(t, f.pwFixture, "alice", "alice")
	dev := accesstest.NewPasskeyDevice(t)
	f.enrol(t, u, dev)
	pr, _ := f.signedInVia(t, u, access.MethodOIDC)
	stepUp, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
	if err != nil {
		t.Fatalf("StepUpPasskeyBegin: %v", err)
	}
	reg, err := f.svc.PasskeyRegisterBegin(t.Context(), localClient, pr, f.origin, account.SecondFactorProof{})
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin: %v", err)
	}
	storeMode(t, f.mem, account.SSOForLinked)
	if _, err := f.svc.StepUpPasskeyFinish(t.Context(), localClient, pr, stepUp.ID, strings.NewReader(string(dev.Assert(browserJSON(t, stepUp.Assertion))))); !errors.Is(err, account.ErrSSOOnly) {
		t.Errorf("StepUpPasskeyFinish = %v, want ErrSSOOnly", err)
	}
	if _, err := f.svc.PasskeyRegisterFinish(t.Context(), pr, reg.ID, strings.NewReader(string(accesstest.NewPasskeyDevice(t).Register(browserJSON(t, reg.Creation))))); !errors.Is(err, account.ErrSSOOnly) {
		t.Errorf("PasskeyRegisterFinish = %v, want ErrSSOOnly", err)
	}
	if n := len(passkeysOf(t, f.mem, u.ID)); n != 1 {
		t.Errorf("alice holds %d passkeys, want 1", n)
	}
}

// Password invite acceptance is refused, and
// the invite stays usable.
func TestSSOOnlyRefusesPasswordInvite(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	token, rec := access.NewOneTimeToken(access.PurposeInvite, time.Hour, time.Now())
	rec.Role = access.RoleUser
	if err := f.mem.CreateOneTimeToken(t.Context(), rec); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}
	storeMode(t, f.mem, account.SSOOnly)
	in := account.AcceptInvite{Token: token, Username: "carol", Password: access.NewSecret(goodPassword)}
	if _, err := f.svc.AcceptInvitePassword(t.Context(), localClient, in); !errors.Is(err, account.ErrSSOOnly) {
		t.Errorf("AcceptInvitePassword under only = %v, want ErrSSOOnly", err)
	}
	if !tokenStored(t, f.mem, rec) {
		t.Error("the refused acceptance spent the invite")
	}
	storeMode(t, f.mem, account.SSOForLinked)
	if _, err := f.svc.AcceptInvitePassword(t.Context(), localClient, in); err != nil {
		t.Errorf("AcceptInvitePassword under for_linked = %v, want nil", err)
	}
}

// Dormant, never deleted; a loosening brings them back.
func TestSSOModeDormantComesBack(t *testing.T) {
	t.Parallel()
	f, root := modeFixture(t, pwOptions{})
	u := linkedUser(t, f.pwFixture, "alice", "alice")
	owner, _ := f.signedInVia(t, root, access.MethodPassword)
	if _, err := f.login(t.Context(), localClient, "alice", goodPassword); err != nil {
		t.Fatalf("sign-in under alongside = %v", err)
	}
	if err := f.svc.ApplySSO(t.Context(), account.As(owner), account.SSOForLinked); err != nil {
		t.Fatalf("ApplySSO(for_linked) = %v", err)
	}
	if n := len(sessionsOf(t, f.mem, u.ID)); n != 0 {
		t.Errorf("alice holds %d sessions after the change, want the password session swept", n)
	}
	if _, err := f.login(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("sign-in under for_linked = %v, want ErrInvalidCredentials", err)
	}
	if storedUser(t, f.mem, u.ID).PasswordHash.IsZero() {
		t.Fatal("the change deleted the password")
	}
	if err := f.svc.ApplySSO(t.Context(), account.As(owner), account.SSOAlongside); err != nil {
		t.Fatalf("ApplySSO(alongside) = %v", err)
	}
	if _, err := f.login(t.Context(), localClient, "alice", goodPassword); err != nil {
		t.Errorf("sign-in after loosening = %v, want signed in", err)
	}
}

// ApplySSO's Update; endForbiddenSessions; sso_mode_changed
// with the old and new mode.
func TestApplySSOEndsForbiddenSessions(t *testing.T) {
	t.Parallel()
	f, root := modeFixture(t, pwOptions{})
	linked := linkedUser(t, f.pwFixture, "alice", "alice")
	unlinked := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
	byPassword := putSession(t, f.mem, liveSession(t, linked))
	bySSO := liveSession(t, linked)
	bySSO.AuthMethod = access.MethodOIDC
	bySSO = putSession(t, f.mem, bySSO)
	bobs := putSession(t, f.mem, liveSession(t, unlinked))
	roots := putSession(t, f.mem, liveSession(t, root))
	mark := len(f.events.all())
	if err := f.svc.ApplySSO(t.Context(), socket, account.SSOForLinked); err != nil {
		t.Fatalf("ApplySSO = %v", err)
	}
	ids := func(u *access.User) []string {
		var out []string
		for _, s := range sessionsOf(t, f.mem, u.ID) {
			out = append(out, s.ID)
		}
		return out
	}
	if got := ids(linked); !slices.Equal(got, []string{bySSO.ID}) {
		t.Errorf("alice's sessions = %v, want only the OIDC one %s", got, bySSO.ID)
	}
	if got := ids(unlinked); !slices.Equal(got, []string{bobs.ID}) {
		t.Errorf("bob's sessions = %v, want kept", got)
	}
	if got := ids(root); !slices.Equal(got, []string{roots.ID}) {
		t.Errorf("the owner's sessions = %v, want kept", got)
	}
	evs := f.events.all()[mark:]
	if len(evs) != 2 || evs[0].Kind != account.EventUserSessionsRevoked || !slices.Equal(evs[0].SessionIDs, []string{byPassword.ID}) ||
		evs[1].Kind != account.EventSSOModeChanged || evs[1].SSOMode != account.SSOForLinked || evs[1].PreviousSSOMode != account.SSOAlongside ||
		evs[1].Actor.OutOfBand != "admin-socket" {
		t.Errorf("events = %+v, want alice's password session revoked, then sso_mode_changed alongside to for_linked by the socket", evs)
	}
	if mode, set := modeOf(t, f.mem); mode != account.SSOForLinked || !set {
		t.Errorf("stored mode = %v, set %t", mode, set)
	}
	mark = len(f.events.all())
	if err := f.svc.ApplySSO(t.Context(), socket, account.SSOForLinked); err != nil || len(f.events.all()) != mark {
		t.Errorf("ApplySSO of the mode already set = %v with %d events, want nil and none", err, len(f.events.all())-mark)
	}
}

// CheckSSOReady: who may change the mode, in either direction.
func TestApplySSOActor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		from   account.SSOMode
		to     account.SSOMode
		actor  func(t *testing.T, f *oidcFixture, root *access.User) account.Actor
		want   error
		reason string
	}{
		{name: "admin_tightening", to: account.SSOForLinked, want: account.ErrPolicyRefused, reason: account.ReasonNotOwner, actor: adminActor},
		{name: "admin_loosening", from: account.SSOOnly, to: account.SSOAlongside, want: account.ErrPolicyRefused, reason: account.ReasonNotOwner, actor: adminActor},
		{name: "plain_owner", to: account.SSOForLinked, want: access.ErrHTTPSRequired, actor: func(t *testing.T, f *oidcFixture, root *access.User) account.Actor {
			pr, _ := f.signedInVia(t, root, access.MethodPassword)
			pr.Secure = false
			return account.As(pr)
		}},
		{name: "stale_owner", to: account.SSOForLinked, want: access.ErrRecentAuthRequired, actor: func(t *testing.T, f *oidcFixture, root *access.User) account.Actor {
			return account.As(f.sessionPrincipal(t, root, time.Now().Add(-time.Hour)))
		}},
		{name: "owner", to: account.SSOForLinked, actor: func(t *testing.T, f *oidcFixture, root *access.User) account.Actor {
			pr, _ := f.signedInVia(t, root, access.MethodPassword)
			return account.As(pr)
		}},
		{name: "out_of_band", from: account.SSOOnly, to: account.SSOAlongside, actor: func(*testing.T, *oidcFixture, *access.User) account.Actor { return socket }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, root := modeFixture(t, pwOptions{})
			storeMode(t, f.mem, tc.from)
			a := tc.actor(t, f, root)
			for name, err := range map[string]error{
				"CheckSSOReady": f.svc.CheckSSOReady(t.Context(), a, tc.to),
				"ApplySSO":      f.svc.ApplySSO(t.Context(), a, tc.to),
			} {
				if !errors.Is(err, tc.want) && (tc.want != nil || err != nil) || reasonOf(err) != tc.reason {
					t.Errorf("%s = %v, want %v (%q)", name, err, tc.want, tc.reason)
				}
			}
			want := tc.to
			if tc.want != nil {
				want = tc.from
			}
			if mode, _ := modeOf(t, f.mem); mode != want {
				t.Errorf("stored mode = %v, want %v", mode, want)
			}
		})
	}
}

func adminActor(t *testing.T, f *oidcFixture, _ *access.User) account.Actor {
	t.Helper()
	admin := passwordUser(t, f.mem, f.hasher, "ann", goodPassword)
	admin.Role = access.RoleAdmin
	if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	pr, _ := f.signedInVia(t, admin, access.MethodPassword)
	return account.As(pr)
}

// The state refusals, each Readiness.Refusal and ApplySSO's
// answer alike, writing nothing.
func TestSSOStateRefusals(t *testing.T) {
	t.Parallel()
	t.Run("provider_off_now", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{edit: func(c *account.Config) { c.OIDC = func() *oidc.Provider { return nil } }})
		checkStateRefusal(t, f, socket, account.SSOForLinked, account.ErrOIDCUnavailable, "")
	})
	t.Run("single_user", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		passwordOwner(t, f.pwFixture, "root")
		checkStateRefusal(t, f, socket, account.SSOForLinked, account.ErrPolicyRefused, account.ReasonSingleOwner)
	})
	t.Run("acting_owner_without_local_method", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		bare := mustOwner(t, f.mem, "bare")
		pr, _ := f.signedInVia(t, bare, access.MethodOIDC)
		checkStateRefusal(t, f, account.As(pr), account.SSOOnly, account.ErrPolicyRefused, account.ReasonOwnerNeedsLocalMethod)
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOForLinked); err != nil {
			t.Errorf("for_linked needs no local method of the owner: %v", err)
		}
	})
	t.Run("no_owner_with_local_method", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{})
		mustOwner(t, f.mem, "bare")
		checkStateRefusal(t, f, socket, account.SSOOnly, account.ErrPolicyRefused, account.ReasonOwnerNeedsLocalMethod)
	})
	t.Run("out_of_band_with_one_owner_holding_one", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		mustOwner(t, f.mem, "bare")
		if err := f.svc.ApplySSO(t.Context(), socket, account.SSOOnly); err != nil {
			t.Errorf("ApplySSO(only) out of band with an owner holding a password = %v", err)
		}
	})
}

func checkStateRefusal(t *testing.T, f *oidcFixture, a account.Actor, mode account.SSOMode, want error, reason string) {
	t.Helper()
	rd, err := f.svc.SSOReadiness(t.Context(), a, mode)
	if err != nil || !errors.Is(rd.Refusal, want) || reasonOf(rd.Refusal) != reason {
		t.Errorf("SSOReadiness = %+v, %v; want refusal %v (%q)", rd, err, want, reason)
	}
	if err := f.svc.CheckSSOReady(t.Context(), a, mode); !errors.Is(err, want) || reasonOf(err) != reason {
		t.Errorf("CheckSSOReady = %v, want %v (%q)", err, want, reason)
	}
	mark := len(f.events.all())
	if err := f.svc.ApplySSO(t.Context(), a, mode); !errors.Is(err, want) || reasonOf(err) != reason || err.Error() != rd.Refusal.Error() {
		t.Errorf("ApplySSO = %v, want exactly the readiness refusal %v", err, rd.Refusal)
	}
	if got, set := modeOf(t, f.mem); got != account.SSOAlongside || set || len(f.events.all()) != mark {
		t.Errorf("after the refusal: mode %v, set %t, %d events; want nothing written", got, set, len(f.events.all())-mark)
	}
}

// With Config.OIDC unset, every mode operation
// answers ErrOIDCUnavailable.
func TestSSOModeUnwired(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	passwordOwner(t, p, "root")
	if _, err := p.svc.SSOReadiness(t.Context(), socket, account.SSOForLinked); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("SSOReadiness = %v", err)
	}
	if err := p.svc.CheckSSOReady(t.Context(), socket, account.SSOForLinked); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("CheckSSOReady = %v", err)
	}
	if err := p.svc.ApplySSO(t.Context(), socket, account.SSOAlongside); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("ApplySSO = %v", err)
	}
	if err := p.svc.MigrateSSO(t.Context(), account.SSOForLinked); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("MigrateSSO = %v", err)
	}
	if _, set := modeOf(t, p.mem); set {
		t.Error("an unwired mode operation set the mode")
	}
}

// An unknown mode is refused before any read.
func TestApplySSOUnknownMode(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	if err := f.svc.ApplySSO(t.Context(), socket, account.SSOMode(7)); !errors.Is(err, account.ErrUnknownSSOMode) {
		t.Errorf("ApplySSO(SSOMode(7)) = %v, want ErrUnknownSSOMode", err)
	}
	if _, set := modeOf(t, f.mem); set {
		t.Error("an unknown mode set the stored one")
	}
}

// MigrateSSO: its condition is inside its write; a refusal leaves
// the mode unset for the next call.
func TestMigrateSSO(t *testing.T) {
	t.Parallel()
	t.Run("unset", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		if err := f.svc.MigrateSSO(t.Context(), account.SSOForLinked); err != nil {
			t.Fatalf("MigrateSSO = %v", err)
		}
		if mode, set := modeOf(t, f.mem); mode != account.SSOForLinked || !set {
			t.Errorf("mode = %v, set %t", mode, set)
		}
		if ev := eventsOf(f.events, account.EventSSOModeChanged); len(ev) != 1 || ev[0].Actor.OutOfBand != "migration" {
			t.Errorf("sso_mode_changed = %+v, want one by the migration", ev)
		}
	})
	t.Run("owner_chose_alongside", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOAlongside); err != nil {
			t.Fatalf("ApplySSO = %v", err)
		}
		if err := f.svc.MigrateSSO(t.Context(), account.SSOForLinked); err != nil {
			t.Fatalf("MigrateSSO = %v", err)
		}
		if mode, set := modeOf(t, f.mem); mode != account.SSOAlongside || !set {
			t.Errorf("mode = %v, set %t; want the owner's alongside", mode, set)
		}
		if n := len(eventsOf(f.events, account.EventSSOModeChanged)); n != 1 {
			t.Errorf("%d sso_mode_changed, want the owner's one", n)
		}
	})
	t.Run("retries_after_refusal", func(t *testing.T) {
		t.Parallel()
		var on atomic.Bool
		rig := rigFor(t, "subject-y")
		f := newOIDCFixture(t, rig, pwOptions{edit: func(c *account.Config) {
			c.OIDC = func() *oidc.Provider {
				if on.Load() {
					return rig.provider
				}
				return nil
			}
		}})
		passwordOwner(t, f.pwFixture, "root")
		if err := f.svc.MigrateSSO(t.Context(), account.SSOForLinked); !errors.Is(err, account.ErrOIDCUnavailable) {
			t.Fatalf("MigrateSSO with the provider off = %v", err)
		}
		if _, set := modeOf(t, f.mem); set {
			t.Fatal("a refused migration set the mode")
		}
		on.Store(true)
		if err := f.svc.MigrateSSO(t.Context(), account.SSOForLinked); err != nil {
			t.Fatalf("MigrateSSO once configured = %v", err)
		}
		if mode, _ := modeOf(t, f.mem); mode != account.SSOForLinked {
			t.Errorf("mode = %v", mode)
		}
	})
	t.Run("owner_commits_while_migration_waits", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{store: fs})
		root := passwordOwner(t, f.pwFixture, "root")
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		entered, release := fs.holdUpdate()
		done := make(chan error, 1)
		go func() { done <- f.svc.MigrateSSO(context.Background(), account.SSOForLinked) }()
		<-entered
		applied := make(chan error, 1)
		go func() { applied <- f.svc.ApplySSO(context.Background(), account.As(pr), account.SSOAlongside) }()
		if err := <-applied; err != nil {
			t.Fatalf("ApplySSO = %v", err)
		}
		release()
		if err := <-done; err != nil {
			t.Fatalf("MigrateSSO = %v", err)
		}
		if mode, set := modeOf(t, fs.mem); mode != account.SSOAlongside || !set {
			t.Errorf("mode = %v, set %t; want the owner's alongside", mode, set)
		}
	})
}

// ApplySSO reads Config.OIDC before its Update opens.
func TestApplySSOReadsProviderOutsideUpdate(t *testing.T) {
	t.Parallel()
	var inUpdate, inside atomic.Bool
	fs := newFaultStore()
	rig := rigFor(t, "subject-y")
	f := newOIDCFixture(t, rig, pwOptions{store: fs, edit: func(c *account.Config) {
		c.OIDC = func() *oidc.Provider {
			if inUpdate.Load() {
				inside.Store(true)
			}
			return rig.provider
		}
	}})
	passwordOwner(t, f.pwFixture, "root")
	fs.onUpdate(func(context.Context, int) { inUpdate.Store(true) })
	if err := f.svc.ApplySSO(t.Context(), socket, account.SSOForLinked); err != nil {
		t.Fatalf("ApplySSO = %v", err)
	}
	if inside.Load() {
		t.Error("ApplySSO called Config.OIDC inside its Update")
	}
}

// A sign-in racing ApplySSO commits before it and is swept, or
// after it and is refused.
func TestSignInRacingApplySSO(t *testing.T) {
	t.Parallel()
	t.Run("commits_before", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		u := linkedUser(t, f.pwFixture, "alice", "alice")
		if _, err := f.login(t.Context(), localClient, "alice", goodPassword); err != nil {
			t.Fatalf("sign-in = %v", err)
		}
		if err := f.svc.ApplySSO(t.Context(), socket, account.SSOForLinked); err != nil {
			t.Fatalf("ApplySSO = %v", err)
		}
		if n := len(sessionsOf(t, f.mem, u.ID)); n != 0 {
			t.Errorf("%d sessions survived the change", n)
		}
	})
	t.Run("commits_after", func(t *testing.T) {
		t.Parallel()
		var svc atomic.Pointer[account.Service]
		var changed atomic.Bool
		f, _ := modeFixture(t, pwOptions{hooks: account.Hooks{AfterVerify: func(ctx context.Context) {
			if s := svc.Load(); s != nil && changed.CompareAndSwap(false, true) {
				if err := s.ApplySSO(context.WithoutCancel(ctx), socket, account.SSOForLinked); err != nil {
					t.Errorf("ApplySSO = %v", err)
				}
			}
		}}})
		u := linkedUser(t, f.pwFixture, "alice", "alice")
		svc.Store(f.svc)
		if _, err := f.login(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("a sign-in verified before the change and committed after = %v, want ErrInvalidCredentials", err)
		}
		if n := len(sessionsOf(t, f.mem, u.ID)); n != 0 {
			t.Errorf("%d sessions", n)
		}
	})
}

// A refused ApplySSO leaves the old mode across a restart.
func TestRefusedApplySSOSurvivesRestart(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{})
	mustOwner(t, f.mem, "bare")
	storeMode(t, f.mem, account.SSOForLinked)
	if err := f.svc.ApplySSO(t.Context(), socket, account.SSOOnly); reasonOf(err) != account.ReasonOwnerNeedsLocalMethod {
		t.Fatalf("ApplySSO(only) = %v", err)
	}
	svc, err := restart(t, f.fixture)
	if err != nil {
		t.Fatalf("restart = %v", err)
	}
	if mode, _, err := svc.SSO(t.Context()); err != nil || mode != account.SSOForLinked {
		t.Errorf("SSO after restart = %v, %v; want for_linked", mode, err)
	}
}

// New refuses a stored mode no ApplySSO
// could have written, or one single sign-on is not wired for; a set
// Config.OIDC returning nil starts.
func TestNewStoredMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		edit   func(*account.Config)
		mode   account.SSOMode
		starts bool
		says   []string
	}{
		{name: "single_user", mode: account.SSOForLinked, edit: func(c *account.Config) {
			c.Policy = account.SingleOwnerPolicy{}
			c.OIDC = func() *oidc.Provider { return nil }
		}, says: []string{"for_linked", "single-user", "alongside with the app stopped"}},
		{name: "unwired", mode: account.SSOOnly, edit: func(c *account.Config) { c.OIDC = nil }, says: []string{"only", "Config.OIDC is unset", "alongside with the app stopped"}},
		{name: "both", mode: account.SSOOnly, edit: func(c *account.Config) {
			c.Policy = account.SingleOwnerPolicy{}
			c.OIDC = nil
		}, says: []string{"single-user", "Config.OIDC is unset"}},
		{name: "off_now", mode: account.SSOOnly, edit: func(c *account.Config) { c.OIDC = func() *oidc.Provider { return nil } }, starts: true},
		{name: "unwired_alongside_set", mode: account.SSOAlongside, edit: func(c *account.Config) { c.OIDC = nil }, starts: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{})
			passwordOwner(t, f.pwFixture, "root")
			storeMode(t, f.mem, tc.mode)
			cfg := f.cfg
			tc.edit(&cfg)
			svc, err := account.New(t.Context(), ownAuthenticator(t, cfg))
			if err == nil {
				t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
			}
			if (err == nil) != tc.starts {
				t.Fatalf("New = %v, want started %t", err, tc.starts)
			}
			for _, s := range tc.says {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("New's error %q does not say %q", err, s)
				}
			}
			if tc.name == "off_now" {
				if err := svc.ApplySSO(t.Context(), socket, account.SSOAlongside); !errors.Is(err, account.ErrOIDCUnavailable) {
					t.Errorf("ApplySSO with the provider off = %v, want ErrOIDCUnavailable", err)
				}
			}
		})
	}
}

// SSOReadiness: the counts, each zero in the direction
// that does not apply.
func TestSSOReadinessCounts(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	linkedUser(t, f.pwFixture, "linked", "linked")
	plain := passwordUser(t, f.mem, f.hasher, "plain", goodPassword)
	mustUser(t, f.mem, "bare", access.RoleUser)
	off := linkedUser(t, f.pwFixture, "off", "off")
	off.Enabled = false
	if err := f.mem.UpdateUser(t.Context(), off); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	read := func(mode account.SSOMode) account.Readiness {
		t.Helper()
		rd, err := f.svc.SSOReadiness(t.Context(), socket, mode)
		if err != nil || rd.Refusal != nil {
			t.Fatalf("SSOReadiness(%v) = %+v, %v", mode, rd, err)
		}
		return rd
	}
	if got, want := read(account.SSOOnly), (account.Readiness{LockedOut: 2, MethodsMadeDormant: 2}); got != want {
		t.Errorf("alongside to only = %+v, want %+v", got, want)
	}
	if got, want := read(account.SSOForLinked), (account.Readiness{MethodsMadeDormant: 1}); got != want {
		t.Errorf("alongside to for_linked = %+v, want %+v", got, want)
	}
	storeMode(t, f.mem, account.SSOOnly)
	if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: plain.ID, Hash: plain.PasswordHash, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Dormant: true}); err != nil {
		t.Fatalf("SetTemporaryPassword: %v", err)
	}
	if got, want := read(account.SSOAlongside), (account.Readiness{MethodsRestored: 2, TemporaryPasswordsWithdrawn: 1}); got != want {
		t.Errorf("only to alongside = %+v, want %+v", got, want)
	}
	if got, want := read(account.SSOForLinked), (account.Readiness{MethodsRestored: 1, TemporaryPasswordsWithdrawn: 1}); got != want {
		t.Errorf("only to for_linked = %+v, want %+v", got, want)
	}
	if got := read(account.SSOOnly); got != (account.Readiness{}) {
		t.Errorf("only to only = %+v, want zero", got)
	}
}

// Loosening and
// SetOwner(true) withdraw a Dormant record, a passkey-only holder's
// included, journalling its issuer.
func TestDormantTemporaryPasswordWithdrawn(t *testing.T) {
	t.Parallel()
	record := func(t *testing.T, f *oidcFixture, u *access.User, dormant bool) {
		t.Helper()
		rec := access.TemporaryPassword{UserID: u.ID, Hash: access.NewHash("x"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), IssuedByUser: 41, IssuedByKey: 42, Dormant: dormant}
		if err := f.mem.SetTemporaryPassword(t.Context(), rec); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
	}
	held := func(t *testing.T, f *oidcFixture, u *access.User) bool {
		t.Helper()
		_, found, err := f.mem.TemporaryPasswordByUserID(t.Context(), u.ID)
		if err != nil {
			t.Fatalf("TemporaryPasswordByUserID: %v", err)
		}
		return found
	}
	t.Run("loosening", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		passkeyOnly := mustUser(t, f.mem, "pk", access.RoleUser)
		addPasskey(t, f.mem, passkeyOnly, rpID)
		live := passwordUser(t, f.mem, f.hasher, "live", goodPassword)
		storeMode(t, f.mem, account.SSOOnly)
		record(t, f, passkeyOnly, true)
		record(t, f, live, false)
		if err := f.svc.ApplySSO(t.Context(), socket, account.SSOAlongside); err != nil {
			t.Fatalf("ApplySSO = %v", err)
		}
		if held(t, f, passkeyOnly) || !held(t, f, live) {
			t.Errorf("records held: dormant %t, live %t; want the dormant one withdrawn", held(t, f, passkeyOnly), held(t, f, live))
		}
		ev := eventsOf(f.events, account.EventTemporaryPasswordWithdrawn)
		if len(ev) != 1 || ev[0].UserID != passkeyOnly.ID || ev[0].IssuerUserID != 41 || ev[0].KeyID != 42 || ev[0].Actor.OutOfBand != "admin-socket" {
			t.Errorf("withdrawn events = %+v, want one for pk by the socket with its issuer", ev)
		}
	})
	t.Run("set_owner", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		admin := passwordUser(t, f.mem, f.hasher, "ann", goodPassword)
		admin.Role = access.RoleAdmin
		if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		storeMode(t, f.mem, account.SSOOnly)
		record(t, f, admin, true)
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if _, err := f.svc.SetOwner(t.Context(), account.As(pr), admin.ID, true); err != nil {
			t.Fatalf("SetOwner = %v", err)
		}
		if held(t, f, admin) {
			t.Error("SetOwner(true) kept the dormant record")
		}
		if ev := eventsOf(f.events, account.EventTemporaryPasswordWithdrawn); len(ev) != 1 || ev[0].Actor.UserID != root.ID {
			t.Errorf("withdrawn events = %+v, want one by the owner", ev)
		}
	})
}

// SetOwner(false) on an owner the mode then keeps dormant ends
// its sessions of a local method in the same Update.
func TestSetOwnerFalseUnderMode(t *testing.T) {
	t.Parallel()
	f, root := modeFixture(t, pwOptions{})
	other := passwordOwner(t, f.pwFixture, "other")
	linkIdentity(t, f.mem, storedUser(t, f.mem, other.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "other"})
	byPassword := putSession(t, f.mem, liveSession(t, other))
	storeMode(t, f.mem, account.SSOForLinked)
	pr, _ := f.signedInVia(t, root, access.MethodPassword)
	if _, err := f.svc.SetOwner(t.Context(), account.As(pr), other.ID, false); err != nil {
		t.Fatalf("SetOwner(false) = %v", err)
	}
	if n := len(sessionsOf(t, f.mem, other.ID)); n != 0 {
		t.Errorf("the ex-owner holds %d sessions", n)
	}
	ev := eventsOf(f.events, account.EventUserSessionsRevoked)
	if len(ev) != 1 || !slices.Equal(ev[0].SessionIDs, []string{byPassword.ID}) {
		t.Errorf("revoked = %+v", ev)
	}
}

// The owner transitions under a forbidding mode, and the owner's
// break-glass when admission refuses it.
func TestSetOwnerUnderMode(t *testing.T) {
	t.Parallel()
	// A linked admin's dormant passkey qualifies under SSOOnly, and
	// becomes usable with the flag.
	t.Run("dormant_passkey_qualifies", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		bob := mustUser(t, f.mem, "bob", access.RoleAdmin)
		dev := accesstest.NewPasskeyDevice(t)
		f.enrol(t, bob, dev)
		linkIdentity(t, f.mem, storedUser(t, f.mem, bob.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "bob"})
		storeMode(t, f.mem, account.SSOOnly)
		if _, err := f.signIn(t.Context(), t, localClient, account.LoginModal, dev); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("bob's passkey before the flag = %v, want ErrInvalidCredentials", err)
		}
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if _, err := f.svc.SetOwner(t.Context(), account.As(pr), bob.ID, true); err != nil {
			t.Fatalf("SetOwner(bob, true) under SSOOnly = %v, want nil", err)
		}
		in, err := f.signIn(t.Context(), t, localClient, account.LoginModal, dev)
		if err != nil || in.User == nil || in.User.ID != bob.ID {
			t.Errorf("bob's passkey after the flag = %+v, %v; want bob signed in", in.User, err)
		}
	})
	// SetOwner(false) on a linked owner with a live password
	// session: the session ends, and an SSO sign-in still works.
	t.Run("false_keeps_sso", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		other := passwordOwner(t, f.pwFixture, "other")
		linkIdentity(t, f.mem, storedUser(t, f.mem, other.ID), f.rig.identity())
		putSession(t, f.mem, liveSession(t, other))
		storeMode(t, f.mem, account.SSOForLinked)
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if _, err := f.svc.SetOwner(t.Context(), account.As(pr), other.ID, false); err != nil {
			t.Fatalf("SetOwner(false) = %v", err)
		}
		if n := len(sessionsOf(t, f.mem, other.ID)); n != 0 {
			t.Errorf("the ex-owner holds %d sessions, want none", n)
		}
		flow, claims := f.rig.signInFlow(t)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil || out.Kind != account.OutcomeSignedIn || out.SignedIn.User.ID != other.ID {
			t.Errorf("the ex-owner's SSO sign-in = %+v, %v; want signed in", out, err)
		}
	})
	// SetOwner(false) of an unlinked owner under SSOOnly ends their
	// sessions.
	t.Run("false_unlinked_under_sso_only", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		other := passwordOwner(t, f.pwFixture, "other")
		putSession(t, f.mem, liveSession(t, other))
		storeMode(t, f.mem, account.SSOOnly)
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if _, err := f.svc.SetOwner(t.Context(), account.As(pr), other.ID, false); err != nil {
			t.Fatalf("SetOwner(false) = %v", err)
		}
		if n := len(sessionsOf(t, f.mem, other.ID)); n != 0 {
			t.Errorf("the ex-owner holds %d sessions, want none", n)
		}
	})
	// A methodless owner refused by admission recovers
	// through an OutOfBand temporary password.
	t.Run("methodless_owner_recovers", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{rules: rulesWith(staffAdmission)})
		boss := mustOwner(t, f.mem, "boss")
		linkIdentity(t, f.mem, boss, f.rig.identity())
		storeMode(t, f.mem, account.SSOOnly)
		flow, claims := f.rig.signInFlow(t)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Fatalf("the owner's SSO sign-in outside the group = %v, want ErrNotAdmitted", err)
		}
		issued, err := f.svc.SetTemporaryPassword(t.Context(), socket, boss.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword(socket) = %v", err)
		}
		out, err := f.step1(t.Context(), localClient, "boss", issued.Password.Reveal())
		p := pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		in, err := f.svc.SetCredentialPassword(t.Context(), localClient, p.Ticket, access.NewSecret(newPassword))
		if err != nil || in.SignedIn.User == nil || in.SignedIn.User.ID != boss.ID {
			t.Errorf("SetCredentialPassword = %+v, %v; want boss signed in", in, err)
		}
	})
}

// The last-method guard counts only local methods for
// an owner, and none the mode keeps dormant for a non-owner.
func TestLastMethodUnderMode(t *testing.T) {
	t.Parallel()
	t.Run("owner_link_does_not_count", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		linkIdentity(t, f.mem, storedUser(t, f.mem, root.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if _, err := f.svc.RemovePassword(t.Context(), localClient, pr, access.NewSecret(goodPassword)); !errors.Is(err, account.ErrLastMethod) {
			t.Errorf("an owner removing its one local method = %v, want ErrLastMethod", err)
		}
	})
	t.Run("only_unlink", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		u := linkedUser(t, f.pwFixture, "alice", "alice")
		storeMode(t, f.mem, account.SSOOnly)
		pr, _ := f.signedInVia(t, u, access.MethodOIDC)
		if err := f.svc.UnlinkOIDC(t.Context(), pr); !errors.Is(err, account.ErrLastMethod) {
			t.Errorf("unlinking under only with a dormant password = %v, want ErrLastMethod", err)
		}
		storeMode(t, f.mem, account.SSOForLinked)
		if err := f.svc.UnlinkOIDC(t.Context(), pr); err != nil {
			t.Errorf("unlinking under for_linked, where the password comes back = %v, want nil", err)
		}
	})
	t.Run("usable_methods", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		u := linkedUser(t, f.pwFixture, "alice", "alice")
		storeMode(t, f.mem, account.SSOForLinked)
		avail, err := f.svc.UsableMethods(t.Context(), f.mem, u.ID, account.MethodState{OIDCIssuer: oidcIssuer})
		if err != nil || avail.HasPassword || !avail.OIDCLinked {
			t.Errorf("UsableMethods = %+v, %v; want the link and no dormant password", avail, err)
		}
	})
}

// Both links from a session, under a mode that then keeps the
// user dormant, move the current session onto MethodOIDC and end the other
// local sessions; only the IntentLink callback moves AuthTime.
func TestLinkUnderMode(t *testing.T) {
	t.Parallel()
	paths := map[string]func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session) error{
		"intent_link": func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session) error {
			flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
			_, err := f.complete(t, localClient, flow, claims)
			return err
		},
		"pending_link": func(t *testing.T, f *oidcFixture, _ *access.User, sess access.Session) error {
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil || out.Kind != account.OutcomeNotLinked {
				t.Fatalf("OIDCComplete = %+v, %v; want NotLinked", out, err)
			}
			pr, _ := f.principalOf(t, &sess)
			_, _, err = f.svc.LinkPendingOIDC(t.Context(), pr, out.Pending)
			return err
		},
	}
	for path, link := range paths {
		for _, mode := range []account.SSOMode{account.SSOAlongside, account.SSOForLinked} {
			t.Run(path+"_"+mode.String(), func(t *testing.T) {
				t.Parallel()
				f, u := linkFixture(t, pwOptions{rules: rulesWith(func(r *account.Rules) { r.RevokeKeysOnCredentialChange = true })})
				addPasskey(t, f.mem, u, rpID)
				f.keyPrincipalFor(t, nil, u, time.Time{}, nil)
				storeMode(t, f.mem, mode)
				authTime := time.Now().Add(-2 * time.Minute)
				cur := liveSession(t, u)
				cur.AuthTime = authTime
				if path == "intent_link" {
					cur = putSession(t, f.mem, cur)
				}
				other := putSession(t, f.mem, liveSession(t, u))
				before := time.Now()
				if err := link(t, f, u, cur); err != nil {
					t.Fatalf("link = %v", err)
				}
				if path == "pending_link" {
					for _, s := range sessionsOf(t, f.mem, u.ID) {
						if s.ID != other.ID {
							cur.ID = s.ID
						}
					}
				}
				stored := storedUser(t, f.mem, u.ID)
				if stored.PasswordHash.IsZero() || len(passkeysOf(t, f.mem, u.ID)) != 1 || len(keysOf(t, f.mem, u.ID)) != 1 {
					t.Error("the link deleted a local method or a key")
				}
				dormant := mode == account.SSOForLinked
				var ids []string
				var got access.Session
				for _, s := range sessionsOf(t, f.mem, u.ID) {
					ids = append(ids, s.ID)
					if s.ID == cur.ID {
						got = s
					}
				}
				if slices.Contains(ids, other.ID) == dormant {
					t.Errorf("sessions = %v; other kept %t, want %t", ids, slices.Contains(ids, other.ID), !dormant)
				}
				wantMethod := access.MethodPassword
				if dormant {
					wantMethod = access.MethodOIDC
				}
				if got.AuthMethod != wantMethod {
					t.Errorf("current session's method = %q, want %q", got.AuthMethod, wantMethod)
				}
				stamped := !got.AuthTime.Before(before)
				if want := dormant && path == "intent_link"; stamped != want {
					t.Errorf("current session's AuthTime %v moved %t, want %t", got.AuthTime, stamped, want)
				}
				want := []account.EventKind{account.EventOIDCLinked}
				if dormant {
					want = append(want, account.EventUserSessionsRevoked)
				}
				if got := kindsOf(f.events); !slices.Equal(got, want) {
					t.Errorf("events = %v, want %v", got, want)
				}
			})
		}
	}
}

// State reports the stored mode (StateResponse.sso).
func TestStateSSO(t *testing.T) {
	t.Parallel()
	f, _ := modeFixture(t, pwOptions{})
	storeMode(t, f.mem, account.SSOOnly)
	st, err := f.svc.State(t.Context(), localClient)
	if err != nil || st.SSO != account.SSOOnly {
		t.Errorf("State = %+v, %v; want SSO only", st, err)
	}
	if mode, set, err := f.svc.SSO(t.Context()); err != nil || mode != account.SSOOnly || !set {
		t.Errorf("SSO = %v, %t, %v", mode, set, err)
	}
}

// CheckRules answers every operation's Rules check.
func TestCheckRules(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	if err := p.svc.CheckRules(t.Context(), account.Rules{}); err != nil {
		t.Errorf("CheckRules(zero) = %v", err)
	}
	var re *account.RulesError
	if err := p.svc.CheckRules(t.Context(), account.Rules{Breach: account.BreachFailClosed}); !errors.As(err, &re) || re.Field != "Breach" {
		t.Errorf("CheckRules(a breach mode with no Config.Breach) = %v, want the Breach RulesError", err)
	}
	if err := p.svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := p.svc.CheckRules(t.Context(), account.Rules{}); !errors.Is(err, account.ErrServiceClosed) {
		t.Errorf("CheckRules after Shutdown = %v", err)
	}
}

// The admin list's row carries whether the stored mode keeps
// the user's local methods dormant, read once for the page.
func TestUsersLocalMethodsDormant(t *testing.T) {
	t.Parallel()
	f, root := modeFixture(t, pwOptions{})
	linked := linkedUser(t, f.pwFixture, "alice", "alice")
	plain := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
	linkIdentity(t, f.mem, storedUser(t, f.mem, root.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
	pr, _ := f.signedInVia(t, root, access.MethodPassword)
	for _, tc := range []struct {
		mode account.SSOMode
		want map[int64]bool
	}{
		{account.SSOAlongside, map[int64]bool{root.ID: false, linked.ID: false, plain.ID: false}},
		{account.SSOForLinked, map[int64]bool{root.ID: false, linked.ID: true, plain.ID: false}},
		{account.SSOOnly, map[int64]bool{root.ID: false, linked.ID: true, plain.ID: true}},
	} {
		storeMode(t, f.mem, tc.mode)
		rows, err := f.svc.Users(t.Context(), pr, account.UserFilter{})
		if err != nil {
			t.Fatalf("Users = %v", err)
		}
		for _, row := range rows {
			if row.LocalMethodsDormant != tc.want[row.User.ID] {
				t.Errorf("%v: %s dormant = %t, want %t", tc.mode, row.User.Username, row.LocalMethodsDormant, tc.want[row.User.ID])
			}
		}
	}
}
