package account_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// putFailure stores one counted failure of u's method m, locked when locked.
func putFailure(t testing.TB, f *sfFixture, u *access.User, m access.Method, locked bool) {
	t.Helper()
	rec := account.FailureCount{Name: account.FailureName(f.svc, u.Username), Method: m, Count: 1}
	if locked {
		rec.Count, rec.Locked, rec.LockedAt = account.FailureCap, true, time.Now().Truncate(time.Millisecond)
	}
	if err := f.mem.PutAuthFailure(t.Context(), rec); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
}

// failureHeld reports whether u's method m has a failure record.
func failureHeld(t testing.TB, f *sfFixture, u *access.User, m access.Method) bool {
	t.Helper()
	_, found, err := f.mem.AuthFailure(t.Context(), account.FailureRef{Name: account.FailureName(f.svc, u.Username), Method: m})
	if err != nil {
		t.Fatalf("AuthFailure: %v", err)
	}
	return found
}

// secondFactorGone reports whether u holds neither a TOTP record nor a
// recovery code.
func secondFactorGone(t testing.TB, s account.Store, u *access.User) bool {
	t.Helper()
	_, totpHeld := totpRecord(t, s, u.ID)
	_, codeHeld, err := s.RecoveryCodeByUserID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("RecoveryCodeByUserID: %v", err)
	}
	return !totpHeld && !codeHeld
}

// TestResetSecondFactor is design 4.10's admin reset: the TOTP record and
// the recovery code go with their locks, the sessions and the pending
// sign-ins, and the password and passkeys stay.
func TestResetSecondFactor(t *testing.T) {
	t.Parallel()
	t.Run("deletes_the_second_factor", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		l := loadUser(t, f, "alice")
		putFailure(t, f, l.user, access.MethodTOTP, true)
		putFailure(t, f, l.user, access.MethodRecoveryCode, true)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), l.user.ID); err != nil {
			t.Fatalf("ResetSecondFactor = %v, want nil", err)
		}
		if !secondFactorGone(t, f.mem, l.user) {
			t.Error("the TOTP record or the recovery code survived the reset")
		}
		// 4.10: "clears both locks", the TOTP's and the recovery code's.
		if failureHeld(t, f, l.user, access.MethodTOTP) || failureHeld(t, f, l.user, access.MethodRecoveryCode) {
			t.Error("a TOTP or recovery-code lock survived the reset")
		}
		// 4.10: the user keeps the password and their passkeys.
		if u := storedUser(t, f.mem, l.user.ID); u.PasswordHash.IsZero() {
			t.Error("the reset cleared the password")
		}
		if _, locked := record(t, f.mem, f.svc, "alice", false); !locked {
			t.Error("the reset cleared the password's lock, which 4.10 does not name")
		}
		if pks, _ := f.mem.PasskeysByUserID(t.Context(), l.user.ID); len(pks) != 1 {
			t.Errorf("passkeys = %d, want the one the user held", len(pks))
		}
		if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), l.user.ID); len(keys) != 1 {
			t.Errorf("keys = %d, want the one the user held", len(keys))
		}
		if n := len(sessionsOf(t, f.mem, l.user.ID)); n != 0 {
			t.Errorf("sessions = %d, want none", n)
		}
		evs := f.events.all()
		want := []account.EventKind{account.EventSecondFactorReset, account.EventUserSessionsRevoked}
		if !slices.Equal(kinds(evs), want) {
			t.Fatalf("events = %v, want %v", kinds(evs), want)
		}
		if evs[0].UserID != l.user.ID || evs[0].Actor.OutOfBand != "cli" || !slices.Equal(evs[1].SessionIDs, []string{l.session.ID}) {
			t.Errorf("events = %+v, want the reset of alice by cli, then her session %s ended", evs, l.session.ID)
		}
	})
	t.Run("password_signs_in_after", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor = %v", err)
		}
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		if err != nil || out.Pending != nil || out.SignedIn.User == nil {
			t.Errorf("password sign-in after the reset = %+v, %v; want a session with no second step", out.Pending, err)
		}
	})
	// 4.10: under the rule the next password sign-in reaches NextEnrol, from
	// a known device (4.4).
	t.Run("rule_reaches_enrol", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		storeRecoveryCode(t, f.mem, u)
		f.set(account.Rules{RequireSecondFactor: true, Scopes: keyRules().Scopes})
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor = %v", err)
		}
		c := clientAt(1)
		c.Device = f.knownDevice("alice")
		out, err := f.step1(t.Context(), c, "alice", goodPassword)
		if err != nil || out.Pending == nil || out.Pending.Next != account.NextEnrol || !slices.Contains(out.Pending.Methods, access.MethodTOTP) {
			t.Fatalf("step 1 after the reset = %+v, %v; want NextEnrol offering totp", out.Pending, err)
		}
	})
	// RULINGS Q16 (design 4.53): a target holding neither record answers
	// ErrNotFound and nothing is written.
	t.Run("nothing_held", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sess := putSession(t, f.mem, liveSession(t, u))
		putFailure(t, f, u, access.MethodTOTP, false)
		for name, a := range map[string]account.Actor{
			"out_of_band": account.OutOfBand("cli"),
			"admin":       account.As(f.sessionPrincipal(t, root, time.Now())),
		} {
			if err := f.svc.ResetSecondFactor(t.Context(), a, u.ID); !errors.Is(err, account.ErrNotFound) {
				t.Errorf("%s: a reset of a user holding no second factor = %v, want ErrNotFound", name, err)
			}
		}
		if got := sessionsOf(t, f.mem, u.ID); len(got) != 1 || got[0].ID != sess.ID {
			t.Errorf("sessions = %+v, want alice's one session kept", got)
		}
		if !failureHeld(t, f, u, access.MethodTOTP) {
			t.Error("a reset that found nothing cleared a failure record")
		}
		if evs := f.events.all(); len(evs) != 0 {
			t.Errorf("events = %v, want none", kinds(evs))
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), 1<<40); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("a reset of a missing user = %v, want ErrNotFound", err)
		}
	})
	// RULINGS Q16: a refused actor's refusal comes before the existence
	// answer, so a refusal never tells a held factor from none.
	t.Run("refusal_before_existence", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		bob := mustUser(t, f.mem, "bob", access.RoleUser)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		held := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, held)
		none := passwordUser(t, f.mem, f.hasher, "carol", goodPassword)
		bp := account.As(f.sessionPrincipal(t, bob, time.Now()))
		for name, id := range map[string]int64{"held": held.ID, "none": none.ID, "missing": 1 << 40} {
			if err := f.svc.ResetSecondFactor(t.Context(), bp, id); reason(err) != account.ReasonNotAdmin {
				t.Errorf("a regular user's reset of %s = %v, want not_admin", name, err)
			}
		}
		key := account.As(f.keyPrincipal(t, root, scopeUsers))
		if err := f.svc.ResetSecondFactor(t.Context(), key, admin.ID); reason(err) != account.ReasonAdminTarget {
			t.Errorf("a key's reset of an admin holding nothing = %v, want admin_target", err)
		}
		if _, found := totpRecord(t, f.mem, held.ID); !found {
			t.Error("a refused reset deleted the TOTP record")
		}
	})
}

// TestResetSecondFactorWho is design 4.10's actors: Admidio
// GHSA-rh3w-4ccx-prf9 (an inverted reset authorization let a non-admin
// strip an admin's TOTP), a test per role, and snipe-it
// GHSA-mr8g-2mj4-pcq2 (admin-only and never self-targeted).
func TestResetSecondFactorWho(t *testing.T) {
	t.Parallel()
	enrolled := func(t *testing.T, f *sfFixture, name string, role access.Role) *access.User {
		t.Helper()
		u := mustUser(t, f.mem, name, role)
		storeTOTP(t, f.mem, u)
		storeRecoveryCode(t, f.mem, u)
		return u
	}
	t.Run("self", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		storeTOTP(t, f.mem, root)
		for name, p := range map[string]access.Principal{
			"session": f.sessionPrincipal(t, root, time.Now()),
			"key":     f.keyPrincipal(t, root, scopeUsers),
		} {
			if err := f.svc.ResetSecondFactor(t.Context(), account.As(p), root.ID); reason(err) != account.ReasonSelfRecovery {
				t.Errorf("%s: a reset of oneself = %v, want self_recovery", name, err)
			}
		}
		if _, found := totpRecord(t, f.mem, root.ID); !found {
			t.Error("a refused self reset deleted the TOTP record")
		}
	})
	t.Run("roles", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		admin := enrolled(t, f, "admin", access.RoleAdmin)
		bob := enrolled(t, f, "bob", access.RoleUser)
		alice := enrolled(t, f, "alice", access.RoleUser)
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.sessionPrincipal(t, bob, time.Now())), admin.ID); reason(err) != account.ReasonNotAdmin {
			t.Errorf("a regular user's reset of an admin = %v, want not_admin", err)
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.sessionPrincipal(t, bob, time.Now())), alice.ID); reason(err) != account.ReasonNotAdmin {
			t.Errorf("a regular user's reset of a regular user = %v, want not_admin", err)
		}
		if secondFactorGone(t, f.mem, admin) || secondFactorGone(t, f.mem, alice) {
			t.Fatal("a refused reset deleted a record")
		}
		p := f.sessionPrincipal(t, admin, time.Now())
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(p), alice.ID); err != nil {
			t.Fatalf("an admin's reset of a regular user = %v, want nil", err)
		}
		if evs := eventsOf(f.events, account.EventSecondFactorReset); len(evs) != 1 || evs[0].Actor.SessionID != p.SessionID {
			t.Errorf("second_factor_reset = %+v, want one by the admin's session", evs)
		}
		if !secondFactorGone(t, f.mem, alice) {
			t.Error("the admin's reset left alice's records")
		}
	})
	// 5.2: only another owner or OutOfBand resets an owner.
	t.Run("owner_target", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		storeTOTP(t, f.mem, root)
		second := mustOwner(t, f.mem, "second")
		storeTOTP(t, f.mem, second)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.sessionPrincipal(t, admin, time.Now())), root.ID); reason(err) != account.ReasonOwnerTarget {
			t.Errorf("an admin's reset of an owner = %v, want owner_target", err)
		}
		if _, found := totpRecord(t, f.mem, root.ID); !found {
			t.Error("the refused reset deleted the owner's TOTP record")
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.sessionPrincipal(t, second, time.Now())), root.ID); err != nil {
			t.Errorf("another owner's reset of an owner = %v, want nil", err)
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), second.ID); err != nil {
			t.Errorf("an out-of-band reset of an owner = %v, want nil", err)
		}
	})
	// 4.10: a manage_users key resets a regular user only (admin_target).
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		admin := enrolled(t, f, "admin", access.RoleAdmin)
		alice := enrolled(t, f, "alice", access.RoleUser)
		p, key := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeUsers)
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(p), admin.ID); reason(err) != account.ReasonAdminTarget {
			t.Errorf("a key's reset of an admin = %v, want admin_target", err)
		}
		if secondFactorGone(t, f.mem, admin) {
			t.Error("the refused key reset deleted the admin's records")
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(p), alice.ID); err != nil {
			t.Fatalf("a key's reset of a regular user = %v, want nil", err)
		}
		if evs := eventsOf(f.events, account.EventSecondFactorReset); len(evs) != 1 || evs[0].Actor.KeyID != key.ID {
			t.Errorf("second_factor_reset = %+v, want one by key %d", evs, key.ID)
		}
	})
	// 4.10: SingleOwnerPolicy allows OutOfBand only.
	t.Run("single_owner", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, account.SingleOwnerPolicy{})
		owner := mustOwner(t, f.mem, "owner")
		storeTOTP(t, f.mem, owner)
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.sessionPrincipal(t, owner, time.Now())), owner.ID); reason(err) != account.ReasonSelfRecovery {
			t.Errorf("the owner's own reset = %v, want self_recovery", err)
		}
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), owner.ID); err != nil {
			t.Errorf("an out-of-band reset of the owner = %v, want nil", err)
		}
		if !secondFactorGone(t, f.mem, owner) {
			t.Error("the out-of-band reset left the owner's TOTP record")
		}
	})
	// 4.12: the reset is allowed over plain HTTP; it answers no secret.
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, access.PosturePerRequest, nil)
		root := mustOwner(t, f.mem, "root")
		alice := enrolled(t, f, "alice", access.RoleUser)
		sess := liveSession(t, root)
		sess.Secure = false
		if err := f.svc.ResetSecondFactor(t.Context(), account.As(f.plainPrincipalOf(t, &sess)), alice.ID); err != nil {
			t.Errorf("a plain reset = %v, want nil", err)
		}
		if !secondFactorGone(t, f.mem, alice) {
			t.Error("the plain reset left alice's records")
		}
	})
}

// TestResetSecondFactorDormant is RULINGS M1 addendum 2 and Q16: a record
// kept dormant, by TOTP unwired or off or by the SSO mode, is still
// something to reset, and is deleted.
func TestResetSecondFactorDormant(t *testing.T) {
	t.Parallel()
	t.Run("totp_unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sealTOTP(t, f.mem, access.NewEphemeralSealer(), u)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor with TOTP unwired = %v, want nil", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the unwired record is still stored")
		}
	})
	t.Run("totp_disabled", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{DisableTOTP: true}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor under DisableTOTP = %v, want nil", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the record DisableTOTP keeps dormant is still stored")
		}
	})
	t.Run("sso_only", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		storeRecoveryCode(t, f.mem, u)
		setMode(t, f.mem, account.SSOOnly)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor under SSOOnly = %v, want nil", err)
		}
		if !secondFactorGone(t, f.mem, u) {
			t.Error("the records the mode keeps dormant are still stored")
		}
		if storedUser(t, f.mem, u.ID).PasswordHash.IsZero() {
			t.Error("the reset cleared the dormant password")
		}
	})
}
