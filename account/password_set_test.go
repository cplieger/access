package account_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

const newPassword = "fresh-horse-battery-11"

func (p *pwFixture) setPassword(ctx context.Context, pr access.Principal, current, next string) (account.Issued, error) {
	return p.svc.SetPassword(ctx, localClient, pr, secretOrZero(current), access.NewSecret(next))
}

func secretOrZero(s string) access.Secret {
	if s == "" {
		return access.Secret{}
	}
	return access.NewSecret(s)
}

// verifies reports whether u's stored hash verifies pw.
func (p *pwFixture) verifies(t *testing.T, u *access.User, pw string) bool {
	t.Helper()
	ok, _, err := p.hasher.Verify(t.Context(), pw, storedUser(t, p.mem, u.ID).PasswordHash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return ok
}

// updates counts the Updates s recorded since its last resetRecord.
func updates(s *faultStore) int {
	n := 0
	for _, c := range s.recorded() {
		if c.name == "Update" {
			n++
		}
	}
	return n
}

// holdBudget takes every share of p's hash budget until the test ends.
func (p *pwFixture) holdBudget(t *testing.T) {
	t.Helper()
	for range 4 {
		permit, err := p.hasher.Reserve(t.Context())
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		t.Cleanup(permit.Release)
	}
}

// accountLimitOne admits one attempt per account, so a second attempt
// shows whether the first was charged.
func accountLimitOne(c *ratelimit.Config) { c.Account = ratelimit.Rate{Limit: 1, Window: time.Hour} }

func TestSetPasswordRevokesOthers(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pr, oldToken := p.signedInVia(t, u, access.MethodPassword)
	others := []access.Principal{}
	for range 2 {
		o, _ := p.signedInVia(t, u, access.MethodPasskey)
		others = append(others, o)
	}
	is, err := p.setPassword(t.Context(), pr, goodPassword, newPassword)
	if err != nil {
		t.Fatalf("SetPassword = %v", err)
	}
	ss := sessionsOf(t, p.mem, u.ID)
	if len(ss) != 1 || ss[0].ID != pr.SessionID {
		t.Fatalf("sessions after SetPassword = %d, want only the current one", len(ss))
	}
	if ss[0].TokenHash.Equal(pr.SessionTokenHash()) || is.Token.IsZero() {
		t.Error("the current session kept its token, want it rotated")
	}
	if _, err := p.authenticate(t.Context(), oldToken); err == nil {
		t.Error("the pre-rotation token still authenticates")
	}
	if _, err := p.authenticate(t.Context(), is.Token); err != nil {
		t.Errorf("the rotated token = %v, want it to authenticate", err)
	}
	revoked := eventsOf(p.events, account.EventUserSessionsRevoked)
	if len(revoked) != 1 || !sameIDs(revoked[0].SessionIDs, others[0].SessionID, others[1].SessionID) {
		t.Errorf("EventUserSessionsRevoked = %+v, want one naming both other sessions", revoked)
	}
	if n := len(eventsOf(p.events, account.EventPasswordChanged)); n != 1 {
		t.Errorf("EventPasswordChanged = %d, want 1", n)
	}
	if !p.verifies(t, u, newPassword) || p.verifies(t, u, goodPassword) {
		t.Error("the stored hash is not the new password's")
	}
}

func sameIDs(got []string, want ...string) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

func TestSetPasswordRevokesKeysInSameUpdate(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*pwFixture, *faultStore, *access.User, access.Principal) {
		fs := newFaultStore()
		p := newPW(t, pwOptions{
			store: fs,
			rules: func() account.Rules { return account.Rules{RevokeKeysOnCredentialChange: true} },
		})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.keyPrincipal(t, u, "read")
		p.keyPrincipal(t, u, "write")
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		return p, fs, u, pr
	}
	t.Run("one_commit", func(t *testing.T) {
		t.Parallel()
		p, fs, u, pr := setup(t)
		fs.resetRecord()
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		if keys := keysOf(t, p.mem, u.ID); len(keys) != 0 {
			t.Errorf("keys after SetPassword = %d, want none", len(keys))
		}
		hashUpdate, keysUpdate := 0, 0
		for _, c := range fs.recorded() {
			switch c.name {
			case "UpdateUser":
				hashUpdate = c.update
			case "DeleteUserAPIKeys":
				keysUpdate = c.update
			}
		}
		if hashUpdate == 0 || hashUpdate != keysUpdate {
			t.Errorf("the hash write ran in Update %d and the key delete in Update %d, want one Update", hashUpdate, keysUpdate)
		}
		if n := len(eventsOf(p.events, account.EventKeyRevoked)); n != 2 {
			t.Errorf("EventKeyRevoked = %d, want 2", n)
		}
	})
	t.Run("key_delete_fails", func(t *testing.T) {
		t.Parallel()
		p, fs, u, pr := setup(t)
		fs.failCall("DeleteUserAPIKeys")
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); !errors.Is(err, access.ErrAuthBackend) {
			t.Fatalf("SetPassword with a failing key delete = %v, want ErrAuthBackend", err)
		}
		if keys := keysOf(t, p.mem, u.ID); len(keys) != 2 {
			t.Errorf("keys = %d, want both", len(keys))
		}
		if !p.verifies(t, u, goodPassword) {
			t.Error("the old hash is gone though the key delete failed")
		}
		for _, kind := range []account.EventKind{account.EventPasswordChanged, account.EventKeyRevoked, account.EventUserSessionsRevoked} {
			if n := len(eventsOf(p.events, kind)); n != 0 {
				t.Errorf("%s events = %d, want none", kind, n)
			}
		}
	})
}

func keysOf(t *testing.T, s account.Store, userID int64) []access.Key {
	t.Helper()
	keys, err := s.ListAPIKeysByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUserID: %v", err)
	}
	return keys
}

func TestSetPasswordCurrent(t *testing.T) {
	t.Parallel()
	t.Run("right", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		p.failStepUps(t, localClient, pr, 2)
		is, err := p.setPassword(t.Context(), pr, goodPassword, newPassword)
		if err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		if is.DeviceCookie.IsZero() {
			t.Error("Issued.DeviceCookie is zero, want the verified password's device cookie")
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("the untrusted record survived the verified change")
		}
		if !p.verifies(t, u, newPassword) {
			t.Error("the stored hash is not the new password's")
		}
	})
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs, limiter: accountLimitOne})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		fs.resetRecord()
		if _, err := p.setPassword(t.Context(), pr, "", newPassword); !errors.Is(err, account.ErrCurrentPasswordRequired) {
			t.Fatalf("SetPassword with no current = %v, want ErrCurrentPasswordRequired", err)
		}
		if n := updates(fs); n != 0 {
			t.Errorf("Updates = %d, want none", n)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("a failure record exists, want no count")
		}
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); err != nil {
			t.Errorf("the next SetPassword under an account limit of 1 = %v, want the zero call uncharged", err)
		}
	})
	t.Run("wrong", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		other, _ := p.signedInVia(t, u, access.MethodPasskey)
		if _, err := p.setPassword(t.Context(), pr, wrongPassword, newPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("SetPassword with a wrong current = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
			t.Errorf("untrusted record = %+v, want count 1", rec)
		}
		if !p.verifies(t, u, goodPassword) {
			t.Error("the stored hash changed")
		}
		if ss := sessionsOf(t, p.mem, u.ID); len(ss) != 2 || !slices.ContainsFunc(ss, func(s access.Session) bool { return s.ID == other.SessionID }) {
			t.Errorf("sessions = %d, want both kept", len(ss))
		}
	})
	t.Run("locked", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		for range account.FailureCap {
			if _, err := p.setPassword(t.Context(), pr, wrongPassword, newPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Fatalf("wrong change = %v, want ErrInvalidCredentials", err)
			}
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); !rec.Locked {
			t.Fatalf("untrusted record after %d wrong changes = %+v, want locked", account.FailureCap, rec)
		}
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the right current on a locked password = %v, want ErrInvalidCredentials", err)
		}
		if !p.verifies(t, u, goodPassword) {
			t.Error("the locked password was replaced")
		}
	})
	t.Run("recovered_between_verify_and_commit", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		recovered := recoverPassword(t, p, u, &hk)
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("SetPassword racing a recovery = %v, want ErrInvalidCredentials", err)
		}
		if !storedUser(t, p.mem, u.ID).PasswordHash.Equal(recovered) {
			t.Error("the recovered hash was replaced")
		}
	})
	t.Run("new_hash_busy", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{wait: 10 * time.Millisecond})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		p.holdBudget(t)
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); !errors.Is(err, access.ErrHashBusy) {
			t.Fatalf("SetPassword under a held budget = %v, want ErrHashBusy", err)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("a failure record exists, want nothing counted")
		}
	})
	t.Run("first_password", func(t *testing.T) {
		t.Parallel()
		for _, current := range []string{"", "ignored-horse-battery-3"} {
			p := newPW(t, pwOptions{})
			u := passwordUser(t, p.mem, nil, "alice", "")
			pr, _ := p.signedInVia(t, u, access.MethodPasskey)
			is, err := p.setPassword(t.Context(), pr, current, newPassword)
			if err != nil {
				t.Fatalf("first SetPassword with current %q = %v", current, err)
			}
			if !p.verifies(t, u, newPassword) {
				t.Errorf("current %q: the first password is not stored", current)
			}
			if !is.DeviceCookie.IsZero() {
				t.Errorf("current %q: a first password returned a device cookie, want none: no password was verified", current)
			}
			if n := len(eventsOf(p.events, account.EventPasswordSet)); n != 1 {
				t.Errorf("current %q: EventPasswordSet = %d, want 1", current, n)
			}
		}
	})
	t.Run("racing_first_passwords", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		u := passwordUser(t, p.mem, nil, "alice", "")
		first, _ := p.signedInVia(t, u, access.MethodPasskey)
		second, _ := p.signedInVia(t, u, access.MethodPasskey)
		entered, release := fs.holdUpdate()
		held := make(chan error, 1)
		go func() {
			_, err := p.setPassword(t.Context(), first, "", "first-horse-battery-1")
			held <- err
		}()
		<-entered
		if _, err := p.setPassword(t.Context(), second, "", newPassword); err != nil {
			t.Fatalf("the unheld first password = %v", err)
		}
		release()
		if err := <-held; !errors.Is(err, account.ErrCurrentPasswordRequired) {
			t.Errorf("the held first password = %v, want ErrCurrentPasswordRequired", err)
		}
		if !p.verifies(t, u, newPassword) {
			t.Error("the stored password is not the one that committed first")
		}
	})
}

// recoverPassword arms hk so that, once the next verification passes, a
// direct store write gives u another hash, standing in for a recovery
// completed between that verification and its success Update. It returns
// that hash.
func recoverPassword(t *testing.T, p *pwFixture, u *access.User, hk *armed) access.Hash {
	t.Helper()
	recovered, err := p.hasher.Hash(t.Context(), "recovered-horse-battery-5")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	hk.arm(func(ctx context.Context) {
		hk.disarm()
		cur := storedUser(t, p.mem, u.ID)
		cur.PasswordHash = recovered
		if err := p.mem.UpdateUser(ctx, cur); err != nil {
			t.Errorf("UpdateUser: %v", err)
		}
	})
	return recovered
}

func TestRemovePasswordCurrent(t *testing.T) {
	t.Parallel()
	rp := newRP(t)
	setup := func(t *testing.T, o pwOptions, passkey bool) (*pwFixture, *access.User, access.Principal) {
		edit := o.edit
		o.edit = func(c *account.Config) {
			c.RP = func() *webauthn.RelyingParty { return rp }
			if edit != nil {
				edit(c)
			}
		}
		p := newPW(t, o)
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		if passkey {
			addPasskey(t, p.mem, u, rpID)
		}
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		return p, u, pr
	}
	remove := func(t *testing.T, p *pwFixture, pr access.Principal, current string) (account.Issued, error) {
		return p.svc.RemovePassword(t.Context(), localClient, pr, secretOrZero(current))
	}
	passkeyOnly := func(t *testing.T, o pwOptions) (*pwFixture, *access.User, access.Principal) {
		o.edit = func(c *account.Config) { c.RP = func() *webauthn.RelyingParty { return rp } }
		p := newPW(t, o)
		u := passwordUser(t, p.mem, nil, "alice", "")
		addPasskey(t, p.mem, u, rpID)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		return p, u, pr
	}
	t.Run("no_password", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p, _, pr := passkeyOnly(t, pwOptions{store: fs, limiter: accountLimitOne})
		fs.resetRecord()
		for i := range 2 {
			if _, err := remove(t, p, pr, goodPassword); !errors.Is(err, account.ErrNotFound) {
				t.Fatalf("RemovePassword %d with no password held = %v, want ErrNotFound, uncharged under an account limit of 1", i, err)
			}
		}
		if n := updates(fs); n != 0 {
			t.Errorf("Updates = %d, want none", n)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("a failure record exists, want nothing counted")
		}
		if n := len(p.events.all()); n != 0 {
			t.Errorf("events = %d, want none", n)
		}
	})
	t.Run("no_password_repeated", func(t *testing.T) {
		t.Parallel()
		p, _, pr := passkeyOnly(t, pwOptions{})
		for range 100 {
			if _, err := remove(t, p, pr, wrongPassword); !errors.Is(err, account.ErrNotFound) {
				t.Fatalf("RemovePassword with no password held = %v, want ErrNotFound", err)
			}
		}
		if _, err := p.setPassword(t.Context(), pr, "", newPassword); err != nil {
			t.Fatalf("the first SetPassword after the refused removals = %v", err)
		}
		if _, err := p.login(t.Context(), localClient, "alice", newPassword); err != nil {
			t.Errorf("PasswordLogin with the first password = %v, want it unlocked and admitted", err)
		}
	})
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		p, u, pr := setup(t, pwOptions{}, true)
		if _, err := remove(t, p, pr, ""); !errors.Is(err, account.ErrCurrentPasswordRequired) {
			t.Fatalf("RemovePassword with no current = %v, want ErrCurrentPasswordRequired", err)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("a failure record exists, want no count")
		}
		if storedUser(t, p.mem, u.ID).PasswordHash.IsZero() {
			t.Fatal("the password is gone")
		}
		if _, err := p.setPassword(t.Context(), pr, "", newPassword); !errors.Is(err, account.ErrCurrentPasswordRequired) {
			t.Errorf("SetPassword with no current after the refused removal = %v, want ErrCurrentPasswordRequired", err)
		}
	})
	t.Run("wrong", func(t *testing.T) {
		t.Parallel()
		p, u, pr := setup(t, pwOptions{}, true)
		if _, err := remove(t, p, pr, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("RemovePassword with a wrong current = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
			t.Errorf("untrusted record = %+v, want count 1", rec)
		}
		if storedUser(t, p.mem, u.ID).PasswordHash.IsZero() {
			t.Error("the password is gone")
		}
	})
	t.Run("right", func(t *testing.T) {
		t.Parallel()
		p, u, pr := setup(t, pwOptions{}, true)
		p.failStepUps(t, localClient, pr, 2)
		is, err := remove(t, p, pr, goodPassword)
		if err != nil {
			t.Fatalf("RemovePassword = %v", err)
		}
		if !storedUser(t, p.mem, u.ID).PasswordHash.IsZero() {
			t.Error("the password is still stored")
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("the untrusted record survived the verified removal")
		}
		if is.DeviceCookie.IsZero() || is.Token.IsZero() || is.Session.ID != pr.SessionID {
			t.Errorf("Issued = token zero %t, device zero %t, session %q; want a rotation of %q with a device cookie", is.Token.IsZero(), is.DeviceCookie.IsZero(), is.Session.ID, pr.SessionID)
		}
		if n := len(eventsOf(p.events, account.EventPasswordRemoved)); n != 1 {
			t.Errorf("EventPasswordRemoved = %d, want 1", n)
		}
	})
	t.Run("only_method", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p, u, pr := setup(t, pwOptions{store: fs, limiter: accountLimitOne}, false)
		fs.resetRecord()
		if _, err := remove(t, p, pr, goodPassword); !errors.Is(err, account.ErrLastMethod) {
			t.Fatalf("RemovePassword of the only method = %v, want ErrLastMethod", err)
		}
		if n := updates(fs); n != 0 {
			t.Errorf("Updates = %d, want none: the guard refuses before the count", n)
		}
		if _, err := p.stepUp(t.Context(), localClient, pr, goodPassword); err != nil {
			t.Errorf("a step-up under an account limit of 1 = %v, want the refused removal uncharged", err)
		}
		if storedUser(t, p.mem, u.ID).PasswordHash.IsZero() {
			t.Error("the password is gone")
		}
	})
	t.Run("recovered_between_verify_and_commit", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p, u, pr := setup(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}}, true)
		recovered := recoverPassword(t, p, u, &hk)
		if _, err := remove(t, p, pr, goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("RemovePassword racing a recovery = %v, want ErrInvalidCredentials", err)
		}
		if !storedUser(t, p.mem, u.ID).PasswordHash.Equal(recovered) {
			t.Error("the recovered hash is gone")
		}
	})
}

func TestRulesReloadInvalid(t *testing.T) {
	t.Parallel()
	t.Run("SetPassword", func(t *testing.T) {
		t.Parallel()
		// Config.Breach stays nil, so no breach call can be made: the
		// reloaded BreachFailOpen is refused as invalid, never run open.
		var (
			mu    sync.Mutex
			rules = account.Rules{}
		)
		fs := newFaultStore()
		p := newPW(t, pwOptions{
			store: fs,
			rules: func() account.Rules {
				mu.Lock()
				defer mu.Unlock()
				return rules
			},
		})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		mu.Lock()
		rules = account.Rules{Breach: account.BreachFailOpen}
		mu.Unlock()
		fs.resetRecord()
		before := errorLogs(p.logs)
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); !errors.Is(err, account.ErrRulesInvalid) {
			t.Fatalf("SetPassword after the reload = %v, want ErrRulesInvalid", err)
		}
		if n := errorLogs(p.logs) - before; n != 1 {
			t.Errorf("ERROR logs = %d, want 1", n)
		}
		if n := len(fs.recorded()); n != 0 {
			t.Errorf("store calls = %d, want none", n)
		}
	})
}
