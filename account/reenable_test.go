package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
)

// seedLock stores the record a FailureCap run of failures leaves for
// name's password in one trust context, reported or not.
func seedLock(t *testing.T, s account.Store, svc *account.Service, name string, trusted, unreported bool) account.FailureCount {
	t.Helper()
	rec := account.FailureCount{
		Name: account.FailureName(svc, name), Method: access.MethodPassword, Trusted: trusted,
		Count: account.FailureCap, Locked: true, LockedAt: time.Now().Add(-time.Hour).Truncate(time.Second), Unreported: unreported,
	}
	if err := s.PutAuthFailure(t.Context(), rec); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
	return rec
}

func kindsOf(l *eventLog) []account.EventKind {
	var kinds []account.EventKind
	for _, ev := range l.all() {
		kinds = append(kinds, ev.Kind)
	}
	return kinds
}

func TestReenableMethod(t *testing.T) {
	t.Parallel()
	// A passkey-signed session is seeded with a direct CreateSession whose
	// AuthMethod is MethodPasskey, not through a passkey sign-in.
	t.Run("passkey_session", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); err != nil {
			t.Fatalf("ReenableMethod from a passkey session = %v, want nil", err)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("the untrusted lock survived ReenableMethod")
		}
		re := eventsOf(p.events, account.EventMethodReenabled)
		want := account.EventActor{SessionID: pr.SessionID, UserID: u.ID}
		if !slices.Equal(kindsOf(p.events), []account.EventKind{account.EventMethodReenabled}) ||
			re[0].UserID != u.ID || re[0].Method != access.MethodPassword || re[0].Trusted || re[0].Actor != want {
			t.Errorf("events = %+v, want one untrusted EventMethodReenabled for alice by session %s", p.events.all(), pr.SessionID)
		}
		if _, err := p.login(t.Context(), clientAt(1), "alice", goodPassword); err != nil {
			t.Errorf("untrusted sign-in after the re-enable = %v, want a sign-in", err)
		}
	})
	t.Run("password_session_stepped_up_with_passkey", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		now := time.Now()
		pr, _ := p.principalOf(t, &access.Session{
			ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPasskey,
			CreatedAt: now.Add(-2 * time.Hour), LastActivity: now, AuthTime: now,
		})
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); err != nil {
			t.Fatalf("ReenableMethod from a session stepped up with a passkey = %v, want nil", err)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("the lock survived ReenableMethod")
		}
	})
	t.Run("password_session_refused", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		lock := seedLock(t, p.mem, p.svc, "alice", false, false)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword)
		if !errors.Is(err, access.ErrRecentAuthRequired) || failreason.Of(err) != failreason.ReenableNeedsOtherMethod {
			t.Errorf("ReenableMethod(password) from a password session = %v, reason %q; want ErrRecentAuthRequired, reason %q",
				err, failreason.Of(err), failreason.ReenableNeedsOtherMethod)
		}
		if err != nil && err.Error() != access.ErrRecentAuthRequired.Error() {
			t.Errorf("refusal text = %q, want the sentinel's %q", err, access.ErrRecentAuthRequired)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec != lock {
			t.Errorf("record after the refusal = %+v, want the lock unchanged", rec)
		}
		if got := p.events.all(); len(got) != 0 {
			t.Errorf("events = %v, want none", got)
		}
	})
	t.Run("stale_session_no_reason", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		now := time.Now()
		pr, _ := p.principalOf(t, &access.Session{
			ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPasskey,
			CreatedAt: now.Add(-2 * time.Hour), LastActivity: now, AuthTime: now.Add(-time.Hour),
		})
		err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword)
		if !errors.Is(err, access.ErrRecentAuthRequired) || failreason.Of(err) != "" {
			t.Errorf("ReenableMethod from a session signed in an hour ago = %v, reason %q; want ErrRecentAuthRequired with no reason", err, failreason.Of(err))
		}
	})
	t.Run("not_locked", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); !errors.Is(err, account.ErrMethodNotLocked) {
			t.Errorf("ReenableMethod with no record = %v, want ErrMethodNotLocked", err)
		}
		p.failN(t, clientAt(1), "alice", 5)
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); !errors.Is(err, account.ErrMethodNotLocked) {
			t.Errorf("ReenableMethod with an unlocked count = %v, want ErrMethodNotLocked", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 5 || rec.Locked {
			t.Errorf("record after ErrMethodNotLocked = %+v, want count 5 kept", rec)
		}
	})
	t.Run("both_contexts", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		seedLock(t, p.mem, p.svc, "alice", true, false)
		before := len(p.events.all())
		pr, _ := p.signedInVia(t, u, access.MethodOIDC)
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); err != nil {
			t.Fatalf("ReenableMethod = %v, want nil", err)
		}
		var contexts []bool
		for _, ev := range p.events.all()[before:] {
			if ev.Kind != account.EventMethodReenabled {
				t.Errorf("event %+v, want only EventMethodReenabled for reported locks", ev)
			}
			contexts = append(contexts, ev.Trusted)
		}
		if !slices.Equal(contexts, []bool{false, true}) {
			t.Errorf("EventMethodReenabled contexts = %v, want untrusted then trusted", contexts)
		}
		// A new Service over the same store, the old one never shut down:
		// the clear is in the store, not in memory.
		next, err := account.New(t.Context(), p.cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = next.Shutdown(context.Background()) })
		in := account.Credentials{Username: "alice", Password: access.NewSecret(goodPassword)}
		if _, err := next.PasswordLogin(t.Context(), clientAt(1), in); err != nil {
			t.Errorf("untrusted sign-in through a new Service = %v, want a sign-in", err)
		}
		if _, err := p.login(t.Context(), trusted, "alice", goodPassword); err != nil {
			t.Errorf("trusted sign-in after the re-enable = %v, want a sign-in", err)
		}
	})
	t.Run("clear_fails", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		lock := seedLock(t, p.mem, p.svc, "alice", false, true)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		fs.failWrite(1)
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("ReenableMethod over a failing Update = %v, want ErrAuthBackend", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec != lock {
			t.Errorf("record after the failed clear = %+v, want the lock kept", rec)
		}
		if got := p.events.all(); len(got) != 0 {
			t.Errorf("events after the failed clear = %v, want none", got)
		}
	})
	t.Run("gates", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		lock := seedLock(t, p.mem, p.svc, "alice", false, false)
		f := p.fixture
		for name, tc := range map[string]struct {
			p    access.Principal
			want error
		}{
			"stale":    {f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour)), access.ErrRecentAuthRequired},
			"key":      {f.keyPrincipal(t, u, "read"), account.ErrSessionRequired},
			"recovery": {f.sessionPrincipal(t, u, access.SessionRecovery, time.Now()), account.ErrSessionRequired},
			"bypass":   {f.bypassPrincipal(t), account.ErrSessionRequired},
		} {
			if err := p.svc.ReenableMethod(t.Context(), tc.p, access.MethodPassword); !errors.Is(err, tc.want) {
				t.Errorf("ReenableMethod(%s) = %v, want %v", name, err, tc.want)
			}
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec != lock {
			t.Errorf("record after the refusals = %+v, want the lock unchanged", rec)
		}
	})
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		if err := p.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		fs.resetRecord()
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("ReenableMethod after Shutdown = %v, want ErrServiceClosed", err)
		}
		if calls := fs.recorded(); len(calls) != 0 {
			t.Errorf("ReenableMethod after Shutdown made store calls %v, want none", calls)
		}
	})
}

func TestReenableBeforeSweepReportsLock(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{edit: noTick})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	p.failN(t, clientAt(1), "alice", account.FailureCap)
	rec, _ := record(t, p.mem, p.svc, "alice", false)
	if !rec.Locked || !rec.Unreported {
		t.Fatalf("record after %d failures = %+v, want an unreported lock", account.FailureCap, rec)
	}
	pr, _ := p.signedInVia(t, u, access.MethodPasskey)
	if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); err != nil {
		t.Fatalf("ReenableMethod = %v, want nil", err)
	}
	if got := kindsOf(p.events); !slices.Equal(got, []account.EventKind{account.EventMethodLocked, account.EventMethodReenabled}) {
		t.Fatalf("events = %v, want EventMethodLocked then EventMethodReenabled", got)
	}
	locked := eventsOf(p.events, account.EventMethodLocked)[0]
	if locked.UserID != u.ID || locked.Trusted || locked.Method != access.MethodPassword || !locked.At.Equal(rec.LockedAt) || locked.Actor != (account.EventActor{}) {
		t.Errorf("EventMethodLocked = %+v, want alice's untrusted lock at %v with no actor", locked, rec.LockedAt)
	}
	sweepFailures(t, p.svc)
	if n := len(p.events.all()); n != 2 {
		t.Errorf("the next sweep emitted %d more events, want none", n-2)
	}
}

func TestReenableRacingCount(t *testing.T) {
	t.Parallel()
	t.Run("count_after_clear", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		entered, release := fs.holdUpdate()
		defer release()
		done := make(chan error, 1)
		go func() {
			_, err := p.login(t.Context(), clientAt(1), "alice", wrongPassword)
			done <- err
		}()
		<-entered
		if err := p.svc.ReenableMethod(t.Context(), pr, access.MethodPassword); err != nil {
			t.Fatalf("ReenableMethod while a count is held = %v, want nil", err)
		}
		release()
		if err := <-done; !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("held wrong sign-in = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 || rec.Locked {
			t.Errorf("record after a count that landed after the clear = %+v, want count 1 and no lock", rec)
		}
	})
	t.Run("count_before_clear", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		hk.arm(func(ctx context.Context) {
			hk.disarm()
			if err := p.svc.ReenableMethod(ctx, pr, access.MethodPassword); err != nil {
				t.Errorf("ReenableMethod between a count and its verify = %v, want nil", err)
			}
		})
		if _, err := p.login(t.Context(), clientAt(1), "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("wrong sign-in = %v, want ErrInvalidCredentials", err)
		}
		if rec, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Errorf("record = %+v, want the count that landed before the clear deleted with it", rec)
		}
		p.failN(t, clientAt(1), "alice", 1)
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 || rec.Locked {
			t.Errorf("record after the next wrong attempt = %+v, want count 1 and no lock", rec)
		}
	})
}
