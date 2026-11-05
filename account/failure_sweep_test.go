package account_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

func sweepFailures(t *testing.T, svc *account.Service) {
	t.Helper()
	if err := account.SweepFailures(t.Context(), svc); err != nil {
		t.Fatalf("SweepFailures: %v", err)
	}
}

func TestLockReportedBySweep(t *testing.T) {
	t.Parallel()
	t.Run("reported_once", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap)
		p.failN(t, clientAt(2), "ghost", account.FailureCap)
		if got := p.events.all(); len(got) != 0 {
			t.Fatalf("events before any sweep = %v, want none: OnEvent ran on the request path", got)
		}
		rec, _ := record(t, p.mem, p.svc, "alice", false)
		sweepFailures(t, p.svc)
		locked := eventsOf(p.events, account.EventMethodLocked)
		if len(locked) != 1 {
			t.Fatalf("EventMethodLocked after the sweep = %v, want one, for alice only", locked)
		}
		ev := locked[0]
		if ev.UserID != u.ID || ev.Trusted || ev.Method != access.MethodPassword || !ev.At.Equal(rec.LockedAt) || ev.Actor != (account.EventActor{}) {
			t.Errorf("EventMethodLocked = %+v, want alice's untrusted password lock at %v with no actor", ev, rec.LockedAt)
		}
		sweepFailures(t, p.svc)
		events := &eventLog{}
		cfg := p.cfg
		cfg.OnEvent = events.record
		next, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = next.Shutdown(context.Background()) })
		if n := len(eventsOf(p.events, account.EventMethodLocked)) + len(events.all()); n != 1 {
			t.Errorf("events after a second sweep and a new Service's first = %d, want only the first report", n)
		}
	})
	t.Run("abandoned_service", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap)
		events := &eventLog{}
		cfg := p.cfg
		cfg.OnEvent = events.record
		next, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = next.Shutdown(context.Background()) })
		locked := eventsOf(events, account.EventMethodLocked)
		if len(locked) != 1 || locked[0].UserID != u.ID {
			t.Errorf("the next Service's first sweep reported %v, want alice's lock once", locked)
		}
		if got := p.events.all(); len(got) != 0 {
			t.Errorf("the abandoned Service emitted %v, want nothing", got)
		}
	})
	t.Run("right_hundredth", func(t *testing.T) {
		t.Parallel()
		for _, v := range storeVariants {
			for _, swept := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s_swept_%t", v.name, swept), func(t *testing.T) {
					t.Parallel()
					rightHundredth(t, v.store, swept)
				})
			}
		}
	})
}

func rightHundredth(t *testing.T, newStore func() *faultStore, swept bool) {
	var hk armed
	o := pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}}
	if newStore != nil {
		o.store = newStore()
	}
	p := newPW(t, o)
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	p.failN(t, clientAt(1), "alice", account.FailureCap-1)
	if swept {
		hk.arm(func(ctx context.Context) {
			hk.disarm()
			if err := account.SweepFailures(ctx, p.svc); err != nil {
				t.Errorf("SweepFailures: %v", err)
			}
		})
	}
	in, err := p.login(t.Context(), clientAt(1), "alice", goodPassword)
	if err != nil {
		t.Fatalf("right 100th password (swept %t) = %v, want a sign-in", swept, err)
	}
	var kinds []account.EventKind
	for _, ev := range p.events.all() {
		kinds = append(kinds, ev.Kind)
	}
	want := []account.EventKind{account.EventSignedIn}
	if swept {
		want = []account.EventKind{account.EventMethodLocked, account.EventMethodReenabled, account.EventSignedIn}
	}
	if !slices.Equal(kinds, want) {
		t.Errorf("events (sweep between count and success %t) = %v, want %v", swept, kinds, want)
	}
	if re := eventsOf(p.events, account.EventMethodReenabled); swept && len(re) == 1 {
		if re[0].UserID != u.ID || re[0].Trusted || re[0].Actor.SessionID != in.Session.ID {
			t.Errorf("EventMethodReenabled = %+v, want alice's untrusted password with the new session as actor", re[0])
		}
	}
	if _, found := record(t, p.mem, p.svc, "alice", false); found {
		t.Errorf("the lock the right 100th attempt set survived its success (swept %t)", swept)
	}
}

func TestFailureNames(t *testing.T) {
	t.Parallel()
	t.Run("hmac_of_the_name", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		p.failN(t, localClient, "alice", 1)
		mac := hmac.New(sha256.New, testFailureKey)
		mac.Write([]byte("alice"))
		want := hex.EncodeToString(mac.Sum(nil))
		if rec, found, err := p.mem.AuthFailure(t.Context(), account.FailureRef{Name: want, Method: access.MethodPassword}); err != nil || !found || rec.Count != 1 {
			t.Errorf("record under hex(HMAC-SHA256(FailureKey, name)) = %+v, %t, %v; want count 1", rec, found, err)
		}
		for _, c := range fs.recorded() {
			if c.name != "UserByUsername" && strings.Contains(c.arg, "alice") {
				t.Errorf("%s carried the typed name %q", c.name, c.arg)
			}
		}
	})
	t.Run("another_key_starts_at_zero", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		p.failN(t, localClient, "alice", 3)
		cfg := p.cfg
		cfg.FailureKey = []byte("another-failure-key-of-32-bytes!")
		other, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = other.Shutdown(context.Background()) })
		if rec, found := record(t, p.mem, other, "alice", false); found {
			t.Errorf("a Service under another key reads %+v, want no record", rec)
		}
		if _, err := other.PasswordLogin(t.Context(), localClient, account.Credentials{Username: "alice", Password: access.NewSecret(wrongPassword)}); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("PasswordLogin: %v", err)
		}
		if rec, _ := record(t, p.mem, other, "alice", false); rec.Count != 1 {
			t.Errorf("the other key's count = %d, want 1", rec.Count)
		}
	})
	t.Run("creation_deletes", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		p.failN(t, localClient, "bob", 3)
		if _, err := p.svc.CreateUser(t.Context(), account.OutOfBand("socket"), account.NewUser{Username: "bob"}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if rec, found := record(t, p.mem, p.svc, "bob", false); found {
			t.Errorf("bob's record after his creation = %+v, want none", rec)
		}
	})
	t.Run("sweep_prunes", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		carol := passwordUser(t, p.mem, nil, "carol", "")
		passwordUser(t, p.mem, nil, "dave", "")
		for _, name := range []string{"ghost", "carol", "dave"} {
			p.failN(t, localClient, name, 1)
		}
		if err := p.mem.DeleteUser(t.Context(), carol.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		sweepFailures(t, p.svc)
		for name, want := range map[string]bool{"ghost": false, "carol": false, "dave": true} {
			if _, found := record(t, p.mem, p.svc, name, false); found != want {
				t.Errorf("%s's record after the sweep: found %t, want %t", name, found, want)
			}
		}
	})
}

func TestSweepVersusCreate(t *testing.T) {
	t.Parallel()
	for _, order := range []string{"sweep_first", "create_first"} {
		t.Run(order, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var hk armed
				p := newPW(t, pwOptions{edit: withInterval, hooks: account.Hooks{FailureSweep: hk.hook}})
				p.failN(t, localClient, "xavier", 1)
				entered, release := make(chan struct{}), make(chan struct{})
				if order == "create_first" {
					hk.arm(func(context.Context) {
						hk.disarm()
						close(entered)
						<-release
					})
				}
				tick()
				if order == "create_first" {
					<-entered
				}
				if _, err := p.svc.CreateUser(t.Context(), account.OutOfBand("socket"), account.NewUser{Username: "xavier"}); err != nil {
					t.Fatalf("CreateUser: %v", err)
				}
				p.failN(t, localClient, "xavier", 1)
				if order == "create_first" {
					close(release)
					synctest.Wait()
				}
				if rec, _ := record(t, p.mem, p.svc, "xavier", false); rec.Count != 1 {
					t.Errorf("xavier's count after %s = %d, want 1", order, rec.Count)
				}
			})
		})
	}
}

func TestWokenSweepFailure(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	var hk armed
	p := newPW(t, pwOptions{edit: noTick, store: fs, hooks: account.Hooks{FailureSweep: hk.hook}})
	loggedIn := make(chan struct{})
	hk.arm(func(ctx context.Context) {
		hk.disarm()
		select {
		case <-loggedIn:
			fs.failAfterApply()
		case <-ctx.Done():
		}
	})
	account.LeaveAllowance(p.svc, 1)
	_, err := p.login(t.Context(), clientAt(0), "flood", wrongPassword)
	close(loggedIn)
	if !errors.Is(err, account.ErrInvalidCredentials) {
		t.Fatalf("attempt taking the last slot = %v, want ErrInvalidCredentials", err)
	}
	const failed = "account: failure-record sweep failed; once the untrusted allowance is spent, " +
		"untrusted password sign-in is refused until a sweep commits; retrying next tick"
	deadline := time.Now().Add(time.Minute)
	for logged(p.logs, slog.LevelError, failed) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the woken failure leg logged no ERROR within a minute")
		}
		time.Sleep(time.Millisecond)
	}
	// Shutdown waits for the sweep goroutine, so every line the woken leg
	// logs after its ERROR is in the recorder before the counts below.
	if err := p.svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	for _, want := range []struct {
		msg   string
		level slog.Level
		n     int
	}{
		{"account: untrusted allowance spent; failure-record sweep started", slog.LevelInfo, 1},
		{failed, slog.LevelError, 1},
		{"account: failure-record sweep finished; untrusted allowance refilled", slog.LevelInfo, 0},
	} {
		if n := logged(p.logs, want.level, want.msg); n != want.n {
			t.Errorf("%v %q logged %d times, want %d", want.level, want.msg, n, want.n)
		}
	}
	if got := account.AllowanceUsed(p.svc); got != account.MaxUntrustedCounts {
		t.Errorf("slots taken after the failed prune = %d, want %d: the allowance stays spent", got, account.MaxUntrustedCounts)
	}
}
