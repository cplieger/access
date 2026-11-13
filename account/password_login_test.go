package account_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/ratelimit"
)

const rehashSkipped = "account: password rehash skipped; the next sign-in retries"

func isHexName(s string) bool {
	_, err := hex.DecodeString(s)
	return len(s) == 64 && err == nil
}

// oneShare is a budget that admits one derivation at fastParams.
func oneShare(t *testing.T) *access.HashBudget {
	t.Helper()
	b, err := access.NewHashBudget(access.HashCost(fastParams))
	if err != nil {
		t.Fatalf("NewHashBudget: %v", err)
	}
	return b
}

// doubleCostHash is pw hashed at twice fastParams' memory, which the
// fixture's hasher verifies and then rehashes.
func doubleCostHash(t *testing.T, pw string) access.Hash {
	t.Helper()
	params := fastParams
	params.Memory *= 2
	h, err := access.NewHasher(access.HasherConfig{Params: params})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	hash, err := h.Hash(t.Context(), pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return hash
}

func debugs(rec *capture.Recorder, msg string) int {
	n := 0
	for _, r := range rec.Records("") {
		if r.Level == slog.LevelDebug && r.Message == msg {
			n++
		}
	}
	return n
}

func storedUser(t *testing.T, s account.Store, id int64) *access.User {
	t.Helper()
	u, found, err := s.UserByID(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("UserByID(%d) = %v, %v", id, found, err)
	}
	return u
}

func sessionsOf(t *testing.T, s account.Store, userID int64) []access.Session {
	t.Helper()
	ss, err := s.SessionsByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("SessionsByUserID: %v", err)
	}
	return ss
}

func TestEqualWorkArms(t *testing.T) {
	t.Parallel()
	locked := func(t *testing.T, p *pwFixture) {
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		lock := account.FailureCount{
			Name: account.FailureName(p.svc, "alice"), Method: access.MethodPassword,
			Count: account.FailureCap, Locked: true, LockedAt: time.Now(),
		}
		if err := p.mem.PutAuthFailure(t.Context(), lock); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
	arms := []struct {
		seed     func(*testing.T, *pwFixture)
		name     string
		password string
		reason   string // the audit reason; the client sees only the sentinel
	}{
		{name: "unknown", password: goodPassword},
		{name: "wrong_password", password: wrongPassword, seed: func(t *testing.T, p *pwFixture) {
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		}},
		{name: "no_password", password: goodPassword, seed: func(t *testing.T, p *pwFixture) {
			passwordUser(t, p.mem, nil, "alice", "")
		}},
		{name: "disabled", password: goodPassword, seed: func(t *testing.T, p *pwFixture) {
			u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			u.Enabled = false
			if err := p.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{name: "locked", password: goodPassword, seed: locked, reason: failreason.MethodLocked},
	}
	shapes := map[string][]string{}
	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			fs := newFaultStore()
			p := newPW(t, pwOptions{store: fs})
			username := "alice"
			if arm.seed == nil {
				username = "nobody"
			} else {
				arm.seed(t, p)
			}
			fs.resetRecord()
			count := fmt.Sprintf("@%d", fs.updates.Load()+1)
			_, err := p.login(t.Context(), localClient, username, arm.password)
			if !errors.Is(err, account.ErrInvalidCredentials) {
				t.Fatalf("PasswordLogin = %v, want ErrInvalidCredentials", err)
			}
			if got := failreason.Of(err); got != arm.reason || err.Error() != account.ErrInvalidCredentials.Error() {
				t.Errorf("PasswordLogin = %q with reason %q, want the sentinel's text with reason %q", err, got, arm.reason)
			}
			calls := fs.recorded()
			var shape []string
			for _, c := range calls {
				shape = append(shape, fmt.Sprintf("%s@%d", c.name, c.update))
			}
			want := []string{"Update" + count, "UserByUsername" + count, "AuthFailure" + count, "PutAuthFailure" + count}
			if !slices.Equal(shape, want) {
				t.Fatalf("store calls = %v, want %v and nothing after", shape, want)
			}
			if name := calls[2].arg; !isHexName(name) || calls[3].arg != name {
				t.Errorf("record names = %q read, %q written; want one 64-hex name", name, calls[3].arg)
			}
			if got := p.events.all(); len(got) != 0 {
				t.Errorf("events = %v, want none", got)
			}
			if got := len(p.counted.verified()); got != 1 {
				t.Errorf("derivations = %d, want 1", got)
			}
			shapes[arm.name] = shape
		})
	}
	for _, arm := range arms[1:] {
		if !slices.Equal(shapes[arm.name], shapes["unknown"]) {
			t.Errorf("%s's calls %v differ from the unknown name's %v", arm.name, shapes[arm.name], shapes["unknown"])
		}
	}
}

func TestCapPerTrustContext(t *testing.T) {
	t.Parallel()
	t.Run("untrusted", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		device := p.deviceCookie(t, localClient, "alice", goodPassword)
		before := len(p.counted.verified())
		p.failN(t, clientAt(1), "alice", account.FailureCap+1)
		compared := p.counted.verified()[before:]
		zero := 0
		for _, h := range compared {
			if h.IsZero() {
				zero++
			}
		}
		if len(compared) != account.FailureCap+1 || zero != 1 {
			t.Errorf("of %d compared attempts %d saw the zero hash, want %d and 1", len(compared), zero, account.FailureCap+1)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); !rec.Locked || rec.Count != account.FailureCap+1 {
			t.Errorf("untrusted record = %+v, want locked at count %d", rec, account.FailureCap+1)
		}
		if _, err := p.login(t.Context(), clientAt(2), "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("untrusted right password while locked = %v, want ErrInvalidCredentials", err)
		}
		trusted := localClient
		trusted.Device = device
		if _, err := p.login(t.Context(), trusted, "alice", goodPassword); err != nil {
			t.Errorf("trusted device while the untrusted context is locked = %v, want a sign-in", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); !rec.Locked {
			t.Error("a trusted sign-in cleared the untrusted lock")
		}
	})
	for _, v := range storeVariants {
		t.Run("own_lock_reset_"+v.name, func(t *testing.T) {
			t.Parallel()
			o := pwOptions{}
			if v.store != nil {
				o.store = v.store()
			}
			p := newPW(t, o)
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			p.failN(t, clientAt(1), "alice", account.FailureCap-1)
			if _, err := p.login(t.Context(), clientAt(2), "alice", goodPassword); err != nil {
				t.Fatalf("right password on the attempt that reaches the cap = %v, want a sign-in", err)
			}
			if rec, found := record(t, p.mem, p.svc, "alice", false); found {
				t.Errorf("untrusted record = %+v after the success, want the lock it set cleared", rec)
			}
			if _, err := p.login(t.Context(), clientAt(3), "alice", goodPassword); err != nil {
				t.Errorf("next untrusted sign-in = %v, want a sign-in", err)
			}
		})
	}
	t.Run("relock_between_count_and_reset", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{store: storeVariants[1].store(), hooks: account.Hooks{AfterVerify: hk.hook}})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		p.failN(t, clientAt(1), "alice", account.FailureCap-1)
		var relock account.FailureCount
		hk.arm(func(ctx context.Context) {
			hk.disarm()
			if err := p.svc.ReenableMethod(ctx, pr, access.MethodPassword); err != nil {
				t.Errorf("ReenableMethod between the count and the success = %v", err)
			}
			p.failN(t, clientAt(2), "alice", account.FailureCap)
			relock, _ = record(t, p.mem, p.svc, "alice", false)
		})
		if _, err := p.login(t.Context(), clientAt(3), "alice", goodPassword); err != nil {
			t.Fatalf("right 100th password = %v, want a sign-in", err)
		}
		if !relock.Locked {
			t.Fatalf("record after the re-enable and %d more failures = %+v, want a new lock", account.FailureCap, relock)
		}
		rec, found := record(t, p.mem, p.svc, "alice", false)
		if !found || !rec.Locked || rec.Count != 0 || !rec.LockedAt.Equal(relock.LockedAt) {
			t.Errorf("record after the success = %+v (found %t), want the new lock at %v kept at count 0", rec, found, relock.LockedAt)
		}
	})
	t.Run("relock_both_contexts_between_count_and_reset", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{store: storeVariants[1].store(), hooks: account.Hooks{AfterVerify: hk.hook}})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap-1)
		var relocked [2]account.FailureCount
		hk.arm(func(ctx context.Context) {
			hk.disarm()
			if err := p.svc.ReenableMethod(ctx, pr, access.MethodPassword); err != nil {
				t.Errorf("ReenableMethod between the count and the success = %v", err)
			}
			p.failN(t, clientAt(2), "alice", account.FailureCap)
			p.failN(t, trusted, "alice", account.FailureCap)
			relocked[0], _ = record(t, p.mem, p.svc, "alice", false)
			relocked[1], _ = record(t, p.mem, p.svc, "alice", true)
		})
		if _, err := p.login(t.Context(), clientAt(3), "alice", goodPassword); err != nil {
			t.Fatalf("right password = %v, want a sign-in", err)
		}
		for i, isTrusted := range []bool{false, true} {
			if !relocked[i].Locked {
				t.Fatalf("trusted=%t record after the re-enable and %d more failures = %+v, want a new lock", isTrusted, account.FailureCap, relocked[i])
			}
			rec, found := record(t, p.mem, p.svc, "alice", isTrusted)
			if !found || !rec.Locked || rec.Count != 0 || !rec.LockedAt.Equal(relocked[i].LockedAt) {
				t.Errorf("trusted=%t record after the success = %+v (found %t), want the new lock at %v kept at count 0", isTrusted, rec, found, relocked[i].LockedAt)
			}
		}
	})
	t.Run("trusted_success_resets_its_record", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		p.failN(t, trusted, "alice", account.FailureCap-1)
		if _, err := p.login(t.Context(), trusted, "alice", goodPassword); err != nil {
			t.Fatalf("trusted right password = %v, want a sign-in", err)
		}
		if rec, found := record(t, p.mem, p.svc, "alice", true); found {
			t.Errorf("trusted record = %+v after the trusted success, want it gone", rec)
		}
	})
	t.Run("other_context_locked_in_the_same_millisecond", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			p := newPW(t, pwOptions{})
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			trusted := localClient
			trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
			p.failN(t, trusted, "alice", account.FailureCap)
			p.failN(t, clientAt(1), "alice", account.FailureCap-1)
			if _, err := p.login(t.Context(), clientAt(2), "alice", goodPassword); err != nil {
				t.Fatalf("right password on the attempt that reaches the untrusted cap = %v, want a sign-in", err)
			}
			if !time.Now().Equal(start) {
				t.Fatalf("the bubble's clock moved from %v to %v, so the two locks are not in one millisecond", start, time.Now())
			}
			if rec, found := record(t, p.mem, p.svc, "alice", false); found {
				t.Errorf("untrusted record = %+v after the success, want the lock it set cleared", rec)
			}
			rec, found := record(t, p.mem, p.svc, "alice", true)
			if !found || !rec.Locked || rec.Count != 0 || !rec.LockedAt.Equal(start.Truncate(time.Millisecond)) {
				t.Errorf("trusted record after the untrusted success = %+v (found %t), want its lock at %v kept at count 0", rec, found, start.Truncate(time.Millisecond))
			}
		})
	})
	t.Run("trusted", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		p.failN(t, trusted, "alice", account.FailureCap)
		if rec, _ := record(t, p.mem, p.svc, "alice", true); !rec.Locked || rec.Count != account.FailureCap {
			t.Errorf("trusted record = %+v, want locked at count %d", rec, account.FailureCap)
		}
		if _, found := record(t, p.mem, p.svc, "alice", false); found {
			t.Error("trusted failures wrote an untrusted record")
		}
		if _, err := p.login(t.Context(), trusted, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("trusted right password while locked = %v, want ErrInvalidCredentials", err)
		}
		if _, err := p.login(t.Context(), clientAt(1), "alice", goodPassword); err != nil {
			t.Errorf("untrusted right password while only the trusted context is locked = %v, want a sign-in", err)
		}
	})
}

// storeVariants are the stores a test of the own-lock reset runs on: the
// MemStore, keeping times to the nanosecond, and a store keeping LockedAt
// only to the millisecond, as StoreContract allows.
var storeVariants = []struct {
	store func() *faultStore // nil: the MemStore
	name  string
}{
	{name: "memstore"},
	{name: "millisecond_store", store: func() *faultStore {
		fs := newFaultStore()
		fs.millisecondTimes()
		return fs
	}},
}

func TestCorrectHundredth(t *testing.T) {
	t.Parallel()
	for _, v := range storeVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			o := pwOptions{}
			if v.store != nil {
				o.store = v.store()
			}
			p := newPW(t, o)
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			p.failN(t, clientAt(1), "alice", account.FailureCap-1)
			if _, err := p.login(t.Context(), clientAt(1), "alice", goodPassword); err != nil {
				t.Fatalf("right 100th password = %v, want a sign-in", err)
			}
			for _, trusted := range []bool{false, true} {
				if rec, found := record(t, p.mem, p.svc, "alice", trusted); found {
					t.Errorf("record (trusted %t) = %+v after the success, want none", trusted, rec)
				}
			}
			if got := len(eventsOf(p.events, account.EventMethodLocked)) + len(eventsOf(p.events, account.EventMethodReenabled)); got != 0 {
				t.Errorf("lock events = %d, want none", got)
			}
			if _, err := p.login(t.Context(), clientAt(2), "alice", goodPassword); err != nil {
				t.Errorf("next untrusted sign-in = %v, want a sign-in: the success left its own lock", err)
			}
		})
	}
}

func TestBusyAndCancelledWriteNothing(t *testing.T) {
	t.Parallel()
	hold := func(t *testing.T, p *pwFixture) func() {
		permit, err := p.hasher.Reserve(t.Context())
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		return permit.Release
	}
	t.Run("one_ip_one_name", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{budget: oneShare(t), wait: time.Millisecond, limiter: func(c *ratelimit.Config) {
			d := ratelimit.DefaultConfig()
			c.IP, c.Account, c.Device = d.IP, d.Account, d.Device
		}})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		release := hold(t, p)
		for i := range ratelimit.DefaultConfig().Account.Limit + 1 {
			if _, err := p.login(t.Context(), localClient, "alice", wrongPassword); !errors.Is(err, access.ErrHashBusy) {
				t.Fatalf("attempt %d with every permit held = %v, want access.ErrHashBusy", i, err)
			}
		}
		release()
		if n, d := p.counted.reserved.Load(), len(p.counted.verified()); n != 0 || d != 0 {
			t.Errorf("busy attempts took %d permits and derived %d times, want none", n, d)
		}
		for _, trusted := range []bool{false, true} {
			if _, found := record(t, p.mem, p.svc, "alice", trusted); found {
				t.Errorf("busy attempts wrote a record (trusted %t)", trusted)
			}
		}
		if _, err := p.login(t.Context(), localClient, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("first attempt with a free permit = %v, want ErrInvalidCredentials: the limiter kept busy attempts", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
			t.Errorf("record count after one counted attempt = %d, want 1", rec.Count)
		}
	})
	t.Run("allowance_stays_full", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{budget: oneShare(t), wait: time.Millisecond})
		release := hold(t, p)
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16)
		errs := make(chan error, 2*account.MaxUntrustedCounts)
		for i := range 2 * account.MaxUntrustedCounts {
			ctx := t.Context()
			if i%2 == 1 {
				ctx = cancelled
			}
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				if _, err := p.login(ctx, clientAt(i), fmt.Sprintf("u%d", i), wrongPassword); !errors.Is(err, access.ErrHashBusy) {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("busy or cancelled attempt = %v, want access.ErrHashBusy", err)
		}
		if got := account.AllowanceUsed(p.svc); got != 0 {
			t.Errorf("allowance slots taken by busy and cancelled attempts = %d, want 0", got)
		}
		release()
		if _, err := p.login(t.Context(), clientAt(0), "next", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("untrusted attempt with a free permit = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "next", false); rec.Count != 1 || account.AllowanceUsed(p.svc) != 1 {
			t.Errorf("after one counted attempt: count %d, slots %d; want 1 and 1", rec.Count, account.AllowanceUsed(p.svc))
		}
	})
}

func TestCancelledAfterCountStillCounts(t *testing.T) {
	t.Parallel()
	var hk armed
	p := newPW(t, pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}, limiter: ipLimit(1)})
	passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	ctx, cancel := context.WithCancel(t.Context())
	hk.arm(func(context.Context) { cancel() })
	if _, err := p.login(ctx, localClient, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Fatalf("attempt cancelled after its count = %v, want ErrInvalidCredentials", err)
	}
	hk.disarm()
	if got := p.counted.verified(); len(got) != 1 || got[0].IsZero() {
		t.Errorf("compared hashes = %d (zero %d), want the user's hash once", len(got), p.counted.zeroCompared())
	}
	if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
		t.Errorf("record count = %d, want 1", rec.Count)
	}
	_, err := p.login(t.Context(), localClient, "alice", wrongPassword)
	if refused, ok := errors.AsType[*ratelimit.RefusedError](err); !ok || refused.Dimension != "ip" {
		t.Errorf("next attempt past the IP limit = %v, want *ratelimit.RefusedError{ip}: the cancelled attempt kept its reservation", err)
	}
}

func TestKillBetweenCountAndVerify(t *testing.T) {
	t.Parallel()
	var hk armed
	p := newPW(t, pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}})
	passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	fresh := func() *account.Service {
		svc, err := account.New(t.Context(), p.cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
		return svc
	}
	p.failN(t, clientAt(1), "alice", account.FailureCap-1)
	if rec, _ := record(t, p.mem, fresh(), "alice", false); rec.Count != account.FailureCap-1 || rec.Locked {
		t.Fatalf("a new Service reads %+v, want count %d unlocked", rec, account.FailureCap-1)
	}
	// The 100th attempt stops after its count and before its comparison
	// returns, standing in for a kill; the old Service is never shut down.
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	hk.arm(func(context.Context) {
		hk.disarm()
		close(entered)
		<-release
	})
	go func() {
		defer close(done)
		_, _ = p.login(context.Background(), clientAt(2), "alice", wrongPassword)
	}()
	t.Cleanup(func() {
		close(release)
		<-done
	})
	<-entered
	next := fresh()
	if rec, _ := record(t, p.mem, next, "alice", false); rec.Count != account.FailureCap || !rec.Locked {
		t.Errorf("a new Service reads %+v, want the held attempt counted: count %d and locked", rec, account.FailureCap)
	}
	if _, err := next.PasswordLogin(t.Context(), clientAt(3), account.Credentials{Username: "alice", Password: access.NewSecret(goodPassword)}); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("right password on the new Service = %v, want ErrInvalidCredentials under the lock", err)
	}
}

func TestCountUpdateFails(t *testing.T) {
	t.Parallel()
	for _, found := range []bool{false, true} {
		t.Run(fmt.Sprintf("user_found_%t", found), func(t *testing.T) {
			t.Parallel()
			fs := newFaultStore()
			p := newPW(t, pwOptions{store: fs, budget: oneShare(t), wait: time.Millisecond, limiter: ipLimit(1)})
			name := "nobody"
			if found {
				name = "alice"
				passwordUser(t, p.mem, p.hasher, name, goodPassword)
			}
			seeded := account.FailureCount{Name: account.FailureName(p.svc, name), Method: access.MethodPassword, Count: 5}
			if err := p.mem.PutAuthFailure(t.Context(), seeded); err != nil {
				t.Fatalf("PutAuthFailure: %v", err)
			}
			fs.failWrite(1)
			if _, err := p.login(t.Context(), localClient, name, wrongPassword); !errors.Is(err, access.ErrAuthBackend) {
				t.Fatalf("attempt whose count Update fails = %v, want access.ErrAuthBackend", err)
			}
			fs.failWrite(0)
			if d := len(p.counted.verified()); d != 0 {
				t.Errorf("derivations = %d, want none", d)
			}
			if rec, _ := record(t, p.mem, p.svc, name, false); rec.Count != 5 {
				t.Errorf("record count = %d, want 5, unchanged", rec.Count)
			}
			permit, err := p.hasher.Reserve(t.Context())
			if err != nil {
				t.Fatalf("Reserve after the failed attempt = %v: its permit was not released", err)
			}
			permit.Release()
			_, err = p.login(t.Context(), localClient, name, wrongPassword)
			if _, ok := errors.AsType[*ratelimit.RefusedError](err); !ok {
				t.Errorf("next attempt past the IP limit = %v, want *ratelimit.RefusedError: the failed attempt kept its reservation", err)
			}
		})
	}
}

func TestSuccessUpdateFails(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	var hk armed
	p := newPW(t, pwOptions{store: fs, hooks: account.Hooks{BeforeVerify: hk.hook}, limiter: ipLimit(1)})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	hk.arm(func(context.Context) { fs.failWrite(1) })
	if _, err := p.login(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, access.ErrAuthBackend) {
		t.Fatalf("sign-in whose success Update fails = %v, want access.ErrAuthBackend", err)
	}
	fs.failWrite(0)
	if ss := sessionsOf(t, p.mem, u.ID); len(ss) != 0 {
		t.Errorf("sessions = %d, want none", len(ss))
	}
	if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
		t.Errorf("record count = %d, want 1: the counted attempt stays counted", rec.Count)
	}
	_, err := p.login(t.Context(), localClient, "alice", goodPassword)
	if _, ok := errors.AsType[*ratelimit.RefusedError](err); !ok {
		t.Errorf("next attempt past the IP limit = %v, want *ratelimit.RefusedError: the failed sign-in kept its reservation", err)
	}
}

func TestCredentialChangeBetweenCountAndSuccess(t *testing.T) {
	t.Parallel()
	var hk armed
	p := newPW(t, pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}})
	u := passwordUser(t, p.mem, nil, "alice", "")
	u.PasswordHash = doubleCostHash(t, goodPassword)
	if err := p.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	const changed = "changed-horse-battery-9"
	changer, _ := p.signedInVia(t, u, access.MethodPasskey)
	hk.arm(func(ctx context.Context) {
		hk.disarm()
		if _, err := p.svc.SetPassword(ctx, localClient, changer, access.NewSecret(goodPassword), access.NewSecret(changed)); err != nil {
			t.Errorf("SetPassword between the count and the success = %v", err)
		}
	})
	if _, err := p.login(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Fatalf("sign-in with the replaced password = %v, want ErrInvalidCredentials", err)
	}
	ss := sessionsOf(t, p.mem, u.ID)
	if len(ss) != 1 || ss[0].ID != changer.SessionID {
		t.Errorf("sessions = %d, want only the changer's: the racing sign-in created none", len(ss))
	}
	if !p.verifies(t, u, changed) {
		t.Error("the stored hash is not the changed one: the racing sign-in wrote its rehash")
	}
}

func TestUserChangeBetweenVerifyAndSuccess(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(ctx context.Context, t *testing.T, p *pwFixture, u *access.User) error{
		"disabled": func(ctx context.Context, t *testing.T, p *pwFixture, u *access.User) error {
			v := storedUser(t, p.mem, u.ID)
			v.Enabled = false
			return p.mem.UpdateUser(ctx, v)
		},
		"deleted": func(ctx context.Context, _ *testing.T, p *pwFixture, u *access.User) error {
			return p.mem.DeleteUser(ctx, u.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var hk armed
			p := newPW(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}})
			u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			hk.arm(func(ctx context.Context) {
				hk.disarm()
				if err := change(ctx, t, p, u); err != nil {
					t.Errorf("%s between the comparison and the success: %v", name, err)
				}
			})
			if _, err := p.login(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("sign-in of a user %s after its comparison = %v, want ErrInvalidCredentials", name, err)
			}
			if ss := sessionsOf(t, p.mem, u.ID); len(ss) != 0 {
				t.Errorf("sessions = %d, want none", len(ss))
			}
		})
	}
}

type ctxMarker struct{}

func TestRehashOnSignIn(t *testing.T) {
	t.Parallel()
	seed := func(t *testing.T, p *pwFixture) (*access.User, access.Hash) {
		u := passwordUser(t, p.mem, nil, "alice", "")
		u.PasswordHash = doubleCostHash(t, goodPassword)
		if err := p.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		return u, u.PasswordHash
	}
	unchanged := func(t *testing.T, p *pwFixture, u *access.User, old access.Hash) {
		t.Helper()
		if got := storedUser(t, p.mem, u.ID).PasswordHash; got.Reveal() != old.Reveal() {
			t.Error("the stored hash changed, want it byte-for-byte unchanged")
		}
		if n := debugs(p.logs, rehashSkipped); n != 1 {
			t.Errorf("rehash-skipped DEBUG lines = %d, want 1", n)
		}
	}
	t.Run("upgraded", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u, _ := seed(t, p)
		in, err := p.login(t.Context(), localClient, "alice", goodPassword)
		if err != nil {
			t.Fatalf("PasswordLogin: %v", err)
		}
		if in.User == nil || in.User.ID != u.ID || in.Session.UserID != u.ID || in.Token.IsZero() {
			t.Errorf("PasswordLogin = user %+v session %+v, want alice signed in with a session", in.User, in.Session)
		}
		got := storedUser(t, p.mem, u.ID).PasswordHash
		if p.hasher.NeedsRehash(got) {
			t.Error("the stored hash still has the old parameters")
		}
		if ok, _, err := p.hasher.Verify(t.Context(), goodPassword, got); !ok || err != nil {
			t.Errorf("the rehashed password does not verify: %t, %v", ok, err)
		}
	})
	t.Run("budget_held", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}, wait: 20 * time.Millisecond})
		u, old := seed(t, p)
		var held []*access.HashPermit
		hk.arm(func(ctx context.Context) {
			for range 4 {
				permit, err := p.hasher.Reserve(ctx)
				if err != nil {
					t.Errorf("Reserve: %v", err)
					return
				}
				held = append(held, permit)
			}
		})
		in, err := p.login(t.Context(), localClient, "alice", goodPassword)
		for _, permit := range held {
			permit.Release()
		}
		if err != nil || in.Session.ID == "" {
			t.Fatalf("sign-in under a held budget = %v, want a session", err)
		}
		unchanged(t, p, u, old)
	})
	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}})
		u, old := seed(t, p)
		ctx, cancel := context.WithCancel(t.Context())
		hk.arm(func(context.Context) { cancel() })
		if in, err := p.login(ctx, localClient, "alice", goodPassword); err != nil || in.Session.ID == "" {
			t.Fatalf("sign-in cancelled after its comparison = %v, want a session from a store that ignores ctx", err)
		}
		unchanged(t, p, u, old)
	})
	t.Run("cancelled_store_decides", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		fs.honourCtx.Store(true)
		var hk armed
		p := newPW(t, pwOptions{store: fs, hooks: account.Hooks{AfterVerify: hk.hook}})
		u, old := seed(t, p)
		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), ctxMarker{}, "request"))
		hk.arm(func(context.Context) { cancel() })
		_, err := p.login(ctx, localClient, "alice", goodPassword)
		if !errors.Is(err, context.Canceled) || !errors.Is(err, access.ErrAuthBackend) {
			t.Fatalf("sign-in cancelled after its comparison = %v, want the store's context.Canceled as access.ErrAuthBackend", err)
		}
		if ss := sessionsOf(t, p.mem, u.ID); len(ss) != 0 {
			t.Errorf("sessions = %d, want none", len(ss))
		}
		var last storeCall
		for _, c := range fs.recorded() {
			if c.name == "Update" {
				last = c
			}
		}
		if last.ctx == nil || last.ctx.Value(ctxMarker{}) != "request" || last.ctx.Err() == nil {
			t.Error("the success Update did not receive the request's cancelled context")
		}
		if n := p.counted.hashed.Load(); n != 0 {
			t.Errorf("rehash derivations = %d, want none under an ended context", n)
		}
		if got := storedUser(t, p.mem, u.ID).PasswordHash; got.Reveal() != old.Reveal() {
			t.Error("the stored hash changed")
		}
	})
}

func TestRefusedAdmissionNoHash(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	p := newPW(t, pwOptions{store: fs, limiter: ipLimit(1)})
	passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	res, err := p.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(localClient.IP())})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	res.Fail()
	fs.resetRecord()
	_, err = p.login(t.Context(), localClient, "alice", goodPassword)
	if _, ok := errors.AsType[*ratelimit.RefusedError](err); !ok {
		t.Fatalf("PasswordLogin past the IP limit = %v, want *ratelimit.RefusedError", err)
	}
	if r, d, h := p.counted.reserved.Load(), len(p.counted.verified()), p.counted.hashed.Load(); r+int64(d)+h != 0 {
		t.Errorf("a refused admission took %d permits, compared %d and hashed %d, want none", r, d, h)
	}
	if calls := fs.recorded(); len(calls) != 0 {
		t.Errorf("store calls = %d, want none", len(calls))
	}
}

func TestOverlongUsernameNoLimiter(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	p := newPW(t, pwOptions{store: fs, limiter: ipLimit(1)})
	fs.resetRecord()
	for name, want := range map[string]string{strings.Repeat("a", account.MaxUsernameLength+1): "too_long", "": "empty"} {
		_, err := p.login(t.Context(), localClient, name, wrongPassword)
		if ue, ok := errors.AsType[*account.UsernameError](err); !ok || ue.Reason != want {
			t.Errorf("PasswordLogin(%d runes) = %v, want *UsernameError{%s}", len(name), err, want)
		}
	}
	if calls := fs.recorded(); len(calls) != 0 {
		t.Errorf("store calls = %d, want none", len(calls))
	}
	if _, err := p.login(t.Context(), localClient, "bob", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("first well-formed attempt under an IP limit of 1 = %v, want ErrInvalidCredentials: a refused username touched the limiter", err)
	}
}

type attemptKey struct{}

func TestConcurrentFailedSignIns(t *testing.T) {
	t.Parallel()
	const attempts, ghosts = 200, 10
	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprintf("grouped_%t", grouped), func(t *testing.T) {
			t.Parallel()
			fs := newFaultStore()
			if grouped {
				fs.group(10 * time.Millisecond)
			}
			p := newPW(t, pwOptions{store: fs, wait: 10 * time.Minute})
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			published := fs.published.Load()
			answered := make([]int64, attempts)
			var wg sync.WaitGroup
			for i := range attempts {
				name := "alice"
				if i%2 == 1 {
					name = fmt.Sprintf("ghost%d", i%(2*ghosts)/2)
				}
				wg.Go(func() {
					ctx := context.WithValue(t.Context(), attemptKey{}, i)
					_, err := p.login(ctx, clientAt(i), name, wrongPassword)
					answered[i] = fs.mark()
					if !errors.Is(err, account.ErrInvalidCredentials) {
						t.Errorf("attempt %d = %v, want ErrInvalidCredentials", i, err)
					}
				})
			}
			wg.Wait()
			if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != attempts/2 || !rec.Locked {
				t.Errorf("alice's record = count %d locked %t, want %d and locked", rec.Count, rec.Locked, attempts/2)
			}
			for g := range ghosts {
				if rec, _ := record(t, p.mem, p.svc, fmt.Sprintf("ghost%d", g), false); rec.Count != attempts/2/ghosts {
					t.Errorf("ghost%d's count = %d, want %d", g, rec.Count, attempts/2/ghosts)
				}
			}
			committedAt := map[int]int64{}
			for _, c := range fs.committed() {
				if i, ok := c.ctx.Value(attemptKey{}).(int); ok {
					committedAt[i] = c.seq
				}
			}
			for i := range attempts {
				if seq, ok := committedAt[i]; !ok || seq > answered[i] {
					t.Errorf("attempt %d answered at %d, its count committed at %d (%t): want the commit first", i, answered[i], seq, ok)
				}
			}
			if n := fs.published.Load() - published; grouped && n >= attempts {
				t.Errorf("grouped store published %d commits for %d attempts, want fewer", n, attempts)
			}
		})
	}
}
