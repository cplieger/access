package account_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

const sweepEvery = time.Minute

// sweepStore wraps a Store's session cleanup: it records each call, can
// fail chosen calls, and can reorder the refs a call returns.
type sweepStore struct {
	account.Store
	events  *eventLog
	reorder func([]access.SessionRef) []access.SessionRef
	fail    func(call int) bool
	calls   []sweepCall
	mu      sync.Mutex
}

// sweepCall is one CleanupExpiredSessions call as the store saw it.
type sweepCall struct {
	timeouts     access.SessionTimeouts
	limit        int
	eventsBefore int // events recorded when the call began
	refs         int
	failed       bool
}

func (s *sweepStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	s.mu.Lock()
	n := len(s.calls) + 1
	call := sweepCall{timeouts: timeouts, limit: limit, eventsBefore: len(s.events.all())}
	fail := s.fail != nil && s.fail(n)
	s.mu.Unlock()
	var refs []access.SessionRef
	var err error
	if fail {
		err = errors.New("cleanup failed")
	} else {
		refs, err = s.Store.CleanupExpiredSessions(ctx, now, timeouts, limit)
		if err == nil && s.reorder != nil {
			refs = s.reorder(refs)
		}
	}
	call.refs, call.failed = len(refs), err != nil
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
	return refs, err
}

func (s *sweepStore) recorded() []sweepCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// putSessions stores one session per (user, inactive) pair in one Update,
// each last active inactive ago, and returns their IDs in order.
func putSessions(t *testing.T, f *fixture, specs ...sessionSpec) []string {
	t.Helper()
	now := time.Now()
	ids := make([]string, len(specs))
	err := f.mem.Update(t.Context(), func(tx account.Tx) error {
		for i, sp := range specs {
			_, hash := access.GenerateSessionToken()
			ids[i] = sp.id
			if ids[i] == "" {
				ids[i] = newSessionID(t)
			}
			s := &access.Session{
				ID: ids[i], TokenHash: hash, UserID: sp.user, AuthMethod: access.MethodPassword,
				CreatedAt: now.Add(-sp.inactive), LastActivity: now.Add(-sp.inactive), AuthTime: now.Add(-sp.inactive),
			}
			if err := tx.CreateSession(t.Context(), s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Update(sessions): %v", err)
	}
	return ids
}

type sessionSpec struct {
	id       string
	user     int64
	inactive time.Duration
}

func expiredEvents(f *fixture) []account.Event {
	var out []account.Event
	for _, ev := range f.events.all() {
		if ev.Kind == account.EventSessionsExpired {
			out = append(out, ev)
		}
	}
	return out
}

func sessionIDsOf(t *testing.T, f *fixture, userID int64) []string {
	t.Helper()
	ss, err := f.mem.SessionsByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("SessionsByUserID: %v", err)
	}
	ids := make([]string, 0, len(ss))
	for i := range ss {
		ids = append(ids, ss[i].ID)
	}
	slices.Sort(ids)
	return ids
}

// tick advances the bubble's clock past the next sweep and waits for it.
func tick() {
	time.Sleep(sweepEvery)
	synctest.Wait()
}

// timeoutSource is an access.Config.TimeoutSource a test moves.
type timeoutSource struct {
	v atomic.Pointer[access.SessionTimeouts]
}

func newTimeoutSource(idle, absolute time.Duration) *timeoutSource {
	s := &timeoutSource{}
	s.set(idle, absolute)
	return s
}

func (s *timeoutSource) get() access.SessionTimeouts { return *s.v.Load() }
func (s *timeoutSource) set(idle, absolute time.Duration) {
	s.v.Store(&access.SessionTimeouts{Idle: idle, Absolute: absolute})
}

func withInterval(c *account.Config) { c.CleanupInterval = sweepEvery }

func TestSweepUsesAuthenticatorTimeouts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := newTimeoutSource(2*time.Hour, 24*time.Hour)
		f := newFixture(t, options{timeouts: src.get, edit: withInterval})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		idle90 := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		idle30 := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		time.Sleep(time.Hour)
		if err := f.mem.UpdateSessionActivity(t.Context(), idle30.SessionTokenHash(), access.SessionActivity{At: time.Now()}); err != nil {
			t.Fatalf("UpdateSessionActivity: %v", err)
		}
		time.Sleep(30 * time.Minute)
		synctest.Wait()
		// Ninety ticks ran: idle90 is 90m idle and idle30 30m, both live under 2h.
		if got := sessionIDsOf(t, f, u.ID); len(got) != 2 {
			t.Fatalf("sessions under a 2h idle limit = %v, want both", got)
		}
		src.set(time.Hour, 24*time.Hour)
		if _, err := f.authn.Recheck(t.Context(), idle90); err == nil {
			t.Error("the verifier accepts a 90m-idle session under a 1h idle limit")
		}
		tick()
		got := sessionIDsOf(t, f, u.ID)
		if !slices.Equal(got, []string{idle30.SessionID}) {
			t.Errorf("sessions after the limit moved to 1h = %v, want only %s", got, idle30.SessionID)
		}
		if _, err := f.authn.Recheck(t.Context(), idle30); err != nil {
			t.Errorf("the verifier refuses the session the sweep kept: %v", err)
		}
	})
}

// ctxStore records, for every store call the sweep makes, whether its
// context carried the test's value and was live.
type ctxStore struct {
	account.Store
	key   any
	calls []string
	mu    sync.Mutex
}

func (s *ctxStore) note(ctx context.Context, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fmt.Sprintf("%s value=%v live=%t", name, ctx.Value(s.key), ctx.Err() == nil))
}

func (s *ctxStore) CleanupExpiredSessions(ctx context.Context, now time.Time, to access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	s.note(ctx, "CleanupExpiredSessions")
	return s.Store.CleanupExpiredSessions(ctx, now, to, limit)
}

func (s *ctxStore) CleanupExpiredOneTimeTokens(ctx context.Context, now time.Time) (int64, error) {
	s.note(ctx, "CleanupExpiredOneTimeTokens")
	return s.Store.CleanupExpiredOneTimeTokens(ctx, now)
}

func (s *ctxStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	s.note(ctx, "Update")
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(ctxTx{Tx: tx, s: s}) })
}

type ctxTx struct {
	account.Tx
	s *ctxStore
}

func (t ctxTx) ListUsers(ctx context.Context) ([]access.User, error) {
	t.s.note(ctx, "ListUsers")
	return t.Tx.ListUsers(ctx)
}

func (t ctxTx) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	t.s.note(ctx, "UnreportedLocks")
	return t.Tx.UnreportedLocks(ctx)
}

func (t ctxTx) PutAuthFailure(ctx context.Context, fc account.FailureCount) error {
	t.s.note(ctx, "PutAuthFailure")
	return t.Tx.PutAuthFailure(ctx, fc)
}

func (t ctxTx) PruneAuthFailures(ctx context.Context, keep []string) (int64, error) {
	t.s.note(ctx, "PruneAuthFailures")
	return t.Tx.PruneAuthFailures(ctx, keep)
}

type ctxKey struct{}

func TestSweepContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mem := &ctxStore{key: ctxKey{}}
		parent, cancel := context.WithCancel(context.WithValue(t.Context(), ctxKey{}, "tag"))
		f := newFixture(t, options{ctx: parent, edit: func(c *account.Config) {
			withInterval(c)
			mem.Store = c.Store
			c.Store = mem
		}})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		if err := f.mem.PutAuthFailure(t.Context(), account.FailureCount{
			Name: account.FailureName(f.svc, u.Username), Method: access.MethodPassword,
			Count: account.FailureCap, Locked: true, Unreported: true, LockedAt: time.Now(),
		}); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
		cancel()
		tick()
		mem.mu.Lock()
		calls := slices.Clone(mem.calls)
		mem.mu.Unlock()
		for _, name := range []string{"CleanupExpiredSessions", "CleanupExpiredOneTimeTokens", "Update", "ListUsers", "UnreportedLocks", "PutAuthFailure", "PruneAuthFailures"} {
			want := name + " value=tag live=true"
			if !slices.Contains(calls, want) {
				t.Errorf("the sweep after New's context ended made no call %q; calls: %q", want, calls)
			}
		}
		for _, c := range calls {
			if c[len(c)-len("value=tag live=true"):] != "value=tag live=true" {
				t.Errorf("sweep call %q lacks New's value or ran on an ended context", c)
			}
		}
	})
}

func TestShutdownStopsSweep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ss := &sweepStore{}
		f := newFixture(t, options{edit: func(c *account.Config) {
			withInterval(c)
			ss.Store, ss.events = c.Store, &eventLog{}
			c.Store = ss
		}})
		tick()
		if n := len(ss.recorded()); n != 1 {
			t.Fatalf("cleanup calls after one tick = %d, want 1", n)
		}
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown = %v, want nil", err)
		}
		tick()
		tick()
		if n := len(ss.recorded()); n != 1 {
			t.Errorf("cleanup calls after Shutdown = %d, want still 1", n)
		}
		if _, err := account.Begin(f.svc); !errors.Is(err, account.ErrServiceClosed) || !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("an operation after Shutdown = %v, want ErrServiceClosed matching access.ErrAuthBackend", err)
		}
		if err := f.svc.RequireAdminScope(access.Principal{}); !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("RequireAdminScope after Shutdown = %v, want ErrServiceClosed", err)
		}
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Errorf("a second Shutdown = %v, want nil", err)
		}
	})
	t.Run("ctx_ends_first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})
			var once sync.Once
			f := newFixture(t, options{edit: func(c *account.Config) {
				withInterval(c)
				c.OnEvent = func(account.Event) {
					once.Do(func() { close(entered) })
					<-release
				}
			}})
			u := mustUser(t, f.mem, "alice", access.RoleUser)
			putSessions(t, f, sessionSpec{user: u.ID, inactive: 48 * time.Hour})
			select {
			case <-entered:
			case <-time.After(time.Hour):
				t.Fatal("the sweep never dispatched an event")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := f.svc.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Shutdown while the sweep is held = %v, want context.DeadlineExceeded", err)
			}
			close(release)
			if err := f.svc.Shutdown(t.Context()); err != nil {
				t.Errorf("Shutdown after the sweep was released = %v, want nil", err)
			}
		})
	})
}

// unsorted returns user 2's refs first, then user 1's in descending ID, so
// an emitter that skips either sort fails on every run.
func unsorted(refs []access.SessionRef) []access.SessionRef {
	out := slices.Clone(refs)
	slices.SortFunc(out, func(a, b access.SessionRef) int {
		if a.UserID != b.UserID {
			return int(b.UserID - a.UserID)
		}
		if a.ID > b.ID {
			return -1
		}
		return 1
	})
	return out
}

func TestSweepEmitsSessionsExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ss := &sweepStore{reorder: unsorted, events: &eventLog{}}
		var failing atomic.Bool
		ss.fail = func(int) bool { return failing.Load() }
		f := newFixture(t, options{events: ss.events, edit: func(c *account.Config) {
			withInterval(c)
			ss.Store = c.Store
			c.Store = ss
		}})
		u1 := mustUser(t, f.mem, "one", access.RoleUser)
		u2 := mustUser(t, f.mem, "two", access.RoleUser)
		if u1.ID >= u2.ID {
			t.Fatalf("user IDs %d, %d: want user 1's below user 2's", u1.ID, u2.ID)
		}
		day := 48 * time.Hour
		dead1 := putSessions(t, f,
			sessionSpec{id: sessionIDFor(0x3000), user: u1.ID, inactive: day},
			sessionSpec{id: sessionIDFor(0x1000), user: u1.ID, inactive: day},
			sessionSpec{id: sessionIDFor(0x2000), user: u1.ID, inactive: day})
		dead2 := putSessions(t, f, sessionSpec{user: u2.ID, inactive: day})
		live := putSessions(t, f, sessionSpec{user: u1.ID}, sessionSpec{user: u2.ID})
		slices.Sort(dead1)

		tick()
		at := time.Now()
		got := expiredEvents(f)
		want := []account.Event{
			{Kind: account.EventSessionsExpired, At: at, UserID: u1.ID, SessionIDs: dead1},
			{Kind: account.EventSessionsExpired, At: at, UserID: u2.ID, SessionIDs: dead2},
		}
		if len(got) != len(want) {
			t.Fatalf("events = %+v, want %+v", got, want)
		}
		for i := range want {
			g := got[i]
			if g.UserID != want[i].UserID || !g.At.Equal(at) || g.Actor != (account.EventActor{}) || !slices.Equal(g.SessionIDs, want[i].SessionIDs) {
				t.Errorf("event %d = %+v, want %+v", i, g, want[i])
			}
			for _, id := range live {
				if slices.Contains(g.SessionIDs, id) {
					t.Errorf("event %d names live session %s", i, id)
				}
			}
		}

		tick()
		if n := len(expiredEvents(f)); n != 2 {
			t.Errorf("a tick with nothing expired emitted %d more events", n-2)
		}

		failing.Store(true)
		late := putSessions(t, f, sessionSpec{user: u1.ID, inactive: day})
		warnsBefore := warnings(f.logs)
		tick()
		if n := len(expiredEvents(f)); n != 2 {
			t.Errorf("a failed cleanup emitted %d events", n-2)
		}
		if n := warnings(f.logs) - warnsBefore; n != 1 {
			t.Errorf("a failed cleanup logged %d WARN lines, want 1", n)
		}
		failing.Store(false)
		tick()
		got = expiredEvents(f)
		if len(got) != 3 || got[2].UserID != u1.ID || !slices.Equal(got[2].SessionIDs, late) {
			t.Errorf("the tick after a failure emitted %+v, want one event naming %v", got[2:], late)
		}
	})
	t.Run("panicking_hook", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var users []int64
			var mu sync.Mutex
			var u1 atomic.Int64
			f := newFixture(t, options{edit: func(c *account.Config) {
				withInterval(c)
				c.OnEvent = func(ev account.Event) {
					if ev.Kind != account.EventSessionsExpired {
						return
					}
					mu.Lock()
					users = append(users, ev.UserID)
					mu.Unlock()
					if ev.UserID == u1.Load() {
						panic("hook failed")
					}
				}
			}})
			one := mustUser(t, f.mem, "one", access.RoleUser)
			u1.Store(one.ID)
			u2 := mustUser(t, f.mem, "two", access.RoleUser)
			putSessions(t, f, sessionSpec{user: one.ID, inactive: 48 * time.Hour}, sessionSpec{user: u2.ID, inactive: 48 * time.Hour})
			tick()
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(users, []int64{one.ID, u2.ID}) {
				t.Errorf("hook saw users %v, want %d then %d", users, one.ID, u2.ID)
			}
			if n := errorLogs(f.logs); n != 1 {
				t.Errorf("the panic logged %d ERROR lines, want 1", n)
			}
		})
	})
}

// manyExpired stores n expired sessions spread over users and returns
// their IDs.
func manyExpired(t *testing.T, f *fixture, n int, users ...int64) []string {
	t.Helper()
	specs := make([]sessionSpec, n)
	for i := range specs {
		specs[i] = sessionSpec{user: users[i%len(users)], inactive: 48 * time.Hour}
	}
	return putSessions(t, f, specs...)
}

func TestSweepSessionsExpiredBounded(t *testing.T) {
	const total = account.MaxSweepBatch*2 + 1
	setup := func(t *testing.T, ss *sweepStore, o options) (*fixture, []int64) {
		t.Helper()
		ss.events = &eventLog{}
		o.events = ss.events
		edit := o.edit
		o.edit = func(c *account.Config) {
			withInterval(c)
			ss.Store = c.Store
			c.Store = ss
			if edit != nil {
				edit(c)
			}
		}
		f := newFixture(t, o)
		var users []int64
		for _, n := range []string{"one", "two", "three"} {
			users = append(users, mustUser(t, f.mem, n, access.RoleUser).ID)
		}
		return f, users
	}
	named := func(evs []account.Event) map[string]int {
		out := map[string]int{}
		for _, ev := range evs {
			for _, id := range ev.SessionIDs {
				out[id]++
			}
		}
		return out
	}
	t.Run("drains_in_one_tick", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ss := &sweepStore{}
			f, users := setup(t, ss, options{})
			ids := manyExpired(t, f, total, users...)
			tick()
			calls := ss.recorded()
			if len(calls) != 3 {
				t.Fatalf("cleanup calls in one tick = %d, want 3", len(calls))
			}
			evs := expiredEvents(f)
			for i, c := range calls {
				if c.limit != account.MaxSweepBatch {
					t.Errorf("call %d limit = %d, want %d", i, c.limit, account.MaxSweepBatch)
				}
				end := len(evs)
				if i+1 < len(calls) {
					end = calls[i+1].eventsBefore
				}
				n := 0
				for _, ev := range evs[c.eventsBefore:end] {
					n += len(ev.SessionIDs)
				}
				if n != c.refs || n > account.MaxSweepBatch {
					t.Errorf("call %d's events name %d IDs, want its %d refs, at most %d", i, n, c.refs, account.MaxSweepBatch)
				}
			}
			counts := named(evs)
			for _, id := range ids {
				if counts[id] != 1 {
					t.Errorf("session %s named %d times, want once", id, counts[id])
				}
			}
			if len(counts) != len(ids) {
				t.Errorf("events name %d sessions, want %d", len(counts), len(ids))
			}
			for _, u := range users {
				if left := sessionIDsOf(t, f, u); len(left) != 0 {
					t.Errorf("user %d keeps %d expired sessions", u, len(left))
				}
			}
			var reported []int64
			for _, rec := range f.logs.Records("account: sweep finished") {
				rec.Attrs(func(a slog.Attr) bool {
					if a.Key == "sessions" {
						reported = append(reported, a.Value.Int64())
					}
					return true
				})
			}
			if len(reported) == 0 || reported[len(reported)-1] != total {
				t.Errorf("sweep finished reported sessions %v, want the tick's line naming all %d", reported, total)
			}
		})
	})
	t.Run("second_call_fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var failNext atomic.Bool
			failNext.Store(true)
			ss := &sweepStore{fail: func(call int) bool { return call == 2 && failNext.Load() }}
			f, users := setup(t, ss, options{})
			ids := manyExpired(t, f, total, users...)
			tick()
			calls := ss.recorded()
			if len(calls) != 2 || calls[0].failed || !calls[1].failed {
				t.Fatalf("calls in the failing tick = %+v, want one success then one failure", calls)
			}
			first := named(expiredEvents(f))
			if len(first) != account.MaxSweepBatch {
				t.Errorf("the first call's events name %d sessions, want %d", len(first), account.MaxSweepBatch)
			}
			if n := warnings(f.logs); n != 1 {
				t.Errorf("the failed call logged %d WARN lines, want 1", n)
			}
			failNext.Store(false)
			tick()
			all := named(expiredEvents(f))
			for _, id := range ids {
				if all[id] != 1 {
					t.Errorf("session %s named %d times over both ticks, want once", id, all[id])
				}
			}
		})
	})
	t.Run("timeouts_read_per_call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			src := newTimeoutSource(time.Hour, 24*time.Hour)
			ss := &sweepStore{}
			var moved atomic.Bool
			f, users := setup(t, ss, options{timeouts: src.get, hook: func(context.Context) {
				if moved.CompareAndSwap(false, true) {
					src.set(90*time.Minute, 24*time.Hour)
				}
			}})
			manyExpired(t, f, total, users...)
			tick()
			calls := ss.recorded()
			if len(calls) < 2 {
				t.Fatalf("calls = %d, want at least 2", len(calls))
			}
			if calls[0].timeouts.Idle != time.Hour || calls[1].timeouts.Idle != 90*time.Minute {
				t.Errorf("idle limits per call = %v, %v, want 1h then 1h30m", calls[0].timeouts.Idle, calls[1].timeouts.Idle)
			}
		})
	})
	t.Run("shutdown_between_calls", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ss := &sweepStore{}
			between := make(chan struct{})
			f, users := setup(t, ss, options{hook: func(ctx context.Context) {
				close(between)
				<-ctx.Done()
			}})
			manyExpired(t, f, total, users...)
			select {
			case <-between:
			case <-time.After(time.Hour):
				t.Fatal("the between-calls hook never ran")
			}
			if err := f.svc.Shutdown(t.Context()); err != nil {
				t.Errorf("Shutdown between calls = %v, want nil", err)
			}
			if calls := ss.recorded(); len(calls) != 1 {
				t.Errorf("cleanup calls = %d, want 1: the second never runs", len(calls))
			}
			if n := len(named(expiredEvents(f))); n != account.MaxSweepBatch {
				t.Errorf("events after Shutdown name %d sessions, want the first call's %d", n, account.MaxSweepBatch)
			}
		})
	})
}

func TestEventPanicRecovered(t *testing.T) {
	t.Parallel()
	var got []account.EventKind
	f := newFixture(t, options{edit: func(c *account.Config) {
		c.OnEvent = func(ev account.Event) {
			got = append(got, ev.Kind)
			if ev.Kind == account.EventKeyMinted {
				panic("sink failed")
			}
		}
	}})
	account.Deliver(f.svc, account.Event{Kind: account.EventKeyMinted})
	account.Deliver(f.svc, account.Event{Kind: account.EventKeyRevoked})
	if !slices.Equal(got, []account.EventKind{account.EventKeyMinted, account.EventKeyRevoked}) {
		t.Errorf("hook saw %v, want key_minted then key_revoked", got)
	}
	if n := errorLogs(f.logs); n != 1 {
		t.Errorf("the panic logged %d ERROR lines, want 1", n)
	}
	none := newFixture(t, options{edit: func(c *account.Config) { c.OnEvent = nil }})
	account.Deliver(none.svc, account.Event{Kind: account.EventKeyMinted})
}

type offlineStore struct {
	account.Store
	cleanups atomic.Int32
}

func (*offlineStore) Update(context.Context, func(account.Tx) error) error {
	return errors.New("store offline")
}

func (s *offlineStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	s.cleanups.Add(1)
	return s.Store.CleanupExpiredSessions(ctx, now, timeouts, limit)
}

func TestNewReturnsSweepError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := newFixture(t, options{}).cfg
		off := &offlineStore{Store: cfg.Store}
		cfg.Store = off
		cfg.CleanupInterval = sweepEvery
		svc, err := account.New(t.Context(), cfg)
		if svc != nil {
			t.Error("New returned a Service though its failure-record sweep failed")
			_ = svc.Shutdown(t.Context())
		}
		if !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("New over a store whose Update fails = %v, want access.ErrAuthBackend", err)
		}
		time.Sleep(3 * sweepEvery)
		synctest.Wait()
		if n := off.cleanups.Load(); n != 0 {
			t.Errorf("session cleanups after a failed New = %d, want 0: no sweep starts", n)
		}
	})
}

func TestSweepPrunesPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, options{edit: withInterval})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		cache := account.Pending(f.svc)
		cache.Put(account.PurposeLogin, *u, time.Now())
		time.Sleep(webauthn.CeremonyTimeout)
		tick()
		if n := cache.Len(); n != 0 {
			t.Errorf("pending entries a ceremony timeout and a tick after the put = %d, want 0", n)
		}
	})
}

type tokenFailStore struct {
	account.Store
	calls atomic.Int32
}

func (s *tokenFailStore) CleanupExpiredOneTimeTokens(context.Context, time.Time) (int64, error) {
	s.calls.Add(1)
	return 0, errors.New("token cleanup failed")
}

func TestSweepTokenLegRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ts := &tokenFailStore{}
		f := newFixture(t, options{edit: func(c *account.Config) {
			withInterval(c)
			ts.Store = c.Store
			c.Store = ts
		}})
		tick()
		if n, w := ts.calls.Load(), warnings(f.logs); n != 1 || w != 1 || f.logs.CountMsg("expired-token sweep failed") != 1 {
			t.Errorf("after one tick: %d token cleanups and %d WARN lines, want 1 and the token leg's one WARN", n, w)
		}
		tick()
		if n, w := ts.calls.Load(), warnings(f.logs); n != 2 || w != 2 {
			t.Errorf("after the next tick: %d token cleanups and %d WARN lines, want 2 and 2: the leg retries", n, w)
		}
	})
}
