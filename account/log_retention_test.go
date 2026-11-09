package account_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// withLogCaps sets the non-default class caps (E15).
func withLogCaps(changes, sessions int) func(*account.Config) {
	return func(c *account.Config) { c.LogMaxChanges, c.LogMaxSessions = changes, sessions }
}

// fill appends n entries of class at at straight through s, as an earlier
// process left them, and returns their Seqs.
func fill(t testing.TB, s account.Store, class account.LogClass, n int, at time.Time) []uint64 {
	t.Helper()
	kind := account.EventUserCreated
	if class == account.LogClassSession {
		kind = account.EventSignedIn
	}
	var seqs []uint64
	err := s.Update(t.Context(), func(tx account.Tx) error {
		seqs = make([]uint64, 0, n)
		for range n {
			e := account.LogEntry{At: at, Class: class, Event: account.Event{Kind: kind, At: at}}
			if err := tx.AppendLog(t.Context(), &e); err != nil {
				return err
			}
			seqs = append(seqs, e.Event.Seq)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fill %s: %v", class, err)
	}
	return seqs
}

// classSeqs is the Seqs s holds of class, ascending.
func classSeqs(t testing.TB, s account.Store, class account.LogClass) []uint64 {
	t.Helper()
	var seqs []uint64
	for _, e := range logOf(t, s) {
		if e.Class == class {
			seqs = append(seqs, e.Event.Seq)
		}
	}
	return seqs
}

// statsOf is s's LogStats by class; a class the store reports nothing for
// is zero.
func statsOf(t testing.TB, s account.Store) map[account.LogClass]account.LogClassStats {
	t.Helper()
	stats, err := s.LogStats(t.Context())
	if err != nil {
		t.Fatalf("LogStats: %v", err)
	}
	out := map[account.LogClass]account.LogClassStats{}
	for _, st := range stats {
		out[st.Class] = account.LogClassStats{Count: st.Count, Evicted: st.Evicted}
	}
	return out
}

// seqsOf is the Seqs of the logged events among evs.
func seqsOf(evs []account.Event) []uint64 {
	var seqs []uint64
	for i := range evs {
		if evs[i].Seq != 0 {
			seqs = append(seqs, evs[i].Seq)
		}
	}
	return seqs
}

var userNames atomic.Int64

// createUsers makes n out-of-band CreateUser changes, one change entry
// each, and returns their Seqs.
func createUsers(t testing.TB, f *fixture, n int) []uint64 {
	t.Helper()
	before := len(f.events.all())
	for range n {
		name := fmt.Sprintf("logged%d", userNames.Add(1))
		if _, err := f.svc.CreateUser(t.Context(), account.OutOfBand("test"), account.NewUser{Username: name}); err != nil {
			t.Fatalf("CreateUser(%s): %v", name, err)
		}
	}
	return seqsOf(f.events.all()[before:])
}

// revokeSessions has a session of u revoke n other sessions of u, one
// session entry each, and returns their Seqs.
func revokeSessions(t *testing.T, f *fixture, u *access.User, n int) []uint64 {
	t.Helper()
	p := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	before := len(f.events.all())
	for range n {
		other := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		if err := f.svc.RevokeSession(t.Context(), p, other.SessionID); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
	}
	return seqsOf(f.events.all()[before:])
}

func TestConfigLogFields(t *testing.T) {
	t.Run("negative_refused", func(t *testing.T) {
		for _, c := range []struct {
			edit  func(*account.Config)
			field string
		}{
			{func(c *account.Config) { c.LogMaxAge = -time.Millisecond }, "LogMaxAge"},
			{func(c *account.Config) { c.LogMaxChanges = -1 }, "LogMaxChanges"},
			{func(c *account.Config) { c.LogMaxSessions = -1 }, "LogMaxSessions"},
		} {
			t.Run(c.field, func(t *testing.T) {
				cfg := newFixture(t, options{}).cfg
				c.edit(&cfg)
				svc, err := account.New(t.Context(), cfg)
				if svc != nil {
					t.Errorf("New with a negative %s returned a Service", c.field)
					_ = svc.Shutdown(t.Context())
				}
				if err == nil || !strings.Contains(err.Error(), "Config."+c.field) {
					t.Errorf("New with a negative %s = %v, want an error naming Config.%s", c.field, err, c.field)
				}
			})
		}
	})
	t.Run("default_changes", func(t *testing.T) {
		fs := newFaultStore()
		filled := fill(t, fs.mem, account.LogClassChange, 10000, time.Now().Truncate(time.Millisecond))
		f := newFixture(t, options{store: fs})
		if got := statsOf(t, fs.mem)[account.LogClassChange]; got.Count != 10000 || got.Evicted != 0 {
			t.Fatalf("change class after New over 10,000 entries = %+v, want 10000 kept, none evicted", got)
		}
		added := createUsers(t, f, 1)
		want := slices.Concat(filled[1:], added)
		if got := classSeqs(t, fs.mem, account.LogClassChange); !slices.Equal(got, want) {
			t.Errorf("change class after the 10,001st change holds %d entries from Seq %d, want the newest 10,000 from Seq %d",
				len(got), got[0], want[0])
		}
		if got := statsOf(t, fs.mem)[account.LogClassChange]; got.Evicted != 1 {
			t.Errorf("change class Evicted after the 10,001st change = %d, want 1", got.Evicted)
		}
	})
	t.Run("default_sessions", func(t *testing.T) {
		fs := newFaultStore()
		filled := fill(t, fs.mem, account.LogClassSession, 10000, time.Now().Truncate(time.Millisecond))
		f := newFixture(t, options{store: fs})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		added := revokeSessions(t, f, u, 1)
		want := slices.Concat(filled[1:], added)
		if got := classSeqs(t, fs.mem, account.LogClassSession); !slices.Equal(got, want) {
			t.Errorf("session class after the 10,001st session entry holds %d entries from Seq %d, want the newest 10,000 from Seq %d",
				len(got), got[0], want[0])
		}
	})
	t.Run("default_age", func(t *testing.T) {
		now := time.Now().Truncate(time.Millisecond)
		bound := now.Add(-365 * 24 * time.Hour)
		fs := newFaultStore()
		fill(t, fs.mem, account.LogClassChange, 1, bound.Add(-time.Millisecond))
		kept := fill(t, fs.mem, account.LogClassChange, 1, bound)
		newFixture(t, options{store: fs, edit: func(c *account.Config) { c.Now = func() time.Time { return now } }})
		if got := classSeqs(t, fs.mem, account.LogClassChange); !slices.Equal(got, kept) {
			t.Errorf("change class after New = %v, want only the entry exactly 365 days old (%v)", got, kept)
		}
	})
}

func TestLogCapAtAppend(t *testing.T) {
	t.Run("per_class", func(t *testing.T) {
		p := newPW(t, pwOptions{edit: withLogCaps(3, 2)})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		changes := createUsers(t, p.fixture, 5)
		if got := classSeqs(t, p.mem, account.LogClassChange); !slices.Equal(got, changes[2:]) {
			t.Errorf("change class after five changes = %v, want the three newest %v", got, changes[2:])
		}
		before := len(p.events.all())
		for range 3 {
			if _, err := p.login(t.Context(), localClient, "alice", goodPassword); err != nil {
				t.Fatalf("PasswordLogin: %v", err)
			}
		}
		signIns := seqsOf(p.events.all()[before:])
		if len(signIns) != 3 {
			t.Fatalf("three sign-ins logged %d entries, want 3", len(signIns))
		}
		if got := classSeqs(t, p.mem, account.LogClassSession); !slices.Equal(got, signIns[1:]) {
			t.Errorf("session class after three sign-ins = %v, want the two newest %v", got, signIns[1:])
		}
		if got := classSeqs(t, p.mem, account.LogClassChange); !slices.Equal(got, changes[2:]) {
			t.Errorf("change class after the sign-ins = %v, want it unchanged %v", got, changes[2:])
		}
	})
	t.Run("trim_fails", func(t *testing.T) {
		fs := newFaultStore()
		f := newFixture(t, options{store: fs, edit: withLogCaps(3, 2)})
		createUsers(t, f, 3)
		before, events := logOf(t, fs.mem), len(f.events.all())
		fs.failCall("PruneLog")
		_, err := f.svc.CreateUser(t.Context(), account.OutOfBand("test"), account.NewUser{Username: "untrimmed"})
		if !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("CreateUser whose trim fails = %v, want access.ErrAuthBackend", err)
		}
		if _, found, _ := fs.mem.UserByUsername(t.Context(), "untrimmed"); found {
			t.Error("CreateUser whose trim failed left the user")
		}
		if got := logOf(t, fs.mem); !slices.EqualFunc(got, before, func(a, b account.LogEntry) bool { return a.Event.Seq == b.Event.Seq }) {
			t.Errorf("log after a failed trim holds %d entries, want the %d before it", len(got), len(before))
		}
		if n := len(f.events.all()); n != events {
			t.Errorf("events after a failed trim = %d, want %d: nothing is emitted", n, events)
		}
	})
}

func TestLogEvictionCounted(t *testing.T) {
	t.Run("at_append", func(t *testing.T) {
		f := newFixture(t, options{edit: withLogCaps(3, 2)})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		createUsers(t, f, 5)
		revokeSessions(t, f, u, 1)
		stats := statsOf(t, f.mem)
		if got := stats[account.LogClassChange]; got.Count != 3 || got.Evicted != 2 {
			t.Errorf("change class after five changes = %+v, want Count 3 and Evicted 2", got)
		}
		if got := stats[account.LogClassSession]; got.Count != 1 || got.Evicted != 0 {
			t.Errorf("session class after one entry = %+v, want Count 1 and Evicted 0", got)
		}
	})
	t.Run("new_drain", func(t *testing.T) {
		fs := newFaultStore()
		filled := fill(t, fs.mem, account.LogClassChange, 7, time.Now().Truncate(time.Millisecond))
		newFixture(t, options{store: fs, edit: withLogCaps(3, 2)})
		if got := statsOf(t, fs.mem)[account.LogClassChange]; got.Count != 3 || got.Evicted != 4 {
			t.Errorf("change class after New over 7 entries = %+v, want Count 3 and Evicted 4", got)
		}
		if got := classSeqs(t, fs.mem, account.LogClassChange); !slices.Equal(got, filled[4:]) {
			t.Errorf("change class after New = %v, want the three newest %v", got, filled[4:])
		}
	})
	t.Run("age_prune", func(t *testing.T) {
		clock := newTestClock(time.Now().Truncate(time.Millisecond))
		f := newFixture(t, options{edit: func(c *account.Config) {
			withLogCaps(3, 2)(c)
			c.LogMaxAge, c.Now = time.Hour, clock.now
		}})
		createUsers(t, f, 5)
		clock.add(time.Hour + time.Millisecond)
		account.SweepLog(t.Context(), f.svc)
		if got := statsOf(t, f.mem)[account.LogClassChange]; got.Count != 0 || got.Evicted != 2 {
			t.Errorf("change class after an age prune = %+v, want Count 0 and Evicted still 2", got)
		}
	})
}

// pruneRecorder records every PruneLog call made inside an Update, and
// fails them all while fail is set.
type pruneRecorder struct {
	account.Store
	prunes  []recordedPrune
	after   func() // runs after each recorded prune when set
	updates int
	mu      sync.Mutex
	fail    atomic.Bool
}

type recordedPrune struct {
	p       account.LogPrune
	update  int
	removed int
}

func (s *pruneRecorder) Update(ctx context.Context, fn func(account.Tx) error) error {
	s.mu.Lock()
	s.updates++
	n := s.updates
	s.mu.Unlock()
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(pruneTx{Tx: tx, s: s, update: n}) })
}

func (s *pruneRecorder) recorded() []recordedPrune {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.prunes)
}

type pruneTx struct {
	account.Tx
	s      *pruneRecorder
	update int
}

func (t pruneTx) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	if t.s.fail.Load() {
		return 0, errors.New("prune failed")
	}
	n, err := t.Tx.PruneLog(ctx, p)
	t.s.mu.Lock()
	t.s.prunes = append(t.s.prunes, recordedPrune{p: p, update: t.update, removed: n})
	after := t.s.after
	t.s.mu.Unlock()
	if after != nil {
		after()
	}
	return n, err
}

func TestNewDrainsLog(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	const maxAge = time.Hour
	caps := map[account.LogClass]int{account.LogClassChange: 3, account.LogClassSession: 2}
	setup := func(t *testing.T) (account.Config, *pruneRecorder) {
		t.Helper()
		cfg := newFixture(t, options{}).cfg
		rec := &pruneRecorder{Store: cfg.Store}
		cfg.Store, cfg.Now, cfg.LogMaxAge = rec, func() time.Time { return now }, maxAge
		withLogCaps(caps[account.LogClassChange], caps[account.LogClassSession])(&cfg)
		return cfg, rec
	}
	t.Run("drains", func(t *testing.T) {
		cfg, rec := setup(t)
		old := now.Add(-maxAge - time.Millisecond)
		fill(t, rec.Store, account.LogClassChange, 2*account.MaxSweepBatch+2, now)
		fill(t, rec.Store, account.LogClassChange, 1, old)
		recent := fill(t, rec.Store, account.LogClassChange, 2, now)
		fill(t, rec.Store, account.LogClassSession, 1, old)
		svc, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
		if got := classSeqs(t, rec.Store, account.LogClassChange); !slices.Equal(got, recent) {
			t.Errorf("change class after New holds %d entries, want the two newest within LogMaxAge %v", len(got), recent)
		}
		if got := classSeqs(t, rec.Store, account.LogClassSession); len(got) != 0 {
			t.Errorf("session class after New = %v, want none: its one entry is older than LogMaxAge", got)
		}
		stats := statsOf(t, rec.Store)
		if got := stats[account.LogClassChange]; got.Count != 2 || got.Evicted != 2*account.MaxSweepBatch+2 {
			t.Errorf("change class stats after New = %+v, want Count 2 and Evicted %d (the cap drain only)", got, 2*account.MaxSweepBatch+2)
		}
		if got := stats[account.LogClassSession]; got.Evicted != 0 {
			t.Errorf("session class Evicted after New = %d, want 0: an age prune is not an eviction", got.Evicted)
		}
		checkDrainCalls(t, rec.recorded(), caps, now.Add(-maxAge))
	})
	t.Run("store_error", func(t *testing.T) {
		cfg, rec := setup(t)
		rec.fail.Store(true)
		svc, err := account.New(t.Context(), cfg)
		if svc != nil {
			t.Error("New returned a Service though its log drain failed")
			_ = svc.Shutdown(t.Context())
		}
		if !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("New whose log drain fails = %v, want access.ErrAuthBackend", err)
		}
	})
	t.Run("ctx_ends", func(t *testing.T) {
		cfg, rec := setup(t)
		fill(t, rec.Store, account.LogClassChange, 2*account.MaxSweepBatch, now)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		rec.after = cancel
		svc, err := account.New(ctx, cfg)
		if svc != nil {
			t.Error("New returned a Service though its ctx ended with the log past its cap")
			_ = svc.Shutdown(t.Context())
		}
		if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, context.Canceled) {
			t.Errorf("New whose ctx ends mid-drain = %v, want access.ErrAuthBackend wrapping context.Canceled", err)
		}
	})
}

// checkDrainCalls requires every prune of New's drain to set exactly one
// criterion, the cap or the age bound, with Limit MaxSweepBatch in an
// Update of its own, and each class's prunes of one criterion to go on
// until a call removes fewer than Limit, the cap's before the age's.
func checkDrainCalls(t *testing.T, prunes []recordedPrune, caps map[account.LogClass]int, before time.Time) {
	t.Helper()
	updates := map[int]bool{}
	byClass := map[account.LogClass][]recordedPrune{}
	for _, r := range prunes {
		p := r.p
		switch {
		case p.Limit != account.MaxSweepBatch:
			t.Errorf("prune %+v: Limit %d, want MaxSweepBatch", p, p.Limit)
		case (p.Keep != 0) == !p.Before.IsZero():
			t.Errorf("prune %+v sets both criteria or neither", p)
		case p.Keep != 0 && p.Keep != caps[p.Class]:
			t.Errorf("prune %+v: Keep %d, want the class's cap %d", p, p.Keep, caps[p.Class])
		case !p.Before.IsZero() && !p.Before.Equal(before):
			t.Errorf("prune %+v: Before %v, want now minus LogMaxAge %v", p, p.Before, before)
		}
		if updates[r.update] {
			t.Errorf("prune %+v shares Update %d with another prune", p, r.update)
		}
		updates[r.update] = true
		byClass[p.Class] = append(byClass[p.Class], r)
	}
	for _, class := range account.LogClasses() {
		rs := byClass[class]
		split := slices.IndexFunc(rs, func(r recordedPrune) bool { return r.p.Keep == 0 })
		if split < 1 || slices.ContainsFunc(rs[split:], func(r recordedPrune) bool { return r.p.Keep != 0 }) {
			t.Errorf("%s prunes %+v: want the cap's calls, then the age's", class, rs)
			continue
		}
		for _, run := range [][]recordedPrune{rs[:split], rs[split:]} {
			for i, r := range run {
				if last := i == len(run)-1; last != (r.removed < r.p.Limit) {
					t.Errorf("%s prune %d of %+v removed %d: the drain goes on exactly while a call removes Limit", class, i, run, r.removed)
				}
			}
		}
	}
}

func TestSweepPrunesLogByAge(t *testing.T) {
	const maxAge = time.Hour
	edit := func(c *account.Config) { withInterval(c); c.LogMaxAge = maxAge }
	t.Run("prunes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFixture(t, options{edit: edit})
			old := time.Now().Add(-maxAge - time.Second)
			fill(t, f.mem, account.LogClassChange, 2*account.MaxSweepBatch+5, old)
			changes := fill(t, f.mem, account.LogClassChange, 1, time.Now())
			fill(t, f.mem, account.LogClassSession, 3, old)
			sessions := fill(t, f.mem, account.LogClassSession, 1, time.Now())
			tick()
			if got := classSeqs(t, f.mem, account.LogClassChange); !slices.Equal(got, changes) {
				t.Errorf("change class a tick later holds %d entries, want only the one within LogMaxAge %v", len(got), changes)
			}
			if got := classSeqs(t, f.mem, account.LogClassSession); !slices.Equal(got, sessions) {
				t.Errorf("session class a tick later = %v, want only the one within LogMaxAge %v", got, sessions)
			}
		})
	})
	t.Run("store_error_retried", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fs := newFaultStore()
			f := newFixture(t, options{store: fs, edit: edit})
			old := time.Now().Add(-maxAge - time.Second)
			stale := fill(t, fs.mem, account.LogClassChange, 2, old)
			fill(t, fs.mem, account.LogClassSession, 2, old)
			fs.failCall("PruneLog")
			tick()
			if got := f.logs.CountMsg("security-log age prune failed"); got != 1 || warnings(f.logs) != 1 {
				t.Errorf("after the failing tick: %d log-prune WARN lines of %d WARN lines, want 1 of 1", got, warnings(f.logs))
			}
			if got := classSeqs(t, fs.mem, account.LogClassChange); !slices.Equal(got, stale) {
				t.Errorf("change class after its failed prune = %v, want its entries kept %v", got, stale)
			}
			if got := classSeqs(t, fs.mem, account.LogClassSession); len(got) != 0 {
				t.Errorf("session class after the change class's failed prune = %v, want pruned: one class's error does not stop the next", got)
			}
			tick()
			if got := classSeqs(t, fs.mem, account.LogClassChange); len(got) != 0 {
				t.Errorf("change class after the next tick = %v, want pruned: the leg retries", got)
			}
			if w := warnings(f.logs); w != 1 {
				t.Errorf("WARN lines after the healthy tick = %d, want still 1", w)
			}
		})
	})
}
