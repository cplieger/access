package access

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access/internal/capture"
)

const (
	sessionWarnMsg = "session activity update failed"
	keyWarnMsg     = "API key touch failed"
)

// warnAttrs returns the attributes of each captured record whose message
// contains msg, in log order.
func warnAttrs(h *capture.Recorder, msg string) []map[string]slog.Value {
	var out []map[string]slog.Value
	for _, r := range h.Records(msg) {
		attrs := map[string]slog.Value{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value
			return true
		})
		out = append(out, attrs)
	}
	return out
}

// checkWarns requires exactly len(want) WARN records for msg, the i-th
// carrying suppressed want[i], where 0 means no suppressed attribute at all.
func checkWarns(t *testing.T, h *capture.Recorder, msg string, want ...int64) {
	t.Helper()
	for i, r := range h.Records(msg) {
		if r.Level != slog.LevelWarn {
			t.Errorf("record %d for %q at level %v, want WARN", i, msg, r.Level)
		}
	}
	got := warnAttrs(h, msg)
	if len(got) != len(want) {
		t.Fatalf("%q WARNs = %d, want %d", msg, len(got), len(want))
	}
	for i, attrs := range got {
		v, ok := attrs["suppressed"]
		switch {
		case want[i] == 0 && ok:
			t.Errorf("WARN %d carries suppressed %v, want none", i, v)
		case want[i] != 0 && (!ok || v.Kind() != slog.KindInt64 || v.Int64() != want[i]):
			t.Errorf("WARN %d suppressed = (%v, present %v), want %d", i, v, ok, want[i])
		}
		_, session := attrs["session_id"]
		_, key := attrs["key_id"]
		if _, ok := attrs["error"]; !ok || session == key {
			t.Errorf("WARN %d attributes = %v, want an error and one of session_id or key_id", i, attrs)
		}
	}
}

// warnFixture is one verifier over a store whose every write fails; grant
// authenticates one request and reports an error unless it is granted.
type warnFixture struct {
	clock *testClock
	store *recordingStore
	grant func() error
}

// requestAt authenticates one request with the clock set to at.
func (f warnFixture) requestAt(t *testing.T, at time.Time) {
	t.Helper()
	f.clock.Set(at)
	if err := f.grant(); err != nil {
		t.Fatal(err)
	}
}

// TestActivityWarnRateLimited pins the failed-write WARN's rate limit, per
// verifier: the first failure logs at once, later ones within the interval
// only count, and the first after it logs the count. Serial: it asserts on
// captured logs (C18).
func TestActivityWarnRateLimited(t *testing.T) { //nolint:paralleltest // asserts on captured logs
	sessionSetup := func(t *testing.T, logger *slog.Logger) warnFixture {
		t.Helper()
		a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}, Config{Logger: logger})
		store.writeFails.Store(math.MaxInt32)
		ctx := t.Context()
		return warnFixture{clock: clock, store: store, grant: func() error {
			if p, err := a.Authenticate(sessionRequest(ctx, token)); err != nil || !p.IsSession() {
				return fmt.Errorf("Authenticate = (%+v, %v), want the session despite the failed write", p, err)
			}
			return nil
		}}
	}
	keySetup := func(t *testing.T, logger *slog.Logger) warnFixture {
		t.Helper()
		a, store, clock, key := clockedKey(t, &Key{ID: 9}, Config{Logger: logger})
		store.writeFails.Store(math.MaxInt32)
		return warnFixture{clock: clock, store: store, grant: func() error {
			if p, err := a.Authenticate(bearerRequest(key)); err != nil || p.KeyID != 9 {
				return fmt.Errorf("Authenticate = (%+v, %v), want the key despite the failed touch", p, err)
			}
			return nil
		}}
	}
	for _, tc := range []struct {
		setup func(*testing.T, *slog.Logger) warnFixture
		name  string
		msg   string
	}{
		{name: "session", msg: sessionWarnMsg, setup: sessionSetup},
		{name: "key", msg: keyWarnMsg, setup: keySetup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("100 failures within one interval", func(t *testing.T) {
				logger, h := capture.New()
				f := tc.setup(t, logger)
				for i := range 100 {
					f.requestAt(t, sessionT0.Add(time.Duration(i)*500*time.Millisecond))
				}
				checkWarns(t, h, tc.msg, 0)
				f.requestAt(t, sessionT0.Add(61*time.Second))
				checkWarns(t, h, tc.msg, 0, 99)
				// The count restarts at each WARN.
				f.requestAt(t, sessionT0.Add(122*time.Second))
				checkWarns(t, h, tc.msg, 0, 99, 0)
				for _, at := range []time.Duration{123 * time.Second, 124 * time.Second, 125 * time.Second} {
					f.requestAt(t, sessionT0.Add(at))
				}
				f.requestAt(t, sessionT0.Add(183*time.Second))
				checkWarns(t, h, tc.msg, 0, 99, 0, 3)
			})
			t.Run("failures two minutes apart", func(t *testing.T) {
				logger, h := capture.New()
				f := tc.setup(t, logger)
				f.requestAt(t, sessionT0)
				f.requestAt(t, sessionT0.Add(2*time.Minute))
				checkWarns(t, h, tc.msg, 0, 0)
			})
			t.Run("a failure one interval after the last WARN logs", func(t *testing.T) {
				logger, h := capture.New()
				f := tc.setup(t, logger)
				f.requestAt(t, sessionT0)
				f.requestAt(t, sessionT0.Add(activityWarnInterval))
				checkWarns(t, h, tc.msg, 0, 0)
			})
			t.Run("failures completing out of order", func(t *testing.T) {
				logger, h := capture.New()
				f := tc.setup(t, logger)
				entered := make(chan chan struct{})
				f.store.beforeWrite = func() {
					release := make(chan struct{})
					entered <- release
					<-release
				}
				done := make(chan error, 2)
				start := func() chan struct{} {
					go func() { done <- f.grant() }()
					return <-entered
				}
				first := start() // its write began at sessionT0
				f.clock.Set(sessionT0.Add(30 * time.Second))
				second := start()
				close(second)
				if err := <-done; err != nil {
					t.Error(err)
				}
				f.clock.Set(sessionT0.Add(40 * time.Second))
				close(first)
				if err := <-done; err != nil {
					t.Error(err)
				}
				checkWarns(t, h, tc.msg, 0)
				f.store.beforeWrite = nil
				f.requestAt(t, sessionT0.Add(91*time.Second))
				checkWarns(t, h, tc.msg, 0, 1)
			})
		})
	}
	t.Run("concurrent first failures", func(t *testing.T) {
		logger, h := capture.New()
		clock := &testClock{at: sessionT0}
		entered, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		// The first failure reads sessionT0 and then stalls, as a goroutine
		// descheduled between reading the clock and taking the lock would.
		l := &warnLimiter{now: func() time.Time {
			at := clock.Now()
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return at
		}}
		fail := func(done chan<- struct{}) {
			l.log(logger, sessionWarnMsg, "session_id", "s", "error", errors.New("store down"))
			close(done)
		}
		firstDone, secondDone := make(chan struct{}), make(chan struct{})
		go fail(firstDone)
		<-entered
		clock.Set(sessionT0.Add(30 * time.Second))
		go fail(secondDone)
		// The second failure cannot finish while the first holds the
		// limiter; the wait gives a limiter that reads its clock outside the
		// lock time to log the second failure first.
		select {
		case <-secondDone:
		case <-time.After(100 * time.Millisecond):
		}
		close(release)
		<-firstDone
		<-secondDone
		checkWarns(t, h, sessionWarnMsg, 0)
		clock.Set(sessionT0.Add(61 * time.Second))
		l.log(logger, sessionWarnMsg, "session_id", "s", "error", errors.New("store down"))
		checkWarns(t, h, sessionWarnMsg, 0, 1)
	})
	t.Run("a session and a key failure each log", func(t *testing.T) {
		logger, h := capture.New()
		a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}, Config{Logger: logger})
		g, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateAPIKey(t.Context(), &Key{ID: 9, UserID: 1, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix}); err != nil {
			t.Fatal(err)
		}
		store.writeFails.Store(math.MaxInt32)
		mustAuthenticate(t, a, sessionRequest(t.Context(), token))
		clock.Set(sessionT0.Add(time.Second))
		mustAuthenticate(t, a, bearerRequest(g.Plaintext.Reveal()))
		checkWarns(t, h, sessionWarnMsg, 0)
		checkWarns(t, h, keyWarnMsg, 0)
		if s, k := warnAttrs(h, sessionWarnMsg), warnAttrs(h, keyWarnMsg); s[0]["session_id"].String() != "s" || k[0]["key_id"].Int64() != 9 {
			t.Errorf("WARN ids = (session %v, key %v), want (s, 9)", s[0]["session_id"], k[0]["key_id"])
		}
	})
}
