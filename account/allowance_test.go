package account_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/ratelimit"
)

// noTick is a CleanupInterval no test outlasts, so only a spent allowance
// wakes the failure leg.
func noTick(c *account.Config) { c.CleanupInterval = 24 * time.Hour }

func logged(rec *capture.Recorder, level slog.Level, msg string) int {
	n := 0
	for _, r := range rec.Records("") {
		if r.Level == level && r.Message == msg {
			n++
		}
	}
	return n
}

// missFree answers a compare against the zero Hash as a miss without
// deriving. MaxUntrustedCounts real derivations under -race outrun go test's
// ten-minute default on a loaded host; the bound needs the count, not the cost.
type missFree struct{ account.Hashing }

func (h missFree) Reserve(ctx context.Context) (account.HashPermit, error) {
	p, err := h.Hashing.Reserve(ctx)
	if err != nil {
		return nil, err
	}
	return missFreePermit{p}, nil
}

type missFreePermit struct{ account.HashPermit }

func (p missFreePermit) Verify(password string, encoded access.Hash) (ok, needsRehash bool, err error) {
	if encoded.IsZero() {
		p.Release()
		return false, false, nil
	}
	return p.HashPermit.Verify(password, encoded)
}

func TestUntrustedAllowanceBound(t *testing.T) {
	t.Parallel()
	t.Run("bound", func(t *testing.T) {
		t.Parallel()
		var hk armed
		wrap := func(h account.Hashing) account.Hashing { return missFree{h} }
		p := newPW(t, pwOptions{edit: noTick, hooks: account.Hooks{FailureSweep: hk.hook, WrapHasher: wrap}, wait: 10 * time.Minute})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		sweepFailures(t, p.svc) // the untrusted sign-in above kept its slot
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unhold := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unhold)
		hk.arm(func(context.Context) {
			hk.disarm()
			close(entered)
			<-release
		})
		const total = account.MaxUntrustedCounts + 1000
		var refused, counted atomic.Int64
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for i := range total {
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				_, err := p.login(t.Context(), clientAt(i), fmt.Sprintf("u%d", i), wrongPassword)
				re, isRefused := errors.AsType[*ratelimit.RefusedError](err)
				switch {
				case isRefused && re.Dimension == "untrusted" && re.RetryAfter == time.Second:
					refused.Add(1)
				case errors.Is(err, account.ErrInvalidCredentials):
					counted.Add(1)
				default:
					t.Errorf("attempt %d = %v", i, err)
				}
			})
		}
		wg.Wait()
		<-entered
		if counted.Load() != account.MaxUntrustedCounts || refused.Load() != 1000 {
			t.Errorf("while the prune is held: %d counted, %d refused; want %d and 1000", counted.Load(), refused.Load(), account.MaxUntrustedCounts)
		}
		stored := func() int {
			n := 0
			for i := range total {
				if _, found := record(t, p.mem, p.svc, fmt.Sprintf("u%d", i), false); found {
					n++
				}
			}
			return n
		}
		if n, bound := stored(), 2*1+2*account.MaxUntrustedCounts; n != account.MaxUntrustedCounts || n > bound {
			t.Errorf("records of the flood's names = %d, want exactly %d, within rule 15's bound %d", n, account.MaxUntrustedCounts, bound)
		}
		before := len(p.counted.verified())
		if _, err := p.login(t.Context(), trusted, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("trusted attempt while the allowance is spent = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", true); rec.Count != 1 || len(p.counted.verified()) != before+1 {
			t.Errorf("trusted attempt: count %d, compared %d; want it counted and compared", rec.Count, len(p.counted.verified())-before)
		}
		unhold()
		deadline := time.Now().Add(time.Minute)
		for account.AllowanceUsed(p.svc) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("the released prune did not refill the allowance within a minute")
			}
			time.Sleep(time.Millisecond)
		}
		if n := stored(); n != 0 {
			t.Errorf("records of the flood's names after the prune = %d, want none", n)
		}
		const finished = "account: failure-record sweep finished; untrusted allowance refilled"
		for logged(p.logs, slog.LevelInfo, finished) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond) // the line follows the refill the loop above saw
		}
		for _, msg := range []string{"account: untrusted allowance spent; failure-record sweep started", finished} {
			if n := logged(p.logs, slog.LevelInfo, msg); n != 1 {
				t.Errorf("INFO %q logged %d times, want once for the woken failure leg", msg, n)
			}
		}
		if _, err := p.login(t.Context(), clientAt(total), "after", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("untrusted attempt after the prune = %v, want ErrInvalidCredentials", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "after", false); rec.Count != 1 {
			t.Errorf("record after the prune = %d, want 1", rec.Count)
		}
	})
	t.Run("return_after_reset", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{edit: noTick, hooks: account.Hooks{Admitted: hk.hook}})
		ctx, cancel := context.WithCancel(t.Context())
		// The slot taken under the first interval goes back only after a
		// prune began the next one, in which another attempt took a slot.
		hk.arm(func(context.Context) {
			hk.disarm()
			if err := account.SweepFailures(t.Context(), p.svc); err != nil {
				t.Errorf("SweepFailures: %v", err)
			}
			if _, err := p.login(t.Context(), clientAt(2), "fresh", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("attempt in the new interval = %v", err)
			}
			cancel()
		})
		_, err := p.login(ctx, clientAt(1), "late", wrongPassword)
		if !errors.Is(err, access.ErrHashBusy) || !errors.Is(err, context.Canceled) {
			t.Fatalf("attempt whose context ended at admission = %v, want access.ErrHashBusy wrapping context.Canceled", err)
		}
		if got := account.AllowanceUsed(p.svc); got != 1 {
			t.Errorf("slots taken in the new interval = %d, want 1: the old interval's return changed it", got)
		}
		if _, found := record(t, p.mem, p.svc, "late", false); found {
			t.Error("the attempt refused at admission wrote a record")
		}
	})
}
