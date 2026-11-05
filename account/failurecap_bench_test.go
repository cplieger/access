package account_test

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// BenchmarkCountCommit is one wrong-password PasswordLogin per iteration,
// reporting the count Update's share of each attempt's time and the durable
// commits per attempt, on the MemStore and on a store grouping concurrent
// Updates behind bbolt's default 10 ms batch delay
// (go.etcd.io/bbolt@v1.5.0/db.go:198).
func BenchmarkCountCommit(b *testing.B) {
	for _, grouped := range []bool{false, true} {
		for _, callers := range []int{1, 16} {
			b.Run(fmt.Sprintf("grouped_%t/callers_%d", grouped, callers), func(b *testing.B) {
				fs := newFaultStore()
				if grouped {
					fs.group(10 * time.Millisecond)
				}
				p := newPW(b, pwOptions{store: fs, wait: 10 * time.Minute})
				passwordUser(b, p.mem, p.hasher, "alice", goodPassword)
				attempt := func(i int) time.Duration {
					start := time.Now()
					_, err := p.login(b.Context(), clientAt(i), "alice", wrongPassword)
					if !errors.Is(err, account.ErrInvalidCredentials) {
						b.Errorf("PasswordLogin = %v", err)
					}
					return time.Since(start)
				}
				published, inUpdate := fs.published.Load(), fs.updateNanos.Load()
				var spent atomic.Int64
				var n atomic.Int64
				if callers == 1 {
					for b.Loop() {
						spent.Add(int64(attempt(int(n.Add(1)))))
					}
				} else {
					b.SetParallelism(max(1, callers/runtime.GOMAXPROCS(0)))
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							spent.Add(int64(attempt(int(n.Add(1)))))
						}
					})
				}
				b.ReportMetric(float64(fs.updateNanos.Load()-inUpdate)/float64(spent.Load()), "commit-share")
				b.ReportMetric(float64(fs.published.Load()-published)/float64(n.Load()), "commits/attempt")
			})
		}
	}
}

// BenchmarkPruneAtBound times one failure-leg Update over rule 15's bound
// for 1,000 users: two records of each user's name and 2 ×
// MaxUntrustedCounts records of other names.
func BenchmarkPruneAtBound(b *testing.B) {
	const users = 1000
	p := newPW(b, pwOptions{})
	ctx := b.Context()
	err := p.mem.Update(ctx, func(tx account.Tx) error {
		for i := range users {
			if err := tx.CreateUser(ctx, &access.User{Username: fmt.Sprintf("user%d", i), Role: access.RoleUser, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle()}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatalf("seeding users: %v", err)
	}
	fill := func() {
		err := p.mem.Update(ctx, func(tx account.Tx) error {
			put := func(name string, trusted bool) error {
				return tx.PutAuthFailure(ctx, account.FailureCount{Name: name, Method: access.MethodPassword, Trusted: trusted, Count: 1})
			}
			for i := range users {
				name := account.FailureName(p.svc, fmt.Sprintf("user%d", i))
				if err := put(name, false); err != nil {
					return err
				}
				if err := put(name, true); err != nil {
					return err
				}
			}
			for i := range 2 * account.MaxUntrustedCounts {
				if err := put(account.FailureName(p.svc, fmt.Sprintf("other%d", i)), false); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			b.Fatalf("filling records: %v", err)
		}
	}
	var swept time.Duration
	for b.Loop() {
		b.StopTimer()
		fill()
		b.StartTimer()
		start := time.Now()
		if err := account.SweepFailures(ctx, p.svc); err != nil {
			b.Fatalf("SweepFailures: %v", err)
		}
		swept += time.Since(start)
	}
	b.ReportMetric(float64(swept)/float64(time.Millisecond)/float64(b.N), "ms/sweep")
}
