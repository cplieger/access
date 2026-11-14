package account

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"time"
)

// run is the cleanup sweep: one pass every interval, and the failure leg
// alone whenever the untrusted allowance is spent, until Shutdown cancels
// ctx, which keeps New's values for every store call.
func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep(ctx)
		case <-s.allowance.wake:
			s.logger().Info("account: untrusted allowance spent; failure-record sweep started")
			if s.sweepFailuresLogged(ctx) {
				s.logger().Info("account: failure-record sweep finished; untrusted allowance refilled")
			}
		}
	}
}

// sweep runs each leg on the tick's one now. A leg's store error is logged
// and retried on the next tick; Shutdown ends the pass between legs.
func (s *Service) sweep(ctx context.Context) {
	now := s.now()
	s.logger().Info("account: sweep started")
	sessions := s.sweepSessions(ctx, now)
	if ctx.Err() != nil {
		return
	}
	tokens, err := s.store.CleanupExpiredOneTimeTokens(ctx, now)
	if err != nil {
		s.logger().Warn("account: expired-token sweep failed; retrying next tick", "err", err)
	}
	s.pending.prune(now)
	if ctx.Err() != nil {
		return
	}
	keys := s.sweepRetiredKeySecrets(ctx, now)
	if ctx.Err() != nil {
		return
	}
	s.sweepFailuresLogged(ctx)
	if ctx.Err() != nil {
		return
	}
	s.sweepLog(ctx, now)
	s.logger().Info("account: sweep finished", "sessions", sessions, "tokens", tokens, "keys", keys)
}

// sweepRetiredKeySecrets clears the previous secrets that no longer verify
// at now in calls of at most MaxSweepBatch, again while a call clears a
// full batch and ctx is live; a failed call ends the leg for this tick. It
// returns how many keys it cleared.
func (s *Service) sweepRetiredKeySecrets(ctx context.Context, now time.Time) int {
	cleared := 0
	for {
		n, err := s.store.ClearRetiredAPIKeySecrets(ctx, now, MaxSweepBatch)
		if err != nil {
			s.logger().Warn("account: retired key-secret sweep failed; retrying next tick", "err", err)
			return cleared
		}
		cleared += n
		if n < MaxSweepBatch || ctx.Err() != nil {
			return cleared
		}
	}
}

// sweepSessions deletes the sessions expired at now in calls of at most
// MaxSweepBatch, reading Authenticator.Timeouts() before each call so a
// timeout moved during a long drain applies from the next call, and emits
// each call's EventSessionsExpired before the next call. It calls again
// while a call returns a full batch and ctx is live; a failed call ends the
// leg for this tick, and earlier calls' events stand. It returns how many
// sessions it deleted.
func (s *Service) sweepSessions(ctx context.Context, now time.Time) int {
	deleted := 0
	for {
		refs, err := s.store.CleanupExpiredSessions(ctx, now, s.authn.Timeouts(), MaxSweepBatch)
		if err != nil {
			s.logger().Warn("account: expired-session sweep failed; retrying next tick", "err", err)
			return deleted
		}
		deleted += len(refs)
		events := sessionsExpired(refs, now)
		for i := range events {
			s.deliver(events[i])
		}
		if len(refs) < MaxSweepBatch {
			return deleted
		}
		if s.hooks.betweenSessionCalls != nil {
			s.hooks.betweenSessionCalls(ctx)
		}
		if ctx.Err() != nil {
			return deleted
		}
	}
}

// sweepFailuresLogged is sweepFailures with its error logged at ERROR; it
// reports whether the leg committed.
func (s *Service) sweepFailuresLogged(ctx context.Context) bool {
	if err := s.sweepFailures(ctx); err != nil {
		s.logger().Error("account: failure-record sweep failed; once the untrusted allowance is spent, "+
			"untrusted password sign-in is refused until a sweep commits; retrying next tick", "err", err)
		return false
	}
	return true
}

// sweepFailures runs the failure-record leg in one Update: it names every
// user's records, reports each unreported lock of a user (clearing its
// Unreported), and prunes every record whose name is no user's. Reading the
// users and pruning in one transaction keeps a user created meanwhile from
// losing a count. Each reported lock's EventMethodLocked is appended in the
// same Update that clears its mark, so a failed append leaves it to the
// next sweep. After the commit it refills the untrusted allowance, so a
// failed prune leaves it spent.
func (s *Service) sweepFailures(ctx context.Context) error {
	if s.hooks.failureSweep != nil {
		s.hooks.failureSweep(ctx)
	}
	err := s.change(ctx, origin{}, func(tx Tx, j *journal) error {
		users, err := tx.ListUsers(ctx)
		if err != nil {
			return err
		}
		mac := s.failureMAC()
		keep := make([]string, 0, len(users))
		userOf := make(map[string]int64, len(users))
		for i := range users {
			name := failureName(mac, users[i].Username)
			keep = append(keep, name)
			userOf[name] = users[i].ID
		}
		if reportErr := reportLocks(ctx, tx, j, userOf); reportErr != nil {
			return reportErr
		}
		_, err = tx.PruneAuthFailures(ctx, keep)
		return err
	})
	if err != nil {
		return err
	}
	s.allowance.reset()
	return nil
}

// reportLocks clears Unreported on every unreported lock of a user's name
// and adds one EventMethodLocked, at the lock time, per lock it cleared.
func reportLocks(ctx context.Context, tx Tx, j *journal, userOf map[string]int64) error {
	locks, err := tx.UnreportedLocks(ctx)
	if err != nil {
		return err
	}
	for i := range locks {
		lock := locks[i]
		userID, ok := userOf[lock.Name]
		if !ok {
			continue
		}
		lock.Unreported = false
		if err := tx.PutAuthFailure(ctx, lock); err != nil {
			return err
		}
		j.add(Event{
			Kind: EventMethodLocked, At: lock.LockedAt, UserID: userID,
			Method: lock.Method, Trusted: lock.Trusted,
		})
	}
	return nil
}

// sweepLog is the log leg: each class's entries older than LogMaxAge at
// now, in calls of MaxSweepBatch. A class's store error is logged and
// retried on the next tick; the cap holds at append and needs no pass.
func (s *Service) sweepLog(ctx context.Context, now time.Time) {
	for _, class := range LogClasses() {
		err := s.pruneLog(ctx, LogPrune{Class: class, Before: now.Add(-s.logMaxAge), Limit: MaxSweepBatch})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.logger().Warn("account: security-log age prune failed; retrying next tick", "class", class, "err", err)
		}
	}
}

// drainLog prunes every class to its cap, then to LogMaxAge, before New
// returns: each append's trim removes at most what it added, so a cap
// lowered since the last run is applied here and never in a request.
func (s *Service) drainLog(ctx context.Context) error {
	before := s.now().Add(-s.logMaxAge)
	for _, class := range LogClasses() {
		for _, p := range []LogPrune{
			{Class: class, Keep: s.logCap(class), Limit: MaxSweepBatch},
			{Class: class, Before: before, Limit: MaxSweepBatch},
		} {
			if err := s.pruneLog(ctx, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// pruneLog runs p in Updates of its own until one removes fewer than
// p.Limit. A ctx that ends with entries left is an error, so New never
// returns over a log past its bound.
func (s *Service) pruneLog(ctx context.Context, p LogPrune) error {
	for {
		var n int
		err := s.update(ctx, func(tx Tx) error {
			var err error
			n, err = tx.PruneLog(ctx, p)
			return err
		})
		switch {
		case err != nil, n < p.Limit:
			return err
		case ctx.Err() != nil:
			return storeErr(ctx.Err())
		}
	}
}

// failureMAC is a fresh HMAC-SHA256 under the failure key, for one caller's
// names only: a cached one would hold the key's pads (RFC 2104 §2).
func (s *Service) failureMAC() hash.Hash {
	return hmac.New(sha256.New, []byte(s.failureKey.Reveal()))
}

// failureName is the record name of a canonical username: the hex of its
// HMAC under mac's key, so the name itself is never stored.
func failureName(mac hash.Hash, canonical string) string {
	mac.Reset()
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
