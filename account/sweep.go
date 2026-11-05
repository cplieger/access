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
	s.sweepFailuresLogged(ctx)
	s.logger().Info("account: sweep finished", "sessions", sessions, "tokens", tokens)
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
			s.emit(events[i])
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
// losing a count. After the commit it refills the untrusted allowance, so a
// failed prune leaves it spent, then emits one EventMethodLocked per
// reported lock.
func (s *Service) sweepFailures(ctx context.Context) error {
	if s.hooks.failureSweep != nil {
		s.hooks.failureSweep(ctx)
	}
	var events []Event
	err := s.update(ctx, func(tx Tx) error {
		events = nil
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
		events, err = reportLocks(ctx, tx, userOf)
		if err != nil {
			return err
		}
		_, err = tx.PruneAuthFailures(ctx, keep)
		return err
	})
	if err != nil {
		return err
	}
	s.allowance.reset()
	for i := range events {
		s.emit(events[i])
	}
	return nil
}

// reportLocks clears Unreported on every unreported lock of a user's name
// and returns one EventMethodLocked per lock it cleared.
func reportLocks(ctx context.Context, tx Tx, userOf map[string]int64) ([]Event, error) {
	locks, err := tx.UnreportedLocks(ctx)
	if err != nil {
		return nil, err
	}
	var events []Event
	for i := range locks {
		lock := locks[i]
		userID, ok := userOf[lock.Name]
		if !ok {
			continue
		}
		lock.Unreported = false
		if err := tx.PutAuthFailure(ctx, lock); err != nil {
			return nil, err
		}
		events = append(events, Event{
			Kind: EventMethodLocked, At: lock.LockedAt, UserID: userID,
			Method: lock.Method, Trusted: lock.Trusted,
		})
	}
	return events, nil
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
