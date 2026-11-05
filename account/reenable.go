package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/failreason"
)

// ReenableMethod clears method's failure-cap locks and counts for p's own
// user, in both trust contexts, in one Update: nil means durable, and an
// error leaves the lock. p must be a full session (ErrSessionRequired)
// within Rules().RecentAuth (access.ErrRecentAuthRequired) whose AuthMethod
// is not method (access.ErrRecentAuthRequired too, carrying an internal
// reason). No lock in either context is ErrMethodNotLocked. After the
// commit it emits EventMethodLocked for each lock the sweep had not
// reported, then EventMethodReenabled per lock.
func (s *Service) ReenableMethod(ctx context.Context, p access.Principal, method access.Method) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return sessErr
	}
	if authErr := s.recentAuth(r, p); authErr != nil {
		return authErr
	}
	if p.Method == method {
		return failreason.Wrap(access.ErrRecentAuthRequired, failreason.ReenableNeedsOtherMethod)
	}
	locks, err := s.clearLocks(ctx, failureName(s.failureMAC(), p.User.Username), method)
	if err != nil {
		return err
	}
	s.emitCleared(p.User.ID, locks, eventActor(As(p)))
	return nil
}

// clearLocks deletes name's records of method in one Update and returns
// the locked ones it deleted, or ErrMethodNotLocked, writing nothing, when
// neither context is locked.
func (s *Service) clearLocks(ctx context.Context, name string, method access.Method) ([]FailureCount, error) {
	var locks []FailureCount
	err := s.update(ctx, func(tx Tx) error {
		var readErr error
		if locks, readErr = lockedRecords(ctx, tx, name, []access.Method{method}); readErr != nil {
			return readErr
		}
		if len(locks) == 0 {
			return refuse(ErrMethodNotLocked)
		}
		return tx.DeleteAuthFailures(ctx, name, []access.Method{method})
	})
	return locks, err
}

// lockedRecords reads name's locked records of methods inside tx, untrusted
// before trusted for each method.
func lockedRecords(ctx context.Context, tx Tx, name string, methods []access.Method) ([]FailureCount, error) {
	var locks []FailureCount
	for _, method := range methods {
		for _, trusted := range []bool{false, true} {
			ref := FailureRef{Name: name, Method: method, Trusted: trusted}
			rec, found, err := tx.AuthFailure(ctx, ref)
			if err != nil {
				return nil, err
			}
			if found && rec.Locked {
				rec.FailureRef = ref
				locks = append(locks, rec)
			}
		}
	}
	return locks, nil
}

// emitCleared reports the locks a committed clear deleted: EventMethodLocked
// for each the sweep had not reported, then EventMethodReenabled per lock.
func (s *Service) emitCleared(userID int64, locks []FailureCount, actor EventActor) {
	for i := range locks {
		if locks[i].Unreported {
			s.emit(Event{Kind: EventMethodLocked, At: locks[i].LockedAt, UserID: userID, Method: locks[i].Method, Trusted: locks[i].Trusted})
		}
	}
	at := s.now()
	for i := range locks {
		s.emit(Event{Kind: EventMethodReenabled, At: at, UserID: userID, Method: locks[i].Method, Trusted: locks[i].Trusted, Actor: actor})
	}
}
