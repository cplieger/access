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
// reason). No lock in either context is ErrMethodNotLocked. The same
// Update appends EventMethodLocked for each lock the sweep had not
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
	name := failureName(s.failureMAC(), p.User.Username)
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		locks, err := lockedRecords(ctx, tx, name, []access.Method{method})
		if err != nil {
			return err
		}
		if len(locks) == 0 {
			return refuse(ErrMethodNotLocked)
		}
		if err := tx.DeleteAuthFailures(ctx, name, []access.Method{method}); err != nil {
			return err
		}
		s.addCleared(j, p.User.ID, locks, eventActor(As(p)))
		return nil
	})
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

// addCleared adds the entries of the locks a clear deleted: EventMethodLocked
// for each the sweep had not reported, then EventMethodReenabled per lock.
func (s *Service) addCleared(j *journal, userID int64, locks []FailureCount, actor EventActor) {
	for i := range locks {
		if locks[i].Unreported {
			j.add(Event{Kind: EventMethodLocked, At: locks[i].LockedAt, UserID: userID, Method: locks[i].Method, Trusted: locks[i].Trusted})
		}
	}
	at := s.now()
	for i := range locks {
		j.add(Event{Kind: EventMethodReenabled, At: at, UserID: userID, Method: locks[i].Method, Trusted: locks[i].Trusted, Actor: actor})
	}
}
