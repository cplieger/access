package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/ratelimit"
)

// hashing is the part of *access.Hasher the operations call. It is an
// interface so a test can count derivations at the hasher's boundary.
type hashing interface {
	Hash(ctx context.Context, password string) (access.Hash, error)
	Reserve(ctx context.Context) (hashPermit, error)
}

// hashPermit is the part of *access.HashPermit the counted path calls.
type hashPermit interface {
	Verify(password string, encoded access.Hash) (ok, needsRehash bool, err error)
	Release()
}

// hasherOf adapts *access.Hasher to hashing.
type hasherOf struct{ *access.Hasher }

func (h hasherOf) Reserve(ctx context.Context) (hashPermit, error) {
	p, err := h.Hasher.Reserve(ctx)
	if err != nil {
		return nil, err // a nil *access.HashPermit in the interface would not be nil
	}
	return p, nil
}

// untrustedRetry is the Retry-After of a refusal for a spent allowance: the
// woken prune refills it within about one store commit.
const untrustedRetry = time.Second

// passwordAttempt is one failure-counted password check on one canonical
// name, shared by sign-in, step-up and the current-password checks. It
// carries the durable count's result into the comparison and the success
// Update.
type passwordAttempt struct {
	res *ratelimit.Reservation
	// user is the name's user as the count Update read it; nil when no user
	// has the name.
	user     *access.User
	verified access.Hash // the stored hash the comparison verified
	rehash   access.Hash // the new hash at the hasher's parameters; zero for none
	// lockedAt is the LockedAt this attempt's own count set; zero when its
	// count set no lock.
	lockedAt time.Time
	ref      FailureRef
	// replaces is set when the success Update replaces or removes the hash,
	// so a rehash of the verified password would be derived for nothing.
	replaces bool
}

// newAttempt names res's record for canonical: the password's record in
// res's trust context.
func (s *Service) newAttempt(res *ratelimit.Reservation, canonical string) *passwordAttempt {
	return &passwordAttempt{res: res, ref: FailureRef{
		Name: failureName(s.failureMAC(), canonical), Method: access.MethodPassword, Trusted: res.Trusted(),
	}}
}

// verifyCounted admits, counts and compares a's attempt, with an allowance
// slot when slot is set, then rehashes an old hash. nil means password
// verified against a.verified, and the caller's success Update settles
// a.res. Every other answer has settled a.res: Cancel before the count, Fail
// from the count on.
func (s *Service) verifyCounted(ctx context.Context, a *passwordAttempt, canonical string, password access.Secret, slot bool) error {
	permit, err := s.admitCount(ctx, a.res, slot)
	if err != nil {
		return err
	}
	defer permit.Release()
	lockedBefore, err := s.count(ctx, a, canonical)
	if err != nil {
		a.res.Fail()
		return err
	}
	var hash access.Hash // the zero hash fails at full cost: every arm derives once
	if u := a.user; u != nil && u.Enabled && !lockedBefore {
		hash = u.PasswordHash
	}
	if s.hooks.beforeVerify != nil {
		s.hooks.beforeVerify(ctx)
	}
	text := password.Reveal()
	ok, needsRehash, err := permit.Verify(text, hash)
	switch {
	case errors.Is(err, access.ErrHashBusy):
		a.res.Fail()
		return err
	case err != nil:
		s.logger().Error("account: a stored password hash exceeds the hash budget and can never verify", "user_id", a.user.ID, "err", err)
		a.res.Fail()
		return ErrInvalidCredentials
	case !ok && lockedBefore:
		a.res.Fail()
		return failreason.Wrap(ErrInvalidCredentials, failreason.MethodLocked)
	case !ok:
		a.res.Fail()
		return ErrInvalidCredentials
	}
	a.verified = hash
	if s.hooks.afterVerify != nil {
		s.hooks.afterVerify(ctx)
	}
	if needsRehash {
		s.rehash(ctx, a, text)
	}
	return nil
}

// rehash derives a's verified password at the hasher's parameters for the
// success Update, unless that Update replaces the hash anyway. A busy
// budget or an ended ctx skips it; the next sign-in retries.
func (s *Service) rehash(ctx context.Context, a *passwordAttempt, password string) {
	if a.replaces {
		return
	}
	var err error
	if a.rehash, err = s.hasher.Hash(ctx, password); err != nil {
		s.logger().Debug("account: password rehash skipped; the next sign-in retries", "err", err)
	}
}

// admitCount takes a hash permit, then an allowance slot when slot is set,
// refusing before anything is written. Only a ctx that is still live
// once both are held keeps them.
func (s *Service) admitCount(ctx context.Context, res *ratelimit.Reservation, slot bool) (hashPermit, error) {
	permit, err := s.hasher.Reserve(ctx)
	if err != nil {
		res.Cancel()
		return nil, err
	}
	var gen uint64
	if slot {
		var ok bool
		if gen, ok = s.allowance.take(); !ok {
			permit.Release()
			res.Cancel()
			return nil, &ratelimit.RefusedError{Dimension: "untrusted", RetryAfter: untrustedRetry}
		}
	}
	if s.hooks.admitted != nil {
		s.hooks.admitted(ctx)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		if slot {
			s.allowance.give(gen)
		}
		permit.Release()
		res.Cancel()
		return nil, fmt.Errorf("%w: %w", access.ErrHashBusy, ctxErr)
	}
	return permit, nil
}

// count is one Update reading the name's user and a's record,
// adding one, locking at FailureCap, and writing the record, the same
// calls whether or not a user has the name. It reports whether the record
// was already locked.
func (s *Service) count(ctx context.Context, a *passwordAttempt, canonical string) (lockedBefore bool, err error) {
	err = s.update(ctx, func(tx Tx) error {
		a.user, a.lockedAt, lockedBefore = nil, time.Time{}, false
		u, found, readErr := tx.UserByUsername(ctx, canonical)
		if readErr != nil {
			return readErr
		}
		rec, _, readErr := tx.AuthFailure(ctx, a.ref)
		if readErr != nil {
			return readErr
		}
		lockedBefore = rec.Locked
		rec.FailureRef = a.ref
		rec.Count++
		if rec.Count >= FailureCap && !rec.Locked {
			rec.Locked, rec.LockedAt, rec.Unreported = true, s.stamp(), true
			a.lockedAt = rec.LockedAt
		}
		if found {
			a.user = u
		}
		return tx.PutAuthFailure(ctx, rec)
	})
	return lockedBefore, err
}

// resetFailures runs inside the success Update: of the password's two
// records of a's name, one that is not locked goes, a locked one keeps its
// lock at Count 0, and the lock a's own count set goes too, since a's
// attempt was no failure. LockedAt, stamped at the millisecond, is that
// lock's identity. It reports whether the lock had been reported, which the
// caller follows with EventMethodReenabled.
func resetFailures(ctx context.Context, tx Tx, a *passwordAttempt) (bool, error) {
	var keep []FailureCount
	found, reenabled := false, false
	for _, trusted := range []bool{false, true} {
		rec, ok, readErr := tx.AuthFailure(ctx, FailureRef{Name: a.ref.Name, Method: access.MethodPassword, Trusted: trusted})
		if readErr != nil {
			return false, readErr
		}
		if !ok {
			continue
		}
		found = true
		own := trusted == a.ref.Trusted && rec.Locked && !a.lockedAt.IsZero() && rec.LockedAt.Equal(a.lockedAt)
		switch {
		case own:
			reenabled = !rec.Unreported
		case rec.Locked:
			rec.Count = 0
			keep = append(keep, rec)
		}
	}
	if !found {
		return false, nil
	}
	if err := tx.DeleteAuthFailures(ctx, a.ref.Name, []access.Method{access.MethodPassword}); err != nil {
		return false, err
	}
	for i := range keep {
		if err := tx.PutAuthFailure(ctx, keep[i]); err != nil {
			return false, err
		}
	}
	return reenabled, nil
}

// commitVerified is the head of every verified password's success Update:
// it goes on only while a's user is still stored, enabled and holding the
// verified hash (else ErrInvalidCredentials, writing nothing), writes the
// rehash, and resets the records. It returns the user as stored and resetFailures'
// answer.
func commitVerified(ctx context.Context, tx Tx, a *passwordAttempt) (*access.User, bool, error) {
	u, found, err := tx.UserByID(ctx, a.user.ID)
	switch {
	case err != nil:
		return nil, false, err
	case !found || !u.Enabled || !u.PasswordHash.Equal(a.verified):
		return nil, false, refuse(ErrInvalidCredentials)
	}
	if !a.rehash.IsZero() {
		u.PasswordHash = a.rehash
		if updateErr := tx.UpdateUser(ctx, u); updateErr != nil {
			return nil, false, updateErr
		}
	}
	reenabled, err := resetFailures(ctx, tx, a)
	if err != nil {
		return nil, false, err
	}
	return u, reenabled, nil
}
