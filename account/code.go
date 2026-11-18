package account

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/totp"
)

// The code inputs a MalformedError names.
const (
	fieldCode        = "code"
	fieldCurrentCode = "current_code"
)

// codeCheck is one counted check of a TOTP code against userID's record,
// shared by the code step, step-up and every proof's code arm.
type codeCheck struct {
	// missing answers a user with no record: the code step's ticket ends,
	// every other site refuses the code.
	missing error
	// recheck, when set, runs first in the count's Update, so a refusal
	// there writes no failure record: the code step's ticket re-check.
	recheck func(tx Tx) error
	raw     string
	field   string     // the input's name, for a MalformedError
	invalid string     // the CodeError Reason of a code that matches no step
	ref     FailureRef // the TOTP record in the reservation's trust context
	userID  int64
}

// newCodeCheck is a check of raw for u in res's trust context.
func (s *Service) newCodeCheck(res *ratelimit.Reservation, u *access.User, raw string) codeCheck {
	return codeCheck{
		ref:     FailureRef{Name: failureName(s.failureMAC(), u.Username), Method: access.MethodTOTP, Trusted: res.Trusted()},
		userID:  u.ID,
		raw:     raw,
		field:   fieldCode,
		invalid: ReasonCodeInvalid,
		missing: &CodeError{Reason: ReasonCodeInvalid},
	}
}

// countCode is ch's count, in its own committed Update, and its match:
// RFC 6238 §5.2's one acceptance needs the count to survive whatever the
// match then answers (Vikunja GHSA-fgfv-pv97-6cmj). A refused recheck, a
// record no key opens (ErrSecondFactorUnavailable) and a malformed code (a
// *MalformedError) write nothing; a locked record is method_locked whatever
// the code.
// Otherwise it adds one, locking at FailureCap, and answers the match or
// the code's *CodeError. It settles res on every refusal.
func (s *Service) countCode(ctx context.Context, res *ratelimit.Reservation, ch *codeCheck) (codeMatch, error) {
	var got counted
	err := s.update(ctx, func(tx Tx) error {
		var countErr error
		got, countErr = s.countIn(ctx, tx, ch)
		return countErr
	})
	if s.hooks.codeCounted != nil {
		s.hooks.codeCounted(ctx)
	}
	if got.unopenable {
		s.logger().Error("account: a TOTP record opens under no sealer key; restore the key or reset the user's second factor", "user_id", ch.userID)
	}
	if err == nil {
		switch got.result {
		case totp.Matched:
			return got.codeMatch, nil
		case totp.Reused:
			err = &CodeError{Reason: ReasonCodeReused}
		default:
			err = &CodeError{Reason: ch.invalid}
		}
	}
	settleRefused(res, err)
	return codeMatch{}, err
}

// codeMatch is a matched step, the CreatedAt of the record it matched,
// which identifies the enrolment whose secret produced the code, and the
// LockedAt its count stamped (zero for none), which resetFailures reads.
type codeMatch struct {
	record   time.Time
	lockedAt time.Time
	step     int64
}

// counted is what countCode's Update found.
type counted struct {
	codeMatch
	result     totp.Result
	unopenable bool
}

// countIn is countCode's Update, inside tx.
func (s *Service) countIn(ctx context.Context, tx Tx, ch *codeCheck) (counted, error) {
	if ch.recheck != nil {
		if err := ch.recheck(tx); err != nil {
			return counted{}, err
		}
	}
	rec, found, err := tx.TOTPByUserID(ctx, ch.userID)
	switch {
	case err != nil:
		return counted{}, err
	case !found:
		return counted{}, refuse(ch.missing)
	}
	secret, _, err := s.openTOTP(&rec)
	if err != nil {
		return counted{unopenable: true}, refuse(ErrSecondFactorUnavailable)
	}
	got := counted{record: rec.CreatedAt}
	if got.step, got.result = totp.Match(secret, ch.raw, s.now(), rec.LastStep); got.result == totp.Malformed {
		return counted{}, refuse(&MalformedError{Field: ch.field})
	}
	got.lockedAt, err = s.addFailure(ctx, tx, ch.ref)
	return got, err
}

// addFailure counts one attempt on ref's record inside tx, locking it at
// FailureCap, and returns the LockedAt it stamped (zero for none); a record
// already locked is method_locked, writing nothing.
func (s *Service) addFailure(ctx context.Context, tx Tx, ref FailureRef) (lockedAt time.Time, err error) {
	f, _, err := tx.AuthFailure(ctx, ref)
	switch {
	case err != nil:
		return time.Time{}, err
	case f.Locked:
		return time.Time{}, refuse(&CodeError{Reason: ReasonMethodLocked})
	}
	f.FailureRef = ref
	f.Count++
	if f.Count >= FailureCap {
		f.Locked, f.LockedAt, f.Unreported = true, s.stamp(), true
	}
	return f.LockedAt, tx.PutAuthFailure(ctx, f)
}

// settleRefused settles res for a refused check: a counted code fails it,
// and an answer given before the count cancels it.
func settleRefused(res *ratelimit.Reservation, err error) {
	if errors.Is(err, ErrCodeInvalid) {
		res.Fail()
		return
	}
	res.Cancel()
}

// commitCode is the head of a matched code's success Update, inside tx: it
// re-reads the record, answers one replaced since the count as gone (ch's
// missing), refuses a step at or below its LastStep, so of two parallel
// matches only one commits (Gitea GHSA-gx3v-q759-g323), then writes the
// step with the secret sealed under the first key and runs resetFailures
// on the check's record, returning its answer.
func (s *Service) commitCode(ctx context.Context, tx Tx, ch *codeCheck, m codeMatch) (reenabled bool, err error) {
	rec, found, err := tx.TOTPByUserID(ctx, ch.userID)
	switch {
	case err != nil:
		return false, err
	case !found, !rec.CreatedAt.Equal(m.record):
		return false, refuse(ch.missing)
	case rec.LastStep >= m.step:
		return false, refuse(&CodeError{Reason: ReasonCodeReused})
	}
	secret, _, err := s.openTOTP(&rec)
	if err != nil {
		return false, refuse(ErrSecondFactorUnavailable)
	}
	if rec.Sealed, err = s.sealTOTP(ch.userID, secret); err != nil {
		return false, err
	}
	rec.LastStep = m.step
	if err := tx.SetTOTP(ctx, rec); err != nil {
		return false, err
	}
	return resetFailures(ctx, tx, ch.ref, m.lockedAt)
}

// totpPurpose is the at-rest purpose of userID's TOTP secret, so a record
// copied onto another user's row does not open.
func totpPurpose(userID int64) string { return "totp:" + strconv.FormatInt(userID, 10) }

// sealTOTP seals secret at rest for userID under the sealer's first key.
func (s *Service) sealTOTP(userID int64, secret []byte) (string, error) {
	return s.totp.Sealer.SealAtRest(totpPurpose(userID), secret)
}

// openTOTP opens rec's secret; current reports the first key opened it.
func (s *Service) openTOTP(rec *access.TOTP) (secret []byte, current bool, err error) {
	return s.totp.Sealer.OpenAtRest(totpPurpose(rec.UserID), rec.Sealed)
}

// proven is a verified code or assertion: a code's match, which the site's
// own Update commits, and the reservation its commit settles. An assertion
// holds neither, since its ceremony was spent when it verified.
type proven struct {
	res   *ratelimit.Reservation
	check *codeCheck
	match codeMatch
}

// commit is commitCode for a code, journalling a cleared reported lock by
// p; nothing for an assertion.
func (pr *proven) commit(ctx context.Context, s *Service, tx Tx, j *journal, p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if pr.check == nil {
		return nil
	}
	reenabled, err := s.commitCode(ctx, tx, pr.check, pr.match)
	if err == nil {
		j.addReenabled(reenabled, pr.check.ref, s.now(), eventActor(As(p)))
	}
	return err
}

// settle settles a code's reservation by its site's result.
func (pr *proven) settle(err error) {
	switch {
	case pr.res == nil:
	case err != nil:
		pr.res.Fail()
	default:
		pr.res.Succeed()
	}
}
