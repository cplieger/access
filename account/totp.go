package account

import (
	"context"
	"math"

	"github.com/cplieger/access"
	"github.com/cplieger/access/totp"
)

// TOTPEnrolment is a begun TOTP enrolment. URI and Text carry the new
// secret, shown only in this answer; Ticket is what FinishTOTP takes, for
// ten minutes, from the session that began it.
type TOTPEnrolment struct {
	URI    access.Secret // the Key Uri Format's otpauth URI, for a QR code
	Text   access.Secret // the secret in base32, for typing in
	Ticket access.Secret
}

// TOTPFinish is FinishTOTP's input: the enrolment's ticket, a code of the
// new secret, and, when a record already exists, a current code of it.
type TOTPFinish struct {
	Ticket      access.Secret
	Code        string
	CurrentCode string
}

// Enrolled is the answer of a change that bound a second factor.
type Enrolled struct {
	// RecoveryCode is the recovery code this binding issued, shown only
	// here; zero when it issued none.
	RecoveryCode access.Secret
}

// BeginTOTP starts enrolling an authenticator app for p's own user, for a
// full session within RecentAuth on a secure request. A TOTP that is not
// usable is ErrTOTPDisabled, a dormant user ErrSSOOnly and a user holding
// no password ErrPasswordRequired, each before a secret is drawn.
func (s *Service) BeginTOTP(ctx context.Context, p access.Principal) (TOTPEnrolment, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(plainRefused, p.Secure, p)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	if !s.totpOn(r) {
		return TOTPEnrolment{}, ErrTOTPDisabled
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return TOTPEnrolment{}, err
	}
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return TOTPEnrolment{}, modeErr
	}
	if u.PasswordHash.IsZero() {
		return TOTPEnrolment{}, ErrPasswordRequired
	}
	secret := totp.NewSecret()
	id := s.pending.put(purposeEnrolTOTP, pending{user: *u, enrol: enrolment{issued: s.stamp(), sessionID: p.SessionID, secret: access.NewSecret(string(secret))}}, s.now())
	return TOTPEnrolment{
		URI:    access.NewSecret(totp.URI(s.totp.Issuer, u.Username, secret)),
		Text:   access.NewSecret(totp.Text(secret)),
		Ticket: access.NewSecret(id),
	}, nil
}

// FinishTOTP stores the secret in.Ticket's enrolment holds once in.Code
// matches it, with its step spent. The ticket must be p's session's own and
// no older than a stored record (else access.ErrTokenInvalid). Replacing a
// record takes in.CurrentCode of the old secret (none:
// ErrSecondFactorProofRequired), counted as a proof; its refusals carry
// current_code_invalid, and the new code's code_invalid. Its refusals are
// BeginTOTP's, plus a plain c, all re-checked in the one Update.
func (s *Service) FinishTOTP(ctx context.Context, c Client, p access.Principal, in TOTPFinish) (Enrolled, error) { //nolint:gocritic // hugeParam: the request's Client, Principal and input, read once
	r, err := s.beginRecentSession(plainRefused, c.Secure && p.Secure, p)
	if err != nil {
		return Enrolled{}, err
	}
	if !s.totpOn(r) {
		return Enrolled{}, ErrTOTPDisabled
	}
	u, e, err := s.enrolmentOf(ctx, p, in)
	if err != nil {
		return Enrolled{}, err
	}
	var pr proven
	if e.replacing {
		if pr, err = s.verifyCode(ctx, c, u, in.CurrentCode, fieldCurrentCode, ReasonCurrentCodeInvalid); err != nil {
			return Enrolled{}, err
		}
	}
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		return s.storeEnrolment(ctx, tx, j, p, &pr, e)
	})
	pr.settle(err)
	if err != nil {
		return Enrolled{}, err
	}
	s.pending.drop(in.Ticket.Reveal())
	return Enrolled{}, nil
}

// enrolmentOf is FinishTOTP's checks before any count, for p's user: the
// ticket p's own session began, the refusals BeginTOTP gives, the record
// it replaces and the current code that needs, and in.Code matching the new
// secret.
func (s *Service) enrolmentOf(ctx context.Context, p access.Principal, in TOTPFinish) (*access.User, enrolled, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	entry, ok := s.pending.peek(in.Ticket.Reveal(), purposeEnrolTOTP, s.now())
	if !ok || entry.user.ID != p.User.ID || entry.enrol.sessionID != p.SessionID {
		return nil, enrolled{}, access.ErrTokenInvalid
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return nil, enrolled{}, err
	}
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return nil, enrolled{}, modeErr
	}
	if u.PasswordHash.IsZero() {
		return nil, enrolled{}, ErrPasswordRequired
	}
	e := enrolled{secret: []byte(entry.enrol.secret.Reveal())}
	if e.old, e.replacing, err = s.store.TOTPByUserID(ctx, u.ID); err != nil {
		return nil, enrolled{}, storeErr(err)
	}
	switch {
	case e.replacing && entry.enrol.issued.Before(e.old.CreatedAt):
		return nil, enrolled{}, access.ErrTokenInvalid
	case e.replacing && in.CurrentCode == "":
		return nil, enrolled{}, ErrSecondFactorProofRequired
	}
	var result totp.Result
	switch e.step, result = totp.Match(e.secret, in.Code, s.now(), math.MinInt64); result {
	case totp.Matched:
		return u, e, nil
	case totp.Malformed:
		return nil, enrolled{}, &MalformedError{Field: fieldCode}
	default:
		return nil, enrolled{}, &CodeError{Reason: ReasonCodeInvalid}
	}
}

// enrolled is what FinishTOTP's Update writes, and the record it read
// before.
type enrolled struct {
	secret    []byte
	old       access.TOTP
	step      int64
	replacing bool
}

// storeEnrolment is FinishTOTP's change for p's user: the password, the
// mode and the record it replaces re-read, the proof committed, then the
// new record and its entry. A record its old secret's failures locked is
// gone, so they go too.
func (s *Service) storeEnrolment(ctx context.Context, tx Tx, j *journal, p access.Principal, pr *proven, e enrolled) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	u, err := ownUserIn(ctx, tx, p)
	switch {
	case err != nil:
		return err
	case u.PasswordHash.IsZero():
		return refuse(ErrPasswordRequired)
	}
	if modeErr := requireLocal(ctx, tx, u, ErrSSOOnly); modeErr != nil {
		return modeErr
	}
	cur, found, err := tx.TOTPByUserID(ctx, u.ID)
	switch {
	case err != nil:
		return err
	case found != e.replacing || found && !cur.CreatedAt.Equal(e.old.CreatedAt):
		return refuse(access.ErrTokenInvalid)
	}
	if commitErr := pr.commit(ctx, s, tx); commitErr != nil {
		return commitErr
	}
	sealed, err := s.sealTOTP(u.ID, e.secret)
	if err != nil {
		return err
	}
	if err := tx.SetTOTP(ctx, access.TOTP{UserID: u.ID, Sealed: sealed, CreatedAt: s.stamp(), LastStep: e.step}); err != nil {
		return err
	}
	if err := tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodTOTP}); err != nil {
		return err
	}
	kind := EventTOTPAdded
	if e.replacing {
		kind = EventTOTPReplaced
	}
	j.add(Event{Kind: kind, At: s.now(), UserID: u.ID, Actor: eventActor(As(p))})
	return nil
}

// RemoveTOTP deletes p's own TOTP record and its failure records, for a
// full session (none held: ErrNotFound). While TOTP is usable it takes a
// proof (verifyProof's answers), and under Rules.RequireSecondFactor it is
// ErrLastSecondFactor for a user it would leave holding none. A record
// TOTP no longer reads is removed with no proof, any sent ignored, but
// only within RecentAuth (access.RequireRecentAuth's answers).
func (s *Service) RemoveTOTP(ctx context.Context, c Client, p access.Principal, proof SecondFactorProof) error { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginOver(plainAllowed, c.Secure && p.Secure)
	if err != nil {
		return err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return sessErr
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return err
	}
	gone := credential{method: access.MethodTOTP}
	if heldErr := answer(requireHeld(ctx, s.store, u, gone)); heldErr != nil {
		return heldErr
	}
	usable := s.totpOn(r)
	pr, err := s.totpRemovalProof(ctx, r, c, p, u, proof, usable)
	if err != nil {
		return err
	}
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		return s.removeTOTPIn(ctx, tx, j, r, p, usable, &pr)
	})
	pr.settle(err)
	return err
}

// removeTOTPIn is RemoveTOTP's change: the record re-read, and while TOTP
// is usable the guard re-run and the proof committed, then the deletion.
func (s *Service) removeTOTPIn(ctx context.Context, tx Tx, j *journal, r Rules, p access.Principal, usable bool, pr *proven) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Principal
	gone := credential{method: access.MethodTOTP}
	cur, err := ownUserIn(ctx, tx, p)
	if err != nil {
		return err
	}
	if heldErr := requireHeld(ctx, tx, cur, gone); heldErr != nil {
		return heldErr
	}
	if usable {
		if guardErr := s.guardSecondFactor(ctx, tx, r, cur, gone); guardErr != nil {
			return guardErr
		}
		if commitErr := pr.commit(ctx, s, tx); commitErr != nil {
			return commitErr
		}
	}
	return s.deleteTOTPIn(ctx, tx, j, cur, eventActor(As(p)))
}

// totpRemovalProof is RemoveTOTP's admission of u's removal: while TOTP is
// usable, the second-factor guard then the proof; for a record it no
// longer reads, recent auth alone.
func (s *Service) totpRemovalProof(ctx context.Context, r Rules, c Client, p access.Principal, u *access.User, proof SecondFactorProof, usable bool) (proven, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Principal
	if !usable {
		return proven{}, s.recentAuth(r, p)
	}
	if err := answer(s.guardSecondFactor(ctx, s.store, r, u, credential{method: access.MethodTOTP})); err != nil {
		return proven{}, err
	}
	return s.verifyProof(ctx, r, c, p, u, proof)
}

// deleteTOTPIn deletes u's TOTP record and its failure records inside tx
// and journals EventTOTPRemoved by actor.
func (s *Service) deleteTOTPIn(ctx context.Context, tx Tx, j *journal, u *access.User, actor EventActor) error {
	if err := tx.DeleteTOTP(ctx, u.ID); err != nil {
		return err
	}
	if err := tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodTOTP}); err != nil {
		return err
	}
	j.add(Event{Kind: EventTOTPRemoved, At: s.now(), UserID: u.ID, Actor: actor})
	return nil
}

// StepUpCode re-proves p's user with a TOTP code and rotates p's session to
// AuthTime now and AuthMethod MethodTOTP, with the device cookie in Issued.
// A plain c or p is access.ErrHTTPSRequired, any but a full session
// ErrSessionRequired, a TOTP that is not usable ErrTOTPDisabled and a
// dormant user ErrSSOOnly. The code is counted and matched once, so a code
// used here is code_reused anywhere else; a user with no record is
// code_invalid.
func (s *Service) StepUpCode(ctx context.Context, c Client, p access.Principal, code string) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	u, err := s.stepUpCodeUser(ctx, c, p)
	if err != nil {
		return Issued{}, err
	}
	pr, err := s.verifyCode(ctx, c, u, code, fieldCode, ReasonCodeInvalid)
	if err != nil {
		return Issued{}, err
	}
	var rot rotated
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		cur, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if modeErr := requireLocal(ctx, tx, cur, ErrSSOOnly); modeErr != nil {
			return modeErr
		}
		if commitErr := pr.commit(ctx, s, tx); commitErr != nil {
			return commitErr
		}
		var rotErr error
		if rot, rotErr = s.rotate(ctx, tx, p, cur.ID, access.MethodTOTP); rotErr != nil {
			return rotErr
		}
		j.add(Event{Kind: EventSteppedUp, At: rot.session.AuthTime, UserID: cur.ID, Method: access.MethodTOTP, SessionIDs: []string{rot.session.ID}, Actor: eventActor(As(p))})
		return nil
	})
	pr.settle(err)
	if err != nil {
		return Issued{}, err
	}
	return Issued{Token: rot.token, DeviceCookie: s.deviceCookie(u.Username, c), Session: rot.session}, nil
}

// stepUpCodeUser is StepUpCode's refusals before the limiter, in its godoc's
// order, and p's user as stored.
func (s *Service) stepUpCodeUser(ctx context.Context, c Client, p access.Principal) (*access.User, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginOver(plainRefused, c.Secure && p.Secure)
	if err != nil {
		return nil, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return nil, sessErr
	}
	if !s.totpOn(r) {
		return nil, ErrTOTPDisabled
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return nil, err
	}
	return u, s.localAllowed(ctx, u)
}

// resealOutcome is what one record's re-seal did.
type resealOutcome int

const (
	resealGone resealOutcome = iota // deleted since the page was read
	resealCurrent
	resealDone
	resealUnopenable
)

// ResealTOTP re-seals every TOTP record under the sealer's first key, in
// MaxSweepBatch pages, each record in its own Update that re-reads it, so a
// LastStep a sign-in sets meanwhile is kept. A record the first key already
// opens is left as is, one no key opens is logged at ERROR and counted in
// unopenable, and one deleted meanwhile is skipped; none is counted twice.
// It returns at the first store error with the counts so far, so a nil
// error means the walk reached the last record. TOTP unwired is
// ErrTOTPDisabled.
func (s *Service) ResealTOTP(ctx context.Context) (resealed, unopenable int, err error) {
	if _, err := s.begin(); err != nil {
		return 0, 0, err
	}
	if s.totp.Sealer == nil {
		return 0, 0, ErrTOTPDisabled
	}
	var after int64
	for {
		page, err := s.store.ListTOTP(ctx, after, MaxSweepBatch)
		if err != nil {
			return resealed, unopenable, storeErr(err)
		}
		for i := range page {
			out, err := s.resealOne(ctx, page[i].UserID)
			if err != nil {
				return resealed, unopenable, err
			}
			switch out {
			case resealDone:
				resealed++
			case resealUnopenable:
				unopenable++
			default:
			}
		}
		if len(page) < MaxSweepBatch {
			return resealed, unopenable, nil
		}
		after = page[len(page)-1].UserID
	}
}

// resealOne is ResealTOTP's Update for userID's record.
func (s *Service) resealOne(ctx context.Context, userID int64) (resealOutcome, error) {
	var out resealOutcome
	err := s.update(ctx, func(tx Tx) error {
		out = resealGone
		rec, found, err := tx.TOTPByUserID(ctx, userID)
		if err != nil || !found {
			return err
		}
		secret, current, openErr := s.openTOTP(&rec)
		switch {
		case openErr != nil:
			out = resealUnopenable
			return nil
		case current:
			out = resealCurrent
			return nil
		}
		if rec.Sealed, err = s.sealTOTP(userID, secret); err != nil {
			return err
		}
		if err := tx.SetTOTP(ctx, rec); err != nil {
			return err
		}
		out = resealDone
		return nil
	})
	if err == nil && out == resealUnopenable {
		s.logger().Error("account: ResealTOTP left a TOTP record no sealer key opens", "user_id", userID)
	}
	return out, err
}
