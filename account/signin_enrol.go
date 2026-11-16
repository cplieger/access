package account

import (
	"context"
	"errors"
	"io"
	"math"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/crockford"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/totp"
	"github.com/cplieger/access/webauthn"
)

// PendingTOTP is a TOTP enrolment begun inside a pending sign-in. URI and
// Text carry the new secret, shown only in this answer; the ticket keeps it
// for PendingTOTPFinish.
type PendingTOTP struct {
	URI  access.Secret // the Key Uri Format's otpauth URI, for a QR code
	Text access.Secret // the secret in base32, for typing in
}

// recoveryMatch is what a matched recovery code replaces its ticket with:
// the NextEnrol methods the count Update decided, and the matched hash.
type recoveryMatch struct {
	hash    access.Hash
	methods []access.Method
}

// SignInWithRecoveryCode spends nothing but a count: a matching recovery
// code replaces ticket's pending sign-in with a NextEnrol one marked
// Recovered, whose enrolment finish spends the code. Its refusals, in order:
// stepTicket's; no live ticket listing recovery_code, access.ErrTokenInvalid;
// a code not 16 Crockford symbols once normalised, a *MalformedError; the
// limiter's and the hasher's; then the count's, where a code or user gone
// ends the ticket. A wrong code keeps the ticket, the first journalling
// EventSecondFactorFailed; an empty enrolment set is ErrNoUsableMethod.
func (s *Service) SignInWithRecoveryCode(ctx context.Context, c Client, ticket access.Secret, code string) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, entry, found, err := s.stepTicket(ticket, c, plainRefused)
	switch {
	case err != nil:
		return LoginResult{}, err
	case !lists(&entry, found, access.MethodRecoveryCode):
		return LoginResult{}, access.ErrTokenInvalid
	}
	canonical := crockford.Normalize(code)
	if b, ok := crockford.Decode(canonical); !ok || len(b) != recoveryCodeBytes {
		return LoginResult{}, &MalformedError{Field: fieldCode}
	}
	m, refused, err := s.matchRecoveryCode(ctx, r, c, &entry, canonical)
	if err != nil {
		return s.stepAnswered(ctx, c, ticket, &entry, access.MethodRecoveryCode, LoginResult{}, err)
	}
	if refused != nil {
		s.pending.drop(ticket.Reveal())
		return LoginResult{}, refused
	}
	next := entry
	next.ticket.next, next.ticket.methods, next.ticket.failed = NextEnrol, m.methods, false
	next.ticket.recovered = m.hash.Key()
	return LoginResult{Pending: s.mintTicket(&next)}, nil
}

// matchRecoveryCode is the recovery-code step's count, in its own committed
// Update, then its compare against the stored hash outside it, holding a
// hash permit taken before the count. A match cancels the reservation,
// since the sign-in goes on, and answers the replacement's methods or the
// refusal of an empty set; a wrong code fails it.
func (s *Service) matchRecoveryCode(ctx context.Context, r Rules, c Client, entry *pending, canonical string) (m recoveryMatch, refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	res, err := s.stepAttempt(c, entry)()
	if err != nil {
		return recoveryMatch{}, nil, err
	}
	permit, err := s.admitCount(ctx, res, !res.Trusted())
	if err != nil {
		return recoveryMatch{}, nil, err
	}
	defer permit.Release()
	ref := FailureRef{Name: failureName(s.failureMAC(), entry.user.Username), Method: access.MethodRecoveryCode, Trusted: res.Trusted()}
	err = s.update(ctx, func(tx Tx) error {
		var countErr error
		m, refused, countErr = s.countRecoveryIn(ctx, tx, r, c, entry, ref)
		return countErr
	})
	if err != nil {
		settleRefused(res, err)
		return recoveryMatch{}, nil, err
	}
	ok, _, err := permit.Verify(canonical, m.hash)
	switch {
	case errors.Is(err, access.ErrHashBusy):
		res.Fail()
		return recoveryMatch{}, nil, err
	case err != nil:
		s.logger().Error("account: a stored recovery code hash exceeds the hash budget and can never verify", "user_id", entry.user.ID, "err", err)
		res.Fail()
		return recoveryMatch{}, nil, &CodeError{Reason: ReasonCodeInvalid}
	case !ok:
		res.Fail()
		return recoveryMatch{}, nil, &CodeError{Reason: ReasonCodeInvalid}
	}
	res.Cancel()
	return m, refused, nil
}

// countRecoveryIn is matchRecoveryCode's Update: the ticket's re-check, the
// stored code (none ends the ticket), one count on ref, and the NextEnrol
// set a match moves to, decided here so the match asks Rules.MethodUsable
// nothing more.
func (s *Service) countRecoveryIn(ctx context.Context, tx Tx, r Rules, c Client, entry *pending, ref FailureRef) (m recoveryMatch, refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	u, err := s.ticketUserIn(ctx, tx, entry)
	if err != nil {
		return recoveryMatch{}, nil, err
	}
	rec, found, err := tx.RecoveryCodeByUserID(ctx, u.ID)
	switch {
	case err != nil:
		return recoveryMatch{}, nil, err
	case !found:
		return recoveryMatch{}, nil, refuse(access.ErrTokenInvalid)
	}
	if countErr := s.addFailure(ctx, tx, ref); countErr != nil {
		return recoveryMatch{}, nil, countErr
	}
	m.hash = rec.Hash
	m.methods, refused, err = s.ticketMethods(ctx, tx, r, u, NextEnrol, ticketMint{secure: c.Secure})
	return m, refused, err
}

// enrolTicket is the head of every pending passkey enrolment call:
// stepTicket under a secure-only rule, then a live NextEnrol ticket
// listing passkey (else access.ErrTokenInvalid).
func (s *Service) enrolTicket(ticket access.Secret, c Client) (Rules, pending, error) { //nolint:gocritic // hugeParam: the request's Client
	r, entry, found, err := s.stepTicket(ticket, c, plainRefused)
	switch {
	case err != nil:
		return Rules{}, pending{}, err
	case !enrolling(&entry, found, access.MethodPasskey):
		return Rules{}, pending{}, access.ErrTokenInvalid
	}
	return r, entry, nil
}

// totpEnrolTicket is enrolTicket for totp, with ErrTOTPDisabled for a
// TOTP that is not usable before the ticket is read, keeping it for its
// other methods.
func (s *Service) totpEnrolTicket(ticket access.Secret, c Client) (Rules, pending, error) { //nolint:gocritic // hugeParam: the request's Client
	r, entry, found, err := s.stepTicket(ticket, c, plainRefused)
	switch {
	case err != nil:
		return Rules{}, pending{}, err
	case !s.totpOn(r):
		return Rules{}, pending{}, ErrTOTPDisabled
	case !enrolling(&entry, found, access.MethodTOTP):
		return Rules{}, pending{}, access.ErrTokenInvalid
	}
	return r, entry, nil
}

// enrolling reports whether entry is a live NextEnrol ticket listing m.
func enrolling(entry *pending, found bool, m access.Method) bool {
	return found && entry.ticket.next == NextEnrol && slices.Contains(entry.ticket.methods, m)
}

// enrolUser is a pending enrolment begin's user: a draft's would-be
// account, or the ticket's user re-checked, dropping a ticket that ends.
func (s *Service) enrolUser(ctx context.Context, ticket access.Secret, entry *pending) (*access.User, error) {
	if entry.ticket.draft != nil {
		u := entry.user
		return &u, nil
	}
	u, err := s.ticketUserIn(ctx, s.store, entry)
	if err = answer(err); errors.Is(err, access.ErrTokenInvalid) {
		s.pending.drop(ticket.Reveal())
	}
	return u, err
}

// PendingTOTPBegin draws a TOTP secret for the NextEnrol ticket names and
// keeps it on the ticket, replacing one an earlier begin drew. Its
// refusals: totpEnrolTicket's, c's IP request limit, and a user the ticket no
// longer signs in, access.ErrTokenInvalid.
func (s *Service) PendingTOTPBegin(ctx context.Context, c Client, ticket access.Secret) (PendingTOTP, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	_, entry, err := s.totpEnrolTicket(ticket, c)
	if err != nil {
		return PendingTOTP{}, err
	}
	if _, limitErr := s.requestLimit(c)(); limitErr != nil {
		return PendingTOTP{}, limitErr
	}
	u, err := s.enrolUser(ctx, ticket, &entry)
	if err != nil {
		return PendingTOTP{}, err
	}
	secret := totp.NewSecret()
	if !s.pending.setEnrolment(ticket.Reveal(), enrolment{secret: access.NewSecret(string(secret))}, s.now()) {
		return PendingTOTP{}, access.ErrTokenInvalid
	}
	return PendingTOTP{URI: access.NewSecret(totp.URI(s.totp.Issuer, u.Username, secret)), Text: access.NewSecret(totp.Text(secret))}, nil
}

// PendingTOTPFinish binds the secret PendingTOTPBegin drew once code matches
// it, its step spent, completing ticket's pending sign-in as a MethodPassword
// session, or a registration draft's under RegistrationApproval as Waiting,
// with the recovery code issueRecoveryIn issued. Its refusals:
// totpEnrolTicket's; no secret drawn, access.ErrTokenInvalid; a malformed or
// wrong code before the limiter, the ticket kept; the limiter's, the
// hasher's, and enrolAccountIn's, ending the ticket. A Recovered ticket's
// finish spends the recovery code and deletes the lost TOTP in its Update.
func (s *Service) PendingTOTPFinish(ctx context.Context, c Client, ticket access.Secret, code string) (EnrolmentResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, entry, err := s.totpEnrolTicket(ticket, c)
	if err != nil {
		return EnrolmentResult{}, err
	}
	secret := []byte(entry.enrol.secret.Reveal())
	if len(secret) == 0 {
		return EnrolmentResult{}, access.ErrTokenInvalid
	}
	step, result := totp.Match(secret, code, s.now(), math.MinInt64)
	switch result {
	case totp.Matched:
	case totp.Malformed:
		return EnrolmentResult{}, &MalformedError{Field: fieldCode}
	default:
		return EnrolmentResult{}, &CodeError{Reason: ReasonCodeInvalid}
	}
	var (
		drawn issuable
		shown access.Secret
		acc   accepted
	)
	out, err := s.complete(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(*ratelimit.Reservation) error {
			var drawErr error
			drawn, drawErr = s.prepareRecoveryCode(ctx)
			return drawErr
		},
		in: func(tx Tx) (*access.User, error) { return s.enrolAccountIn(ctx, tx, r, &entry, &acc) },
		bind: func(tx Tx, j *journal, u *access.User, sess *access.Session) error {
			actor := boundBy(u, sess)
			if spendErr := s.spendRecoveryIn(ctx, tx, j, &entry, u, actor); spendErr != nil {
				return spendErr
			}
			if stagedErr := s.writeStagedIn(ctx, tx, j, &entry, u, actor); stagedErr != nil {
				return stagedErr
			}
			if bindErr := s.bindTOTPIn(ctx, tx, j, u, secret, step, actor); bindErr != nil {
				return bindErr
			}
			var issueErr error
			shown, issueErr = s.issueRecoveryIn(ctx, tx, j, r, u, &drawn, actor)
			return issueErr
		},
		announce: entry.announcer(&acc),
	})
	return s.enrolAnswered(ticket, out, shown, acc.spent, err)
}

// bindTOTPIn stores secret as u's TOTP record inside tx with step spent,
// deleting the method's failure records, and journals EventTOTPAdded by
// actor. A record already stored means another enrolment finished first:
// access.ErrTokenInvalid.
func (s *Service) bindTOTPIn(ctx context.Context, tx Tx, j *journal, u *access.User, secret []byte, step int64, actor EventActor) error {
	_, found, err := tx.TOTPByUserID(ctx, u.ID)
	switch {
	case err != nil:
		return err
	case found:
		return refuse(access.ErrTokenInvalid)
	}
	sealed, err := s.sealTOTP(u.ID, secret)
	if err != nil {
		return err
	}
	if err := tx.SetTOTP(ctx, access.TOTP{UserID: u.ID, Sealed: sealed, CreatedAt: s.stamp(), LastStep: step}); err != nil {
		return err
	}
	if err := tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodTOTP}); err != nil {
		return err
	}
	j.add(Event{Kind: EventTOTPAdded, At: s.now(), UserID: u.ID, Actor: actor})
	return nil
}

// spendRecoveryIn is a Recovered ticket's recovery, inside its enrolment
// finish's Update: the code that matched, still u's (else
// access.ErrTokenInvalid), is deleted with the lost TOTP and the TOTP and
// recovery-code failure records, journalling EventRecoveryCodeUsed. Nothing for a ticket
// no recovery code moved.
func (s *Service) spendRecoveryIn(ctx context.Context, tx Tx, j *journal, entry *pending, u *access.User, actor EventActor) error {
	if entry.ticket.recovered == (access.HashKey{}) {
		return nil
	}
	rec, found, err := tx.RecoveryCodeByUserID(ctx, u.ID)
	switch {
	case err != nil:
		return err
	case !found || rec.Hash.Key() != entry.ticket.recovered:
		return refuse(access.ErrTokenInvalid)
	}
	if err := tx.DeleteRecoveryCode(ctx, u.ID); err != nil {
		return err
	}
	if _, held, err := tx.TOTPByUserID(ctx, u.ID); err != nil {
		return err
	} else if held {
		if err := s.deleteTOTPIn(ctx, tx, j, u, actor); err != nil {
			return err
		}
	}
	if err := tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodTOTP, access.MethodRecoveryCode}); err != nil {
		return err
	}
	j.add(Event{Kind: EventRecoveryCodeUsed, At: s.now(), UserID: u.ID, Actor: actor})
	return nil
}

// announcer is entry's enrolment finish's sessionOp.announce: a draft's
// journals the account its creation made (acc), and nil otherwise.
func (entry *pending) announcer(acc *accepted) func(j *journal, u *access.User, sess *access.Session) {
	if entry.ticket.draft == nil {
		return nil
	}
	return acc.announce
}

// boundBy is the actor of what a binding journals for u: u in sess, or u
// alone when u waits for approval and holds no session.
func boundBy(u *access.User, sess *access.Session) EventActor {
	if sess == nil {
		return EventActor{UserID: u.ID}
	}
	return EventActor{UserID: u.ID, SessionID: sess.ID}
}

// enrolAnswered settles a pending enrolment finish's answer in the cache: a
// sign-in, or a registration that waits, drops the ticket and the user's
// others and carries shown; a draft whose invite was spent is
// access.ErrTokenInvalid; and a refusal no retry of the ticket can pass
// (access.ErrTokenInvalid, ErrSetupComplete, ErrUsernameTaken,
// ErrRegistrationClosed, ErrRegistrationFull) drops it.
func (s *Service) enrolAnswered(ticket access.Secret, out completion, shown access.Secret, spent bool, err error) (EnrolmentResult, error) { //nolint:gocritic // hugeParam: the step's own result
	if err == nil && spent {
		err = access.ErrTokenInvalid
	}
	switch {
	case err == nil && out.waiting != nil:
		s.pending.drop(ticket.Reveal())
		return EnrolmentResult{Waiting: &Waiting{User: out.waiting, RecoveryCode: shown}}, nil
	case err == nil:
		s.pending.drop(ticket.Reveal())
		s.pending.dropUser(out.SignedIn.User.ID)
		out.SignedIn.RecoveryCode = shown
		return EnrolmentResult{SignedIn: out.SignedIn}, nil
	case errors.Is(err, access.ErrTokenInvalid), errors.Is(err, ErrSetupComplete), errors.Is(err, ErrUsernameTaken),
		errors.Is(err, ErrRegistrationClosed), errors.Is(err, ErrRegistrationFull):
		s.pending.drop(ticket.Reveal())
	}
	return EnrolmentResult{}, err
}

// PendingPasskeyBegin starts registering a passkey for the NextEnrol ticket
// names, at origin. Its refusals: enrolTicket's; a nil RP()
// ErrPasskeysUnavailable; c's IP request limit; a user the ticket no longer
// signs in, access.ErrTokenInvalid; the relying party's
// *webauthn.OriginError.
func (s *Service) PendingPasskeyBegin(ctx context.Context, c Client, ticket access.Secret, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	_, entry, err := s.enrolTicket(ticket, c)
	if err != nil {
		return PendingCeremony{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	if _, limitErr := s.requestLimit(c)(); limitErr != nil {
		return PendingCeremony{}, limitErr
	}
	u, err := s.enrolUser(ctx, ticket, &entry)
	if err != nil {
		return PendingCeremony{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	cc, ceremony, err := webauthn.BeginRegistration(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeEnrolPasskey, pending{user: *u, ceremony: ceremony, ticketID: ticket}, s.now())
	return PendingCeremony{ID: id, Creation: cc}, nil
}

// PendingPasskeyFinish completes the pending sign-in ceremonyID's ticket
// names by registering the passkey in body, as a session of
// MethodPassword with the recovery code it issued (issueRecoveryIn), or as
// PendingTOTPFinish's Waiting account. An
// unknown, spent or expired ceremony is ErrCeremonyInvalid; then
// enrolTicket's refusals, the limiter's, the registration's, the hasher's,
// ErrDuplicateCredential, and enrolAccountIn's, ending the ticket. A
// Recovered ticket's finish spends the recovery as PendingTOTPFinish does.
func (s *Service) PendingPasskeyFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (EnrolmentResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	cer, ok := s.pending.take(ceremonyID, purposeEnrolPasskey, s.now())
	if !ok {
		if _, err := s.beginOver(plainRefused, c.Secure); err != nil {
			return EnrolmentResult{}, err
		}
		return EnrolmentResult{}, ErrCeremonyInvalid
	}
	ticket := cer.ticketID
	r, entry, err := s.enrolTicket(ticket, c)
	switch {
	case err != nil:
		return EnrolmentResult{}, err
	case entry.user.ID != cer.user.ID:
		return EnrolmentResult{}, access.ErrTokenInvalid
	}
	rp := s.relyingParty()
	if rp == nil {
		return EnrolmentResult{}, ErrPasskeysUnavailable
	}
	var (
		cred  *access.PasskeyCredential
		drawn issuable
		shown access.Secret
		acc   accepted
	)
	out, err := s.complete(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(*ratelimit.Reservation) error {
			var prepErr error
			if cred, prepErr = webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: &cer.user}, cer.ceremony, body); prepErr != nil {
				return prepErr
			}
			drawn, prepErr = s.prepareRecoveryCode(ctx)
			return prepErr
		},
		in: func(tx Tx) (*access.User, error) { return s.enrolAccountIn(ctx, tx, r, &entry, &acc) },
		bind: func(tx Tx, j *journal, u *access.User, sess *access.Session) error {
			actor := boundBy(u, sess)
			if spendErr := s.spendRecoveryIn(ctx, tx, j, &entry, u, actor); spendErr != nil {
				return spendErr
			}
			if stagedErr := s.writeStagedIn(ctx, tx, j, &entry, u, actor); stagedErr != nil {
				return stagedErr
			}
			pk, addErr := s.addPasskey(ctx, tx, u.ID, cred, ErrDuplicateCredential)
			if addErr != nil {
				return addErr
			}
			j.add(Event{Kind: EventPasskeyAdded, At: pk.CreatedAt, UserID: u.ID, PasskeyID: pk.ID, Actor: actor})
			var issueErr error
			shown, issueErr = s.issueRecoveryIn(ctx, tx, j, r, u, &drawn, actor)
			return issueErr
		},
		announce: entry.announcer(&acc),
	})
	return s.enrolAnswered(ticket, out, shown, acc.spent, err)
}
