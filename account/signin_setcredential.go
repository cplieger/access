package account

import (
	"context"
	"errors"
	"io"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// setCredentialTicket is the head of every NextSetCredential step:
// stepTicket under rule, then a live NextSetCredential ticket listing m
// (else access.ErrTokenInvalid).
func (s *Service) setCredentialTicket(ticket access.Secret, c Client, rule plainRule, m access.Method) (Rules, pending, error) { //nolint:gocritic // hugeParam: the request's Client
	r, entry, found, err := s.stepTicket(ticket, c, rule)
	switch {
	case err != nil:
		return Rules{}, pending{}, err
	case !found || entry.ticket.next != NextSetCredential:
		return Rules{}, pending{}, access.ErrTokenInvalid
	case !slices.Contains(entry.ticket.methods, m):
		if m == access.MethodPassword {
			return Rules{}, pending{}, ErrPasswordLoginDisabled
		}
		return Rules{}, pending{}, access.ErrTokenInvalid
	}
	return r, entry, nil
}

// SetCredentialPassword completes the NextSetCredential pending sign-in
// ticket names with password, of the user's own choosing. Its refusals, in
// order: stepTicket's; no live NextSetCredential ticket,
// access.ErrTokenInvalid; one not listing password, or password sign-in
// off, ErrPasswordLoginDisabled; the limiter's; a *access.PasswordError
// (PasswordIsTemporary for the temporary password that minted the ticket,
// then checkPassword's), keeping the ticket; the hasher's; then a user the
// ticket no longer signs in, ending it. With Rules.RequireSecondFactor off
// it writes the password and signs in; with it on it writes nothing and
// answers a NextEnrol ticket holding the password, which the enrolment
// finish writes.
func (s *Service) SetCredentialPassword(ctx context.Context, c Client, ticket, password access.Secret) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, entry, err := s.setCredentialTicket(ticket, c, plainPerRequest, access.MethodPassword)
	if err != nil {
		return LoginResult{}, err
	}
	if r.DisablePasswordLogin {
		return LoginResult{}, ErrPasswordLoginDisabled
	}
	var hash access.Hash
	out, err := s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(*ratelimit.Reservation) error {
			var prepErr error
			hash, prepErr = s.chosenPassword(ctx, r, &entry, password)
			return prepErr
		},
		in: func(tx Tx) (*access.User, error) { return s.ticketUserIn(ctx, tx, &entry) },
		pend: func(tx Tx, _ *journal, u *access.User) (*pending, error, error) {
			if !r.RequireSecondFactor {
				return nil, nil, nil
			}
			return s.stagePassword(ctx, tx, r, c, &entry, u, hash)
		},
		bind: func(tx Tx, j *journal, u *access.User, sess *access.Session) error {
			return s.writeChosenIn(ctx, tx, j, u, hash, EventActor{UserID: u.ID, SessionID: sess.ID})
		},
	})
	return s.setAnswered(ticket, &entry, out, err)
}

// chosenPassword is SetCredentialPassword's check and hash of password, a
// refusal keeping the ticket. Only a value in the one form the ticket's
// temporary password hash can match is verified against it, under a hash
// permit and before checkPassword, so no other password costs a second
// derivation or a breach lookup.
func (s *Service) chosenPassword(ctx context.Context, r Rules, entry *pending, password access.Secret) (access.Hash, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if canonical, ok := temporaryPasswordForm(password.Reveal()); ok && !entry.ticket.temporary.IsZero() {
		same, err := s.verifyOnce(ctx, canonical, entry.ticket.temporary)
		switch {
		case err != nil:
			return access.Hash{}, err
		case same:
			return access.Hash{}, &access.PasswordError{Reason: access.PasswordIsTemporary}
		}
	}
	if err := s.checkPassword(ctx, r, entry.user.Username, password); err != nil {
		return access.Hash{}, err
	}
	return s.hasher.Hash(ctx, password.Reveal())
}

// verifyOnce compares text against hash under one hash permit.
func (s *Service) verifyOnce(ctx context.Context, text string, hash access.Hash) (bool, error) {
	permit, err := s.hasher.Reserve(ctx)
	if err != nil {
		return false, err
	}
	defer permit.Release()
	ok, _, err := permit.Verify(text, hash)
	return ok, err
}

// stagePassword is SetCredentialPassword's replacement under the rule,
// inside its Update: a NextEnrol ticket of entry's origin holding hash,
// with the methods ticketMethods gives u, or its refusal.
func (s *Service) stagePassword(ctx context.Context, tx Tx, r Rules, c Client, entry *pending, u *access.User, hash access.Hash) (*pending, error, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	methods, refused, err := s.ticketMethods(ctx, tx, r, u, NextEnrol, ticketMint{secure: c.Secure})
	if err != nil || refused != nil {
		return nil, refused, err
	}
	next := *entry
	next.user = *u
	next.ticket.next, next.ticket.methods, next.ticket.staged, next.ticket.failed = NextEnrol, methods, hash, false
	return &next, nil, nil
}

// writeChosenIn writes hash as u's password inside tx, deleting any
// temporary password, and journals EventPasswordSet by actor.
func (s *Service) writeChosenIn(ctx context.Context, tx Tx, j *journal, u *access.User, hash access.Hash, actor EventActor) error {
	u.PasswordHash, u.UpdatedAt = hash, s.now()
	if err := tx.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := tx.DeleteTemporaryPassword(ctx, u.ID); err != nil {
		return err
	}
	j.add(Event{Kind: EventPasswordSet, At: s.now(), UserID: u.ID, Method: access.MethodPassword, Actor: actor})
	return nil
}

// writeStagedIn is a staged ticket's password write inside its enrolment
// finish's Update, before the factor's, so the issue rule sees it; nothing
// for a ticket SetCredentialPassword did not stage.
func (s *Service) writeStagedIn(ctx context.Context, tx Tx, j *journal, entry *pending, u *access.User, actor EventActor) error {
	if entry.ticket.staged.IsZero() {
		return nil
	}
	return s.writeChosenIn(ctx, tx, j, u, entry.ticket.staged, actor)
}

// setAnswered settles a NextSetCredential step's answer in the cache: a
// sign-in drops the user's tickets; a replacement drops the old ticket; a
// refusal no retry of the ticket can pass (access.ErrTokenInvalid, an
// empty enrolment set, a transport the replacement refuses) drops it.
func (s *Service) setAnswered(ticket access.Secret, entry *pending, out LoginResult, err error) (LoginResult, error) { //nolint:gocritic // hugeParam: the step's own result
	switch {
	case err == nil && out.Pending != nil:
		s.pending.drop(ticket.Reveal())
		return out, nil
	case err == nil:
		s.pending.dropUser(entry.user.ID)
		s.pending.drop(ticket.Reveal())
		return out, nil
	case errors.Is(err, access.ErrTokenInvalid), errors.Is(err, ErrNoUsableMethod), errors.Is(err, access.ErrHTTPSRequired):
		s.pending.drop(ticket.Reveal())
	}
	return LoginResult{}, err
}

// SetCredentialPasskeyBegin starts registering a passkey for the
// NextSetCredential ticket names, at origin. Its refusals: stepTicket's
// under a secure-only rule; no live ticket listing passkey,
// access.ErrTokenInvalid; a nil RP() ErrPasskeysUnavailable; c's IP request
// limit; a user the ticket no longer signs in, access.ErrTokenInvalid; the
// relying party's *webauthn.OriginError.
func (s *Service) SetCredentialPasskeyBegin(ctx context.Context, c Client, ticket access.Secret, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	_, entry, err := s.setCredentialTicket(ticket, c, plainRefused, access.MethodPasskey)
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
	id := s.pending.put(purposeSetPasskey, pending{user: *u, ceremony: ceremony, ticketID: ticket}, s.now())
	return PendingCeremony{ID: id, Creation: cc}, nil
}

// SetCredentialPasskeyFinish completes the NextSetCredential pending
// sign-in ceremonyID's ticket names by registering the passkey in body, as
// a session of MethodPassword under either setting of
// Rules.RequireSecondFactor, since a passkey meets it. An unknown, spent or
// expired ceremony is ErrCeremonyInvalid; then SetCredentialPasskeyBegin's
// ticket refusals, the limiter's, the registration's,
// ErrDuplicateCredential, and a user the ticket no longer signs in, ending
// it.
func (s *Service) SetCredentialPasskeyFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	cer, ok := s.pending.take(ceremonyID, purposeSetPasskey, s.now())
	if !ok {
		if _, err := s.beginOver(plainRefused, c.Secure); err != nil {
			return SignedIn{}, err
		}
		return SignedIn{}, ErrCeremonyInvalid
	}
	ticket := cer.ticketID
	r, entry, err := s.setCredentialTicket(ticket, c, plainRefused, access.MethodPasskey)
	switch {
	case err != nil:
		return SignedIn{}, err
	case entry.user.ID != cer.user.ID:
		return SignedIn{}, access.ErrTokenInvalid
	}
	rp := s.relyingParty()
	if rp == nil {
		return SignedIn{}, ErrPasskeysUnavailable
	}
	var cred *access.PasskeyCredential
	out, err := s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(*ratelimit.Reservation) error {
			var regErr error
			cred, regErr = webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: &cer.user}, cer.ceremony, body)
			return regErr
		},
		in: func(tx Tx) (*access.User, error) { return s.ticketUserIn(ctx, tx, &entry) },
		bind: func(tx Tx, j *journal, u *access.User, sess *access.Session) error {
			pk, addErr := s.addPasskey(ctx, tx, u.ID, cred, ErrDuplicateCredential)
			if addErr != nil {
				return addErr
			}
			j.add(Event{Kind: EventPasskeyAdded, At: pk.CreatedAt, UserID: u.ID, PasskeyID: pk.ID, Actor: EventActor{UserID: u.ID, SessionID: sess.ID}})
			return nil
		},
	})
	out, err = s.setAnswered(ticket, &entry, out, err)
	return out.SignedIn, err
}
