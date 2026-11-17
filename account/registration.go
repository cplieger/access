package account

import (
	"context"
	"io"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// Registration is the input of RegisterPassword.
type Registration struct {
	Password access.Secret
	Username string
}

// RegistrationPasskey is the input of RegisterPasskeyBegin.
type RegistrationPasskey struct {
	Username string
	Origin   webauthn.Origin
}

// RegisterPassword creates a regular account with a password under
// Rules.Registration, signed in under RegistrationOpen and Waiting under
// RegistrationApproval, in one Update re-checking the mode and the cap, or
// as a Pending NextEnrol under Rules.RequireSecondFactor. Refusals, in
// order: plain access.ErrHTTPSRequired; c's IP request limit;
// ErrRegistrationClosed; the username and password rules; the Policy
// (ViaRegistration); ErrSSOOnly; ErrRegistrationFull at RegistrationApproval's
// MaxWaitingRegistrations; c's IP attempt; a taken name ErrUsernameTaken.
func (s *Service) RegisterPassword(ctx context.Context, c Client, in Registration) (RegistrationResult, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.registrationBegin(c)
	if err != nil {
		return RegistrationResult{}, err
	}
	var username string
	checks := func() error {
		var checkErr error
		if username, checkErr = s.registrationChecks(ctx, r, in.Username); checkErr != nil {
			return checkErr
		}
		return s.checkPassword(ctx, r, username, in.Password)
	}
	if r.RequireSecondFactor {
		out, draftErr := s.passwordDraft(ctx, r, c, in.Password, func() (access.User, draftOf, error) {
			if checkErr := checks(); checkErr != nil {
				return access.User{}, draftOf{}, checkErr
			}
			return s.newAccount(username, access.RoleUser), draftOf{via: ViaRegistration}, nil
		})
		return RegistrationResult{Pending: out.Pending}, draftErr
	}
	var base access.User
	out, err := s.complete(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{refusals: checks, limit: s.ipAttempt(c)},
		prepare: func(*ratelimit.Reservation) error {
			hash, hashErr := s.hasher.Hash(ctx, in.Password.Reveal())
			base = s.newAccount(username, access.RoleUser)
			base.PasswordHash = hash
			return hashErr
		},
		in: func(tx Tx) (*access.User, error) {
			user := base
			return &user, s.registrantIn(ctx, tx, r, &user)
		},
		announce: announceCreated,
	})
	switch {
	case err != nil:
		return RegistrationResult{}, err
	case out.waiting != nil:
		return RegistrationResult{Waiting: &Waiting{User: out.waiting}}, nil
	}
	return RegistrationResult{SignedIn: out.SignedIn}, nil
}

// RegisterPasskeyBegin starts registering a regular account with a passkey
// under Rules.Registration: after the transport refusal and c's IP request
// limit, a nil RP() is ErrPasskeysUnavailable, then RegisterPassword's
// refusals before its IP attempt but the password rule. A passkey meets
// Rules.RequireSecondFactor, so no draft is kept.
func (s *Service) RegisterPasskeyBegin(ctx context.Context, c Client, in RegistrationPasskey) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.registrationBegin(c)
	if err != nil {
		return PendingCeremony{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	username, err := s.registrationChecks(ctx, r, in.Username)
	if err != nil {
		return PendingCeremony{}, err
	}
	user := s.newAccount(username, access.RoleUser)
	creation, ceremony, err := webauthn.BeginRegistration(rp, &webauthn.User{AuthUser: &user}, in.Origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id, err := s.pending.put(purposeRegistration, pending{user: user, ceremony: ceremony}, s.now())
	if err != nil {
		return PendingCeremony{}, err
	}
	return PendingCeremony{ID: id, Creation: creation}, nil
}

// RegisterPasskeyFinish verifies the attestation of the registration
// ceremonyID began, then in one Update re-checks the mode, the Policy, the
// stored SSO mode and the cap (admitRegistrantIn) and creates the account with its
// passkey: under RegistrationOpen signed in by passkey, under
// RegistrationApproval Waiting. A plain c is access.ErrHTTPSRequired, an
// unknown, spent, expired or other ceremony ErrCeremonyInvalid, and a taken
// name ErrUsernameTaken.
func (s *Service) RegisterPasskeyFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (EnrolmentResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return EnrolmentResult{}, err
	}
	var (
		entry pending
		cred  *access.PasskeyCredential
	)
	out, err := s.complete(ctx, r, c, &sessionOp{
		method: access.MethodPasskey,
		prepare: func(*ratelimit.Reservation) error {
			rp := s.relyingParty()
			if rp == nil {
				return ErrPasskeysUnavailable
			}
			var ok bool
			if entry, ok = s.pending.take(ceremonyID, purposeRegistration, s.now()); !ok {
				return ErrCeremonyInvalid
			}
			var verifyErr error
			cred, verifyErr = webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: &entry.user}, entry.ceremony, body)
			return verifyErr
		},
		in: func(tx Tx) (*access.User, error) {
			now := s.now()
			user := entry.user
			user.CreatedAt, user.UpdatedAt = now, now
			if admitErr := s.admitRegistrantIn(ctx, tx, r, &user); admitErr != nil {
				return nil, admitErr
			}
			if _, addErr := s.addPasskey(ctx, tx, user.ID, cred); addErr != nil {
				return nil, addErr
			}
			return &user, nil
		},
		announce: announceCreated,
	})
	switch {
	case err != nil:
		return EnrolmentResult{}, err
	case out.waiting != nil:
		return EnrolmentResult{Waiting: &Waiting{User: out.waiting}}, nil
	}
	return EnrolmentResult{SignedIn: out.SignedIn}, nil
}

// registrationBegin is the head of each registration begin: the transport
// refusal, then c's IP request limit before every other check, so a refused
// call is counted too and one address bounds its breach lookups, store
// reads and hashes. RegisterPasskeyFinish charges nothing: it completes
// only the take-once ceremony a charged begin stored.
func (s *Service) registrationBegin(c Client) (Rules, error) { //nolint:gocritic // hugeParam: the request's Client
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return Rules{}, err
	}
	if _, err := s.requestLimit(c)(); err != nil {
		return Rules{}, err
	}
	return r, nil
}

// registrationChecks is a registration's refusals before its IP attempt, but
// the password rule: the mode, the username rule, the Policy, the stored SSO
// mode, and the waiting cap. It returns the canonical username.
func (s *Service) registrationChecks(ctx context.Context, r Rules, name string) (string, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if r.Registration == RegistrationOff {
		return "", ErrRegistrationClosed
	}
	username, err := canonicalUsername(name)
	if err != nil {
		return "", err
	}
	if err := s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaRegistration, Role: access.RoleUser}); err != nil {
		return "", err
	}
	if err := s.localAllowed(ctx, &access.User{Role: access.RoleUser, Enabled: true}); err != nil {
		return "", err
	}
	if err := waitingRoom(ctx, s.store, r); err != nil {
		return "", answer(err)
	}
	return username, nil
}

// admitRegistrantIn is registrantIn for an operation whose own begin
// checked nothing under its r, a draft's or a passkey registration's
// finish: ErrRegistrationClosed while the mode is off, then the Policy.
func (s *Service) admitRegistrantIn(ctx context.Context, tx Tx, r Rules, u *access.User) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if r.Registration == RegistrationOff {
		return refuse(ErrRegistrationClosed)
	}
	if err := s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaRegistration, Role: u.Role}); err != nil {
		return refuse(err)
	}
	return s.registrantIn(ctx, tx, r, u)
}

// registrantIn creates u, a registration's regular account, inside tx under
// the operation's r, re-checking the stored state its checks read: refused
// under the stored mode SSOOnly and at the waiting cap. Under
// RegistrationApproval u is created disabled and waiting for approval.
func (s *Service) registrantIn(ctx context.Context, tx Tx, r Rules, u *access.User) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if err := requireLocal(ctx, tx, u, ErrSSOOnly); err != nil {
		return err
	}
	if err := waitingRoom(ctx, tx, r); err != nil {
		return err
	}
	if r.Registration == RegistrationApproval {
		u.Enabled, u.WaitingApproval = false, true
	}
	return s.createUser(ctx, tx, u, tx.CreateUser, ErrUsernameTaken)
}

// waitingRoom refuses a registration under RegistrationApproval while tx
// holds Rules.MaxWaitingRegistrations waiting accounts: ErrRegistrationFull.
func waitingRoom(ctx context.Context, tx Tx, r Rules) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if r.Registration != RegistrationApproval {
		return nil
	}
	waiting, err := tx.UsersWaiting(ctx, r.MaxWaitingRegistrations)
	switch {
	case err != nil:
		return err
	case len(waiting) >= r.MaxWaitingRegistrations:
		return refuse(ErrRegistrationFull)
	}
	return nil
}
