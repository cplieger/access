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

// stepTicket is the head of every second step: the Rules, then ticket's
// pending sign-in read without removing it, then its transport binding,
// then rule for c. A ticket presented on the other transport than its own
// is dropped, having crossed in clear or come from a plain response: a
// plain c is access.ErrHTTPSRequired and a secure one access.ErrTokenInvalid.
// found is false for no live ticket, which each step answers itself.
func (s *Service) stepTicket(ticket access.Secret, c Client, rule plainRule) (r Rules, entry pending, found bool, err error) { //nolint:gocritic // hugeParam: the request's Client
	if r, err = s.begin(); err != nil {
		return Rules{}, pending{}, false, err
	}
	entry, found = s.pending.peek(ticket.Reveal(), purposeSignIn, s.now())
	if found && entry.ticket.secure != c.Secure {
		s.pending.drop(ticket.Reveal())
		if c.Secure {
			return Rules{}, pending{}, false, access.ErrTokenInvalid
		}
		return Rules{}, pending{}, false, access.ErrHTTPSRequired
	}
	if err := s.transport(rule, c.Secure); err != nil {
		return Rules{}, pending{}, false, err
	}
	return r, entry, found, nil
}

// lists reports whether entry is a live NextSecondFactor ticket listing m.
func lists(entry *pending, found bool, m access.Method) bool {
	return found && entry.ticket.next == NextSecondFactor && slices.Contains(entry.ticket.methods, m)
}

// ticketUserIn is a second step's re-check, inside tx, of what step 1
// verified: the ticket's user still stored and enabled, its PasswordHash
// still the one step 1 left, and the stored mode not keeping it dormant.
// Any miss ends the ticket as a refused access.ErrTokenInvalid.
func ticketUserIn(ctx context.Context, tx Tx, entry *pending) (*access.User, error) {
	u, found, err := tx.UserByID(ctx, entry.user.ID)
	switch {
	case err != nil:
		return nil, err
	case !found || !u.Enabled || u.PasswordHash.Key() != entry.ticket.digest:
		return nil, refuse(access.ErrTokenInvalid)
	}
	return u, requireLocal(ctx, tx, u, access.ErrTokenInvalid)
}

// stepAttempt is a second step's limiter key: the request's IP, the
// ticket's account and the request's device.
func (s *Service) stepAttempt(c Client, entry *pending) func() (*ratelimit.Reservation, error) { //nolint:gocritic // hugeParam: the request's Client
	return func() (*ratelimit.Reservation, error) {
		return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP()), Account: ratelimit.AccountKey(entry.user.Username), Device: c.Device})
	}
}

// SignInWithCode completes the pending sign-in ticket names with a TOTP
// code, as a session of MethodPassword. Its refusals, in order: stepTicket's;
// a TOTP that is not usable, ErrTOTPDisabled with the ticket kept; no live
// ticket listing totp, access.ErrTokenInvalid; a *ratelimit.RefusedError;
// then countCode's, where a record that is gone, a disabled user or a
// changed password ends the ticket as access.ErrTokenInvalid. A wrong code
// keeps the ticket, and the first one journals EventSecondFactorFailed.
func (s *Service) SignInWithCode(ctx context.Context, c Client, ticket access.Secret, code string) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, entry, found, err := s.stepTicket(ticket, c, plainPerRequest)
	switch {
	case err != nil:
		return LoginResult{}, err
	case !s.totpOn(r):
		return LoginResult{}, ErrTOTPDisabled
	case !lists(&entry, found, access.MethodTOTP):
		return LoginResult{}, access.ErrTokenInvalid
	}
	var (
		ch   codeCheck
		step int64
	)
	out, err := s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(res *ratelimit.Reservation) error {
			ch = s.newCodeCheck(res, &entry.user, code)
			ch.missing = access.ErrTokenInvalid
			var countErr error
			step, countErr = s.countCode(ctx, res, &ch)
			return countErr
		},
		in: func(tx Tx) (*access.User, error) {
			u, userErr := ticketUserIn(ctx, tx, &entry)
			if userErr != nil {
				return nil, userErr
			}
			return u, s.commitCode(ctx, tx, &ch, step)
		},
	})
	return s.stepAnswered(ctx, c, ticket, &entry, access.MethodTOTP, out, err)
}

// stepAnswered settles a second step's answer in the cache: a sign-in
// drops the user's tickets, a refusal that ends the ticket drops it, and
// the ticket's first refused proof journals EventSecondFactorFailed, with
// a refused code's Reason as its Detail.
func (s *Service) stepAnswered(ctx context.Context, c Client, ticket access.Secret, entry *pending, m access.Method, out LoginResult, err error) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client and the step's own result
	switch {
	case err == nil:
		s.pending.dropUser(entry.user.ID)
		return out, nil
	case errors.Is(err, access.ErrTokenInvalid):
		s.pending.drop(ticket.Reveal())
		return LoginResult{}, err
	case !refusedProof(err, m):
		return LoginResult{}, err
	}
	id := ticket.Reveal()
	if !s.pending.markFailed(id) {
		return LoginResult{}, err
	}
	var detail string
	if ce, ok := errors.AsType[*CodeError](err); ok {
		detail = ce.Reason
	}
	logErr := s.change(ctx, byClient(Actor{}, c), func(_ Tx, j *journal) error {
		j.addDetail(Event{Kind: EventSecondFactorFailed, At: s.now(), UserID: entry.user.ID, Method: m}, detail)
		return nil
	})
	if logErr != nil {
		s.pending.unmarkFailed(id)
		return LoginResult{}, logErr
	}
	return LoginResult{}, err
}

// refusedProof reports whether err refused the proof itself: a code that
// does not match, or a passkey step's ceremony or assertion, never an
// answer of the store, the limiter or the request's shape.
func refusedProof(err error, m access.Method) bool {
	if m == access.MethodTOTP {
		return errors.Is(err, ErrCodeInvalid)
	}
	if _, limited := errors.AsType[*ratelimit.RefusedError](err); limited {
		return false
	}
	return !errors.Is(err, access.ErrAuthBackend) && !errors.Is(err, ErrPasskeysUnavailable) && !errors.Is(err, webauthn.ErrResponseTooLarge)
}

// SecondFactorPasskeyBegin starts the passkey second step of the pending
// sign-in ticket names, at origin, limited to the user's passkeys under the
// relying party's ID. Its refusals: stepTicket's under a secure-only rule;
// no live ticket listing passkey, or a user it no longer signs in,
// access.ErrTokenInvalid; a nil RP() ErrPasskeysUnavailable; c's IP
// request limit; the relying party's *webauthn.OriginError.
func (s *Service) SecondFactorPasskeyBegin(ctx context.Context, c Client, ticket access.Secret, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	_, entry, found, err := s.stepTicket(ticket, c, plainRefused)
	if err != nil {
		return PendingCeremony{}, err
	}
	if !lists(&entry, found, access.MethodPasskey) {
		return PendingCeremony{}, access.ErrTokenInvalid
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	if _, limitErr := s.requestLimit(c)(); limitErr != nil {
		return PendingCeremony{}, limitErr
	}
	u, found, err := s.store.UserByID(ctx, entry.user.ID)
	switch {
	case err != nil:
		return PendingCeremony{}, storeErr(err)
	case !found || !u.Enabled:
		s.pending.drop(ticket.Reveal())
		return PendingCeremony{}, access.ErrTokenInvalid
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	if wu.Credentials = currentRP(wu.Credentials, rp); len(wu.Credentials) == 0 {
		return PendingCeremony{}, access.ErrTokenInvalid
	}
	assertion, ceremony, err := webauthn.BeginReauthentication(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeSecondFactor, pending{user: *u, ceremony: ceremony, ticketID: ticket}, s.now())
	return PendingCeremony{ID: id, Assertion: assertion}, nil
}

// SecondFactorPasskeyFinish completes the pending sign-in ceremonyID's
// ticket names with the passkey assertion in body, as a session of
// MethodPassword. An unknown, spent or expired ceremony is
// ErrCeremonyInvalid; then stepTicket's refusals, a ticket gone
// access.ErrTokenInvalid, the limiter's, and the assertion's, which keep
// the ticket, the first journalling EventSecondFactorFailed.
func (s *Service) SecondFactorPasskeyFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	cer, ok := s.pending.take(ceremonyID, purposeSecondFactor, s.now())
	if !ok {
		if _, err := s.beginOver(plainRefused, c.Secure); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrCeremonyInvalid
	}
	ticket := cer.ticketID
	r, entry, found, err := s.stepTicket(ticket, c, plainRefused)
	switch {
	case err != nil:
		return LoginResult{}, err
	case !lists(&entry, found, access.MethodPasskey) || entry.user.ID != cer.user.ID:
		return LoginResult{}, access.ErrTokenInvalid
	}
	rp := s.relyingParty()
	if rp == nil {
		return LoginResult{}, ErrPasskeysUnavailable
	}
	out, err := s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate:   admission{limit: s.stepAttempt(c, &entry)},
		prepare: func(res *ratelimit.Reservation) error {
			wu, userErr := s.webauthnUser(ctx, &cer.user)
			if userErr != nil {
				return userErr
			}
			wu.Credentials = currentRP(wu.Credentials, rp)
			if _, verifyErr := webauthn.CompleteReauthentication(ctx, rp, ceremonyStore{s.store}, wu, cer.ceremony, body); verifyErr != nil {
				res.Fail()
				return verifyErr
			}
			return nil
		},
		in: func(tx Tx) (*access.User, error) { return ticketUserIn(ctx, tx, &entry) },
	})
	return s.stepAnswered(ctx, c, ticket, &entry, access.MethodPasskey, out, err)
}
