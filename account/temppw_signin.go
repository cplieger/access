package account

import (
	"context"

	"github.com/cplieger/access"
)

// lockName waits for canonical's name lock (Service.names) until ctx ends,
// which answers ctx.Err(); unlock releases it.
func (s *Service) lockName(ctx context.Context, canonical string) (unlock func(), err error) {
	if s.hooks.nameLockWait != nil {
		s.hooks.nameLockWait(ctx, canonical)
	}
	return s.names.Lock(ctx, canonical)
}

// liveTemporaryIn is the head of every write after a temporary password
// verified, step 1's and the admin link's: it goes on only while userID is
// stored and enabled and its record is live and holds the verified hash,
// else it answers ErrInvalidCredentials and writes nothing. It returns the
// user and the record as stored.
func (s *Service) liveTemporaryIn(ctx context.Context, tx Tx, userID int64, verified access.Hash) (*access.User, access.TemporaryPassword, error) {
	u, found, err := tx.UserByID(ctx, userID)
	switch {
	case err != nil:
		return nil, access.TemporaryPassword{}, err
	case !found || !u.Enabled:
		return nil, access.TemporaryPassword{}, refuse(ErrInvalidCredentials)
	}
	rec, held, err := tx.TemporaryPasswordByUserID(ctx, u.ID)
	switch {
	case err != nil:
		return nil, access.TemporaryPassword{}, err
	case !held || !rec.ExpiresAt.After(s.now()) || !rec.Hash.Equal(verified):
		return nil, access.TemporaryPassword{}, refuse(ErrInvalidCredentials)
	}
	return u, rec, nil
}

// pendTemporary is step 1's decision, in its success Update, for u whose
// temporary password rec verified: the issuer re-check, the SSO mode, the
// burn over plain where the path cannot finish, then the spend into a
// NextSetCredential ticket. A refusal that answers as a wrong secret
// commits only the deletion it makes, and none on a secure request the mode
// refuses; reenabled is resetFailures' answer on the paths that settle the
// attempt as correct.
func (s *Service) pendTemporary(ctx context.Context, tx Tx, j *journal, r Rules, c Client, a *passwordAttempt, u *access.User, rec *access.TemporaryPassword) (entry *pending, refused error, reenabled bool, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	mode, err := storedMode(ctx, tx)
	if err != nil {
		return nil, nil, false, err
	}
	modeRefused := mode.dormantFor(u)
	current, err := s.temporaryIssuerCurrent(ctx, tx, rec, u)
	switch {
	case err != nil:
		return nil, nil, false, err
	case modeRefused && c.Secure:
		return nil, nil, false, refuse(ErrInvalidCredentials)
	case !current:
		return nil, ErrInvalidCredentials, false, tx.DeleteTemporaryPassword(ctx, u.ID)
	case modeRefused:
		return nil, ErrInvalidCredentials, false, s.useTemporaryIn(ctx, tx, j, u, c)
	}
	if reenabled, err = resetFailures(ctx, tx, a); err != nil {
		return nil, nil, false, err
	}
	methods, refused, err := s.ticketMethods(ctx, tx, r, u, NextSetCredential, ticketMint{secure: c.Secure})
	switch {
	case err != nil:
		return nil, nil, false, err
	case !c.Secure && (refused != nil || r.RequireSecondFactor):
		return nil, ErrTemporaryPasswordExposed, reenabled, s.useTemporaryIn(ctx, tx, j, u, c)
	case refused != nil:
		return nil, refused, reenabled, nil
	}
	if err := s.useTemporaryIn(ctx, tx, j, u, c); err != nil {
		return nil, nil, false, err
	}
	t := ticket{next: NextSetCredential, methods: methods, digest: u.PasswordHash.Key(), temporary: rec.Hash, secure: c.Secure}
	return &pending{user: *u, ticket: t}, nil, reenabled, nil
}

// useTemporaryIn deletes u's temporary password, which a step 1 spent or
// burned, and journals EventTemporaryPasswordUsed with c's transport.
func (s *Service) useTemporaryIn(ctx context.Context, tx Tx, j *journal, u *access.User, c Client) error { //nolint:gocritic // hugeParam: the request's Client
	if err := tx.DeleteTemporaryPassword(ctx, u.ID); err != nil {
		return err
	}
	j.add(Event{Kind: EventTemporaryPasswordUsed, At: s.now(), UserID: u.ID, Plain: !c.Secure})
	return nil
}

// temporaryIssuerCurrent re-runs, inside tx, every check the issue of rec
// for target ran: an out-of-band issue passes; a user's must still be an
// enabled user the Policy and the owner protections allow
// OpSetTemporaryPassword on target; a key's must still pass tokenIssuer.
// false is a refused issuer; err is the store's.
func (s *Service) temporaryIssuerCurrent(ctx context.Context, tx Tx, rec *access.TemporaryPassword, target *access.User) (bool, error) {
	if rec.IssuedByUser == 0 && rec.IssuedByKey == 0 {
		return true, nil
	}
	_, _, users, err := targetIn(ctx, tx, target.ID)
	if err != nil {
		return false, err
	}
	d := Decision{Op: OpSetTemporaryPassword, Target: target, Users: users}
	if rec.IssuedByKey != 0 {
		_, current, keyErr := s.tokenIssuer(ctx, tx, rec.IssuedByKey, d, target.Role)
		return current, keyErr
	}
	issuer, found, err := tx.UserByID(ctx, rec.IssuedByUser)
	if err != nil || !found || !issuer.Enabled {
		return false, err
	}
	d.Actor = As(access.Principal{User: issuer})
	return s.authorizeOwned(ctx, &d) == nil, nil
}
