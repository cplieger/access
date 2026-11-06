package account

import (
	"context"
	"fmt"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

const (
	defaultSetupTTL = 24 * time.Hour
	// maxTTLFactor bounds an explicit token lifetime at this many times its
	// kind's default, so no minted token is near-permanent.
	maxTTLFactor = 7
)

// SetupPassword is the input of SetupWithPassword.
type SetupPassword struct {
	Token    access.Secret // zero when the setup rule asks for none
	Password access.Secret
	Username string
}

// tokenTTL is ttl, or def for 0, refusing a negative one with
// ErrTTLNegative and one over maxTTLFactor × def with ErrTTLTooLong.
func tokenTTL(ttl, def time.Duration) (time.Duration, error) {
	switch {
	case ttl == 0:
		return def, nil
	case ttl < 0:
		return 0, fmt.Errorf("%w: %s", ErrTTLNegative, ttl)
	case ttl > maxTTLFactor*def:
		return 0, fmt.Errorf("%w: %s is above %s", ErrTTLTooLong, ttl, maxTTLFactor*def)
	}
	return ttl, nil
}

// tokenHash is the stored hash of a presented one-time token.
func tokenHash(token access.Secret) access.Hash {
	return access.NewHash(access.HexSHA256(token.Reveal()))
}

// State reports whether setup is needed and which sign-in methods are
// offered. It writes nothing.
func (s *Service) State(ctx context.Context) (State, error) {
	r, err := s.begin()
	if err != nil {
		return State{}, err
	}
	n, err := s.store.UserCount(ctx)
	if err != nil {
		return State{}, storeErr(err)
	}
	return State{
		SetupRequired: n == 0,
		PasswordLogin: !r.DisablePasswordLogin,
		Passkeys:      s.passkeysAvailable(),
		OIDC:          s.OIDCProvider() != nil,
	}, nil
}

// IssueSetupToken mints the token for the first account. Only an
// out-of-band actor may call it, and only while no user exists
// (ErrSetupComplete). It asks no Policy: the token creates the account only
// through setup's own Policy call. It voids every earlier setup token. A
// ttl of 0 means 24h; one above 7 × 24h is ErrTTLTooLong.
func (s *Service) IssueSetupToken(ctx context.Context, a Actor, ttl time.Duration) (access.Secret, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	if _, err := s.begin(); err != nil {
		return access.Secret{}, err
	}
	if !a.isOutOfBand() {
		return access.Secret{}, &PolicyError{Op: OpCreateUser, Reason: ReasonOutOfBandOnly}
	}
	ttl, err := tokenTTL(ttl, defaultSetupTTL)
	if err != nil {
		return access.Secret{}, err
	}
	plaintext, rec := access.NewOneTimeToken(access.PurposeSetup, 0, ttl, s.now())
	err = s.update(ctx, func(tx Tx) error {
		n, countErr := tx.UserCount(ctx)
		switch {
		case countErr != nil:
			return countErr
		case n != 0:
			return refuse(ErrSetupComplete)
		}
		if _, delErr := tx.DeleteOneTimeTokens(ctx, access.PurposeSetup, 0); delErr != nil {
			return delErr
		}
		return tx.CreateOneTimeToken(ctx, rec)
	})
	if err != nil {
		return access.Secret{}, err
	}
	s.emit(Event{Kind: EventSetupTokenIssued, At: rec.CreatedAt, Actor: eventActor(a)})
	return plaintext, nil
}

// SetupWithPassword creates the first account, an admin, and signs it in.
// Every check that can refuse runs before the hash: the user count, the
// token when Rules.SetupTokenRequired asks for one (nil: always), the
// username and password rules, then the IP limiter. One Update then
// consumes the token, asks the Policy (OpCreateUser, ViaSetup), creates the
// user and the session; a concurrent setup that won makes it
// ErrSetupComplete or access.ErrTokenInvalid, and a backend error leaves the
// token usable.
func (s *Service) SetupWithPassword(ctx context.Context, c Client, in SetupPassword) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.begin()
	if err != nil {
		return SignedIn{}, err
	}
	var (
		spend    access.Hash
		username string
		base     access.User
	)
	return s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate: admission{
			refusals: func() error {
				var checkErr error
				if spend, username, checkErr = s.setupChecks(ctx, r, c, in.Token, in.Username); checkErr != nil {
					return checkErr
				}
				return s.checkPassword(ctx, r, username, in.Password)
			},
			limit: s.ipAttempt(c),
		},
		prepare: func(*ratelimit.Reservation) error {
			hash, hashErr := s.hasher.Hash(ctx, in.Password.Reveal())
			now := s.now()
			base = access.User{
				Username: username, PasswordHash: hash, Role: access.RoleAdmin, Enabled: true,
				WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now,
			}
			return hashErr
		},
		in: func(tx Tx) (*access.User, error) {
			user := base
			return &user, s.createFirstUser(ctx, tx, spend, &user)
		},
	})
}

// setupChecks runs setup steps 1 to 3, the refusals that need neither a
// hash nor a ceremony: the user count, the token when the rule asks for
// one, then the username rule. It returns the hash of the token setup must
// spend, zero when the rule asks for none, and the canonical username.
func (s *Service) setupChecks(ctx context.Context, r Rules, c Client, token access.Secret, name string) (spend access.Hash, username string, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Client
	n, err := s.store.UserCount(ctx)
	if err != nil {
		return access.Hash{}, "", storeErr(err)
	}
	if n != 0 {
		return access.Hash{}, "", ErrSetupComplete
	}
	if r.SetupTokenRequired == nil || r.SetupTokenRequired(ctx, c) {
		if tokErr := s.peekSetupToken(ctx, token); tokErr != nil {
			return access.Hash{}, "", tokErr
		}
		spend = tokenHash(token)
	}
	if username, err = canonicalUsername(name); err != nil {
		return access.Hash{}, "", err
	}
	return spend, username, nil
}

// createFirstUser is setup step 7 inside tx, up to the session
// createSession writes: spend the setup token whose hash is spend (none
// when zero), ask the Policy (OpCreateUser, ViaSetup), then create user
// through CreateInitialUser.
func (s *Service) createFirstUser(ctx context.Context, tx Tx, spend access.Hash, user *access.User) error {
	if !spend.IsZero() {
		if err := spendSetupToken(ctx, tx, spend, s.now()); err != nil {
			return err
		}
	}
	if err := s.policy.Authorize(ctx, Decision{Op: OpCreateUser, Via: ViaSetup, Role: access.RoleAdmin}); err != nil {
		return refuse(err)
	}
	return s.createUser(ctx, tx, user, tx.CreateInitialUser, ErrSetupComplete)
}

// spendSetupToken consumes the setup token whose hash is spend inside the
// setup's Update; one a concurrent setup spent, or of another purpose, is
// access.ErrTokenInvalid.
func spendSetupToken(ctx context.Context, tx Tx, spend access.Hash, now time.Time) error {
	tok, found, err := tx.ConsumeOneTimeToken(ctx, spend, now)
	if err != nil {
		return err
	}
	if !found || tok.Purpose != access.PurposeSetup {
		return refuse(access.ErrTokenInvalid)
	}
	return nil
}

// peekSetupToken requires a presented, unexpired setup token without
// consuming it: ErrSetupTokenRequired when none was presented, else
// access.ErrTokenInvalid.
func (s *Service) peekSetupToken(ctx context.Context, token access.Secret) error {
	if token.IsZero() {
		return ErrSetupTokenRequired
	}
	tok, found, err := s.store.OneTimeTokenByHash(ctx, tokenHash(token))
	if err != nil {
		return storeErr(err)
	}
	if !found || tok.Purpose != access.PurposeSetup || !tok.ExpiresAt.After(s.now()) {
		return access.ErrTokenInvalid
	}
	return nil
}
