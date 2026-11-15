package account

import (
	"context"
	"errors"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

const defaultInviteTTL = 7 * 24 * time.Hour

// AcceptInvite is the input of AcceptInvitePassword.
type AcceptInvite struct {
	Token    access.Secret
	Password access.Secret
	Username string
}

// CreateInvite mints an invite for an account of role (empty is
// access.RoleUser), for an admin principal or a ManageUsersScope key (plain:
// access.ErrHTTPSRequired), and returns its plaintext once. Policy (OpInvite)
// decides inside the Update; a key's authority is re-read there
// (key_not_current) and needs its current secret (key_retiring), its invite may
// carry RoleUser only (admin_target), records the key as IssuedByKey and
// expires no later than the key. A ttl of 0 means 7 days; one above 7 × 7 days
// is ErrTTLTooLong.
func (s *Service) CreateInvite(ctx context.Context, p access.Principal, role access.Role, ttl time.Duration) (IssuedToken, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginOver(plainRefused, p.Secure)
	if err != nil {
		return IssuedToken{}, err
	}
	if admitErr := s.admitUserAdmin(r, As(p)); admitErr != nil {
		return IssuedToken{}, admitErr
	}
	if ttl, err = tokenTTL(ttl, defaultInviteTTL); err != nil {
		return IssuedToken{}, err
	}
	if role == "" {
		role = access.RoleUser
	}
	plaintext, base := access.NewOneTimeToken(access.PurposeInvite, ttl, s.now())
	base.Role = role
	var rec access.OneTimeToken
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		rec = base
		ua, uaErr := s.userAdminIn(ctx, tx, j, OpInvite, As(p))
		if uaErr != nil {
			return uaErr
		}
		if keyErr := requireCurrentSecret(OpInvite, ua.key, p); keyErr != nil {
			return keyErr
		}
		if polErr := s.authorize(ctx, Decision{Op: OpInvite, Actor: ua.actor, Role: role}); polErr != nil {
			return refuse(polErr)
		}
		if ruleErr := ua.target(OpInvite, role); ruleErr != nil {
			return ruleErr
		}
		ua.issue(&rec)
		if createErr := tx.CreateOneTimeToken(ctx, rec); createErr != nil {
			return createErr
		}
		j.add(Event{Kind: EventInviteIssued, At: rec.CreatedAt, Role: role, Actor: eventActor(As(p))})
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Plaintext: plaintext, ExpiresAt: rec.ExpiresAt}, nil
}

// AcceptInvitePassword creates the invited account with a password and signs it
// in; a plain c is access.ErrHTTPSRequired. Under Rules.RequireSecondFactor
// it answers a Pending NextEnrol instead (passwordDraft), whose finish
// consumes the invite. The username, password and Policy (ViaInvite) checks
// and the IP limiter run before the hash; a refusal there, a taken name or a
// backend error leaves the invite usable. One Update consumes the invite and
// creates the user and session, re-checking a key-issued invite's issuer: a
// refused issuer deletes the invite and answers access.ErrTokenInvalid, an
// accepted one appends an invite_accepted attribution.
func (s *Service) AcceptInvitePassword(ctx context.Context, c Client, in AcceptInvite) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return LoginResult{}, err
	}
	if r.RequireSecondFactor {
		return s.passwordDraft(ctx, r, c, in.Password, func() (access.User, draftOf, error) {
			username, role, checkErr := s.inviteChecks(ctx, r, in)
			if checkErr != nil {
				return access.User{}, draftOf{}, checkErr
			}
			return s.newAccount(username, role), draftOf{token: tokenHash(in.Token), via: ViaInvite}, nil
		})
	}
	var (
		username string
		base     access.User
		acc      accepted
	)
	out, err := s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate: admission{
			refusals: func() error {
				var checkErr error
				username, _, checkErr = s.inviteChecks(ctx, r, in)
				return checkErr
			},
			limit: s.ipAttempt(c),
		},
		prepare: func(*ratelimit.Reservation) error {
			hash, hashErr := s.hasher.Hash(ctx, in.Password.Reveal())
			base = s.newAccount(username, "")
			base.PasswordHash = hash
			return hashErr
		},
		in: func(tx Tx) (*access.User, error) {
			acc = accepted{user: base}
			if modeErr := requireLocal(ctx, tx, &acc.user, ErrSSOOnly); modeErr != nil {
				return nil, modeErr
			}
			if acceptErr := s.acceptIn(ctx, tx, tokenHash(in.Token), &acc); acceptErr != nil || acc.spent {
				return nil, acceptErr
			}
			return &acc.user, nil
		},
		announce: acc.announce,
	})
	if err == nil && acc.spent {
		return LoginResult{}, access.ErrTokenInvalid
	}
	return out, err
}

// inviteChecks is the acceptance's refusals before the limiter and the
// hash: the invite peeked, the username and password rules, then the
// Policy (OpCreateUser, ViaInvite). It returns the canonical username and
// the invite's role.
func (s *Service) inviteChecks(ctx context.Context, r Rules, in AcceptInvite) (string, access.Role, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its input
	invite, err := s.peekToken(ctx, in.Token, access.PurposeInvite)
	if err != nil {
		return "", "", err
	}
	username, err := canonicalUsername(in.Username)
	if err != nil {
		return "", "", err
	}
	if err := s.checkPassword(ctx, r, username, in.Password); err != nil {
		return "", "", err
	}
	if err := s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaInvite, Role: invite.Role}); err != nil {
		return "", "", err
	}
	if err := s.localAllowed(ctx, &access.User{Role: invite.Role, Enabled: true}); err != nil {
		return "", "", err
	}
	return username, invite.Role, nil
}

// accepted is what an acceptance's Update did: the user, the re-read
// issuer of a key-issued invite, or spent when the invite was consumed
// without creating anyone.
type accepted struct {
	issuer *access.Key
	user   access.User
	spent  bool
}

// announce adds the acceptance's EventUserCreated, naming a key-issued
// invite's issuer.
func (acc *accepted) announce(j *journal, u *access.User, sess *access.Session) {
	created := Event{Kind: EventUserCreated, At: sess.CreatedAt, UserID: u.ID, Role: u.Role}
	if acc.issuer != nil {
		created.KeyID = acc.issuer.ID
	}
	j.add(created)
}

// acceptIn is the acceptance's part of the Update, before its session:
// consume the invite stored under hash, re-check a key-issued one's issuer,
// create the user with the invite's role, and append a key-issued invite's
// attribution. An invite the store found expired or absent, or a refused
// issuer, sets acc.spent and commits the consumption alone.
func (s *Service) acceptIn(ctx context.Context, tx Tx, hash access.Hash, acc *accepted) error {
	tok, found, err := tx.ConsumeOneTimeToken(ctx, hash, s.now())
	switch {
	case err != nil:
		return err
	case !found:
		acc.spent = true
		return nil
	case tok.Purpose != access.PurposeInvite:
		return refuse(access.ErrTokenInvalid)
	}
	if tok.IssuedByKey != 0 {
		var current bool
		decision := Decision{Op: OpInvite, Role: tok.Role}
		if acc.issuer, current, err = s.tokenIssuer(ctx, tx, tok.IssuedByKey, decision, tok.Role); err != nil || !current {
			acc.spent = err == nil
			return err
		}
	}
	acc.user.Role = tok.Role
	if createErr := s.createUser(ctx, tx, &acc.user, tx.CreateUser, ErrUsernameTaken); createErr != nil {
		return createErr
	}
	if acc.issuer == nil {
		return nil
	}
	return s.attribute(ctx, tx, acc.user.ID, access.AttributionInviteAccepted, acc.issuer)
}

// peekToken reads a presented token without consuming it: an absent,
// expired or other-purpose token is access.ErrTokenInvalid.
func (s *Service) peekToken(ctx context.Context, token access.Secret, purpose access.TokenPurpose) (access.OneTimeToken, error) {
	if token.IsZero() {
		return access.OneTimeToken{}, access.ErrTokenInvalid
	}
	return s.peekTokenHash(ctx, tokenHash(token), purpose)
}

// peekTokenHash is peekToken of the token stored under hash.
func (s *Service) peekTokenHash(ctx context.Context, hash access.Hash, purpose access.TokenPurpose) (access.OneTimeToken, error) {
	tok, found, err := s.store.OneTimeTokenByHash(ctx, hash)
	if err != nil {
		return access.OneTimeToken{}, storeErr(err)
	}
	if !found || tok.Purpose != purpose || !tok.ExpiresAt.After(s.now()) {
		return access.OneTimeToken{}, access.ErrTokenInvalid
	}
	return tok, nil
}

// tokenIssuer re-checks the issuer keyID of a key-issued token inside the
// Update that consumes it: keyAuthority under
// ManageUsersScope, the issuing operation's d again with that actor, then
// the admin-target rule on role. It calls keyAuthority, not currentKeyActor,
// because the issuer is not the change's actor. current is false on any
// refusal; err is the store's.
func (s *Service) tokenIssuer(ctx context.Context, tx Tx, keyID int64, d Decision, role access.Role) (key *access.Key, current bool, err error) { //nolint:gocritic // hugeParam: the Decision is built for this one call
	actor, key, err := s.keyAuthority(ctx, tx, d.Op, access.KeyRef{ID: keyID}, s.usersScope)
	if _, refused := errors.AsType[*refusal](err); refused {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d.Actor = actor
	if s.authorize(ctx, d) != nil || requireUserTarget(d.Op, role) != nil {
		return nil, false, nil
	}
	return key, true, nil
}
