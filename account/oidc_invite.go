package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
)

// oidcInvite accepts the invite stored under hash for claims' identity:
// the invite read (gone, expired or used: access.ErrTokenInvalid) and the
// Policy (OpCreateUser, ViaInvite, its Role) before admission, so a flow
// begun before a restart or a Policy change meets both again. Then
// acceptOIDC creates the account under the name provisionName gives. A
// name taken or absent commits nothing and answers OutcomeNotLinked, its
// PendingLink holding the invite.
func (s *Service) oidcInvite(ctx context.Context, r Rules, c Client, hash access.Hash, claims oidc.Claims, admitted bool) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Claims
	if err := s.inviteAuthorized(ctx, hash); err != nil {
		return OIDCOutcome{}, err
	}
	if !admitted {
		return OIDCOutcome{}, s.refuseInvite(ctx, c)
	}
	name, named := provisionName(claims)
	in, err := s.acceptOIDC(ctx, r, c, hash, claims.Identity, name, nil)
	switch {
	case err != nil:
		return OIDCOutcome{}, err
	case in.User != nil:
		return OIDCOutcome{Kind: OutcomeSignedIn, SignedIn: in}, nil
	}
	pending := pendingLink(claims)
	pending.Invite = hash
	if named {
		pending.SuggestedUsername = suggestedName(name)
	}
	return OIDCOutcome{Kind: OutcomeNotLinked, Pending: pending}, nil
}

// createPendingInvite is CreatePendingOIDC's invite arm: the invite read
// (access.ErrTokenInvalid) and the Policy, then acceptOIDC under name, a
// taken one ErrUsernameTaken.
func (s *Service) createPendingInvite(ctx context.Context, r Rules, c Client, pending PendingLink, name string) (SignedIn, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and pending link
	if err := s.inviteAuthorized(ctx, pending.Invite); err != nil {
		return SignedIn{}, err
	}
	return s.acceptOIDC(ctx, r, c, pending.Invite, pending.Identity, name, ErrUsernameTaken)
}

// inviteAuthorized reads the invite stored under hash and asks the Policy
// (OpCreateUser, ViaInvite) with its Role.
func (s *Service) inviteAuthorized(ctx context.Context, hash access.Hash) error {
	invite, err := s.peekTokenHash(ctx, hash, access.PurposeInvite)
	if err != nil {
		return err
	}
	return s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaInvite, Role: invite.Role})
}

// refuseInvite journals an invite's identity OIDCAdmission refused, naming
// no account, and answers ErrNotAdmitted.
func (s *Service) refuseInvite(ctx context.Context, c Client) error { //nolint:gocritic // hugeParam: the callback's Client
	err := s.change(ctx, byClient(Actor{}, c), func(_ Tx, j *journal) error {
		s.notAdmitted(j, 0, EventActor{})
		return nil
	})
	if err != nil {
		return err
	}
	return ErrNotAdmitted
}

// acceptOIDC is one Update that accepts the invite stored under hash for
// id: an identity already linked is ErrOIDCIdentityTaken; an empty or
// taken name answers taken, or, when taken is nil, commits nothing and
// returns the zero SignedIn; else acceptIn creates the account under name
// with the invite's role, signed in by OIDC. A spent invite or a refused
// issuer is access.ErrTokenInvalid.
func (s *Service) acceptOIDC(ctx context.Context, r Rules, c Client, hash access.Hash, id access.OIDCIdentity, name string, taken error) (SignedIn, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	var acc accepted
	in, err := s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodOIDC,
		in: func(tx Tx) (*access.User, error) {
			acc = accepted{user: *s.newOIDCUser(name, "", id)}
			free, checkErr := inviteeIn(ctx, tx, &acc.user)
			switch {
			case checkErr != nil:
				return nil, checkErr
			case !free && taken != nil:
				return nil, refuse(taken)
			case !free:
				return nil, nil
			}
			if acceptErr := s.acceptIn(ctx, tx, hash, &acc); acceptErr != nil || acc.spent {
				return nil, acceptErr
			}
			return &acc.user, nil
		},
		announce: acc.announce,
	})
	if err == nil && acc.spent {
		err = access.ErrTokenInvalid
	}
	return in, err
}

// inviteeIn is an OIDC acceptance's check of u inside tx before acceptIn:
// an identity already linked is ErrOIDCIdentityTaken; free reports whether
// u has a name and no user holds it.
func inviteeIn(ctx context.Context, tx Tx, u *access.User) (free bool, err error) {
	if err = identityFreeIn(ctx, tx, u.OIDC); err != nil || u.Username == "" {
		return false, err
	}
	_, held, err := tx.UserByUsername(ctx, u.Username)
	return !held, err
}

// identityFreeIn refuses, inside tx, an identity a user is linked to:
// ErrOIDCIdentityTaken.
func identityFreeIn(ctx context.Context, tx Tx, id access.OIDCIdentity) error {
	_, linked, err := tx.UserByOIDC(ctx, id)
	switch {
	case err != nil:
		return err
	case linked:
		return refuse(ErrOIDCIdentityTaken)
	}
	return nil
}
