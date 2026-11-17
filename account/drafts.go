package account

import (
	"context"

	"github.com/cplieger/access"
)

// draftOf is a draft's creation: the path its enrolment finish creates the
// account by, and the hash of the token it spends there, zero for a
// registration and for a setup that asked for none.
type draftOf struct {
	token access.Hash
	via   CreateVia // ViaSetup, ViaInvite or ViaRegistration
}

// newAccount is the enabled user a setup, an invite or a registration
// creates for username, with a fresh WebAuthn handle.
func (s *Service) newAccount(username string, role access.Role) access.User {
	now := s.now()
	return access.User{Username: username, Role: role, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now}
}

// passwordDraft is a password setup's, invite acceptance's or
// registration's answer under
// Rules.RequireSecondFactor: a new account holds no second factor, so
// pendAt's rule pends it at NextEnrol. checks are the operation's own
// refusals and answer the would-be user and its creation; then the ticket's
// methods, read through the Store; then c's IP attempt and the hash. The
// ticket holds the account, created only by its enrolment finish, so
// nothing is written and no token spent. A draft replaces its token's
// earlier one (pendingCache.put).
func (s *Service) passwordDraft(ctx context.Context, r Rules, c Client, password access.Secret, checks func() (access.User, draftOf, error)) (LoginResult, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	var (
		u       access.User
		d       draftOf
		methods []access.Method
	)
	gate := admission{
		refusals: func() error {
			var err, refused error
			if u, d, err = checks(); err != nil {
				return err
			}
			if methods, refused, err = s.ticketMethods(ctx, s.store, r, &u, NextEnrol, ticketMint{secure: c.Secure}); err != nil {
				return storeErr(err)
			}
			return refused
		},
		limit: s.ipAttempt(c),
	}
	res, err := gate.admit()
	if err != nil {
		return LoginResult{}, err
	}
	hash, err := s.hasher.Hash(ctx, password.Reveal())
	res.Cancel()
	if err != nil {
		return LoginResult{}, err
	}
	u.PasswordHash = hash
	entry := pending{user: u, ticket: ticket{next: NextEnrol, methods: methods, digest: hash.Key(), secure: c.Secure, draft: &d}}
	minted, err := s.mintTicket(&entry)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Pending: minted}, nil
}

// enrolAccountIn is a pending enrolment finish's user inside tx under the
// finish's r: the ticket's user re-checked (ticketUserIn), or a draft's new
// account (draftAccountIn), with acc what its creation did.
func (s *Service) enrolAccountIn(ctx context.Context, tx Tx, r Rules, entry *pending, acc *accepted) (*access.User, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if entry.ticket.draft == nil {
		return s.ticketUserIn(ctx, tx, entry)
	}
	return s.draftAccountIn(ctx, tx, r, entry, acc)
}

// draftAccountIn creates a draft's account inside its finish's Update,
// running the draft's admission again: a setup's
// createFirstUser (no user yet, the token spent, the Policy), a
// registration's admitRegistrantIn under the finish's r, or an
// invite's stored mode, Policy and acceptIn. An invite spent or whose
// issuer is refused since step 1 sets acc.spent and creates no one.
func (s *Service) draftAccountIn(ctx context.Context, tx Tx, r Rules, entry *pending, acc *accepted) (*access.User, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	now := s.now()
	*acc = accepted{user: entry.user}
	acc.user.CreatedAt, acc.user.UpdatedAt = now, now
	d := entry.ticket.draft
	switch d.via {
	case ViaSetup:
		return &acc.user, s.createFirstUser(ctx, tx, d.token, &acc.user)
	case ViaRegistration:
		return &acc.user, s.admitRegistrantIn(ctx, tx, r, &acc.user)
	}
	if err := requireLocal(ctx, tx, &acc.user, ErrSSOOnly); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaInvite, Role: acc.user.Role}); err != nil {
		return nil, refuse(err)
	}
	if err := s.acceptIn(ctx, tx, d.token, acc); err != nil || acc.spent {
		return nil, err
	}
	return &acc.user, nil
}
