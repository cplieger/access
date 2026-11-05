package account

import (
	"context"

	"github.com/cplieger/access"
)

// NewUser is the input of CreateUser.
type NewUser struct {
	Password access.Secret // zero creates a user with no sign-in method
	Username string
	Role     access.Role // empty is access.RoleUser
}

// CreateUser creates a user for an admin principal, a ManageUsersScope key
// or an out-of-band actor, under the same rules: the username rule, the
// password rule when in.Password is set (zero: no sign-in method), and
// Policy (OpCreateUser, ViaActor) on the user set read inside the creating
// Update. The hash runs first and authorises nothing: a key is re-read
// inside the Update (key_not_current), creates a RoleUser only
// (admin_target), and appends a created attribution with its LineageIDs.
func (s *Service) CreateUser(ctx context.Context, a Actor, in NewUser) (*access.User, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return nil, err
	}
	if admitErr := s.admitUserAdmin(r, a); admitErr != nil {
		return nil, admitErr
	}
	username, err := canonicalUsername(in.Username)
	if err != nil {
		return nil, err
	}
	hash, err := s.initialPassword(ctx, r, username, in.Password)
	if err != nil {
		return nil, err
	}
	role := in.Role
	if role == "" {
		role = access.RoleUser
	}
	now := s.now()
	base := access.User{
		Username: username, PasswordHash: hash, Role: role, Enabled: true,
		WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now,
	}
	var user access.User
	err = s.update(ctx, func(tx Tx) error {
		user = base
		return s.createUserIn(ctx, tx, a, &user)
	})
	if err != nil {
		return nil, err
	}
	s.emit(Event{Kind: EventUserCreated, At: now, UserID: user.ID, Actor: eventActor(a)})
	return user.Clone(), nil
}

// createUserIn is CreateUser's Update: a's authority, the Policy on the
// user set read in tx, the admin-target rule, the user, and a key's
// created attribution.
func (s *Service) createUserIn(ctx context.Context, tx Tx, a Actor, user *access.User) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, OpCreateUser, a)
	if err != nil {
		return err
	}
	users, err := tx.ListUsers(ctx)
	if err != nil {
		return err
	}
	if polErr := s.policy.Authorize(ctx, Decision{Op: OpCreateUser, Via: ViaActor, Actor: ua.actor, Role: user.Role, Users: users}); polErr != nil {
		return refuse(polErr)
	}
	if ruleErr := ua.target(OpCreateUser, user.Role); ruleErr != nil {
		return ruleErr
	}
	if err := s.createUser(ctx, tx, user, tx.CreateUser); err != nil {
		return err
	}
	if ua.key == nil {
		return nil
	}
	return s.attribute(ctx, tx, user.ID, access.AttributionCreated, ua.key)
}

// initialPassword checks and hashes a new user's optional password; the
// zero Secret is no password and the zero Hash.
func (s *Service) initialPassword(ctx context.Context, r Rules, username string, pw access.Secret) (access.Hash, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if pw.IsZero() {
		return access.Hash{}, nil
	}
	if err := s.checkPassword(ctx, r, username, pw); err != nil {
		return access.Hash{}, err
	}
	return s.hasher.Hash(ctx, pw.Reveal())
}
