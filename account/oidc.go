package account

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// AdmitOIDC is an anonymous OIDC request's one provider read, for the
// sign-in start and the callback: ErrServiceClosed, then ErrOIDCUnavailable
// for a nil OIDC(), both charging nothing, then Limiter.Request on c's IP
// (*ratelimit.RefusedError), else the provider for the whole request.
func (s *Service) AdmitOIDC(c Client) (*oidc.Provider, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	p := s.OIDCProvider()
	if p == nil {
		return nil, ErrOIDCUnavailable
	}
	if err := s.limiter.Request(ratelimit.IPKey(c.IP())); err != nil {
		return nil, err
	}
	return p, nil
}

// OIDCComplete completes the callback oidc.Provider.Finish returned, after
// AdmitOIDC admitted it and returned that provider; OIDCComplete charges no
// limiter. A
// nil OIDC() is ErrOIDCUnavailable; the outcome carries flow.Redirect. A
// sign-in signs in the linked user (disabled: ErrInvalidCredentials) or one
// Rules.Provisioning admits, else gives one same OutcomeNotLinked. A link
// begun within RecentAuth, or a step-up of the linked identity (else
// ErrInvalidCredentials), needs flow's live full session (else ErrSessionGone).
func (s *Service) OIDCComplete(ctx context.Context, c Client, flow oidc.Flow, claims oidc.Claims) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the callback's Client, Flow and Claims, read once
	r, err := s.begin()
	if err != nil {
		return OIDCOutcome{}, err
	}
	if s.OIDCProvider() == nil {
		return OIDCOutcome{}, ErrOIDCUnavailable
	}
	var out OIDCOutcome
	switch flow.Intent {
	case oidc.IntentSignIn:
		out, err = s.oidcSignIn(ctx, r, c, claims)
	case oidc.IntentLink:
		out, err = s.oidcLink(ctx, r, c, flow, claims.Identity)
	case oidc.IntentStepUp:
		out, err = s.oidcStepUp(ctx, c, flow, claims.Identity)
	default:
		return OIDCOutcome{}, fmt.Errorf("%w: unknown intent %q", oidc.ErrFlowInvalid, flow.Intent)
	}
	if err != nil {
		return OIDCOutcome{}, err
	}
	out.Redirect = flow.Redirect
	return out, nil
}

// oidcSignIn signs in the user linked to claims.Identity, or provisions one,
// in one Update. With neither, the outcome is OutcomeNotLinked holding the
// identity's PendingLink alone, so it is the same whether or not a local
// account of that name exists.
func (s *Service) oidcSignIn(ctx context.Context, r Rules, c Client, claims oidc.Claims) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Claims
	candidate := s.provisional(r, claims)
	var created bool
	in, err := s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodOIDC,
		in: func(tx Tx) (*access.User, error) {
			var u *access.User
			var err error
			u, created, err = s.oidcUserIn(ctx, tx, claims.Identity, candidate)
			return u, err
		},
		announce: func(j *journal, u *access.User, sess *access.Session) {
			if created {
				announceCreated(j, u, sess)
			}
		},
	})
	switch {
	case err != nil:
		return OIDCOutcome{}, err
	case in.User == nil:
		return OIDCOutcome{Kind: OutcomeNotLinked, Pending: pendingLink(claims)}, nil
	}
	return OIDCOutcome{Kind: OutcomeSignedIn, SignedIn: in}, nil
}

// oidcUserIn is the user a sign-in signs in, read or created inside tx: the
// user linked to id (disabled: ErrInvalidCredentials), else the candidate,
// created when provisioning admits it here, else nil.
func (s *Service) oidcUserIn(ctx context.Context, tx Tx, id access.OIDCIdentity, candidate *access.User) (user *access.User, created bool, err error) {
	u, found, err := tx.UserByOIDC(ctx, id)
	switch {
	case err != nil:
		return nil, false, err
	case found && !u.Enabled:
		return nil, false, refuse(ErrInvalidCredentials)
	case found:
		return u, false, nil
	case candidate == nil:
		return nil, false, nil
	}
	admitted, err := s.provisionAdmitted(ctx, tx, candidate)
	if err != nil || !admitted {
		return nil, false, err
	}
	fresh := *candidate
	if err := s.createUser(ctx, tx, &fresh, tx.CreateUser); err != nil {
		return nil, false, err
	}
	return &fresh, true, nil
}

// provisional is the user Rules.Provisioning would create for claims: nil
// when Admit refuses them or UsernameCandidate gives no name the username
// rule accepts. Whether the store already holds a user, whether the name is
// free and whether the Policy allows it are decided inside the Update.
func (s *Service) provisional(r Rules, claims oidc.Claims) *access.User { //nolint:gocritic // hugeParam: the operation's one Rules value and Claims
	if r.Provisioning.Admit(claims) != nil {
		return nil
	}
	name, err := oidc.UsernameCandidate(claims)
	if err != nil {
		return nil
	}
	username, err := canonicalUsername(name)
	if err != nil {
		return nil
	}
	now := s.now()
	return &access.User{
		Username: username, Role: cmp.Or(r.Provisioning.Role, access.RoleUser), OIDC: claims.Identity, Enabled: true,
		WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now,
	}
}

// provisionAdmitted is provisioning's checks on the rows tx reads: some
// user exists, so the first account always comes through setup; no user
// holds candidate's name, password or not; then the Policy allows
// OpCreateUser from the zero Actor with ViaProvisioning.
func (s *Service) provisionAdmitted(ctx context.Context, tx Tx, candidate *access.User) (bool, error) {
	n, err := tx.UserCount(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	_, taken, err := tx.UserByUsername(ctx, candidate.Username)
	if err != nil || taken {
		return false, err
	}
	users, err := tx.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	return s.policy.Authorize(ctx, Decision{Op: OpCreateUser, Via: ViaProvisioning, Role: candidate.Role, Users: users}) == nil, nil
}

// pendingLink is claims' identity with its display hints: the
// preferred_username as sent, and the email only when verified.
func pendingLink(claims oidc.Claims) PendingLink { //nolint:gocritic // hugeParam: Claims is plain data, passed as the caller holds it
	p := PendingLink{Identity: claims.Identity, UsernameHint: claims.PreferredUsername}
	if claims.EmailVerified {
		p.Email = claims.Email
	}
	return p
}

// oidcLink links id to flow's user in one Update: the session check, then
// flow.BeganAt within r.RecentAuth (else access.ErrRecentAuthRequired), then
// linkIn, rotating the session by (UserID, ID), from c's address.
func (s *Service) oidcLink(ctx context.Context, r Rules, c Client, flow oidc.Flow, id access.OIDCIdentity) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Flow
	var l linked
	err := s.change(ctx, byClient(Actor{}, c), func(tx Tx, j *journal) error {
		u, sess, err := s.flowSession(ctx, tx, flow)
		if err != nil {
			return err
		}
		j.actorSession(sess)
		now := s.now()
		if flow.BeganAt.Before(now.Add(-r.RecentAuth)) || flow.BeganAt.After(now) {
			return refuse(access.ErrRecentAuthRequired)
		}
		if err := s.linkIn(ctx, tx, r, sessionActor(u, sess), u, sess, access.Hash{}, id, &l); err != nil {
			return err
		}
		s.addLinked(j, &l)
		return nil
	})
	if err != nil {
		return OIDCOutcome{}, err
	}
	return OIDCOutcome{Kind: OutcomeLinked, Issued: Issued{Token: l.rot.token, Session: l.rot.session}}, nil
}

// oidcStepUp re-proves flow's user by its linked identity in one Update:
// the session check, id equal to the user's non-zero link (else
// ErrInvalidCredentials), then a rotation by (UserID, ID) to AuthTime now
// and MethodOIDC, with a device cookie that keeps the ID of c.Device when
// that is valid for the user.
func (s *Service) oidcStepUp(ctx context.Context, c Client, flow oidc.Flow, id access.OIDCIdentity) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the callback's Client and Flow
	var (
		user *access.User
		rot  rotated
	)
	err := s.change(ctx, byClient(Actor{}, c), func(tx Tx, j *journal) error {
		u, sess, err := s.flowSession(ctx, tx, flow)
		if err != nil {
			return err
		}
		j.actorSession(sess)
		if u.OIDC.IsZero() || u.OIDC != id {
			return refuse(ErrInvalidCredentials)
		}
		user = u
		if rot, err = s.rotateSession(ctx, tx, sess, access.Hash{}, access.MethodOIDC); err != nil {
			return err
		}
		actor := EventActor{SessionID: rot.session.ID, UserID: u.ID}
		j.add(Event{Kind: EventSteppedUp, At: rot.session.AuthTime, UserID: u.ID, Method: access.MethodOIDC, SessionIDs: []string{rot.session.ID}, Actor: actor})
		return nil
	})
	if err != nil {
		return OIDCOutcome{}, err
	}
	device := s.limiter.DeviceCookie(ratelimit.AccountKey(user.Username), c.Device)
	return OIDCOutcome{Kind: OutcomeSteppedUp, Issued: Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}}, nil
}

// flowSession is the session check of a link or step-up callback, inside
// tx: flow.SessionID must name a full session of flow.UserID that
// access.ValidateSession accepts under the Authenticator's Timeouts(), which
// its verifier enforces, and the user must be enabled; else ErrSessionGone.
// SessionsByUserID returns idle-expired sessions until the sweep, so
// without ValidateSession a step-up would revive one.
func (s *Service) flowSession(ctx context.Context, tx Tx, flow oidc.Flow) (*access.User, *access.Session, error) { //nolint:gocritic // hugeParam: the callback's Flow
	u, found, err := tx.UserByID(ctx, flow.UserID)
	switch {
	case err != nil:
		return nil, nil, err
	case !found || !u.Enabled:
		return nil, nil, refuse(ErrSessionGone)
	}
	sessions, err := tx.SessionsByUserID(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	i := slices.IndexFunc(sessions, func(sess access.Session) bool { return sess.ID == flow.SessionID })
	if i < 0 || sessions[i].Kind != access.SessionFull || access.ValidateSession(&sessions[i], s.authn.Timeouts(), s.now()) != nil {
		return nil, nil, refuse(ErrSessionGone)
	}
	return u, &sessions[i], nil
}

// sessionActor is the actor of a callback's session, which no verifier
// produced: a principal Actor holding the user and session tx read, so a
// Policy sees the user it decides for, and IsSession is false on it.
func sessionActor(u *access.User, sess *access.Session) Actor {
	return As(access.Principal{User: u, Method: sess.AuthMethod, SessionID: sess.ID, SessionKind: sess.Kind, AuthTime: sess.AuthTime})
}

// LinkPendingOIDC links pending's identity to p's own user (a full session
// within RecentAuth) in one Update that re-reads the user, rotates p's
// session into Issued and reads the returned Me, so a failed read rolls the
// link back. No identity is ErrNotFound, a disabled user ErrSessionGone, a
// linked user ErrAlreadyLinked, an identity of another user
// ErrOIDCIdentityTaken. Under Rules.SSOGoverned the link migrates the
// account: Policy (OpMigrateToSSO), then the password, the passkeys, the
// other sessions and, under RevokeKeysOnCredentialChange, the keys go.
func (s *Service) LinkPendingOIDC(ctx context.Context, p access.Principal, pending PendingLink) (Issued, Me, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(p)
	if err != nil {
		return Issued{}, Me{}, err
	}
	if s.OIDCProvider() == nil {
		return Issued{}, Me{}, ErrOIDCUnavailable
	}
	if pending.Identity.Issuer == "" || pending.Identity.Subject == "" {
		return Issued{}, Me{}, ErrNotFound
	}
	var (
		l  linked
		me Me
	)
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		u, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if !u.Enabled {
			return refuse(ErrSessionGone)
		}
		sess, sessErr := principalSession(ctx, tx, p, u.ID)
		if sessErr != nil {
			return sessErr
		}
		if linkErr := s.linkIn(ctx, tx, r, As(p), u, sess, p.SessionTokenHash(), pending.Identity, &l); linkErr != nil {
			return linkErr
		}
		var meErr error
		if me, meErr = s.meIn(ctx, tx, r, u, p); meErr != nil {
			return meErr
		}
		s.addLinked(j, &l)
		return nil
	})
	if err != nil {
		return Issued{}, Me{}, err
	}
	return Issued{Token: l.rot.token, Session: l.rot.session}, me, nil
}

// linked is what a link's Update wrote besides the link: the rotated
// session and what an SSO migration removed.
type linked struct {
	actor    EventActor
	passkeys []int64  // deleted, ascending
	keys     []int64  // deleted under RevokeKeysOnCredentialChange, ascending
	sessions []string // the other sessions revoked
	rot      rotated
	userID   int64
	password bool // a password was cleared
}

// linkIn links id to u inside tx and rotates sess, as tx read it, with
// expect as the compare-and-swap. A user already linked is ErrAlreadyLinked,
// then an identity linked to another user ErrOIDCIdentityTaken. Under
// r.SSOGoverned the account migrates in the same Update: Policy
// (OpMigrateToSSO) from actor first, so a refusal fails the link whole.
func (s *Service) linkIn(ctx context.Context, tx Tx, r Rules, actor Actor, u *access.User, sess *access.Session, expect access.Hash, id access.OIDCIdentity, l *linked) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	*l = linked{userID: u.ID, actor: eventActor(actor)}
	if !u.OIDC.IsZero() {
		return refuse(ErrAlreadyLinked)
	}
	_, taken, err := tx.UserByOIDC(ctx, id)
	switch {
	case err != nil:
		return err
	case taken:
		return refuse(ErrOIDCIdentityTaken)
	}
	if r.SSOGoverned {
		if migErr := s.migrateIn(ctx, tx, r, actor, u, l); migErr != nil {
			return migErr
		}
	}
	u.OIDC, u.UpdatedAt = id, s.now()
	if writeErr := tx.UpdateUser(ctx, u); writeErr != nil {
		return writeErr
	}
	if l.rot, err = s.rotateSession(ctx, tx, sess, expect, ""); err != nil {
		return err
	}
	if r.SSOGoverned {
		l.sessions, err = tx.DeleteUserSessions(ctx, u.ID, sess.ID)
	}
	return err
}

// migrateIn is the SSO migration of u inside tx, before the link is
// written: Policy (OpMigrateToSSO) on the user set read here, then u's
// password cleared on u, every passkey deleted and, under
// r.RevokeKeysOnCredentialChange, every key with the tokens it issued.
func (s *Service) migrateIn(ctx context.Context, tx Tx, r Rules, actor Actor, u *access.User, l *linked) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	users, err := tx.ListUsers(ctx)
	if err != nil {
		return err
	}
	if polErr := s.policy.Authorize(ctx, Decision{Op: OpMigrateToSSO, Actor: actor, Target: u, Users: users}); polErr != nil {
		return refuse(polErr)
	}
	l.password = !u.PasswordHash.IsZero()
	u.PasswordHash = access.Hash{}
	if l.passkeys, err = tx.DeleteUserPasskeys(ctx, u.ID); err != nil {
		return err
	}
	slices.Sort(l.passkeys)
	if r.RevokeKeysOnCredentialChange {
		l.keys, err = deleteUserKeys(ctx, tx, u.ID)
	}
	return err
}

// addLinked adds a link's entries: EventOIDCLinked, then a migration's
// EventPasswordRemoved, one EventPasskeyRemoved per passkey, one
// EventKeyRevoked per key and EventUserSessionsRevoked.
func (s *Service) addLinked(j *journal, l *linked) {
	at := s.now()
	j.add(Event{Kind: EventOIDCLinked, At: at, UserID: l.userID, Actor: l.actor})
	if l.password {
		j.add(Event{Kind: EventPasswordRemoved, At: at, UserID: l.userID, Method: access.MethodPassword, Actor: l.actor})
	}
	for _, id := range l.passkeys {
		j.add(Event{Kind: EventPasskeyRemoved, At: at, UserID: l.userID, PasskeyID: id, Actor: l.actor})
	}
	s.addKeysRevoked(j, l.userID, l.keys, l.actor)
	s.addRevoked(j, l.userID, l.sessions, l.actor)
}

// UnlinkOIDC removes p's own user's OIDC link, for a full session within
// RecentAuth, in one Update: a user with no link is ErrNotFound, and a
// removal that leaves no method able to sign the user in now ErrLastMethod,
// both with nothing written.
func (s *Service) UnlinkOIDC(ctx context.Context, p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(p)
	if err != nil {
		return err
	}
	gone := credential{method: access.MethodOIDC}
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		u, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if heldErr := requireHeld(ctx, tx, u, gone); heldErr != nil {
			return heldErr
		}
		if guardErr := s.guardLastMethod(ctx, tx, r, u, gone); guardErr != nil {
			return guardErr
		}
		u.OIDC, u.UpdatedAt = access.OIDCIdentity{}, s.now()
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		j.add(Event{Kind: EventOIDCUnlinked, At: s.now(), UserID: p.User.ID, Actor: eventActor(As(p))})
		return nil
	})
}
