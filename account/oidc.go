package account

import (
	"context"
	"fmt"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// AdmitOIDC is an anonymous OIDC request's one provider read, for the
// sign-in and invite starts, the callback and the pending routes: ErrServiceClosed, then
// access.ErrHTTPSRequired for a plain c, then ErrOIDCUnavailable for a nil
// OIDC(), each charging nothing, then Limiter.Request on c's IP
// (*ratelimit.RefusedError), else the provider for the whole request.
func (s *Service) AdmitOIDC(c Client) (*oidc.Provider, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	if err := s.transport(plainRefused, c.Secure); err != nil {
		return nil, err
	}
	p := s.provider()
	if p == nil {
		return nil, ErrOIDCUnavailable
	}
	if err := s.limiter.Request(ratelimit.IPKey(c.IP())); err != nil {
		return nil, err
	}
	return p, nil
}

// AdmitOIDCSession is a session-bound OIDC start's one provider read, for
// a link or a step-up by p from c: ErrServiceClosed, then
// access.ErrHTTPSRequired unless c and p are both secure, then
// ErrOIDCUnavailable for a nil OIDC(), else the provider for the whole
// request. It charges no limiter.
func (s *Service) AdmitOIDCSession(c Client, p access.Principal) (*oidc.Provider, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	if err := s.transport(plainRefused, c.Secure && p.Secure); err != nil {
		return nil, err
	}
	provider := s.provider()
	if provider == nil {
		return nil, ErrOIDCUnavailable
	}
	return provider, nil
}

// AcceptInviteOIDCBegin starts an invite's acceptance by OIDC after
// AdmitOIDC, writing nothing: the IntentInvite request for Provider.Begin,
// sealing token's stored hash. An absent, unknown, expired, used or
// other-purpose token is access.ErrTokenInvalid before the Policy
// (OpCreateUser, ViaInvite, its Role); plain: access.ErrHTTPSRequired; nil
// OIDC(): ErrOIDCUnavailable. Its callback asks both again, then creates the
// account linked, with the invite's role; a taken name commits nothing and
// gives OutcomeNotLinked holding the invite.
func (s *Service) AcceptInviteOIDCBegin(ctx context.Context, c Client, token access.Secret) (oidc.BeginRequest, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	if _, err := s.beginOver(plainRefused, c.Secure); err != nil {
		return oidc.BeginRequest{}, err
	}
	if s.provider() == nil {
		return oidc.BeginRequest{}, ErrOIDCUnavailable
	}
	invite, err := s.peekToken(ctx, token, access.PurposeInvite)
	if err != nil {
		return oidc.BeginRequest{}, err
	}
	if err := s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaInvite, Role: invite.Role}); err != nil {
		return oidc.BeginRequest{}, err
	}
	return oidc.BeginRequest{Intent: oidc.IntentInvite, InviteHash: []byte(tokenHash(token).Reveal())}, nil
}

// OIDCComplete completes the callback Finish returned after AdmitOIDC,
// charging no limiter (plain: access.ErrHTTPSRequired; nil OIDC():
// ErrOIDCUnavailable), the outcome carrying flow.Redirect. A sign-in signs in
// the linked user or a provisioned one, else gives one same OutcomeNotLinked
// (disabled, or unlinked in a single-user app: ErrInvalidCredentials). A link
// within RecentAuth or a step-up needs flow's live full session (else
// ErrSessionGone); an invite answers as AcceptInviteOIDCBegin says. A token
// Rules.OIDCAdmission refuses is then ErrNotAdmitted, journalled alone.
func (s *Service) OIDCComplete(ctx context.Context, c Client, flow oidc.Flow, claims oidc.Claims) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the callback's Client, Flow and Claims, read once
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return OIDCOutcome{}, err
	}
	if s.provider() == nil {
		return OIDCOutcome{}, ErrOIDCUnavailable
	}
	admitted := r.OIDCAdmission.admit(claims) == nil
	var out OIDCOutcome
	switch flow.Intent {
	case oidc.IntentSignIn:
		out, err = s.oidcSignIn(ctx, r, c, claims, admitted)
	case oidc.IntentLink:
		out, err = s.oidcLink(ctx, r, c, flow, claims.Identity, admitted)
	case oidc.IntentStepUp:
		out, err = s.oidcStepUp(ctx, c, flow, claims.Identity, admitted)
	case oidc.IntentInvite:
		out, err = s.oidcInvite(ctx, r, c, access.NewHash(string(flow.InviteHash)), claims, admitted)
	default:
		return OIDCOutcome{}, fmt.Errorf("%w: unknown intent %q", oidc.ErrFlowInvalid, flow.Intent)
	}
	if err != nil {
		return OIDCOutcome{}, err
	}
	out.Redirect = flow.Redirect
	return out, nil
}

// notAdmitted is the EventOIDCNotAdmitted entry of a refused token about
// userID, zero for an identity no account is linked to.
func (s *Service) notAdmitted(j *journal, userID int64, actor EventActor) {
	j.add(Event{Kind: EventOIDCNotAdmitted, At: s.now(), UserID: userID, Method: access.MethodOIDC, Actor: actor})
}

// signInResult is what one run of a sign-in's Update decided besides the
// user it signs in.
type signInResult struct {
	sync    *Event // EventRoleSynced or EventRoleSyncSkipped
	pending PendingLink
	created bool
}

// oidcSignIn signs in the user linked to claims.Identity, or provisions one,
// in one Update. With neither, the outcome is OutcomeNotLinked holding the
// identity's PendingLink, with a Provision only when provisioning admits the
// identity but its name is taken.
func (s *Service) oidcSignIn(ctx context.Context, r Rules, c Client, claims oidc.Claims, admitted bool) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Claims
	if !admitted {
		return OIDCOutcome{}, s.refuseSignIn(ctx, c, claims.Identity)
	}
	var res signInResult
	in, err := s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodOIDC,
		in: func(tx Tx) (*access.User, error) {
			res = signInResult{}
			return s.oidcUserIn(ctx, tx, r, claims, &res)
		},
		announce: func(j *journal, u *access.User, sess *access.Session) {
			if res.created {
				announceCreated(j, u, sess)
			}
			if res.sync != nil {
				j.add(*res.sync)
			}
		},
	})
	switch {
	case err != nil:
		return OIDCOutcome{}, err
	case in.User == nil:
		return OIDCOutcome{Kind: OutcomeNotLinked, Pending: res.pending}, nil
	}
	return OIDCOutcome{Kind: OutcomeSignedIn, SignedIn: in}, nil
}

// refuseSignIn answers a sign-in token OIDCAdmission refused: the answers
// that come before admission (a disabled linked user, an unlinked identity
// in a single-user app: ErrInvalidCredentials), else ErrNotAdmitted after
// journalling it.
func (s *Service) refuseSignIn(ctx context.Context, c Client, id access.OIDCIdentity) error { //nolint:gocritic // hugeParam: the callback's Client
	err := s.change(ctx, byClient(Actor{}, c), func(tx Tx, j *journal) error {
		u, found, err := tx.UserByOIDC(ctx, id)
		switch {
		case err != nil:
			return err
		case found && !u.Enabled, !found && s.singleUser:
			return refuse(ErrInvalidCredentials)
		case found:
			s.notAdmitted(j, u.ID, EventActor{})
		default:
			s.notAdmitted(j, 0, EventActor{})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ErrNotAdmitted
}

// oidcUserIn is the user a sign-in signs in, read or created inside tx: the
// user linked to the identity (disabled: ErrInvalidCredentials) with its
// role synced, else in a single-user app ErrInvalidCredentials, else a
// provisioned user, else nil with res.pending set.
func (s *Service) oidcUserIn(ctx context.Context, tx Tx, r Rules, claims oidc.Claims, res *signInResult) (*access.User, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Claims
	u, found, err := tx.UserByOIDC(ctx, claims.Identity)
	switch {
	case err != nil:
		return nil, err
	case found && !u.Enabled:
		return nil, refuse(ErrInvalidCredentials)
	case found:
		return u, s.syncRoleIn(ctx, tx, r, u, claims, res)
	case s.singleUser:
		return nil, refuse(ErrInvalidCredentials)
	}
	res.pending = pendingLink(claims)
	if !r.Provisioning.Enabled {
		return nil, nil
	}
	role, _ := r.Provisioning.role(claims)
	if refusal, err := s.provisionGate(ctx, tx, role); err != nil || refusal != nil {
		return nil, err
	}
	name, named := provisionName(claims)
	if named {
		_, taken, err := tx.UserByUsername(ctx, name)
		if err != nil {
			return nil, err
		}
		if !taken {
			fresh := s.newOIDCUser(name, role, claims.Identity)
			if err := s.createUser(ctx, tx, fresh, tx.CreateUser); err != nil {
				return nil, err
			}
			res.created = true
			return fresh, nil
		}
		res.pending.SuggestedUsername = suggestedName(name)
	}
	res.pending.Provision = &Provision{Role: role}
	return nil, nil
}

// syncRoleIn re-applies Rules.Provisioning's role mapping to u inside tx
// when SyncRole applies to u: a changed role is written and its
// EventRoleSynced kept in res, and an unreadable RoleClaim changes nothing
// and keeps EventRoleSyncSkipped.
func (s *Service) syncRoleIn(ctx context.Context, tx Tx, r Rules, u *access.User, claims oidc.Claims, res *signInResult) error { //nolint:gocritic // hugeParam: the operation's one Rules value and Claims
	if !r.Provisioning.syncs(u) {
		return nil
	}
	role, readable := r.Provisioning.role(claims)
	switch {
	case !readable:
		res.sync = &Event{Kind: EventRoleSyncSkipped, At: s.now(), UserID: u.ID, Role: u.Role}
		return nil
	case role == u.Role:
		return nil
	}
	u.Role, u.UpdatedAt = role, s.now()
	if err := tx.UpdateUser(ctx, u); err != nil {
		return err
	}
	res.sync = &Event{Kind: EventRoleSynced, At: s.now(), UserID: u.ID, Role: role}
	return nil
}

// provisionName is the username provisioning gives claims, and false when
// UsernameCandidate gives none the username rule accepts.
func provisionName(claims oidc.Claims) (string, bool) { //nolint:gocritic // hugeParam: Claims is plain data, passed as the caller holds it
	name, err := oidc.UsernameCandidate(claims)
	if err != nil {
		return "", false
	}
	username, err := canonicalUsername(name)
	return username, err == nil
}

// suggestedName is name with the suffix "_2", trimmed to fit
// MaxUsernameLength; empty when that is no valid name. It reads no user,
// so the pending answer names nothing the store holds.
func suggestedName(name string) string {
	const suffix = "_2"
	base := []rune(name)
	base = base[:min(len(base), MaxUsernameLength-len(suffix))]
	candidate, err := canonicalUsername(string(base) + suffix)
	if err != nil {
		return ""
	}
	return candidate
}

// newOIDCUser is the account provisioning or an invite creates for id.
func (s *Service) newOIDCUser(username string, role access.Role, id access.OIDCIdentity) *access.User {
	now := s.now()
	return &access.User{
		Username: username, Role: role, OIDC: id, Enabled: true,
		WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now,
	}
}

// provisionGate is provisioning's checks on the rows tx reads, as a
// refusal: some user exists, so the first account always comes through
// setup (else ErrProvisioningDisabled), then the Policy allows OpCreateUser
// of role from the zero Actor with ViaProvisioning. err is a store error.
func (s *Service) provisionGate(ctx context.Context, tx Tx, role access.Role) (refusal, err error) {
	users, err := tx.ListUsers(ctx)
	switch {
	case err != nil:
		return nil, err
	case len(users) == 0:
		return ErrProvisioningDisabled, nil
	}
	return s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaProvisioning, Role: role, Users: users}), nil
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

// CreatePendingOIDC creates an account named username for pending's
// identity and signs it in (plain: access.ErrHTTPSRequired; the zero
// PendingLink, a pending state that did not open: ErrNotFound). A pending
// Invite needs the invite (else access.ErrTokenInvalid) and the Policy
// (ViaInvite); otherwise Provision, Rules.Provisioning and a stored user
// (else ErrProvisioningDisabled) and the Policy (ViaProvisioning). One Update
// checks the identity unlinked (ErrOIDCIdentityTaken) and the name free
// (ErrUsernameTaken, which leaves pending usable for another name).
func (s *Service) CreatePendingOIDC(ctx context.Context, c Client, pending PendingLink, username string) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client and the pending link it read
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return SignedIn{}, err
	}
	if s.provider() == nil {
		return SignedIn{}, ErrOIDCUnavailable
	}
	switch {
	case pending.Identity.Issuer == "" || pending.Identity.Subject == "":
		return SignedIn{}, ErrNotFound
	case pending.Invite.IsZero() && (pending.Provision == nil || !r.Provisioning.Enabled):
		return SignedIn{}, ErrProvisioningDisabled
	}
	name, err := canonicalUsername(username)
	if err != nil {
		return SignedIn{}, err
	}
	if !pending.Invite.IsZero() {
		return s.createPendingInvite(ctx, r, c, pending, name)
	}
	role := pending.Provision.Role
	return s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodOIDC,
		in: func(tx Tx) (*access.User, error) {
			return s.createPendingIn(ctx, tx, name, role, pending.Identity)
		},
		announce: announceCreated,
	})
}

// createPendingIn is CreatePendingOIDC's gates and creation inside tx.
func (s *Service) createPendingIn(ctx context.Context, tx Tx, name string, role access.Role, id access.OIDCIdentity) (*access.User, error) {
	refusal, err := s.provisionGate(ctx, tx, role)
	switch {
	case err != nil:
		return nil, err
	case refusal != nil:
		return nil, refuse(refusal)
	}
	if linkErr := identityFreeIn(ctx, tx, id); linkErr != nil {
		return nil, linkErr
	}
	_, taken, err := tx.UserByUsername(ctx, name)
	switch {
	case err != nil:
		return nil, err
	case taken:
		return nil, refuse(ErrUsernameTaken)
	}
	fresh := s.newOIDCUser(name, role, id)
	if err := s.createUser(ctx, tx, fresh, tx.CreateUser, ErrUsernameTaken); err != nil {
		return nil, err
	}
	return fresh, nil
}

// oidcLink links id to flow's user in one Update: the session check, then
// flow.BeganAt within r.RecentAuth (else access.ErrRecentAuthRequired), then
// admission, then linkIn, rotating the session by (UserID, ID), from c's
// address.
func (s *Service) oidcLink(ctx context.Context, r Rules, c Client, flow oidc.Flow, id access.OIDCIdentity, admitted bool) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Flow
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
		if !admitted {
			s.notAdmitted(j, u.ID, eventActor(sessionActor(u, sess)))
			return nil
		}
		if err := s.linkIn(ctx, tx, sessionActor(u, sess), u, linkSession{sess: sess, fresh: true}, id, &l); err != nil {
			return err
		}
		s.addLinked(j, &l)
		return nil
	})
	switch {
	case err != nil:
		return OIDCOutcome{}, err
	case !admitted:
		return OIDCOutcome{}, ErrNotAdmitted
	}
	return OIDCOutcome{Kind: OutcomeLinked, Issued: Issued{Token: l.rot.token, Session: l.rot.session}}, nil
}

// oidcStepUp re-proves flow's user by its linked identity in one Update:
// the session check, id equal to the user's non-zero link (else
// ErrInvalidCredentials), admission, then a rotation by (UserID, ID) to AuthTime now
// and MethodOIDC, with a device cookie that keeps the ID of c.Device when
// that is valid for the user.
func (s *Service) oidcStepUp(ctx context.Context, c Client, flow oidc.Flow, id access.OIDCIdentity, admitted bool) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the callback's Client and Flow
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
		if !admitted {
			s.notAdmitted(j, u.ID, eventActor(sessionActor(u, sess)))
			return nil
		}
		user = u
		if rot, err = s.rotateSession(ctx, tx, sess, access.Hash{}, access.MethodOIDC, true); err != nil {
			return err
		}
		actor := EventActor{SessionID: rot.session.ID, UserID: u.ID}
		j.add(Event{Kind: EventSteppedUp, At: rot.session.AuthTime, UserID: u.ID, Method: access.MethodOIDC, SessionIDs: []string{rot.session.ID}, Actor: actor})
		return nil
	})
	switch {
	case err != nil:
		return OIDCOutcome{}, err
	case !admitted:
		return OIDCOutcome{}, ErrNotAdmitted
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
	if i < 0 || access.ValidateSession(&sessions[i], s.authn.Timeouts(), s.now()) != nil {
		return nil, nil, refuse(ErrSessionGone)
	}
	return u, &sessions[i], nil
}

// sessionActor is the actor of a callback's session, which no verifier
// produced: a principal Actor holding the user and session tx read, so a
// Policy sees the user it decides for, and IsSession is false on it.
func sessionActor(u *access.User, sess *access.Session) Actor {
	return As(access.Principal{User: u, Method: sess.AuthMethod, SessionID: sess.ID, AuthTime: sess.AuthTime})
}

// LinkPendingOIDC links pending's identity to p's own user (a full session
// within RecentAuth; plain: access.ErrHTTPSRequired) in one Update that
// re-reads the user, rotates p's session into Issued and reads the returned Me,
// so a failed read rolls the link back. No identity is ErrNotFound, a disabled
// user ErrSessionGone, a linked user ErrAlreadyLinked, an identity of another
// user ErrOIDCIdentityTaken. A link that leaves the user's local methods
// dormant under the stored SSO mode moves p's session onto MethodOIDC, its
// AuthTime kept, and ends the user's other sessions of a local method.
func (s *Service) LinkPendingOIDC(ctx context.Context, p access.Principal, pending PendingLink) (Issued, Me, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(plainRefused, p.Secure, p)
	if err != nil {
		return Issued{}, Me{}, err
	}
	if s.provider() == nil {
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
		if linkErr := s.linkIn(ctx, tx, As(p), u, linkSession{sess: sess, expect: p.SessionTokenHash()}, pending.Identity, &l); linkErr != nil {
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
// session and the sessions the stored mode then forbids, ended.
type linked struct {
	actor    EventActor
	sessions []string
	rot      rotated
	userID   int64
}

// linkSession is the session a link rotates, as tx read it. expect is the
// RotateSession compare-and-swap (zero: by UserID and ID). fresh is a link
// whose provider round trip authenticated now, so a rotation onto
// MethodOIDC also moves AuthTime to now.
type linkSession struct {
	sess   *access.Session
	expect access.Hash
	fresh  bool
}

// linkIn links id to u inside tx and rotates ls's session. A user already
// linked is ErrAlreadyLinked, then an identity linked to another user
// ErrOIDCIdentityTaken. When the link leaves u's local methods dormant
// under the stored mode, the rotation moves the session onto MethodOIDC and
// endForbiddenSessions ends u's others.
func (s *Service) linkIn(ctx context.Context, tx Tx, actor Actor, u *access.User, ls linkSession, id access.OIDCIdentity, l *linked) error { //nolint:gocritic // hugeParam: the operation's Actor
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
	mode, err := storedMode(ctx, tx)
	if err != nil {
		return err
	}
	u.OIDC, u.UpdatedAt = id, s.now()
	if writeErr := tx.UpdateUser(ctx, u); writeErr != nil {
		return writeErr
	}
	if !mode.dormantFor(u) {
		l.rot, err = s.rotateSession(ctx, tx, ls.sess, ls.expect, "", false)
		return err
	}
	if l.rot, err = s.rotateSession(ctx, tx, ls.sess, ls.expect, access.MethodOIDC, ls.fresh); err != nil {
		return err
	}
	l.sessions, err = endForbiddenSessions(ctx, tx, u)
	return err
}

// addLinked adds a link's entries: EventOIDCLinked, then
// EventUserSessionsRevoked for the sessions it ended.
func (s *Service) addLinked(j *journal, l *linked) {
	j.add(Event{Kind: EventOIDCLinked, At: s.now(), UserID: l.userID, Actor: l.actor})
	s.addRevoked(j, l.userID, l.sessions, l.actor)
}

// UnlinkOIDC removes p's own user's OIDC link, for a full session within
// RecentAuth, in one Update: a user with no link is ErrNotFound, and a
// removal that leaves no method able to sign the user in now ErrLastMethod,
// both with nothing written.
func (s *Service) UnlinkOIDC(ctx context.Context, p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(plainAllowed, p.Secure, p)
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

// AdminUnlinkOIDC removes userID's OIDC link for an admin principal, a
// ManageUsersScope key or an out-of-band actor, under Policy
// (OpUnlinkOIDC) and the owner protections, in one Update that also ends
// every session of the user. A key unlinks RoleUser targets only
// (admin_target). A refusal answers before existence; a missing or
// unlinked user is ErrNotFound. No last-method guard applies: a link to a
// lost or reassigned provider account goes even when nothing else remains.
func (s *Service) AdminUnlinkOIDC(ctx context.Context, a Actor, userID int64) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return err
	}
	if admitErr := s.admitUserAdmin(r, a); admitErr != nil {
		return admitErr
	}
	return s.change(ctx, by(a), func(tx Tx, j *journal) error {
		target, targetErr := s.unlinkTargetIn(ctx, tx, j, a, userID)
		if targetErr != nil {
			return targetErr
		}
		target.OIDC, target.UpdatedAt = access.OIDCIdentity{}, s.now()
		if writeErr := tx.UpdateUser(ctx, target); writeErr != nil {
			return writeErr
		}
		sessions, deleteErr := tx.DeleteUserSessions(ctx, userID, "")
		if deleteErr != nil {
			return deleteErr
		}
		slices.Sort(sessions)
		actor := eventActor(a)
		j.add(Event{Kind: EventOIDCUnlinked, At: s.now(), UserID: userID, Actor: actor})
		s.addRevoked(j, userID, sessions, actor)
		return nil
	})
}

// unlinkTargetIn is AdminUnlinkOIDC's authority inside tx: the Policy and
// the owner protections, then existence, the key's admin_target rule and
// a link to remove, returning the target.
func (s *Service) unlinkTargetIn(ctx context.Context, tx Tx, j *journal, a Actor, userID int64) (*access.User, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, j, OpUnlinkOIDC, a)
	if err != nil {
		return nil, err
	}
	target, found, users, err := targetIn(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	if polErr := s.authorizeOwned(ctx, &Decision{Op: OpUnlinkOIDC, Actor: ua.actor, Target: target, Users: users}); polErr != nil {
		return nil, refuse(polErr)
	}
	if !found {
		return nil, refuse(ErrNotFound)
	}
	if ruleErr := ua.target(OpUnlinkOIDC, target.Role); ruleErr != nil {
		return nil, ruleErr
	}
	if target.OIDC.IsZero() {
		return nil, refuse(ErrNotFound)
	}
	return target, nil
}
