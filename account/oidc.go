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
// sign-in start, the callback and the pending-link read: ErrServiceClosed, then
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

// OIDCComplete completes the callback oidc.Provider.Finish returned, after
// AdmitOIDC admitted it and returned that provider, charging no limiter. A
// plain c is access.ErrHTTPSRequired and a nil OIDC() ErrOIDCUnavailable; the
// outcome carries flow.Redirect. A sign-in signs in the linked user (disabled:
// ErrInvalidCredentials) or one Rules.Provisioning admits, else gives one same
// OutcomeNotLinked. A link begun within RecentAuth, or a step-up of the linked
// identity (else ErrInvalidCredentials), needs flow's live full session (else
// ErrSessionGone).
func (s *Service) OIDCComplete(ctx context.Context, c Client, flow oidc.Flow, claims oidc.Claims) (OIDCOutcome, error) { //nolint:gocritic // hugeParam: the callback's Client, Flow and Claims, read once
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return OIDCOutcome{}, err
	}
	if s.provider() == nil {
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
	return s.authorize(ctx, Decision{Op: OpCreateUser, Via: ViaProvisioning, Role: candidate.Role, Users: users}) == nil, nil
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
		if err := s.linkIn(ctx, tx, sessionActor(u, sess), u, linkSession{sess: sess, fresh: true}, id, &l); err != nil {
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
		if rot, err = s.rotateSession(ctx, tx, sess, access.Hash{}, access.MethodOIDC, true); err != nil {
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
