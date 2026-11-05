package account

import (
	"github.com/cplieger/access"
)

// Client is what the transport knows about the caller, as data.
type Client struct {
	// Host is the request's Host header (r.Host) as the transport received
	// it, port included; only the setup rule reads it. Empty when the
	// transport has none.
	Host      string
	UserAgent string        // sanitised and capped before storage
	Device    access.Secret // the device cookie as presented; zero when absent
	// ClientAddr is the Authenticator's resolver's answer for the request;
	// account never reads a header.
	access.ClientAddr
}

// Actor is who performs an operation. The zero Actor is anonymous: the
// caller proved nothing yet (setup, invite acceptance, OIDC provisioning).
type Actor struct {
	channel   string
	principal access.Principal
	kind      actorKind
}

type actorKind int

const (
	actorAnonymous actorKind = iota
	actorPrincipal
	actorOutOfBand
)

// As is the actor of a request's principal.
func As(p access.Principal) Actor { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	return Actor{principal: p, kind: actorPrincipal}
}

// OutOfBand is an actor outside any request (an admin socket, a CLI);
// channel names it in events.
func OutOfBand(channel string) Actor {
	return Actor{channel: channel, kind: actorOutOfBand}
}

// Principal returns the actor's principal, and false for an out-of-band or
// the zero Actor.
func (a Actor) Principal() (access.Principal, bool) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	return a.principal, a.kind == actorPrincipal
}

// OutOfBandChannel returns the channel of an out-of-band actor, and false
// for any other.
func (a Actor) OutOfBandChannel() (string, bool) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	return a.channel, a.kind == actorOutOfBand
}

func (a Actor) isZero() bool      { return a.kind == actorAnonymous } //nolint:gocritic // hugeParam: as Principal
func (a Actor) isOutOfBand() bool { return a.kind == actorOutOfBand } //nolint:gocritic // hugeParam: as Principal

// user returns a principal actor's user, never nil when ok.
func (a Actor) user() (u *access.User, ok bool) { //nolint:gocritic // hugeParam: as Principal
	if a.kind != actorPrincipal || a.principal.User == nil {
		return nil, false
	}
	return a.principal.User, true
}

// requireSession is the session-actor precondition every operation whose
// actor is a session runs before any read: only a full session the built-in
// session verifier produced passes. A key, a custom verifier's principal, a
// bypass principal and a recovery session get ErrSessionRequired.
func requireSession(p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if !p.IsSession() || p.User == nil {
		return ErrSessionRequired
	}
	return nil
}

// eventActor is a's identity as events carry it.
func eventActor(a Actor) EventActor { //nolint:gocritic // hugeParam: as Principal
	switch a.kind {
	case actorPrincipal:
		ea := EventActor{SessionID: a.principal.SessionID, KeyID: a.principal.KeyID}
		if a.principal.User != nil {
			ea.UserID = a.principal.User.ID
		}
		return ea
	case actorOutOfBand:
		return EventActor{OutOfBand: a.channel}
	default:
		return EventActor{}
	}
}
