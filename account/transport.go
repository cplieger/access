package account

import "github.com/cplieger/access"

// plainRule is an operation's answer to a plain request; docs/plain-http.md
// owns which operation answers which.
type plainRule int

const (
	plainAllowed    plainRule = iota // neither posture refuses it
	plainPerRequest                  // only access.PostureSecure refuses it
	plainRefused                     // both postures refuse it
)

// transport is access.ErrHTTPSRequired for a plain request (secure false)
// that rule refuses under the Authenticator's posture.
func (s *Service) transport(rule plainRule, secure bool) error {
	switch {
	case secure, rule == plainAllowed:
		return nil
	case rule == plainPerRequest && s.authn.Cookie().Posture == access.PosturePerRequest:
		return nil
	}
	return access.ErrHTTPSRequired
}

// beginOver is begin, then transport: an operation's head, ahead of every
// other check, limiter charge and store read, so a refused plain request
// costs nothing and its answer never depends on its input.
func (s *Service) beginOver(rule plainRule, secure bool) (Rules, error) {
	r, err := s.begin()
	if err != nil {
		return Rules{}, err
	}
	if err := s.transport(rule, secure); err != nil {
		return Rules{}, err
	}
	return r, nil
}

// secure is a's transport as the transport checks read it: an out-of-band
// actor crossed no network, and any other is its principal's.
func (a Actor) secure() bool { //nolint:gocritic // hugeParam: as Principal
	return a.kind == actorOutOfBand || a.principal.Secure
}
