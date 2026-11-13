package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

// Me returns p's own view: the user as stored, its sign-in methods with
// their failure-cap locks, whether single sign-on governs them, and p's
// session with the deadlines p was verified under. Only a full session may
// call it (ErrSessionRequired); a user deleted since p was verified is
// ErrSessionGone. It writes nothing.
func (s *Service) Me(ctx context.Context, p access.Principal) (Me, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return Me{}, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return Me{}, sessErr
	}
	u, found, err := s.store.UserByID(ctx, p.User.ID)
	switch {
	case err != nil:
		return Me{}, storeErr(err)
	case !found:
		return Me{}, ErrSessionGone
	}
	me, err := s.meIn(ctx, s.store, r, u, p)
	if err != nil {
		return Me{}, storeErr(err)
	}
	return me, nil
}

// meIn is p's own view of u under r, its methods read from tx (the store
// itself for single calls). A read error is returned as it is.
func (s *Service) meIn(ctx context.Context, tx Tx, r Rules, u *access.User, p access.Principal) (Me, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and the Principal Authenticate returned
	m, err := s.methods(ctx, tx, r, u)
	if err != nil {
		return Me{}, err
	}
	return Me{
		User:        u,
		Methods:     m,
		CanLinkOIDC: m.OIDCAvailable && !m.OIDCLinked,
		SSOGoverned: r.SSOGoverned && m.OIDCLinked,
		Current: CurrentSession{
			ID: p.SessionID, Method: p.Method, AuthTime: p.AuthTime,
			IdleDeadline: p.IdleDeadline, AbsoluteDeadline: p.AbsoluteDeadline,
		},
	}, nil
}

// methods is what u can sign in with under r, read from tx (the store
// itself for single calls): its passkey count and the locks of its failure
// records. A read error is returned as it is.
func (s *Service) methods(ctx context.Context, tx Tx, r Rules, u *access.User) (Methods, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	passkeys, err := tx.PasskeysByUserID(ctx, u.ID)
	if err != nil {
		return Methods{}, err
	}
	m := Methods{
		PasskeyCount:      len(passkeys),
		HasPassword:       !u.PasswordHash.IsZero(),
		OIDCLinked:        !u.OIDC.IsZero(),
		OIDCAvailable:     s.OIDCProvider() != nil,
		PasskeysAvailable: s.passkeysAvailable(),
		PasswordLogin:     !r.DisablePasswordLogin,
	}
	name := failureName(s.failureMAC(), u.Username)
	for _, method := range countedMethods {
		lock, lockErr := lockOf(ctx, tx, name, method)
		if lockErr != nil {
			return Methods{}, lockErr
		}
		if lock.Untrusted || lock.Trusted {
			m.Locks = append(m.Locks, lock)
		}
	}
	return m, nil
}

// lockOf reads from tx which trust contexts of name's method records are
// locked.
func lockOf(ctx context.Context, tx Tx, name string, method access.Method) (MethodLock, error) {
	locked := func(trusted bool) (bool, error) {
		rec, found, err := tx.AuthFailure(ctx, FailureRef{Name: name, Method: method, Trusted: trusted})
		if err != nil {
			return false, err
		}
		return found && rec.Locked, nil
	}
	untrusted, err := locked(false)
	if err != nil {
		return MethodLock{}, err
	}
	trusted, err := locked(true)
	if err != nil {
		return MethodLock{}, err
	}
	return MethodLock{Method: method, Untrusted: untrusted, Trusted: trusted}, nil
}

// passkeysAvailable reports whether Config.RP currently resolves to a
// relying party.
func (s *Service) passkeysAvailable() bool { return s.relyingParty() != nil }

// relyingParty resolves Config.RP once; nil means passkeys are off.
func (s *Service) relyingParty() *webauthn.RelyingParty {
	if s.rp == nil {
		return nil
	}
	return s.rp()
}
