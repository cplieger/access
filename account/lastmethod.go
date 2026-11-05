package account

import (
	"context"
	"slices"

	"github.com/cplieger/access"
)

// credential is one sign-in credential of a user: the password, the OIDC
// link, or the passkey passkeyID names.
type credential struct {
	method    access.Method
	passkeyID int64
}

// holds reports whether u, as tx read it, holds c.
func holds(ctx context.Context, tx Tx, u *access.User, c credential) (bool, error) {
	switch c.method {
	case access.MethodPassword:
		return !u.PasswordHash.IsZero(), nil
	case access.MethodOIDC:
		return !u.OIDC.IsZero(), nil
	case access.MethodPasskey:
		passkeys, err := tx.PasskeysByUserID(ctx, u.ID)
		if err != nil {
			return false, err
		}
		return slices.ContainsFunc(passkeys, func(pk access.PasskeyCredential) bool { return pk.ID == c.passkeyID }), nil
	}
	return false, nil
}

// requireHeld is the precondition of every removal of u's own credential c,
// run before any limiter, failure-cap or Policy call: a credential u does
// not hold is a refused ErrNotFound, so nothing is charged or counted for
// it.
func requireHeld(ctx context.Context, tx Tx, u *access.User, c credential) error {
	held, err := holds(ctx, tx, u, c)
	switch {
	case err != nil:
		return err
	case !held:
		return refuse(ErrNotFound)
	}
	return nil
}

// UsableMethods counts what userID can sign in with under st, read through
// tx (the Store itself, or the app's own Update) as the last-method guard
// counts: a password held, allowed, usable and not locked in both trust
// contexts; passkeys registered under st.RPID; an OIDC link of
// st.OIDCIssuer; each only while st.Rules.MethodUsable allows it. The app
// decides with access.CanDisableMethod or its own rule. ErrServiceClosed
// after Shutdown, ErrRulesInvalid for an invalid st.Rules, ErrNotFound for
// an unknown user; a store error is returned as it is.
func (s *Service) UsableMethods(ctx context.Context, tx Tx, userID int64, st MethodState) (access.MethodAvailability, error) { //nolint:gocritic // hugeParam: the caller's one MethodState value
	if s.closed.Load() {
		return access.MethodAvailability{}, ErrServiceClosed
	}
	if err := s.checkRules(st.Rules); err != nil {
		return access.MethodAvailability{}, err
	}
	u, found, err := tx.UserByID(ctx, userID)
	switch {
	case err != nil:
		return access.MethodAvailability{}, err
	case !found:
		return access.MethodAvailability{}, ErrNotFound
	}
	return s.availability(ctx, tx, st, u, credential{})
}

// guardLastMethod is the last-method guard of every removal, run on u as
// tx read it, with tx the removal's own Update for the check that decides.
// It counts the methods left after gone under r and the published relying
// party and provider. No method left is a refused ErrLastMethod; a store
// error is returned as it is.
func (s *Service) guardLastMethod(ctx context.Context, tx Tx, r Rules, u *access.User, gone credential) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	st := MethodState{Rules: r}
	if rp := s.relyingParty(); rp != nil {
		st.RPID = rp.ID()
	}
	if p := s.OIDCProvider(); p != nil {
		st.OIDCIssuer = p.Issuer()
	}
	avail, err := s.availability(ctx, tx, st, u, gone)
	if err != nil {
		return err
	}
	if !access.CanDisableMethod(gone.method, avail) {
		return refuse(ErrLastMethod)
	}
	return nil
}

// availability is the one count of UsableMethods and guardLastMethod: what
// u, as tx read it, signs in with under st, leaving out gone. A store error
// is returned as it is.
func (s *Service) availability(ctx context.Context, tx Tx, st MethodState, u *access.User, gone credential) (access.MethodAvailability, error) { //nolint:gocritic // hugeParam: the operation's one MethodState value
	usable := func(m access.Method) bool {
		return st.Rules.MethodUsable == nil || st.Rules.MethodUsable(ctx, tx, u, m)
	}
	var (
		avail access.MethodAvailability
		err   error
	)
	if gone.method != access.MethodPassword && !u.PasswordHash.IsZero() && !st.Rules.DisablePasswordLogin && usable(access.MethodPassword) {
		if avail.HasPassword, err = s.passwordSignsIn(ctx, tx, u); err != nil {
			return access.MethodAvailability{}, err
		}
	}
	if st.RPID != "" && usable(access.MethodPasskey) {
		if avail.PasskeyCount, err = passkeysLeft(ctx, tx, u.ID, st.RPID, gone); err != nil {
			return access.MethodAvailability{}, err
		}
	}
	if gone.method != access.MethodOIDC && !u.OIDC.IsZero() && usable(access.MethodOIDC) {
		avail.OIDCLinked = true
		avail.OIDCEnabled = st.OIDCIssuer != "" && u.OIDC.Issuer == st.OIDCIssuer
	}
	return avail, nil
}

// passwordSignsIn reports whether u's password is unlocked in at least one
// trust context.
func (s *Service) passwordSignsIn(ctx context.Context, tx Tx, u *access.User) (bool, error) {
	locked, err := lockedInBoth(ctx, tx, failureName(s.failureMAC(), u.Username))
	return !locked, err
}

// passkeysLeft counts userID's passkeys registered under rpID, leaving out
// the one gone names.
func passkeysLeft(ctx context.Context, tx Tx, userID int64, rpID string, gone credential) (int, error) {
	passkeys, err := tx.PasskeysByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range passkeys {
		removed := gone.method == access.MethodPasskey && passkeys[i].ID == gone.passkeyID
		if !removed && passkeys[i].RPID == rpID {
			n++
		}
	}
	return n, nil
}

// lockedInBoth reports whether name's password is locked in both trust
// contexts, so it signs in from no browser.
func lockedInBoth(ctx context.Context, tx Tx, name string) (bool, error) {
	for _, trusted := range []bool{false, true} {
		rec, found, err := tx.AuthFailure(ctx, FailureRef{Name: name, Method: access.MethodPassword, Trusted: trusted})
		if err != nil {
			return false, err
		}
		if !found || !rec.Locked {
			return false, nil
		}
	}
	return true, nil
}
