package account

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// LoginMode is how a passkey sign-in asks the browser for a credential.
type LoginMode int

const (
	// LoginModal is the default: the browser shows its passkey dialog.
	LoginModal LoginMode = iota
	// LoginConditional offers the passkeys through the browser's autofill
	// (conditional mediation).
	LoginConditional
)

// PasskeyLoginBegin starts a discoverable passkey sign-in at origin, in
// mode. A nil RP() is ErrPasskeysUnavailable and an unknown mode an error;
// a call past those counts against c's IP request limit
// (*ratelimit.RefusedError) before the pending cache grows. An origin the
// relying party refuses is its *webauthn.OriginError.
func (s *Service) PasskeyLoginBegin(_ context.Context, c Client, origin webauthn.Origin, mode LoginMode) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	if _, err := s.begin(); err != nil {
		return PendingCeremony{}, err
	}
	var rp *webauthn.RelyingParty
	beginLogin := webauthn.BeginLogin
	gate := admission{
		refusals: func() error {
			if rp = s.relyingParty(); rp == nil {
				return ErrPasskeysUnavailable
			}
			switch mode {
			case LoginModal:
			case LoginConditional:
				beginLogin = webauthn.BeginConditionalLogin
			default:
				return fmt.Errorf("account: unknown LoginMode %d", mode)
			}
			return nil
		},
		limit: s.requestLimit(c),
	}
	if _, err := gate.admit(); err != nil {
		return PendingCeremony{}, err
	}
	assertion, ceremony, err := beginLogin(rp, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeLogin, pending{ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Assertion: assertion}, nil
}

// PasskeyLoginFinish completes the sign-in ceremonyID began and creates a
// full session for the asserting user, with a device cookie that keeps the
// ID of c.Device when that is valid for the user. An unknown, spent,
// expired or other ceremony is ErrCeremonyInvalid; a credential no user
// holds is webauthn.ErrUnknownCredential; a disabled user is
// ErrInvalidCredentials, after the credential's custody update is stored.
// CloneWarning reports a regressed sign counter.
func (s *Service) PasskeyLoginFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, err := s.begin()
	if err != nil {
		return SignedIn{}, err
	}
	var res webauthn.LoginResult
	out, err := s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodPasskey,
		prepare: func(*ratelimit.Reservation) error {
			rp := s.relyingParty()
			if rp == nil {
				return ErrPasskeysUnavailable
			}
			entry, ok := s.pending.take(ceremonyID, purposeLogin, s.now())
			if !ok {
				return ErrCeremonyInvalid
			}
			var verifyErr error
			res, verifyErr = webauthn.CompleteLogin(ctx, rp, s.store, entry.ceremony, body)
			return verifyErr
		},
		in: func(tx Tx) (*access.User, error) {
			u, found, readErr := tx.UserByID(ctx, res.User.ID)
			switch {
			case readErr != nil:
				return nil, readErr
			case !found || !u.Enabled:
				return nil, refuse(ErrInvalidCredentials)
			}
			return u, nil
		},
	})
	if err != nil {
		return SignedIn{}, err
	}
	out.CloneWarning = res.CloneWarning
	return out, nil
}

// PasskeyRegisterBegin starts enrolling a passkey for p's own user, for a
// full session within RecentAuth. A nil RP() is ErrPasskeysUnavailable, and
// a linked user under Rules.SSOGoverned is ErrSSOGoverned.
func (s *Service) PasskeyRegisterBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(p)
	if err != nil {
		return PendingCeremony{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return PendingCeremony{}, err
	}
	if r.SSOGoverned && !u.OIDC.IsZero() {
		return PendingCeremony{}, ErrSSOGoverned
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	cc, ceremony, err := webauthn.BeginRegistration(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeRegister, pending{user: u, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Creation: cc}, nil
}

// PasskeyRegisterFinish stores the passkey ceremonyID enrols for p's own
// user, named by webauthn.PasskeyFriendlyName against the user's passkeys,
// and rotates p's session into Issued, in one Update. A ceremony another
// user began is ErrCeremonyInvalid; a credential already registered to any
// user is ErrDuplicateCredential.
func (s *Service) PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (Registered, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(p)
	if err != nil {
		return Registered{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return Registered{}, ErrPasskeysUnavailable
	}
	entry, err := s.takeOwn(ceremonyID, purposeRegister, p)
	if err != nil {
		return Registered{}, err
	}
	cred, err := webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: entry.user}, entry.ceremony, body)
	if err != nil {
		return Registered{}, err
	}
	var (
		pk  access.PasskeyCredential
		rot rotated
	)
	err = s.update(ctx, func(tx Tx) error {
		u, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if r.SSOGoverned && !u.OIDC.IsZero() {
			return refuse(ErrSSOGoverned)
		}
		var addErr error
		if pk, addErr = s.addPasskey(ctx, tx, u.ID, cred); addErr != nil {
			return addErr
		}
		var rotErr error
		rot, rotErr = s.rotate(ctx, tx, p, u.ID, "")
		return rotErr
	})
	if err != nil {
		return Registered{}, err
	}
	s.emit(Event{Kind: EventPasskeyAdded, At: pk.CreatedAt, UserID: pk.UserID, PasskeyID: pk.ID, Actor: eventActor(As(p))})
	return Registered{Passkey: pk, Issued: Issued{Token: rot.token, Session: rot.session}}, nil
}

// StepUpPasskeyBegin starts re-proving p's user with one of its passkeys
// under the current relying party's ID, for a full session. A nil RP() is
// ErrPasskeysUnavailable, and a user holding no such passkey ErrNotFound.
func (s *Service) StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return PendingCeremony{}, err
	}
	if err := requireSession(p); err != nil {
		return PendingCeremony{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return PendingCeremony{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	wu.Credentials = currentRP(wu.Credentials, rp)
	if len(wu.Credentials) == 0 {
		return PendingCeremony{}, ErrNotFound
	}
	assertion, ceremony, err := webauthn.BeginReauthentication(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeStepUp, pending{user: u, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Assertion: assertion}, nil
}

// StepUpPasskeyFinish completes the step-up ceremonyID began, against the
// passkeys p's user holds now, and rotates p's session to AuthTime now and
// AuthMethod MethodPasskey, returning in Issued a device cookie that keeps
// the ID of c.Device when that is valid for the user. A ceremony another
// user began is ErrCeremonyInvalid, and a session rotated or ended
// meanwhile ErrSessionGone.
func (s *Service) StepUpPasskeyFinish(ctx context.Context, c Client, p access.Principal, ceremonyID string, body io.Reader) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	if _, err := s.begin(); err != nil {
		return Issued{}, err
	}
	if err := requireSession(p); err != nil {
		return Issued{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return Issued{}, ErrPasskeysUnavailable
	}
	entry, err := s.takeOwn(ceremonyID, purposeStepUp, p)
	if err != nil {
		return Issued{}, err
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return Issued{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return Issued{}, err
	}
	if _, verifyErr := webauthn.CompleteReauthentication(ctx, rp, s.store, wu, entry.ceremony, body); verifyErr != nil {
		return Issued{}, verifyErr
	}
	var rot rotated
	err = s.update(ctx, func(tx Tx) error {
		var rotErr error
		rot, rotErr = s.rotate(ctx, tx, p, u.ID, access.MethodPasskey)
		return rotErr
	})
	if err != nil {
		return Issued{}, err
	}
	device := s.limiter.DeviceCookie(ratelimit.AccountKey(u.Username), c.Device)
	actor := eventActor(As(p))
	s.emit(Event{Kind: EventSteppedUp, At: rot.session.AuthTime, UserID: u.ID, Method: access.MethodPasskey, SessionIDs: []string{rot.session.ID}, Actor: actor})
	return Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}, nil
}

// Passkeys returns p's own passkeys as stored, for a full session. It works
// with a nil RP(), so stale passkeys stay listable.
func (s *Service) Passkeys(ctx context.Context, p access.Principal) ([]access.PasskeyCredential, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return nil, err
	}
	if err := requireSession(p); err != nil {
		return nil, err
	}
	passkeys, err := s.store.PasskeysByUserID(ctx, p.User.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	return passkeys, nil
}

// RenamePasskey renames p's own passkey id, for a full session, with or
// without an RP(). A name of more than 128 runes or not on one line is a
// *TextError with Field label; a passkey p's user does not hold is
// ErrNotFound.
func (s *Service) RenamePasskey(ctx context.Context, p access.Principal, id int64, name string) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	if err := requireSession(p); err != nil {
		return err
	}
	if err := checkLine(TextFieldLabel, name, maxDisplayRunes); err != nil {
		return err
	}
	if err := s.store.RenamePasskey(ctx, access.PasskeyRef{ID: id, UserID: p.User.ID}, name); err != nil {
		return storeErr(err)
	}
	return nil
}

// RemovePasskey removes p's own passkey id, for a full session within
// RecentAuth, in one Update, with or without an RP(), so stale passkeys
// stay removable: a passkey the user does not hold is ErrNotFound, and a
// removal that leaves no method able to sign the user in now ErrLastMethod,
// both with nothing written.
func (s *Service) RemovePasskey(ctx context.Context, p access.Principal, id int64) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(p)
	if err != nil {
		return err
	}
	gone := credential{method: access.MethodPasskey, passkeyID: id}
	err = s.update(ctx, func(tx Tx) error {
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
		return tx.DeletePasskey(ctx, access.PasskeyRef{ID: id, UserID: u.ID})
	})
	if err != nil {
		return err
	}
	s.emit(Event{Kind: EventPasskeyRemoved, At: s.now(), UserID: p.User.ID, PasskeyID: id, Actor: eventActor(As(p))})
	return nil
}

// WebAuthnSignals returns the reconciliation payloads for p's own user and
// the passkeys it holds under the current relying party's ID, for a full
// session. A nil RP() is ErrPasskeysUnavailable.
func (s *Service) WebAuthnSignals(ctx context.Context, p access.Principal) (webauthn.Signals, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return webauthn.Signals{}, err
	}
	if err := requireSession(p); err != nil {
		return webauthn.Signals{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return webauthn.Signals{}, ErrPasskeysUnavailable
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return webauthn.Signals{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return webauthn.Signals{}, err
	}
	wu.Credentials = currentRP(wu.Credentials, rp)
	return webauthn.NewSignals(rp.ID(), wu), nil
}

// currentRP keeps the passkeys registered under rp's ID; no authenticator
// answers a ceremony for another.
func currentRP(passkeys []access.PasskeyCredential, rp *webauthn.RelyingParty) []access.PasskeyCredential {
	return slices.DeleteFunc(passkeys, func(pk access.PasskeyCredential) bool { return pk.RPID != rp.ID() })
}

// addPasskey stores the registered cred for userID inside tx, named by
// webauthn.PasskeyFriendlyName against the passkeys the user holds there.
func (s *Service) addPasskey(ctx context.Context, tx Tx, userID int64, cred *access.PasskeyCredential) (access.PasskeyCredential, error) {
	held, err := tx.PasskeysByUserID(ctx, userID)
	if err != nil {
		return access.PasskeyCredential{}, err
	}
	names := make([]string, len(held))
	for i := range held {
		names[i] = held[i].Name
	}
	pk := *cred
	pk.UserID, pk.CreatedAt = userID, s.now()
	pk.Name = webauthn.PasskeyFriendlyName(pk.AAGUID, names)
	if err := tx.CreatePasskey(ctx, &pk); err != nil {
		return access.PasskeyCredential{}, err
	}
	return pk, nil
}

// webauthnUser is u with the passkeys it holds as stored.
func (s *Service) webauthnUser(ctx context.Context, u *access.User) (*webauthn.User, error) {
	passkeys, err := s.store.PasskeysByUserID(ctx, u.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	return &webauthn.User{AuthUser: u, Credentials: passkeys}, nil
}

// takeOwn takes p's own pending ceremony id of purpose: one that is
// unknown, spent, expired, of another purpose or another user's is
// ErrCeremonyInvalid, and is spent all the same.
func (s *Service) takeOwn(id string, purpose pendingPurpose, p access.Principal) (pending, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	entry, ok := s.pending.take(id, purpose, s.now())
	if !ok || entry.user == nil || entry.user.ID != p.User.ID {
		return pending{}, ErrCeremonyInvalid
	}
	return entry, nil
}

// ownUserIn reads p's user inside tx; one deleted since p was verified is
// a refused ErrSessionGone.
func ownUserIn(ctx context.Context, tx Tx, p access.Principal) (*access.User, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	u, found, err := tx.UserByID(ctx, p.User.ID)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, refuse(ErrSessionGone)
	}
	return u, nil
}
