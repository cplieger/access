package account

import (
	"bytes"
	"cmp"
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

// PasskeyLoginBegin starts a discoverable passkey sign-in at origin, in mode. A
// plain c is access.ErrHTTPSRequired, a nil RP() ErrPasskeysUnavailable and an
// unknown mode an error; a call past those counts against c's IP request limit
// (*ratelimit.RefusedError) before the pending cache grows. An origin the
// relying party refuses is its *webauthn.OriginError.
func (s *Service) PasskeyLoginBegin(_ context.Context, c Client, origin webauthn.Origin, mode LoginMode) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	if _, err := s.beginOver(plainRefused, c.Secure); err != nil {
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

// PasskeyLoginFinish completes the sign-in ceremonyID began and creates a full
// session for the asserting user, with a device cookie that keeps the ID of
// c.Device when that is valid for the user. A plain c is
// access.ErrHTTPSRequired, an unknown, spent, expired or other ceremony
// ErrCeremonyInvalid, a credential no user holds webauthn.ErrUnknownCredential,
// and a disabled or dormant user ErrInvalidCredentials, after the credential's
// custody update is stored. CloneWarning reports a regressed sign counter.
func (s *Service) PasskeyLoginFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, err := s.beginOver(plainRefused, c.Secure)
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
			res, verifyErr = webauthn.CompleteLogin(ctx, rp, ceremonyStore{s.store}, entry.ceremony, body)
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
			return u, requireLocal(ctx, tx, u, ErrInvalidCredentials)
		},
	})
	if err != nil {
		return SignedIn{}, err
	}
	out.CloneWarning = res.CloneWarning
	return out, nil
}

// PasskeyRegisterBegin starts enrolling a passkey for p's own user, for a
// full session within RecentAuth. A plain p is access.ErrHTTPSRequired, a
// nil RP() ErrPasskeysUnavailable, and a dormant user ErrSSOOnly. While the
// user holds a second factor it takes proof, which verifyProof answers and
// spends here.
func (s *Service) PasskeyRegisterBegin(ctx context.Context, c Client, p access.Principal, origin webauthn.Origin, proof SecondFactorProof) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginRecentSession(plainRefused, p.Secure, p)
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
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return PendingCeremony{}, modeErr
	}
	if proofErr := s.proveIfHeld(ctx, r, c, p, u, proof); proofErr != nil {
		return PendingCeremony{}, proofErr
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	cc, ceremony, err := webauthn.BeginRegistration(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeAddPasskey, pending{user: *u, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Creation: cc}, nil
}

// proveIfHeld verifies and commits proof, in its own change, while u holds
// a second factor; it is nil otherwise, any proof sent unread.
func (s *Service) proveIfHeld(ctx context.Context, r Rules, c Client, p access.Principal, u *access.User, proof SecondFactorProof) error { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Principal
	held, err := s.secondFactorHeld(ctx, s.store, r, u)
	if err != nil {
		return storeErr(err)
	}
	if !held {
		return nil
	}
	pr, err := s.verifyProof(ctx, r, c, p, u, proof)
	if err != nil {
		return err
	}
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error { return pr.commit(ctx, s, tx, j, p) })
	pr.settle(err)
	return err
}

// PasskeyRegisterFinish stores the passkey ceremonyID enrols for p's own user,
// named by webauthn.PasskeyFriendlyName against the user's passkeys, and
// rotates p's session into Issued, in one Update. A plain p is
// access.ErrHTTPSRequired, a ceremony another user began ErrCeremonyInvalid,
// and a credential already registered to any user ErrDuplicateCredential.
// The same Update runs the recovery code's issue rule (issueRecoveryIn).
func (s *Service) PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (Registered, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.beginRecentSession(plainRefused, p.Secure, p)
	if err != nil {
		return Registered{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return Registered{}, ErrPasskeysUnavailable
	}
	entry, err := s.takeOwn(ceremonyID, purposeAddPasskey, p)
	if err != nil {
		return Registered{}, err
	}
	cred, err := webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: &entry.user}, entry.ceremony, body)
	if err != nil {
		return Registered{}, err
	}
	var (
		pk    Passkey
		rot   rotated
		shown access.Secret
	)
	err = s.issuingChange(ctx, by(As(p)), false, func(tx Tx, j *journal, code *issuable) error {
		u, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if modeErr := requireLocal(ctx, tx, u, ErrSSOOnly); modeErr != nil {
			return modeErr
		}
		var addErr error
		if pk.Credential, addErr = s.addPasskey(ctx, tx, u.ID, cred, ErrDuplicateCredential); addErr != nil {
			return addErr
		}
		if pk.Removable, addErr = s.removable(ctx, tx, r, u, credential{method: access.MethodPasskey, passkeyID: pk.Credential.ID}); addErr != nil {
			return addErr
		}
		var rotErr error
		if rot, rotErr = s.rotate(ctx, tx, p, u.ID, ""); rotErr != nil {
			return rotErr
		}
		j.add(Event{Kind: EventPasskeyAdded, At: pk.Credential.CreatedAt, UserID: u.ID, PasskeyID: pk.Credential.ID, Actor: eventActor(As(p))})
		var issueErr error
		shown, issueErr = s.issueRecoveryIn(ctx, tx, j, r, u, code, eventActor(As(p)))
		return issueErr
	})
	if err != nil {
		return Registered{}, err
	}
	return Registered{Passkey: pk, Issued: Issued{Token: rot.token, Session: rot.session}, RecoveryCode: shown}, nil
}

// StepUpPasskeyBegin starts re-proving p's user with one of its passkeys under
// the current relying party's ID, for a full session. A plain p is
// access.ErrHTTPSRequired, a nil RP() ErrPasskeysUnavailable, a dormant user
// ErrSSOOnly, and a user holding no such passkey ErrNotFound.
func (s *Service) StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.beginOver(plainRefused, p.Secure); err != nil {
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
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return PendingCeremony{}, modeErr
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
	id := s.pending.put(purposeStepUp, pending{user: *u, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Assertion: assertion}, nil
}

// StepUpPasskeyFinish completes the step-up ceremonyID began, against the
// passkeys p's user holds now, and rotates p's session to AuthTime now and
// AuthMethod MethodPasskey, returning in Issued a device cookie that keeps the
// ID of c.Device when that is valid for the user. A plain c or p is
// access.ErrHTTPSRequired, a ceremony another user began ErrCeremonyInvalid,
// a dormant user ErrSSOOnly,
// and a session rotated or ended meanwhile ErrSessionGone.
func (s *Service) StepUpPasskeyFinish(ctx context.Context, c Client, p access.Principal, ceremonyID string, body io.Reader) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	if _, err := s.beginOver(plainRefused, c.Secure && p.Secure); err != nil {
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
	if _, verifyErr := webauthn.CompleteReauthentication(ctx, rp, ceremonyStore{s.store}, wu, entry.ceremony, body); verifyErr != nil {
		return Issued{}, verifyErr
	}
	var rot rotated
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		cur, userErr := ownUserIn(ctx, tx, p)
		if userErr != nil {
			return userErr
		}
		if modeErr := requireLocal(ctx, tx, cur, ErrSSOOnly); modeErr != nil {
			return modeErr
		}
		var rotErr error
		if rot, rotErr = s.rotate(ctx, tx, p, u.ID, access.MethodPasskey); rotErr != nil {
			return rotErr
		}
		j.add(Event{Kind: EventSteppedUp, At: rot.session.AuthTime, UserID: u.ID, Method: access.MethodPasskey, SessionIDs: []string{rot.session.ID}, Actor: eventActor(As(p))})
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	device := s.deviceCookie(u.Username, c)
	return Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}, nil
}

// Passkeys returns p's own passkeys as stored, each with whether
// RemovePasskey would remove it, for a full session. It works with a nil
// RP(), so stale passkeys stay listable.
func (s *Service) Passkeys(ctx context.Context, p access.Principal) ([]Passkey, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return nil, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return nil, sessErr
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return nil, err
	}
	creds, err := s.store.PasskeysByUserID(ctx, u.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	out := make([]Passkey, len(creds))
	for i := range creds {
		out[i].Credential = creds[i]
		if out[i].Removable, err = s.removable(ctx, s.store, r, u, credential{method: access.MethodPasskey, passkeyID: creds[i].ID}); err != nil {
			return nil, storeErr(err)
		}
	}
	return out, nil
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
		return answer(refusedBy(err, ErrNotFound))
	}
	return nil
}

// RemovePasskey removes p's own passkey id, for a full session within
// RecentAuth, in one Update, with or without an RP(), so stale passkeys
// stay removable. A passkey the user does not hold is ErrNotFound, a
// removal that leaves no method able to sign the user in now
// ErrLastMethod, and one the second-factor guard refuses
// ErrLastSecondFactor, each with nothing written or counted. While the
// user holds a second factor it takes proof (verifyProof's answers).
func (s *Service) RemovePasskey(ctx context.Context, c Client, p access.Principal, id int64, proof SecondFactorProof) error { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginRecentSession(plainAllowed, c.Secure && p.Secure, p)
	if err != nil {
		return err
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return err
	}
	gone := credential{method: access.MethodPasskey, passkeyID: id}
	if guardErr := answer(s.removalGuards(ctx, s.store, r, u, gone)); guardErr != nil {
		return guardErr
	}
	held, err := s.secondFactorHeld(ctx, s.store, r, u)
	if err != nil {
		return storeErr(err)
	}
	var pr proven
	if held {
		if pr, err = s.verifyProof(ctx, r, c, p, u, proof); err != nil {
			return err
		}
	}
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		return s.removePasskeyIn(ctx, tx, j, r, p, gone, held, &pr)
	})
	pr.settle(err)
	return err
}

// removePasskeyIn is RemovePasskey's change: the guards and the factor held
// re-read in tx, the proof committed, then the removal and its entry. A
// factor bound since the pre-check, which took no proof, refuses.
func (s *Service) removePasskeyIn(ctx context.Context, tx Tx, j *journal, r Rules, p access.Principal, gone credential, held bool, pr *proven) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Principal
	cur, err := ownUserIn(ctx, tx, p)
	if err != nil {
		return err
	}
	if guardErr := s.removalGuards(ctx, tx, r, cur, gone); guardErr != nil {
		return guardErr
	}
	if heldNow, heldErr := s.secondFactorHeld(ctx, tx, r, cur); heldErr != nil || heldNow && !held {
		return cmp.Or(heldErr, refuse(ErrSecondFactorProofRequired))
	}
	if commitErr := pr.commit(ctx, s, tx, j, p); commitErr != nil {
		return commitErr
	}
	if delErr := tx.DeletePasskey(ctx, access.PasskeyRef{ID: gone.passkeyID, UserID: cur.ID}); delErr != nil {
		return delErr
	}
	j.add(Event{Kind: EventPasskeyRemoved, At: s.now(), UserID: cur.ID, PasskeyID: gone.passkeyID, Actor: eventActor(As(p))})
	return nil
}

// removalGuards are a passkey removal's preconditions inside tx: the
// passkey held, the last-method guard, then the second-factor guard.
func (s *Service) removalGuards(ctx context.Context, tx Tx, r Rules, u *access.User, gone credential) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if err := requireHeld(ctx, tx, u, gone); err != nil {
		return err
	}
	if err := s.guardLastMethod(ctx, tx, r, u, gone); err != nil {
		return err
	}
	return s.guardSecondFactor(ctx, tx, r, u, gone)
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

// ceremonyStore is the store a passkey sign-in reads and writes, each error
// through withoutSentinel, since webauthn wraps it as access.ErrAuthBackend:
// no store refusal is the ceremony's answer.
type ceremonyStore struct{ store Store }

var _ webauthn.Store = ceremonyStore{}

func (c ceremonyStore) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	pks, err := c.store.PasskeysByUserID(ctx, userID)
	if err != nil {
		return nil, withoutSentinel(err)
	}
	return pks, nil
}

// RecordAssertion merges upd into the stored credential in one Update, per
// webauthn.Store's contract.
func (c ceremonyStore) RecordAssertion(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	err := c.store.Update(ctx, func(tx Tx) error {
		held, err := tx.PasskeysByUserID(ctx, userID)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(held, func(pk access.PasskeyCredential) bool { return bytes.Equal(pk.CredentialID, credID) })
		if i < 0 {
			return ErrNotFound
		}
		merged := upd
		merged.SignCount = max(held[i].SignCount, upd.SignCount)
		merged.CloneWarning = held[i].CloneWarning || upd.CloneWarning
		return tx.UpdatePasskeyAfterLogin(ctx, userID, credID, merged)
	})
	return withoutSentinel(err)
}

func (c ceremonyStore) UserByWebAuthnHandle(ctx context.Context, handle []byte) (*access.User, bool, error) {
	u, found, err := c.store.UserByWebAuthnHandle(ctx, handle)
	if err != nil {
		return nil, false, withoutSentinel(err)
	}
	return u, found, nil
}

// addPasskey stores the registered cred for userID inside tx, named by
// webauthn.PasskeyFriendlyName against the passkeys the user holds there.
// refusals are the store refusals CreatePasskey answers (refusedBy).
func (s *Service) addPasskey(ctx context.Context, tx Tx, userID int64, cred *access.PasskeyCredential, refusals ...error) (access.PasskeyCredential, error) {
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
		return access.PasskeyCredential{}, refusedBy(err, refusals...)
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
	if !ok || entry.user.ID != p.User.ID {
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
