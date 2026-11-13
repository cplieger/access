package account

import (
	"context"
	"io"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// SetupPasskey is the input of SetupPasskeyBegin.
type SetupPasskey struct {
	Token    access.Secret // zero when the setup rule asks for none
	Username string
	Origin   webauthn.Origin
}

// SetupPasskeyBegin starts creating the first account, an admin signing in
// with a passkey. A nil RP() is ErrPasskeysUnavailable; then, as
// SetupWithPassword, a user present is ErrSetupComplete, a missing or
// invalid token where Rules.SetupTokenRequired asks for one
// ErrSetupTokenRequired or access.ErrTokenInvalid, and a refused name
// *UsernameError. Only a call past those refusals counts against c's IP
// request limit (*ratelimit.RefusedError). The token is only peeked; the
// finish spends it.
func (s *Service) SetupPasskeyBegin(ctx context.Context, c Client, in SetupPasskey) (PendingCeremony, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.begin()
	if err != nil {
		return PendingCeremony{}, err
	}
	var (
		rp       *webauthn.RelyingParty
		spend    access.Hash
		username string
	)
	gate := admission{
		refusals: func() error {
			if rp = s.relyingParty(); rp == nil {
				return ErrPasskeysUnavailable
			}
			var checkErr error
			spend, username, checkErr = s.setupChecks(ctx, r, c, in.Token, in.Username)
			return checkErr
		},
		limit: s.requestLimit(c),
	}
	if _, admitErr := gate.admit(); admitErr != nil {
		return PendingCeremony{}, admitErr
	}
	user := access.User{Username: username, Role: access.RoleAdmin, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle()}
	creation, ceremony, err := webauthn.BeginRegistration(rp, &webauthn.User{AuthUser: &user}, in.Origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeSetup, pending{user: user, setupToken: spend, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Creation: creation}, nil
}

// SetupPasskeyFinish verifies the attestation of the setup ceremonyID
// began, then in one Update spends the token the begin peeked, asks the
// Policy (OpCreateUser, ViaSetup), and creates the admin, its passkey and a
// full session. A concurrent setup that won is ErrSetupComplete or
// access.ErrTokenInvalid, with nothing written. An unknown, spent, expired or
// other ceremony is ErrCeremonyInvalid.
func (s *Service) SetupPasskeyFinish(ctx context.Context, c Client, ceremonyID string, body io.Reader) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, err := s.begin()
	if err != nil {
		return SignedIn{}, err
	}
	var (
		entry pending
		cred  *access.PasskeyCredential
	)
	return s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodPasskey,
		prepare: func(*ratelimit.Reservation) error {
			rp := s.relyingParty()
			if rp == nil {
				return ErrPasskeysUnavailable
			}
			var ok bool
			if entry, ok = s.pending.take(ceremonyID, purposeSetup, s.now()); !ok {
				return ErrCeremonyInvalid
			}
			var verifyErr error
			cred, verifyErr = webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: &entry.user}, entry.ceremony, body)
			return verifyErr
		},
		in: func(tx Tx) (*access.User, error) {
			now := s.now()
			user := entry.user
			user.CreatedAt, user.UpdatedAt = now, now
			if err := s.createFirstUser(ctx, tx, entry.setupToken, &user); err != nil {
				return nil, err
			}
			if _, err := s.addPasskey(ctx, tx, user.ID, cred); err != nil {
				return nil, err
			}
			return &user, nil
		},
		announce: announceCreated,
	})
}
