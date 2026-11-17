package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// The assertion's refusals (WebAuthn §7.2).
var (
	errNoUserHandle       = errors.New("access/webauthn: a discoverable assertion carries no userHandle")
	errAssertionUser      = errors.New("access/webauthn: the assertion's userHandle is not the user's")
	errBackupEligibility  = errors.New("access/webauthn: backup eligibility differs from the stored credential's")
	errAssertionSignature = errors.New("access/webauthn: the assertion signature does not verify")
)

// verifyLogin runs WebAuthn §7.2's ceremony for a user not identified before
// it, on body, an AuthenticationResponseJSON answering st, and records the
// assertion's custody in store.
func verifyLogin(ctx context.Context, rp *RelyingParty, store Store, st *ceremonyState, body []byte) (LoginResult, error) {
	if err := st.check(ceremonyLogin); err != nil {
		return LoginResult{}, err
	}
	r, err := parseAssertionResponse(body)
	if err != nil {
		return LoginResult{}, err
	}
	user, cred, err := discoverableCredential(ctx, store, r)
	if err != nil {
		return LoginResult{}, err
	}
	a, err := verifyAssertion(rp, st, cred, r)
	if err != nil {
		return LoginResult{}, err
	}
	return recordAssertion(ctx, store, user, cred, a)
}

// verifyReauthentication runs WebAuthn §7.2's ceremony for user, identified
// before it and holding the passkeys stored now, on body answering st, and
// records the assertion's custody in store.
func verifyReauthentication(ctx context.Context, rp *RelyingParty, store Store, user *User, st *ceremonyState, body []byte) (LoginResult, error) {
	if err := st.check(ceremonyReauthentication); err != nil {
		return LoginResult{}, err
	}
	if err := st.heldBy(user); err != nil {
		return LoginResult{}, err
	}
	r, err := parseAssertionResponse(body)
	if err != nil {
		return LoginResult{}, err
	}
	cred, err := st.allowedCredential(user, r)
	if err != nil {
		return LoginResult{}, err
	}
	a, err := verifyAssertion(rp, st, cred, r)
	if err != nil {
		return LoginResult{}, err
	}
	return recordAssertion(ctx, store, user, cred, a)
}

// discoverableCredential is WebAuthn §7.2's identification step for a user not
// identified before the ceremony: the account userHandle names, and its
// credential record whose id is rawId.
func discoverableCredential(ctx context.Context, store Store, r *assertionResponse) (*User, *access.PasskeyCredential, error) {
	if r.userHandle == nil {
		return nil, nil, errNoUserHandle
	}
	account, found, err := store.UserByWebAuthnHandle(ctx, r.userHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: access/webauthn: passkey lookup: %w", access.ErrAuthBackend, err)
	}
	if !found || account == nil {
		return nil, nil, ErrUnknownCredential
	}
	creds, err := store.PasskeysByUserID(ctx, account.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: access/webauthn: passkey lookup: %w", access.ErrAuthBackend, err)
	}
	user := &User{AuthUser: account, Credentials: creds}
	cred, held := user.credential(r.rawID)
	if !held {
		return nil, nil, ErrUnknownCredential
	}
	return user, cred, nil
}

// allowedCredential is WebAuthn §7.2's allowCredentials and identification
// steps for user, identified before the ceremony: rawId must be on both st's
// allowed list and the user's passkeys now, so one deleted since Begin fails.
func (st *ceremonyState) allowedCredential(user *User, r *assertionResponse) (*access.PasskeyCredential, error) {
	cred, held := user.credential(r.rawID)
	if !held || !slices.ContainsFunc(st.allowed, func(id []byte) bool { return bytes.Equal(id, r.rawID) }) {
		return nil, ErrUnknownCredential
	}
	if r.userHandle != nil && !bytes.Equal(r.userHandle, user.WebAuthnID()) {
		return nil, errAssertionUser
	}
	return cred, nil
}

// verifyAssertion runs WebAuthn §7.2's steps from the client data to the
// signature against cred, the stored record, and returns the checked
// authenticator data. Client extension outputs are not read: no Begin
// requests one.
func verifyAssertion(rp *RelyingParty, st *ceremonyState, cred *access.PasskeyCredential, r *assertionResponse) (*authData, error) {
	hash, err := verifyClientData(r.clientDataJSON, clientDataGet, st.challenge, st.origin)
	if err != nil {
		return nil, err
	}
	a, err := assertionAuthData(r.authenticatorData, rp.id)
	if err != nil {
		return nil, err
	}
	// BE never changes over a credential's life (WebAuthn §6.1.3), so a store
	// that dropped the octet fails here.
	_, _, storedBE, _ := access.DecodePasskeyFlags(cred.RawFlags)
	if _, _, be, _ := access.DecodePasskeyFlags(a.flags); be != storedBE {
		return nil, errBackupEligibility
	}
	key, err := cose.ParseKey(cred.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCredentialKey, err)
	}
	if err := key.Verify(r.authenticatorData, hash, r.signature); err != nil {
		return nil, fmt.Errorf("%w: %w", errAssertionSignature, err)
	}
	return a, nil
}

// recordAssertion is WebAuthn §7.2's signCount and update steps: the clone
// signal is decided against the count read at identification, and the store
// merges the asserted state (Store.RecordAssertion's contract).
func recordAssertion(ctx context.Context, store Store, user *User, cred *access.PasskeyCredential, a *authData) (LoginResult, error) {
	regressed := signCountRegressed(cred.SignCount, a.signCount)
	err := store.RecordAssertion(ctx, user.AuthUser.ID, cred.CredentialID, access.PasskeyLoginUpdate{
		At:           time.Now(),
		SignCount:    a.signCount,
		RawFlags:     a.flags,
		CloneWarning: regressed,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: access/webauthn: post-login passkey update: %w", access.ErrAuthBackend, err)
	}
	return LoginResult{
		User:         user.AuthUser,
		CredentialID: slices.Clone(cred.CredentialID),
		CloneWarning: regressed,
	}, nil
}

// signCountRegressed is WebAuthn §7.2's signCount step's clone signal: either
// count nonzero and the asserted one not above the stored one. A stored 0
// meets asserted <= stored only when both are 0, which signals nothing.
func signCountRegressed(stored, asserted uint32) bool {
	return stored != 0 && asserted <= stored
}
