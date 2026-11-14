package webauthn

import (
	"slices"
	"strings"

	"github.com/cplieger/access"
)

// finishRegistration runs §7.1's registration ceremony for user on body, a
// RegistrationResponseJSON answering st, and returns the credential record
// to store. The alg step is cose.ParseKey's: it parses only the algorithms
// the creation options offer.
func finishRegistration(rp *RelyingParty, st *ceremonyState, user *User, body []byte) (*access.PasskeyCredential, error) {
	if err := st.check(ceremonyRegistration); err != nil {
		return nil, err
	}
	if err := st.heldBy(user); err != nil {
		return nil, err
	}
	r, err := parseRegistrationResponse(body)
	if err != nil {
		return nil, err
	}
	hash, err := verifyClientData(r.clientDataJSON, clientDataCreate, st.challenge, st.origin)
	if err != nil {
		return nil, err
	}
	o, err := parseAttestationObject(r.attestationObject)
	if err != nil {
		return nil, err
	}
	a, key, err := registrationAuthData(o.authData, rp.id, r.rawID)
	if err != nil {
		return nil, err
	}
	if err := o.verifyStatement(key, hash); err != nil {
		return nil, err
	}
	// rk false is the client reporting a credential no discoverable login
	// can use (§10.1.3); an absent report is accepted (§7.1's extension step).
	if r.residentKey != nil && !*r.residentKey {
		return nil, ErrNotDiscoverable
	}
	return credentialRecord(rp, user, r, a), nil
}

// credentialRecord is §7.1's credentialRecord in access's names, the flag
// booleans decoded from the octet. Name is left for the caller, which
// derives it from the user's other passkeys (PasskeyFriendlyName).
func credentialRecord(rp *RelyingParty, user *User, r *registrationResponse, a *authData) *access.PasskeyCredential {
	up, uv, be, bs := access.DecodePasskeyFlags(a.flags)
	return &access.PasskeyCredential{
		UserID: user.AuthUser.ID,
		// Clipped, so growing one cannot write over the next: authData holds
		// the AAGUID, the ID and the key in that order (§6.5.1).
		CredentialID:   slices.Clip(a.attested.id),
		PublicKey:      a.attested.publicKey,
		AAGUID:         slices.Clip(a.attested.aaguid),
		SignCount:      a.signCount,
		RawFlags:       a.flags,
		UserPresent:    up,
		UserVerified:   uv,
		BackupEligible: be,
		BackupState:    bs,
		Transport:      strings.Join(r.transports, ","),
		Attachment:     r.attachment,
		RPID:           rp.id,
		Discoverable:   r.residentKey,
	}
}
