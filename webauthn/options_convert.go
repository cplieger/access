package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
)

// The conversions from upstream's options values to this package's own. Every
// member is assigned explicitly so a member added or renamed upstream is a
// compile error here rather than a member that silently stops reaching the
// browser.

// creationFromUpstream converts upstream's registration options. The user handle
// is taken from the user rather than from upstream's UserEntity.ID, which is an
// `any` holding either bytes or a string depending on a config flag this library
// does not set; reading the typed source avoids a runtime assertion on a field
// whose type is decided elsewhere.
func creationFromUpstream(in *protocol.CredentialCreation, userHandle []byte) *CredentialCreation {
	opts := in.Response
	return &CredentialCreation{
		Response: CredentialCreationOptions{
			RelyingParty: RelyingPartyEntity{
				Name: opts.RelyingParty.Name,
				ID:   opts.RelyingParty.ID,
			},
			User: UserEntity{
				Name:        opts.User.Name,
				DisplayName: opts.User.DisplayName,
				ID:          Base64URL(userHandle),
			},
			Challenge:          Base64URL(opts.Challenge),
			Parameters:         credentialParameters(opts.Parameters),
			Timeout:            opts.Timeout,
			ExcludeCredentials: credentialDescriptors(opts.CredentialExcludeList),
			AuthenticatorSelection: AuthenticatorSelection{
				ResidentKey:        ResidentKeyRequirement(opts.AuthenticatorSelection.ResidentKey),
				RequireResidentKey: opts.AuthenticatorSelection.RequireResidentKey != nil && *opts.AuthenticatorSelection.RequireResidentKey,
				UserVerification:   UserVerificationRequirement(opts.AuthenticatorSelection.UserVerification),
			},
			Extensions: RegistrationExtensions{
				CredProps: opts.Extensions.CredProps,
			},
		},
	}
}

// assertionFromUpstream converts upstream's assertion options.
func assertionFromUpstream(in *protocol.CredentialAssertion) *CredentialAssertion {
	opts := in.Response
	return &CredentialAssertion{
		Response: CredentialRequestOptions{
			Challenge:        Base64URL(opts.Challenge),
			Timeout:          opts.Timeout,
			RelyingPartyID:   opts.RelyingPartyID,
			AllowCredentials: credentialDescriptors(opts.AllowedCredentials),
			UserVerification: UserVerificationRequirement(opts.UserVerification),
		},
		Mediation: Mediation(in.Mediation),
	}
}

func credentialParameters(in []protocol.CredentialParameter) []CredentialParameter {
	if len(in) == 0 {
		return nil
	}
	out := make([]CredentialParameter, len(in))
	for i, p := range in {
		out[i] = CredentialParameter{
			Type:      CredentialType(p.Type),
			Algorithm: COSEAlgorithm(p.Algorithm),
		}
	}
	return out
}

func credentialDescriptors(in []protocol.CredentialDescriptor) []CredentialDescriptor {
	if len(in) == 0 {
		return nil
	}
	out := make([]CredentialDescriptor, len(in))
	for i, d := range in {
		out[i] = CredentialDescriptor{
			Type:       CredentialType(d.Type),
			ID:         Base64URL(d.CredentialID),
			Transports: authenticatorTransports(d.Transport),
		}
	}
	return out
}

func authenticatorTransports(in []protocol.AuthenticatorTransport) []AuthenticatorTransport {
	if len(in) == 0 {
		return nil
	}
	out := make([]AuthenticatorTransport, len(in))
	for i, t := range in {
		out[i] = AuthenticatorTransport(t)
	}
	return out
}
