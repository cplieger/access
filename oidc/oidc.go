// Package oidc signs a user in with an OpenID Connect provider, on
// coreos/go-oidc. [Provider.Begin] seals the flow's state, nonce, PKCE
// verifier and intent into a browser-bound cookie and returns the
// authorization URL; [Provider.Finish] opens that cookie on the callback,
// exchanges the code and verifies the ID token. Nothing is stored server-side.
// It imports the root access package and never the reverse.
package oidc

import (
	"errors"
	"slices"
)

// Sentinel errors for OIDC operations.
var (
	ErrDiscovery     = errors.New("oidc: provider discovery failed")
	ErrExchange      = errors.New("oidc: code exchange failed")
	ErrTokenInvalid  = errors.New("oidc: ID token verification failed")
	ErrNonceMismatch = errors.New("oidc: nonce mismatch")
	ErrConfigInvalid = errors.New("oidc: invalid configuration")
	ErrNoUsername    = errors.New("oidc: token has no preferred_username or verified email claim")

	// ErrFlowInvalid reports a flow cookie that is missing, forged, expired,
	// sealed by another provider or answered with another state, and a
	// malformed BeginRequest or a cross-site begin that Begin refuses.
	ErrFlowInvalid = errors.New("oidc: sign-in flow invalid")
	// ErrStaleAuthentication reports a link or step-up whose ID token does
	// not prove a sign-in at the provider after the flow began.
	ErrStaleAuthentication = errors.New("oidc: the provider did not authenticate the user again")
	ErrRedirectTooLong     = errors.New("oidc: redirect longer than MaxRedirectBytes")
	// ErrProvisioningDisabled and ErrNotAdmitted are Provisioning.Admit's
	// refusals.
	ErrProvisioningDisabled = errors.New("oidc: provisioning is disabled")
	ErrNotAdmitted          = errors.New("oidc: identity not admitted for provisioning")
)

// ProviderError is the provider's error answer to the authorization request,
// read only after the callback's state matched the flow's.
type ProviderError struct {
	// Code is one of the codes of RFC 6749 section 4.1.2.1, or "other" for
	// any other value. The provider's error_description is never read.
	Code string
}

func (e *ProviderError) Error() string { return "oidc: the provider answered " + e.Code }

// providerErrorCodes are RFC 6749 section 4.1.2.1's error codes.
var providerErrorCodes = []string{
	"invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type",
	"invalid_scope", "server_error", "temporarily_unavailable",
}

func providerError(code string) *ProviderError {
	if !slices.Contains(providerErrorCodes, code) {
		code = "other"
	}
	return &ProviderError{Code: code}
}

// UsernameError reports that the claim UsernameCandidate chose is not a
// username access.NormalizeUsername accepts.
type UsernameError struct {
	// Err is NormalizeUsername's error, matching access.ErrUsernameEmpty or
	// access.ErrUsernameInvalid.
	Err error
	// Claim is "preferred_username" or "email".
	Claim string
}

func (e *UsernameError) Error() string {
	return "oidc: the " + e.Claim + " claim is not a valid username: " + e.Err.Error()
}

func (e *UsernameError) Unwrap() error { return e.Err }
