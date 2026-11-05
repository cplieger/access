package accesshttp

import (
	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/webauthn"
)

// The Error.Reason values accesshttp assigns itself, in Reasons order.
const (
	ReasonSSOGoverned              = "sso_governed"
	ReasonTTLTooLong               = "ttl_too_long"
	ReasonTTLNegative              = "ttl_negative"
	ReasonNoChange                 = "no_change"
	ReasonExpiryInvalid            = "expiry_invalid"
	ReasonRedirectTooLong          = "redirect_too_long"
	ReasonCurrentPasswordRequired  = "current_password_required"
	ReasonSessionGone              = "session_gone"
	ReasonPendingTooLarge          = "pending_too_large"
	ReasonStaleAuthentication      = "stale_authentication"
	ReasonFlowInvalid              = "flow_invalid"
	ReasonDiscoveryFailed          = "discovery_failed"
	ReasonExchangeFailed           = "exchange_failed"
	ReasonTokenInvalid             = "token_invalid"
	ReasonNonceMismatch            = "nonce_mismatch"
	ReasonNoUsername               = "no_username"
	ReasonProvisioningDisabled     = "provisioning_disabled"
	ReasonNotAdmitted              = "not_admitted"
	ReasonUsernameInvalid          = "username_invalid"
	ReasonRecovery                 = "recovery" // auth_session_required on a recovery route
	ReasonReenableNeedsOtherMethod = failreason.ReenableNeedsOtherMethod
	ReasonTrailingData             = "trailing_data"  // auth_bad_request: data after the JSON value
	ReasonMalformedJSON            = "malformed_json" // auth_bad_request: the body is not one JSON value
	ReasonContentType              = "content_type"   // auth_bad_request: the body is not application/json
	ReasonBody                     = "body"           // auth_bad_request: the body is unreadable or not an object
	ReasonUnknownField             = "unknown_field"  // auth_bad_request: a key the request type lacks
	ReasonTokenInQuery             = "token_in_query" // auth_bad_request: a token route got a token in its URL
)

// ownReasons is accesshttp's part of Reasons.
var ownReasons = []string{
	ReasonSSOGoverned, ReasonTTLTooLong, ReasonTTLNegative, ReasonNoChange, ReasonExpiryInvalid, ReasonRedirectTooLong,
	ReasonCurrentPasswordRequired, ReasonSessionGone, ReasonPendingTooLarge, ReasonStaleAuthentication,
	ReasonFlowInvalid, ReasonDiscoveryFailed, ReasonExchangeFailed, ReasonTokenInvalid, ReasonNonceMismatch,
	ReasonNoUsername, ReasonProvisioningDisabled, ReasonNotAdmitted, ReasonUsernameInvalid, ReasonRecovery,
	ReasonReenableNeedsOtherMethod, ReasonTrailingData, ReasonMalformedJSON, ReasonContentType, ReasonBody,
	ReasonUnknownField, ReasonTokenInQuery,
}

// providerErrorPrefix starts the Reason of an IdP's own error answer, which
// carries the IdP's error code after it.
const providerErrorPrefix = "provider_error:"

// Reasons returns every fixed Error.Reason, each once, in a stable order:
// accesshttp's own, then access's PasswordRejections, account's PolicyReasons,
// UsernameReasons and TextError reasons, and webauthn's OriginRejections.
// Two families stay open and are not listed: "provider_error:" followed by
// an IdP's error code on auth_oidc_failed, and on auth_bad_request the name
// of the body field, path value or query key that was refused; the
// refusals of the body or URL as a whole are listed.
func Reasons() []string {
	all := append([]string{}, ownReasons...)
	for _, r := range access.PasswordRejections() {
		all = append(all, string(r))
	}
	all = append(all, account.PolicyReasons()...)
	all = append(all, account.UsernameReasons()...)
	for _, field := range account.TextErrorFields() {
		for _, r := range account.TextErrorReasons() {
			all = append(all, textReason(field, r))
		}
	}
	for _, r := range webauthn.OriginRejections() {
		all = append(all, string(r))
	}
	seen := make(map[string]bool, len(all))
	out := all[:0]
	for _, r := range all {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// textReason is the wire Reason of a *account.TextError.
func textReason(field, reason string) string { return field + "_" + reason }
