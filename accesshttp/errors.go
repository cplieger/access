package accesshttp

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// ceremony is what an unclassified error on a WebAuthn finish means.
type ceremony int

const (
	ceremonyNone ceremony = iota
	ceremonyAssertion
	ceremonyRegistration
)

// requestError is a transport refusal (decode, query, path). A Reason
// constant means the body or URL was refused as a whole; any other reason
// is the refused field, path value or query key.
type requestError struct {
	reason string
}

func (e *requestError) Error() string { return "accesshttp: bad request: " + e.reason }

func badRequest(reason string) error { return &requestError{reason: reason} }

// sentinelCodes maps the plain sentinels; classify checks the
// authentication errors and the typed errors first, then these in order.
var sentinelCodes = []struct {
	err    error
	code   access.Code
	reason string
}{
	{errMethodNotAllowed, access.CodeMethodNotAllowed, ""},
	{errCrossOrigin, access.CodeCrossOrigin, ""},
	{account.ErrSessionRequired, access.CodeSessionRequired, ""},
	{account.ErrScopeRequired, access.CodeScopeRequired, ""},
	{access.ErrHashBusy, access.CodeBusy, ""},
	{access.ErrBreachCheckUnavailable, access.CodeBreachCheckUnavailable, ""},
	{account.ErrRulesInvalid, access.CodeUnavailable, ""},
	// Service.Owner's answers reach no route; an app handler mapping one
	// answers a store the operator must repair, or a misconfigured Policy.
	{account.ErrNoOwner, access.CodeUnavailable, ""},
	{account.ErrNotSingleUser, access.CodeUnavailable, ""},
	{account.ErrTTLTooLong, access.CodeBadRequest, ReasonTTLTooLong},
	{account.ErrTTLNegative, access.CodeBadRequest, ReasonTTLNegative},
	{account.ErrNoChange, access.CodeBadRequest, ReasonNoChange},
	{account.ErrKeyExpiryInvalid, access.CodeBadRequest, ReasonExpiryInvalid},
	{oidc.ErrRedirectTooLong, access.CodeBadRequest, ReasonRedirectTooLong},
	{account.ErrCurrentPasswordRequired, access.CodeBadRequest, ReasonCurrentPasswordRequired},
	{webauthn.ErrResponseTooLarge, access.CodeBodyTooLarge, ""},
	{account.ErrUsernameTaken, access.CodeUsernameTaken, ""},
	{account.ErrKeyLabelTaken, access.CodeKeyLabelTaken, ""},
	{account.ErrPasswordLoginDisabled, access.CodePasswordLoginDisabled, ""},
	{account.ErrSetupComplete, access.CodeSetupComplete, ""},
	{account.ErrSetupTokenRequired, access.CodeSetupTokenRequired, ""},
	{access.ErrTokenInvalid, access.CodeTokenInvalid, ""},
	{account.ErrLastSecondFactor, access.CodeLastMethod, ReasonLastSecondFactor},
	{account.ErrLastMethod, access.CodeLastMethod, ""},
	{account.ErrOIDCIdentityTaken, access.CodeIdentityTaken, ""},
	{account.ErrAlreadyLinked, access.CodeAlreadyLinked, ""},
	{account.ErrMethodNotLocked, access.CodeMethodNotLocked, ""},
	{account.ErrDuplicateCredential, access.CodeDuplicateCredential, ""},
	{account.ErrUnknownScope, access.CodeUnknownScope, ""},
	{account.ErrPasskeysUnavailable, access.CodePasskeysUnavailable, ""},
	{account.ErrCeremonyInvalid, access.CodeCeremonyInvalid, ""},
	{webauthn.ErrNotDiscoverable, access.CodeNotDiscoverable, ""},
	{webauthn.ErrUnknownCredential, access.CodeUnknownCredential, ""},
	{account.ErrOIDCUnavailable, access.CodeOIDCUnavailable, ""},
	{account.ErrSessionGone, access.CodeSessionExpired, ReasonSessionGone},
	{errPendingTooLarge, access.CodeOIDCFailed, ReasonPendingTooLarge},
	{oidc.ErrStaleAuthentication, access.CodeOIDCFailed, ReasonStaleAuthentication},
	{oidc.ErrFlowInvalid, access.CodeOIDCFailed, ReasonFlowInvalid},
	{oidc.ErrDiscovery, access.CodeOIDCFailed, ReasonDiscoveryFailed},
	{oidc.ErrExchange, access.CodeOIDCFailed, ReasonExchangeFailed},
	{oidc.ErrTokenInvalid, access.CodeOIDCFailed, ReasonTokenInvalid},
	{oidc.ErrNonceMismatch, access.CodeOIDCFailed, ReasonNonceMismatch},
	{oidc.ErrNoUsername, access.CodeOIDCFailed, ReasonNoUsername},
	{account.ErrProvisioningDisabled, access.CodeForbidden, ReasonProvisioningDisabled},
	{account.ErrNotAdmitted, access.CodeForbidden, ReasonNotAdmitted},
	{account.ErrNotFound, access.CodeNotFound, ""},
	{account.ErrInvalidCredentials, access.CodeInvalidCredentials, ""},
	{account.ErrCodeInvalid, access.CodeCodeInvalid, ""},
	{account.ErrCodeMalformed, access.CodeBadRequest, ""},
	{account.ErrSecondFactorProofRequired, access.CodeBadRequest, ReasonSecondFactorProofRequired},
	{account.ErrSecondFactorHeld, access.CodeSecondFactorRequired, ReasonSecondFactorHeld},
	{account.ErrPasswordRequired, access.CodeForbidden, ReasonTOTPNeedsPassword},
	{account.ErrEnrolNeedsKnownDevice, access.CodeSecondFactorRequired, ReasonEnrolNeedsKnownDevice},
	{account.ErrSecondFactorRequired, access.CodeSecondFactorRequired, ""},
	{account.ErrNoUsableMethod, access.CodeForbidden, ReasonNoUsableMethod},
	{account.ErrSecondFactorUnavailable, access.CodeSecondFactorUnavailable, ""},
	{account.ErrTOTPDisabled, access.CodeTOTPDisabled, ""},
	{account.ErrRegistrationClosed, access.CodeRegistrationClosed, ""},
	{account.ErrRegistrationFull, access.CodeRegistrationFull, ""},
	{account.ErrSSOOnly, access.CodeSSOOnly, ""},
	{account.ErrUnknownSSOMode, access.CodeBadRequest, ""},
}

// routeError maps err for a route answering codes. broken reports a code
// outside them, or an error the mapping does not name: a contract break
// with account, so a route never answers a code its descriptor lacks.
func routeError(err error, cer ceremony, codes []access.Code) (e access.Error, broken bool) {
	e, ok := classify(err, cer)
	return e, !ok || !slices.Contains(codes, e.Code)
}

// classify is the one error-to-code mapping. It reports false for an error the
// table does not name, which the caller answers as a contract break.
func classify(err error, cer ceremony) (access.Error, bool) {
	if e, ok := access.ErrorFor(err); ok {
		return e, true
	}
	code, reason, ok := typedCode(err)
	if !ok {
		code, reason, ok = sentinelCode(err)
	}
	if !ok {
		if code, ok = ceremonyCode(cer); !ok {
			return access.Error{}, false
		}
	}
	e := access.NewError(code, reason, err)
	if refused, isRefused := errors.AsType[*ratelimit.RefusedError](err); isRefused {
		e.RetryAfter = refused.RetryAfter
	}
	if pe, isPassword := errors.AsType[*access.PasswordError](err); isPassword && (pe.Min != 0 || pe.Max != 0) {
		e.Detail += " Length: " + strconv.Itoa(pe.Min) + " to " + strconv.Itoa(pe.Max) + " characters."
	}
	return e, true
}

func sentinelCode(err error) (code access.Code, reason string, ok bool) {
	for _, s := range sentinelCodes {
		if errors.Is(err, s.err) {
			return s.code, s.reason, true
		}
	}
	return "", "", false
}

// ceremonyCode is cer's fallback code; false off a WebAuthn finish.
func ceremonyCode(cer ceremony) (access.Code, bool) {
	switch cer {
	case ceremonyAssertion:
		return access.CodeAssertionFailed, true
	case ceremonyRegistration:
		return access.CodeRegistrationFailed, true
	default:
		return "", false
	}
}

// typedCode maps the error types whose fields carry the Reason.
func typedCode(err error) (code access.Code, reason string, ok bool) {
	if re, is := errors.AsType[*requestError](err); is {
		return access.CodeBadRequest, re.reason, true
	}
	if _, is := errors.AsType[*http.MaxBytesError](err); is {
		return access.CodeBodyTooLarge, "", true
	}
	if _, is := errors.AsType[*ratelimit.RefusedError](err); is {
		return access.CodeRateLimited, "", true
	}
	if ue, is := errors.AsType[*account.UsernameError](err); is {
		return access.CodeUsernameInvalid, ue.Reason, true
	}
	if te, is := errors.AsType[*account.TextError](err); is {
		return access.CodeBadRequest, textReason(te.Field, te.Reason), true
	}
	if le, is := errors.AsType[*account.LogFilterError](err); is {
		return access.CodeBadRequest, le.Reason, true
	}
	if pe, is := errors.AsType[*access.PasswordError](err); is {
		return access.CodePasswordRejected, string(pe.Reason), true
	}
	if oe, is := errors.AsType[*webauthn.OriginError](err); is {
		return access.CodeOriginRefused, string(oe.Reason), true
	}
	if ce, is := errors.AsType[*account.CodeError](err); is {
		return access.CodeCodeInvalid, ce.Reason, true
	}
	if me, is := errors.AsType[*account.MalformedError](err); is {
		return access.CodeBadRequest, me.Field, true
	}
	if pe, is := errors.AsType[*account.PolicyError](err); is {
		return access.CodeForbidden, pe.Reason, true
	}
	if pe, is := errors.AsType[*oidc.ProviderError](err); is {
		return access.CodeOIDCFailed, providerErrorPrefix + pe.Code, true
	}
	if _, is := errors.AsType[*oidc.UsernameError](err); is {
		return access.CodeOIDCFailed, ReasonUsernameInvalid, true
	}
	return "", "", false
}
