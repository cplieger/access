package accesshttp

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// ErrorWriter renders one refusal in the app's own envelope. accesshttp writes
// no error body itself: Cache-Control and, when RetryAfter is set,
// Retry-After are already on w when it is called.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, e Error)

// Error is one refusal, handed to the ErrorWriter.
type Error struct {
	Err        error         // for the app's log; never sent
	Code       Code          // stable data a client branches on
	Detail     string        // safe to show; never a secret or a raw cause
	Reason     string        // a stable sub-reason a client may branch on
	RetryAfter time.Duration // set with 429 and 503
	Status     int
}

// Code is a stable error code; Codes lists every one.
type Code string

// The codes, in Codes order.
const (
	CodeAuthRequired           Code = "auth_required"
	CodeSessionExpired         Code = "auth_session_expired"
	CodeInvalidCredentials     Code = "auth_invalid_credentials" //nolint:gosec // G101: an error code, not a credential
	CodeKeyInvalid             Code = "auth_key_invalid"
	CodeRecentAuthRequired     Code = "auth_recent_auth_required"
	CodeSessionRequired        Code = "auth_session_required"
	CodeScopeRequired          Code = "auth_scope_required"
	CodeForbidden              Code = "auth_forbidden"
	CodeRateLimited            Code = "auth_rate_limited"
	CodeBusy                   Code = "auth_busy"
	CodeUnavailable            Code = "auth_unavailable"
	CodeBadRequest             Code = "auth_bad_request"
	CodeBodyTooLarge           Code = "auth_body_too_large"
	CodeUsernameInvalid        Code = "auth_username_invalid"
	CodeUsernameTaken          Code = "auth_username_taken"
	CodePasswordRejected       Code = "auth_password_rejected"
	CodeBreachCheckUnavailable Code = "auth_breach_check_unavailable"
	CodePasswordLoginDisabled  Code = "auth_password_login_disabled"
	CodeSetupComplete          Code = "auth_setup_complete"
	CodeSetupTokenRequired     Code = "auth_setup_token_required" //nolint:gosec // G101: an error code, not a credential
	CodeTokenInvalid           Code = "auth_token_invalid"        //nolint:gosec // G101: an error code, not a credential
	CodeLastMethod             Code = "auth_last_method"
	CodeIdentityTaken          Code = "auth_identity_taken"
	CodeAlreadyLinked          Code = "auth_already_linked"
	CodeMethodNotLocked        Code = "auth_method_not_locked"
	CodeCrossOrigin            Code = "auth_cross_origin"
	CodeDuplicateCredential    Code = "auth_duplicate_credential" //nolint:gosec // G101: an error code, not a credential
	CodeUnknownScope           Code = "auth_unknown_scope"
	CodePasskeysUnavailable    Code = "auth_passkeys_unavailable" //nolint:gosec // G101: an error code, not a credential
	CodeOriginRefused          Code = "auth_origin_refused"
	CodeCeremonyInvalid        Code = "auth_ceremony_invalid"
	CodeNotDiscoverable        Code = "auth_not_discoverable"
	CodeUnknownCredential      Code = "auth_unknown_credential" //nolint:gosec // G101: an error code, not a credential
	CodeAssertionFailed        Code = "auth_assertion_failed"
	CodeRegistrationFailed     Code = "auth_registration_failed"
	CodeOIDCUnavailable        Code = "auth_oidc_unavailable"
	CodeOIDCFailed             Code = "auth_oidc_failed"
	CodeNotFound               Code = "auth_not_found"
	CodeMethodNotAllowed       Code = "auth_method_not_allowed"
)

type codeRow struct {
	code   Code
	detail string
	status int
}

// codeTable is the one code table: its order is Codes' order, which every
// Descriptor.Codes follows.
var codeTable = [...]codeRow{
	{CodeAuthRequired, "Sign in to continue.", http.StatusUnauthorized},
	{CodeSessionExpired, "Your session has ended. Sign in again.", http.StatusUnauthorized},
	{CodeInvalidCredentials, "The credentials are not valid.", http.StatusUnauthorized},
	{CodeKeyInvalid, "The API key is not valid.", http.StatusUnauthorized},
	{CodeRecentAuthRequired, "Confirm it is you to continue.", http.StatusForbidden},
	{CodeSessionRequired, "A signed-in session is required.", http.StatusForbidden},
	{CodeScopeRequired, "The key lacks the required scope.", http.StatusForbidden},
	{CodeForbidden, "This action is not allowed.", http.StatusForbidden},
	{CodeRateLimited, "Too many attempts. Try again later.", http.StatusTooManyRequests},
	{CodeBusy, "The server is busy. Try again shortly.", http.StatusServiceUnavailable},
	{CodeUnavailable, "The service is unavailable. Try again shortly.", http.StatusServiceUnavailable},
	{CodeBadRequest, "The request is malformed.", http.StatusBadRequest},
	{CodeBodyTooLarge, "The request body is too large.", http.StatusRequestEntityTooLarge},
	{CodeUsernameInvalid, "The username is not valid.", http.StatusBadRequest},
	{CodeUsernameTaken, "The username is taken.", http.StatusConflict},
	{CodePasswordRejected, "The password is not allowed.", http.StatusBadRequest},
	{CodeBreachCheckUnavailable, "The password check is unavailable. Try again shortly.", http.StatusServiceUnavailable},
	{CodePasswordLoginDisabled, "Password sign-in is turned off.", http.StatusForbidden},
	{CodeSetupComplete, "Setup is already complete.", http.StatusConflict},
	{CodeSetupTokenRequired, "A setup token is required.", http.StatusUnauthorized},
	{CodeTokenInvalid, "The link is not valid or has expired.", http.StatusUnauthorized},
	{CodeLastMethod, "The last sign-in method cannot be removed.", http.StatusConflict},
	{CodeIdentityTaken, "That identity is linked to another account.", http.StatusConflict},
	{CodeAlreadyLinked, "An identity is already linked. Unlink it first.", http.StatusConflict},
	{CodeMethodNotLocked, "That sign-in method is not locked.", http.StatusConflict},
	{CodeCrossOrigin, "Cross-origin requests are refused.", http.StatusForbidden},
	{CodeDuplicateCredential, "That passkey is already registered.", http.StatusConflict},
	{CodeUnknownScope, "A requested scope is unknown.", http.StatusBadRequest},
	{CodePasskeysUnavailable, "Passkeys are not available.", http.StatusBadRequest},
	{CodeOriginRefused, "The request origin is refused.", http.StatusBadRequest},
	{CodeCeremonyInvalid, "The passkey request expired. Try again.", http.StatusUnauthorized},
	{CodeNotDiscoverable, "The authenticator did not create a passkey.", http.StatusBadRequest},
	{CodeUnknownCredential, "That passkey is not registered.", http.StatusUnauthorized},
	{CodeAssertionFailed, "The passkey could not be verified.", http.StatusUnauthorized},
	{CodeRegistrationFailed, "The passkey could not be registered.", http.StatusBadRequest},
	{CodeOIDCUnavailable, "Single sign-on is not available.", http.StatusBadRequest},
	{CodeOIDCFailed, "Single sign-on failed.", http.StatusUnauthorized},
	{CodeNotFound, "Not found.", http.StatusNotFound},
	{CodeMethodNotAllowed, "Method not allowed.", http.StatusMethodNotAllowed},
}

var codeIndex = func() map[Code]int {
	m := make(map[Code]int, len(codeTable))
	for i := range codeTable {
		m[codeTable[i].code] = i
	}
	return m
}()

// Codes returns every code accesshttp answers, in its table's order.
func Codes() []Code {
	out := make([]Code, len(codeTable))
	for i := range codeTable {
		out[i] = codeTable[i].code
	}
	return out
}

// Retry-After for the 503 answers that carry no limiter window.
const (
	busyRetryAfter        = 1 * time.Second
	unavailableRetryAfter = 5 * time.Second
)

// newError fills Status and Detail from the table; code must be in it.
func newError(code Code, reason string, err error) Error {
	row := codeTable[codeIndex[code]]
	e := Error{Status: row.status, Code: code, Detail: row.detail, Reason: reason, Err: err}
	switch code {
	case CodeBusy:
		e.RetryAfter = busyRetryAfter
	case CodeUnavailable, CodeBreachCheckUnavailable:
		e.RetryAfter = unavailableRetryAfter
	default:
	}
	return e
}

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

// sentinelCodes maps the plain sentinels; classify checks
// the typed errors and the authentication errors first, then these in
// order.
var sentinelCodes = []struct {
	err    error
	code   Code
	reason string
}{
	{errMethodNotAllowed, CodeMethodNotAllowed, ""},
	{errCrossOrigin, CodeCrossOrigin, ""},
	{access.ErrRecentAuthRequired, CodeRecentAuthRequired, ""},
	{account.ErrSessionRequired, CodeSessionRequired, ""},
	{account.ErrScopeRequired, CodeScopeRequired, ""},
	{account.ErrSSOGoverned, CodeForbidden, ReasonSSOGoverned},
	{access.ErrHashBusy, CodeBusy, ""},
	{access.ErrBreachCheckUnavailable, CodeBreachCheckUnavailable, ""},
	{access.ErrAuthBackend, CodeUnavailable, ""},
	{account.ErrRulesInvalid, CodeUnavailable, ""},
	{account.ErrTTLTooLong, CodeBadRequest, ReasonTTLTooLong},
	{account.ErrTTLNegative, CodeBadRequest, ReasonTTLNegative},
	{account.ErrNoChange, CodeBadRequest, ReasonNoChange},
	{account.ErrKeyExpiryInvalid, CodeBadRequest, ReasonExpiryInvalid},
	{oidc.ErrRedirectTooLong, CodeBadRequest, ReasonRedirectTooLong},
	{account.ErrCurrentPasswordRequired, CodeBadRequest, ReasonCurrentPasswordRequired},
	{webauthn.ErrResponseTooLarge, CodeBodyTooLarge, ""},
	{account.ErrUsernameTaken, CodeUsernameTaken, ""},
	{account.ErrPasswordLoginDisabled, CodePasswordLoginDisabled, ""},
	{account.ErrSetupComplete, CodeSetupComplete, ""},
	{account.ErrSetupTokenRequired, CodeSetupTokenRequired, ""},
	{access.ErrTokenInvalid, CodeTokenInvalid, ""},
	{account.ErrLastMethod, CodeLastMethod, ""},
	{account.ErrOIDCIdentityTaken, CodeIdentityTaken, ""},
	{account.ErrAlreadyLinked, CodeAlreadyLinked, ""},
	{account.ErrMethodNotLocked, CodeMethodNotLocked, ""},
	{account.ErrDuplicateCredential, CodeDuplicateCredential, ""},
	{account.ErrUnknownScope, CodeUnknownScope, ""},
	{account.ErrPasskeysUnavailable, CodePasskeysUnavailable, ""},
	{account.ErrCeremonyInvalid, CodeCeremonyInvalid, ""},
	{webauthn.ErrNotDiscoverable, CodeNotDiscoverable, ""},
	{webauthn.ErrUnknownCredential, CodeUnknownCredential, ""},
	{account.ErrOIDCUnavailable, CodeOIDCUnavailable, ""},
	{account.ErrSessionGone, CodeSessionExpired, ReasonSessionGone},
	{errPendingTooLarge, CodeOIDCFailed, ReasonPendingTooLarge},
	{oidc.ErrStaleAuthentication, CodeOIDCFailed, ReasonStaleAuthentication},
	{oidc.ErrFlowInvalid, CodeOIDCFailed, ReasonFlowInvalid},
	{oidc.ErrDiscovery, CodeOIDCFailed, ReasonDiscoveryFailed},
	{oidc.ErrExchange, CodeOIDCFailed, ReasonExchangeFailed},
	{oidc.ErrTokenInvalid, CodeOIDCFailed, ReasonTokenInvalid},
	{oidc.ErrNonceMismatch, CodeOIDCFailed, ReasonNonceMismatch},
	{oidc.ErrNoUsername, CodeOIDCFailed, ReasonNoUsername},
	{oidc.ErrProvisioningDisabled, CodeOIDCFailed, ReasonProvisioningDisabled},
	{oidc.ErrNotAdmitted, CodeOIDCFailed, ReasonNotAdmitted},
	{account.ErrNotFound, CodeNotFound, ""},
	{account.ErrInvalidCredentials, CodeInvalidCredentials, ""},
}

// routeError maps err for a route answering codes. broken reports a code
// outside them, or an error the mapping does not name: a contract break
// with account, so a route never answers a code its descriptor lacks.
func routeError(err error, cer ceremony, codes []Code) (e Error, broken bool) {
	e, ok := classify(err, cer)
	return e, !ok || !slices.Contains(codes, e.Code)
}

// classify is the one error-to-code mapping. It reports false for an error the
// table does not name, which the caller answers as a contract break.
func classify(err error, cer ceremony) (Error, bool) {
	var reason string
	code, ok := authenticationCode(err)
	if !ok {
		code, reason, ok = typedCode(err)
	}
	if !ok {
		code, reason, ok = sentinelCode(err)
	}
	if !ok {
		if code, ok = ceremonyCode(cer); !ok {
			return Error{}, false
		}
	}
	if code == CodeRecentAuthRequired || code == CodeSessionRequired {
		reason = failreason.Of(err)
	}
	e := newError(code, reason, err)
	if refused, isRefused := errors.AsType[*ratelimit.RefusedError](err); isRefused {
		e.RetryAfter = refused.RetryAfter
	}
	if pe, isPassword := errors.AsType[*access.PasswordError](err); isPassword && (pe.Min != 0 || pe.Max != 0) {
		e.Detail += " Length: " + strconv.Itoa(pe.Min) + " to " + strconv.Itoa(pe.Max) + " characters."
	}
	return e, true
}

func sentinelCode(err error) (code Code, reason string, ok bool) {
	for _, s := range sentinelCodes {
		if errors.Is(err, s.err) {
			return s.code, s.reason, true
		}
	}
	return "", "", false
}

// ceremonyCode is cer's fallback code; false off a WebAuthn finish.
func ceremonyCode(cer ceremony) (Code, bool) {
	switch cer {
	case ceremonyAssertion:
		return CodeAssertionFailed, true
	case ceremonyRegistration:
		return CodeRegistrationFailed, true
	default:
		return "", false
	}
}

// authenticationCode maps the Authenticator's refusals.
func authenticationCode(err error) (Code, bool) {
	if ice, isICE := errors.AsType[*access.InvalidCredentialError](err); isICE {
		switch {
		case errors.Is(err, access.ErrRestrictedSession):
			return CodeSessionRequired, true
		case ice.Method == access.MethodAPIKey:
			return CodeKeyInvalid, true
		default:
			return CodeInvalidCredentials, true
		}
	}
	if errors.Is(err, access.ErrUnauthenticated) {
		if errors.Is(err, access.ErrSessionExpired) || errors.Is(err, access.ErrSessionNotFound) {
			return CodeSessionExpired, true
		}
		return CodeAuthRequired, true
	}
	return "", false
}

// typedCode maps the error types whose fields carry the Reason.
func typedCode(err error) (code Code, reason string, ok bool) {
	if re, is := errors.AsType[*requestError](err); is {
		return CodeBadRequest, re.reason, true
	}
	if _, is := errors.AsType[*http.MaxBytesError](err); is {
		return CodeBodyTooLarge, "", true
	}
	if _, is := errors.AsType[*ratelimit.RefusedError](err); is {
		return CodeRateLimited, "", true
	}
	if ue, is := errors.AsType[*account.UsernameError](err); is {
		return CodeUsernameInvalid, ue.Reason, true
	}
	if te, is := errors.AsType[*account.TextError](err); is {
		return CodeBadRequest, textReason(te.Field, te.Reason), true
	}
	if pe, is := errors.AsType[*access.PasswordError](err); is {
		return CodePasswordRejected, string(pe.Reason), true
	}
	if oe, is := errors.AsType[*webauthn.OriginError](err); is {
		return CodeOriginRefused, string(oe.Reason), true
	}
	if pe, is := errors.AsType[*account.PolicyError](err); is {
		return CodeForbidden, pe.Reason, true
	}
	if pe, is := errors.AsType[*oidc.ProviderError](err); is {
		return CodeOIDCFailed, providerErrorPrefix + pe.Code, true
	}
	if _, is := errors.AsType[*oidc.UsernameError](err); is {
		return CodeOIDCFailed, ReasonUsernameInvalid, true
	}
	return "", "", false
}
