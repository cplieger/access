package access

import (
	"errors"
	"net/http"
	"time"
)

// ErrorWriter renders one refusal in the app's own envelope. The library
// writes no error body itself: Cache-Control and, when RetryAfter is set,
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

// codeTable is the one code table: its order is Codes' order.
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

// Codes returns every code the library answers, in its table's order.
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

// NewError builds the refusal for code: Status and Detail from the code
// table, and RetryAfter for auth_busy, auth_unavailable and
// auth_breach_check_unavailable. It panics for a code Codes does not list,
// which is a programming error.
func NewError(code Code, reason string, err error) Error {
	i, ok := codeIndex[code]
	if !ok {
		panic("access: NewError: unknown code " + string(code))
	}
	row := codeTable[i]
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

// ErrorFor maps an error [Authenticator.Authenticate] returned to its
// refusal, with an empty Reason so the answer names no stored state. It
// reports false for any other error.
func ErrorFor(err error) (Error, bool) {
	code, ok := authenticationCode(err)
	if !ok {
		return Error{}, false
	}
	return NewError(code, "", err), true
}

func authenticationCode(err error) (Code, bool) {
	if ice, isICE := errors.AsType[*InvalidCredentialError](err); isICE {
		switch {
		case errors.Is(err, ErrRestrictedSession):
			return CodeSessionRequired, true
		case ice.Method == MethodAPIKey:
			return CodeKeyInvalid, true
		default:
			return CodeInvalidCredentials, true
		}
	}
	if errors.Is(err, ErrUnauthenticated) {
		if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionNotFound) {
			return CodeSessionExpired, true
		}
		return CodeAuthRequired, true
	}
	if errors.Is(err, ErrAuthBackend) {
		return CodeUnavailable, true
	}
	return "", false
}
