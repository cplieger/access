package access

import (
	"errors"
	"net/http"
	"time"

	"github.com/cplieger/access/internal/failreason"
)

// ErrorWriter renders one refusal in the app's own envelope. The library
// writes no error body itself: Cache-Control, the WWW-Authenticate
// [Authenticator.Challenge] sets for e.Code and, when RetryAfter is set,
// Retry-After are already on w when it is called.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, e Error)

// Error is one refusal, handed to the ErrorWriter.
type Error struct {
	Err        error         // for the app's log; never sent
	Code       Code          // stable data a client branches on
	Detail     string        // safe to show; never a secret or a raw cause
	Reason     string        // a stable sub-reason a client may branch on
	RetryAfter time.Duration // set with 429 and every 503 but auth_second_factor_unavailable
	Status     int
}

// Code is a stable error code; Codes lists every one.
type Code string

// The codes, in Codes order.
const (
	CodeAuthRequired            Code = "auth_required"
	CodeSessionExpired          Code = "auth_session_expired"
	CodeInvalidCredentials      Code = "auth_invalid_credentials" //nolint:gosec // G101: an error code, not a credential
	CodeKeyInvalid              Code = "auth_key_invalid"
	CodeRecentAuthRequired      Code = "auth_recent_auth_required"
	CodeSessionRequired         Code = "auth_session_required"
	CodeScopeRequired           Code = "auth_scope_required"
	CodeKeyRequired             Code = "auth_key_required"
	CodeHTTPSRequired           Code = "auth_https_required"
	CodeForbidden               Code = "auth_forbidden"
	CodeRateLimited             Code = "auth_rate_limited"
	CodeBusy                    Code = "auth_busy"
	CodeUnavailable             Code = "auth_unavailable"
	CodeBadRequest              Code = "auth_bad_request"
	CodeBodyTooLarge            Code = "auth_body_too_large"
	CodeUsernameInvalid         Code = "auth_username_invalid"
	CodeUsernameTaken           Code = "auth_username_taken"
	CodeKeyLabelTaken           Code = "auth_key_label_taken"
	CodePasswordRejected        Code = "auth_password_rejected"
	CodeBreachCheckUnavailable  Code = "auth_breach_check_unavailable"
	CodePasswordLoginDisabled   Code = "auth_password_login_disabled"
	CodeCodeInvalid             Code = "auth_code_invalid"
	CodeSecondFactorRequired    Code = "auth_second_factor_required"
	CodeSecondFactorUnavailable Code = "auth_second_factor_unavailable"
	CodeTOTPDisabled            Code = "auth_totp_disabled"
	CodeSetupComplete           Code = "auth_setup_complete"
	CodeSetupTokenRequired      Code = "auth_setup_token_required" //nolint:gosec // G101: an error code, not a credential
	CodeRegistrationClosed      Code = "auth_registration_closed"
	CodeRegistrationFull        Code = "auth_registration_full"
	CodeTokenInvalid            Code = "auth_token_invalid" //nolint:gosec // G101: an error code, not a credential
	CodeLastMethod              Code = "auth_last_method"
	CodeIdentityTaken           Code = "auth_identity_taken"
	CodeAlreadyLinked           Code = "auth_already_linked"
	CodeMethodNotLocked         Code = "auth_method_not_locked"
	CodeCrossOrigin             Code = "auth_cross_origin"
	CodeDuplicateCredential     Code = "auth_duplicate_credential" //nolint:gosec // G101: an error code, not a credential
	CodeUnknownScope            Code = "auth_unknown_scope"
	CodePasskeysUnavailable     Code = "auth_passkeys_unavailable" //nolint:gosec // G101: an error code, not a credential
	CodeOriginRefused           Code = "auth_origin_refused"
	CodeCeremonyInvalid         Code = "auth_ceremony_invalid"
	CodeNotDiscoverable         Code = "auth_not_discoverable"
	CodeUnknownCredential       Code = "auth_unknown_credential" //nolint:gosec // G101: an error code, not a credential
	CodeAssertionFailed         Code = "auth_assertion_failed"
	CodeRegistrationFailed      Code = "auth_registration_failed"
	CodeOIDCUnavailable         Code = "auth_oidc_unavailable"
	CodeOIDCFailed              Code = "auth_oidc_failed"
	CodeSSOOnly                 Code = "auth_sso_only"
	CodeNotFound                Code = "auth_not_found"
	CodeMethodNotAllowed        Code = "auth_method_not_allowed"
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
	{CodeKeyRequired, "This route needs an API key.", http.StatusForbidden},
	{CodeHTTPSRequired, "This needs HTTPS.", http.StatusForbidden},
	{CodeForbidden, "This action is not allowed.", http.StatusForbidden},
	{CodeRateLimited, "Too many attempts. Try again later.", http.StatusTooManyRequests},
	{CodeBusy, "The server is busy. Try again shortly.", http.StatusServiceUnavailable},
	{CodeUnavailable, "The service is unavailable. Try again shortly.", http.StatusServiceUnavailable},
	{CodeBadRequest, "The request is malformed.", http.StatusBadRequest},
	{CodeBodyTooLarge, "The request body is too large.", http.StatusRequestEntityTooLarge},
	{CodeUsernameInvalid, "The username is not valid.", http.StatusBadRequest},
	{CodeUsernameTaken, "The username is taken.", http.StatusConflict},
	{CodeKeyLabelTaken, "A key with this label already exists.", http.StatusConflict},
	{CodePasswordRejected, "The password is not allowed.", http.StatusBadRequest},
	{CodeBreachCheckUnavailable, "The password check is unavailable. Try again shortly.", http.StatusServiceUnavailable},
	{CodePasswordLoginDisabled, "Password sign-in is turned off.", http.StatusForbidden},
	{CodeCodeInvalid, "That code is not right.", http.StatusUnauthorized},
	{CodeSecondFactorRequired, "A second factor is required.", http.StatusForbidden},
	{CodeSecondFactorUnavailable, "The second factor cannot be checked right now. Try again later.", http.StatusServiceUnavailable},
	{CodeTOTPDisabled, "Authenticator apps are turned off in this app.", http.StatusForbidden},
	{CodeSetupComplete, "Setup is already complete.", http.StatusConflict},
	{CodeSetupTokenRequired, "A setup token is required.", http.StatusUnauthorized},
	{CodeRegistrationClosed, "Sign-ups are closed.", http.StatusForbidden},
	{CodeRegistrationFull, "Sign-ups are paused until an administrator reviews the waiting accounts.", http.StatusForbidden},
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
	{CodeSSOOnly, "Use your organisation's sign-in.", http.StatusForbidden},
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

// codeStatus is code's status in the code table, 0 for a code it lacks.
func codeStatus(code Code) int {
	if i, ok := codeIndex[code]; ok {
		return codeTable[i].status
	}
	return 0
}

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

// The [Error] Reason values access assigns, in [ErrorReasons] order.
const (
	// ReasonTransportChanged is a session presented on the other transport,
	// answered with [CodeSessionExpired] once the session is revoked.
	ReasonTransportChanged = failreason.TransportChanged
	// ReasonSignInAgain is [RequireRecentAuth] refusing a plain session,
	// answered with [CodeRecentAuthRequired]: a step-up cannot run over
	// plain HTTP, so the client asks for a fresh sign-in.
	ReasonSignInAgain = failreason.SignInAgain
)

// ErrorReasons returns every Reason access assigns, in a stable order.
func ErrorReasons() []string { return []string{ReasonTransportChanged, ReasonSignInAgain} }

// ErrorFor maps an error [Authenticator.Authenticate] or [RequireRecentAuth]
// returned to its refusal. Its Reason is empty, so the answer names no
// stored state, except [ReasonTransportChanged] for a session presented on
// the other transport, which the verifier revokes when a [SessionRevoker] is
// registered, and for [ErrRecentAuthRequired] and [ErrHTTPSRequired] the
// reason the refusal carries, such as [ReasonSignInAgain]. It reports false
// for any other error.
func ErrorFor(err error) (Error, bool) {
	code, ok := authenticationCode(err)
	if !ok {
		return Error{}, false
	}
	var reason string
	switch code {
	case CodeSessionExpired:
		if errors.Is(err, ErrSessionTransport) {
			reason = ReasonTransportChanged
		}
	case CodeRecentAuthRequired, CodeHTTPSRequired:
		reason = failreason.Of(err)
	default:
	}
	return NewError(code, reason, err), true
}

func authenticationCode(err error) (Code, bool) {
	if errors.Is(err, ErrHTTPSRequired) {
		return CodeHTTPSRequired, true
	}
	if errors.Is(err, ErrRecentAuthRequired) {
		return CodeRecentAuthRequired, true
	}
	if ice, isICE := errors.AsType[*InvalidCredentialError](err); isICE {
		switch {
		case errors.Is(err, ErrSessionTransport):
			return CodeSessionExpired, true
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
