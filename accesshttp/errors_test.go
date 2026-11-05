package accesshttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// designCodes is the specified code table, each code with its status, in
// Codes order; it is written from the spec, not from codeTable.
var designCodes = []struct {
	code   Code
	status int
}{
	{"auth_required", 401},
	{"auth_session_expired", 401},
	{"auth_invalid_credentials", 401},
	{"auth_key_invalid", 401},
	{"auth_recent_auth_required", 403},
	{"auth_session_required", 403},
	{"auth_scope_required", 403},
	{"auth_forbidden", 403},
	{"auth_rate_limited", 429},
	{"auth_busy", 503},
	{"auth_unavailable", 503},
	{"auth_bad_request", 400},
	{"auth_body_too_large", 413},
	{"auth_username_invalid", 400},
	{"auth_username_taken", 409},
	{"auth_password_rejected", 400},
	{"auth_breach_check_unavailable", 503},
	{"auth_password_login_disabled", 403},
	{"auth_setup_complete", 409},
	{"auth_setup_token_required", 401},
	{"auth_token_invalid", 401},
	{"auth_last_method", 409},
	{"auth_identity_taken", 409},
	{"auth_already_linked", 409},
	{"auth_method_not_locked", 409},
	{"auth_cross_origin", 403},
	{"auth_duplicate_credential", 409},
	{"auth_unknown_scope", 400},
	{"auth_passkeys_unavailable", 400},
	{"auth_origin_refused", 400},
	{"auth_ceremony_invalid", 401},
	{"auth_not_discoverable", 400},
	{"auth_unknown_credential", 401},
	{"auth_assertion_failed", 401},
	{"auth_registration_failed", 400},
	{"auth_oidc_unavailable", 400},
	{"auth_oidc_failed", 401},
	{"auth_not_found", 404},
	{"auth_method_not_allowed", 405},
}

func designStatus(t *testing.T, c Code) int {
	t.Helper()
	for _, d := range designCodes {
		if d.code == c {
			return d.status
		}
	}
	t.Fatalf("code %s is not in section 7.2", c)
	return 0
}

func TestErrorCodeTable(t *testing.T) {
	wrapped := func(err error) error { return fmt.Errorf("context: %w", err) }
	rows := []struct {
		err    error
		name   string
		code   Code
		reason string
		cer    ceremony
	}{
		{name: "unauthenticated", err: access.ErrUnauthenticated, code: "auth_required"},
		{name: "session_expired", err: fmt.Errorf("%w: %w", access.ErrUnauthenticated, access.ErrSessionExpired), code: "auth_session_expired"},
		{name: "session_not_found", err: fmt.Errorf("%w: %w", access.ErrUnauthenticated, access.ErrSessionNotFound), code: "auth_session_expired"},
		{name: "account_invalid_credentials", err: account.ErrInvalidCredentials, code: "auth_invalid_credentials"},
		{name: "method_locked_stays_invalid_credentials", err: failreason.Wrap(account.ErrInvalidCredentials, failreason.MethodLocked), code: "auth_invalid_credentials"},
		{name: "custom_credential_refused", err: &access.InvalidCredentialError{Method: "agent", Err: access.ErrAccountDisabled}, code: "auth_invalid_credentials"},
		{name: "key_refused", err: &access.InvalidCredentialError{Method: access.MethodAPIKey, Err: access.ErrInvalidAPIKey}, code: "auth_key_invalid"},
		{name: "recovery_cookie_elsewhere", err: &access.InvalidCredentialError{Method: access.MethodRecovery, Err: access.ErrRestrictedSession}, code: "auth_session_required"},
		{name: "recent_auth", err: access.ErrRecentAuthRequired, code: "auth_recent_auth_required"},
		{name: "reenable_needs_other_method", err: failreason.Wrap(access.ErrRecentAuthRequired, failreason.ReenableNeedsOtherMethod), code: "auth_recent_auth_required", reason: "reenable_needs_other_method"},
		{name: "session_required", err: account.ErrSessionRequired, code: "auth_session_required"},
		{name: "recovery_route", err: failreason.Wrap(account.ErrSessionRequired, "recovery"), code: "auth_session_required", reason: "recovery"},
		{name: "scope_required", err: account.ErrScopeRequired, code: "auth_scope_required"},
		{name: "policy", err: &account.PolicyError{Op: account.OpCreateUser, Reason: "admin_target"}, code: "auth_forbidden", reason: "admin_target"},
		{name: "self_recovery", err: wrapped(&account.PolicyError{Reason: "self_recovery"}), code: "auth_forbidden", reason: "self_recovery"},
		{name: "sso_governed", err: account.ErrSSOGoverned, code: "auth_forbidden", reason: "sso_governed"},
		{name: "rate_limited", err: &ratelimit.RefusedError{Dimension: "ip", RetryAfter: time.Second}, code: "auth_rate_limited"},
		{name: "hash_busy", err: access.ErrHashBusy, code: "auth_busy"},
		{name: "backend", err: fmt.Errorf("%w: %w", access.ErrAuthBackend, errors.New("disk")), code: "auth_unavailable"},
		{name: "service_closed", err: account.ErrServiceClosed, code: "auth_unavailable"},
		{name: "rules_invalid", err: &account.RulesError{Field: "Breach", Reason: "no client"}, code: "auth_unavailable"},
		{name: "decode", err: badRequest("password"), code: "auth_bad_request", reason: "password"},
		{name: "ttl_too_long", err: account.ErrTTLTooLong, code: "auth_bad_request", reason: "ttl_too_long"},
		{name: "ttl_negative", err: account.ErrTTLNegative, code: "auth_bad_request", reason: "ttl_negative"},
		{name: "no_change", err: account.ErrNoChange, code: "auth_bad_request", reason: "no_change"},
		{name: "expiry_invalid", err: account.ErrKeyExpiryInvalid, code: "auth_bad_request", reason: "expiry_invalid"},
		{name: "redirect_too_long", err: oidc.ErrRedirectTooLong, code: "auth_bad_request", reason: "redirect_too_long"},
		{name: "current_password_required", err: account.ErrCurrentPasswordRequired, code: "auth_bad_request", reason: "current_password_required"},
		{name: "text_label_too_long", err: &account.TextError{Field: "label", Reason: "too_long"}, code: "auth_bad_request", reason: "label_too_long"},
		{name: "text_display_name_character", err: wrapped(&account.TextError{Field: "display_name", Reason: "disallowed_character"}), code: "auth_bad_request", reason: "display_name_disallowed_character"},
		{name: "max_bytes", err: &http.MaxBytesError{Limit: 4096}, code: "auth_body_too_large"},
		{name: "response_too_large", err: webauthn.ErrResponseTooLarge, code: "auth_body_too_large"},
		{name: "username_invalid", err: &account.UsernameError{Reason: "too_long"}, code: "auth_username_invalid", reason: "too_long"},
		{name: "username_taken", err: account.ErrUsernameTaken, code: "auth_username_taken"},
		{name: "password_rejected", err: &access.PasswordError{Reason: "common"}, code: "auth_password_rejected", reason: "common"},
		{name: "breach_unavailable", err: account.ErrBreachCheckUnavailable, code: "auth_breach_check_unavailable"},
		{name: "password_login_disabled", err: account.ErrPasswordLoginDisabled, code: "auth_password_login_disabled"},
		{name: "setup_complete", err: account.ErrSetupComplete, code: "auth_setup_complete"},
		{name: "setup_token_required", err: account.ErrSetupTokenRequired, code: "auth_setup_token_required"},
		{name: "token_invalid", err: access.ErrTokenInvalid, code: "auth_token_invalid"},
		{name: "last_method", err: account.ErrLastMethod, code: "auth_last_method"},
		{name: "identity_taken", err: account.ErrOIDCIdentityTaken, code: "auth_identity_taken"},
		{name: "already_linked", err: account.ErrAlreadyLinked, code: "auth_already_linked"},
		{name: "method_not_locked", err: account.ErrMethodNotLocked, code: "auth_method_not_locked"},
		{name: "cross_origin", err: errCrossOrigin, code: "auth_cross_origin"},
		{name: "duplicate_credential", err: account.ErrDuplicateCredential, code: "auth_duplicate_credential"},
		{name: "unknown_scope", err: account.ErrUnknownScope, code: "auth_unknown_scope"},
		{name: "passkeys_unavailable", err: account.ErrPasskeysUnavailable, code: "auth_passkeys_unavailable"},
		{name: "origin_refused", err: &webauthn.OriginError{Reason: webauthn.RejectNotAllowlisted}, code: "auth_origin_refused", reason: "not_allowlisted"},
		{name: "ceremony_invalid", err: account.ErrCeremonyInvalid, code: "auth_ceremony_invalid"},
		{name: "not_discoverable", err: webauthn.ErrNotDiscoverable, code: "auth_not_discoverable"},
		{name: "unknown_credential", err: webauthn.ErrUnknownCredential, code: "auth_unknown_credential"},
		{name: "assertion_failed", err: errors.New("signature"), cer: ceremonyAssertion, code: "auth_assertion_failed"},
		{name: "registration_failed", err: errors.New("attestation"), cer: ceremonyRegistration, code: "auth_registration_failed"},
		{name: "oidc_unavailable", err: account.ErrOIDCUnavailable, code: "auth_oidc_unavailable"},
		{name: "oidc_exchange", err: oidc.ErrExchange, code: "auth_oidc_failed", reason: "exchange_failed"},
		{name: "oidc_provider_error", err: &oidc.ProviderError{Code: "access_denied"}, code: "auth_oidc_failed", reason: "provider_error:access_denied"},
		{name: "session_gone", err: account.ErrSessionGone, code: "auth_session_expired", reason: "session_gone"},
		{name: "oidc_stale", err: oidc.ErrStaleAuthentication, code: "auth_oidc_failed", reason: "stale_authentication"},
		{name: "not_found", err: account.ErrNotFound, code: "auth_not_found"},
		{name: "method_not_allowed", err: errMethodNotAllowed, code: "auth_method_not_allowed"},
	}
	reached := map[Code]bool{}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e, ok := classify(row.err, row.cer)
			if !ok {
				t.Fatalf("classify(%v) is unmapped", row.err)
			}
			reached[e.Code] = true
			if e.Code != row.code || e.Reason != row.reason || e.Status != designStatus(t, row.code) {
				t.Errorf("classify(%v) = %s %q %d, want %s %q %d", row.err, e.Code, e.Reason, e.Status, row.code, row.reason, designStatus(t, row.code))
			}
			if !errors.Is(e.Err, row.err) {
				t.Errorf("Err = %v, want the mapped error", e.Err)
			}
		})
	}
	for _, d := range designCodes {
		if !reached[d.code] {
			t.Errorf("no row maps to %s", d.code)
		}
	}
	t.Run("unmapped_error", func(t *testing.T) {
		if _, ok := classify(errors.New("foreign"), ceremonyNone); ok {
			t.Error("a foreign error on a non-ceremony route is mapped, want a contract break")
		}
	})
	t.Run("codes_equal_the_table", func(t *testing.T) {
		var want []Code
		for _, d := range designCodes {
			want = append(want, d.code)
		}
		if got := Codes(); !slices.Equal(got, want) {
			t.Errorf("Codes() = %v, want %v", got, want)
		}
	})
	t.Run("retry_after_and_no_body", func(t *testing.T) {
		for _, tc := range []struct {
			err  error
			want string
		}{
			{&ratelimit.RefusedError{Dimension: "ip", RetryAfter: 1500 * time.Millisecond}, "2"},
			{access.ErrHashBusy, "1"},
			{access.ErrAuthBackend, "5"},
			{access.ErrBreachCheckUnavailable, "5"},
		} {
			var got Error
			h := &Handler{errors: func(w http.ResponseWriter, _ *http.Request, e Error) { got = e; w.WriteHeader(e.Status) }}
			w := httptest.NewRecorder()
			s := &routeSpec{name: "test"}
			h.fail(&call{w: w, r: httptest.NewRequest(http.MethodPost, "/", nil), spec: s, desc: &Descriptor{Name: "test", Codes: Codes()}}, tc.err)
			if w.Header().Get("Retry-After") != tc.want || w.Code != got.Status || w.Body.Len() != 0 {
				t.Errorf("%v: Retry-After %q status %d body %q, want %q, the writer's status and no body", tc.err, w.Header().Get("Retry-After"), w.Code, w.Body.String(), tc.want)
			}
		}
	})
}

func TestCodeFilter(t *testing.T) {
	var logged int
	run := func(t *testing.T, codes []Code, err error) Error {
		t.Helper()
		e := newEnv(t, envOptions{})
		var got Error
		e.h.errors = func(w http.ResponseWriter, _ *http.Request, er Error) { got = er; w.WriteHeader(er.Status) }
		s := &routeSpec{name: "testRoute", method: http.MethodPost, class: ClassPublic, serve: func(*Handler, *call) error { return err }}
		d := &Descriptor{Name: "testRoute", Method: http.MethodPost, Path: "/test", Class: ClassPublic, Codes: codes}
		before := e.logs.CountMsg("contract break")
		rt := Route{Descriptor: *d, Handler: e.h.mount(s, d)}
		do(rt, request(rt, ""))
		logged = e.logs.CountMsg("contract break") - before
		return got
	}
	t.Run("unlisted_sentinel", func(t *testing.T) {
		got := run(t, []Code{CodeMethodNotAllowed, CodeCrossOrigin}, account.ErrLastMethod)
		if got.Code != CodeUnavailable || logged != 1 || !errors.Is(got.Err, account.ErrLastMethod) {
			t.Errorf("got %s with %d ERROR logs, want auth_unavailable and one", got.Code, logged)
		}
	})
	t.Run("listed_sentinel", func(t *testing.T) {
		got := run(t, []Code{CodeLastMethod}, account.ErrLastMethod)
		if got.Code != CodeLastMethod || logged != 0 {
			t.Errorf("got %s with %d ERROR logs, want auth_last_method and none", got.Code, logged)
		}
	})
	t.Run("foreign_error", func(t *testing.T) {
		got := run(t, Codes(), errors.New("foreign"))
		if got.Code != CodeUnavailable || logged != 1 {
			t.Errorf("got %s with %d ERROR logs, want auth_unavailable and one", got.Code, logged)
		}
	})
}

func TestSessionGoneCodes(t *testing.T) {
	e := newEnv(t, envOptions{})
	// Each operation rereads its caller's session or user and answers
	// account.ErrSessionGone once it has gone.
	for _, name := range []string{"authStepUpPassword", "authPasswordSet", "authPasswordRemove", "authRecoveryPassword", "authRecoveryPasskeyBegin", "authRecoveryPasskeyFinish", "authOIDCLinkPending", "authOIDCUnlink"} {
		t.Run(name, func(t *testing.T) {
			rt := e.route(t, name)
			if !slices.Contains(opCodes[specNamed(t, name).op], CodeSessionExpired) {
				t.Errorf("operation codes %v lack auth_session_expired", opCodes[specNamed(t, name).op])
			}
			if slices.Contains(rt.Codes, CodeOIDCFailed) {
				t.Errorf("Codes %v hold auth_oidc_failed", rt.Codes)
			}
			errsBefore, breaksBefore := len(e.errs.all()), e.logs.CountMsg("contract break")
			w := httptest.NewRecorder()
			e.h.fail(&call{w: w, r: httptest.NewRequest(rt.Method, rt.Path, nil), spec: specNamed(t, name), desc: &rt.Descriptor}, fmt.Errorf("rotate: %w", account.ErrSessionGone))
			errs := e.errs.all()[errsBefore:]
			if len(errs) != 1 || errs[0].Code != CodeSessionExpired || errs[0].Status != http.StatusUnauthorized || errs[0].Reason != "session_gone" {
				t.Errorf("errors %+v, want one 401 auth_session_expired session_gone", errs)
			}
			if n := e.logs.CountMsg("contract break") - breaksBefore; n != 0 {
				t.Errorf("%d contract-break logs, want none", n)
			}
		})
	}
	// The callback answers through its redirect, and lists auth_oidc_failed
	// for the oidc errors.
	t.Run("authOIDCCallback", func(t *testing.T) {
		rt := e.route(t, "authOIDCCallback")
		if !slices.Contains(rt.Codes, CodeSessionExpired) {
			t.Errorf("Codes %v lack auth_session_expired", rt.Codes)
		}
		errsBefore, breaksBefore := len(e.errs.all()), e.logs.CountMsg("contract break")
		w := httptest.NewRecorder()
		c := &call{w: w, r: httptest.NewRequest(rt.Method, rt.Path, nil), spec: specNamed(t, rt.Name), desc: &rt.Descriptor}
		e.h.redirectFailure(c, fmt.Errorf("link: %w", account.ErrSessionGone), oidc.Flow{Intent: oidc.IntentLink, Redirect: "/settings"})
		if loc := w.Header().Get("Location"); w.Code != http.StatusFound || loc != "/settings?auth_error=auth_session_expired" {
			t.Errorf("status %d Location %q, want 302 /settings?auth_error=auth_session_expired", w.Code, loc)
		}
		if n := len(e.errs.all()) - errsBefore; n != 0 {
			t.Errorf("%d ErrorWriter calls, want none", n)
		}
		if n := e.logs.CountMsg("contract break") - breaksBefore; n != 0 {
			t.Errorf("%d contract-break logs, want none", n)
		}
	})
}

func TestClientGoneIsNotContractBreak(t *testing.T) {
	ended := func(r *http.Request) *http.Request {
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		return r.WithContext(ctx)
	}
	expired := func(r *http.Request) *http.Request {
		ctx, cancel := context.WithDeadline(r.Context(), time.Unix(0, 0))
		t.Cleanup(cancel)
		return r.WithContext(ctx)
	}
	live := func(r *http.Request) *http.Request { return r }
	cases := []struct {
		name   string
		err    error
		ctx    func(*http.Request) *http.Request
		breaks int
	}{
		{"client_cancelled", fmt.Errorf("account: password check ended: %w", context.Canceled), ended, 0},
		{"client_deadline", fmt.Errorf("account: password check ended: %w", context.DeadlineExceeded), expired, 0},
		{"live_request_canceled_error", fmt.Errorf("account: password check ended: %w", context.Canceled), live, 1},
		{"ended_request_other_context_error", fmt.Errorf("account: timeout: %w", context.DeadlineExceeded), ended, 1},
		{"ended_request_foreign_error", errors.New("foreign"), ended, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			s := &routeSpec{name: "testRoute", method: http.MethodPost, class: ClassPublic, serve: func(*Handler, *call) error { return tc.err }}
			d := &Descriptor{Name: "testRoute", Method: http.MethodPost, Path: "/test", Class: ClassPublic, Codes: Codes()}
			rt := Route{Descriptor: *d, Handler: e.h.mount(s, d)}
			w := do(rt, tc.ctx(request(rt, "")))
			errs := e.errs.all()
			if w.Code != http.StatusServiceUnavailable || len(errs) != 1 || errs[0].Code != CodeUnavailable {
				t.Errorf("status %d errors %+v, want 503 auth_unavailable", w.Code, errs)
			}
			if n := e.logs.CountMsg("contract break"); n != tc.breaks {
				t.Errorf("%d contract-break logs, want %d", n, tc.breaks)
			}
		})
	}
}
