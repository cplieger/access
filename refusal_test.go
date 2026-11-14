package access_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
)

// specCodes is the specified code table, in Codes order, each code with its
// status and detail; it is written from the spec, not from the table.
var specCodes = []struct {
	code   access.Code
	detail string
	status int
}{
	{"auth_required", "Sign in to continue.", 401},
	{"auth_session_expired", "Your session has ended. Sign in again.", 401},
	{"auth_invalid_credentials", "The credentials are not valid.", 401},
	{"auth_key_invalid", "The API key is not valid.", 401},
	{"auth_recent_auth_required", "Confirm it is you to continue.", 403},
	{"auth_session_required", "A signed-in session is required.", 403},
	{"auth_scope_required", "The key lacks the required scope.", 403},
	{"auth_key_required", "This route needs an API key.", 403},
	{"auth_forbidden", "This action is not allowed.", 403},
	{"auth_rate_limited", "Too many attempts. Try again later.", 429},
	{"auth_busy", "The server is busy. Try again shortly.", 503},
	{"auth_unavailable", "The service is unavailable. Try again shortly.", 503},
	{"auth_bad_request", "The request is malformed.", 400},
	{"auth_body_too_large", "The request body is too large.", 413},
	{"auth_username_invalid", "The username is not valid.", 400},
	{"auth_username_taken", "The username is taken.", 409},
	{"auth_key_label_taken", "A key with this label already exists.", 409},
	{"auth_password_rejected", "The password is not allowed.", 400},
	{"auth_breach_check_unavailable", "The password check is unavailable. Try again shortly.", 503},
	{"auth_password_login_disabled", "Password sign-in is turned off.", 403},
	{"auth_setup_complete", "Setup is already complete.", 409},
	{"auth_setup_token_required", "A setup token is required.", 401},
	{"auth_token_invalid", "The link is not valid or has expired.", 401},
	{"auth_last_method", "The last sign-in method cannot be removed.", 409},
	{"auth_identity_taken", "That identity is linked to another account.", 409},
	{"auth_already_linked", "An identity is already linked. Unlink it first.", 409},
	{"auth_method_not_locked", "That sign-in method is not locked.", 409},
	{"auth_cross_origin", "Cross-origin requests are refused.", 403},
	{"auth_duplicate_credential", "That passkey is already registered.", 409},
	{"auth_unknown_scope", "A requested scope is unknown.", 400},
	{"auth_passkeys_unavailable", "Passkeys are not available.", 400},
	{"auth_origin_refused", "The request origin is refused.", 400},
	{"auth_ceremony_invalid", "The passkey request expired. Try again.", 401},
	{"auth_not_discoverable", "The authenticator did not create a passkey.", 400},
	{"auth_unknown_credential", "That passkey is not registered.", 401},
	{"auth_assertion_failed", "The passkey could not be verified.", 401},
	{"auth_registration_failed", "The passkey could not be registered.", 400},
	{"auth_oidc_unavailable", "Single sign-on is not available.", 400},
	{"auth_oidc_failed", "Single sign-on failed.", 401},
	{"auth_not_found", "Not found.", 404},
	{"auth_method_not_allowed", "Method not allowed.", 405},
}

// specRetryAfter is the Retry-After the spec gives the 503 codes that carry
// no limiter window; every other code has none.
var specRetryAfter = map[access.Code]time.Duration{
	"auth_busy":                     time.Second,
	"auth_unavailable":              5 * time.Second,
	"auth_breach_check_unavailable": 5 * time.Second,
}

func TestNewErrorTable(t *testing.T) {
	t.Parallel()
	t.Run("codes_in_spec_order", func(t *testing.T) {
		t.Parallel()
		var want []access.Code
		for _, s := range specCodes {
			want = append(want, s.code)
		}
		if got := access.Codes(); !slices.Equal(got, want) {
			t.Errorf("Codes() = %v, want %v", got, want)
		}
	})
	cause := errors.New("cause")
	for _, s := range specCodes {
		t.Run(string(s.code), func(t *testing.T) {
			t.Parallel()
			e := access.NewError(s.code, "a_reason", cause)
			if e.Code != s.code || e.Status != s.status || e.Detail != s.detail {
				t.Errorf("NewError(%s) = %s %d %q, want %s %d %q", s.code, e.Code, e.Status, e.Detail, s.code, s.status, s.detail)
			}
			if e.Reason != "a_reason" || !errors.Is(e.Err, cause) {
				t.Errorf("NewError(%s) Reason %q Err %v, want the given reason and error", s.code, e.Reason, e.Err)
			}
			if e.RetryAfter != specRetryAfter[s.code] {
				t.Errorf("NewError(%s).RetryAfter = %v, want %v", s.code, e.RetryAfter, specRetryAfter[s.code])
			}
		})
	}
	t.Run("unknown_code_panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("NewError(an unlisted code) returned, want a panic")
			}
		}()
		access.NewError("auth_not_a_code", "", nil)
	})
}

// TestErrorFor is the mapping of every error Authenticate returns, each
// row's code, status and detail from the spec and its Reason empty, so a
// refusal names no stored state.
func TestErrorFor(t *testing.T) {
	t.Parallel()
	unauth := func(detail error) error { return fmt.Errorf("%w: %w", access.ErrUnauthenticated, detail) }
	rows := []struct {
		err        error
		name       string
		code       access.Code
		status     int
		detail     string
		retryAfter time.Duration
	}{
		{name: "no_credential", err: access.ErrUnauthenticated, code: "auth_required", status: 401, detail: "Sign in to continue."},
		{name: "session_expired", err: unauth(access.ErrSessionExpired), code: "auth_session_expired", status: 401, detail: "Your session has ended. Sign in again."},
		{name: "session_not_found", err: unauth(access.ErrSessionNotFound), code: "auth_session_expired", status: 401, detail: "Your session has ended. Sign in again."},
		{name: "key_unknown", err: &access.InvalidCredentialError{Method: access.MethodAPIKey, Err: access.ErrInvalidAPIKey}, code: "auth_key_invalid", status: 401, detail: "The API key is not valid."},
		{name: "key_owner_disabled", err: &access.InvalidCredentialError{Method: access.MethodAPIKey, Err: access.ErrAccountDisabled, KeyID: 7}, code: "auth_key_invalid", status: 401, detail: "The API key is not valid."},
		{name: "session_owner_disabled", err: &access.InvalidCredentialError{Method: access.MethodPassword, Err: access.ErrAccountDisabled}, code: "auth_invalid_credentials", status: 401, detail: "The credentials are not valid."},
		{name: "custom_verifier_refusal", err: &access.InvalidCredentialError{Method: "agent"}, code: "auth_invalid_credentials", status: 401, detail: "The credentials are not valid."},
		{name: "recovery_session", err: &access.InvalidCredentialError{Method: access.MethodRecovery, Err: access.ErrRestrictedSession}, code: "auth_session_required", status: 403, detail: "A signed-in session is required."},
		{name: "backend", err: fmt.Errorf("%w: %w", access.ErrAuthBackend, errors.New("disk")), code: "auth_unavailable", status: 503, detail: "The service is unavailable. Try again shortly.", retryAfter: 5 * time.Second},
		{name: "wrapped", err: fmt.Errorf("verify: %w", &access.InvalidCredentialError{Method: access.MethodAPIKey, Err: access.ErrInvalidAPIKey}), code: "auth_key_invalid", status: 401, detail: "The API key is not valid."},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e, ok := access.ErrorFor(row.err)
			if !ok {
				t.Fatalf("ErrorFor(%v) is unmapped", row.err)
			}
			if e.Code != row.code || e.Status != row.status || e.Detail != row.detail || e.RetryAfter != row.retryAfter {
				t.Errorf("ErrorFor(%v) = %s %d %q %v, want %s %d %q %v", row.err, e.Code, e.Status, e.Detail, e.RetryAfter, row.code, row.status, row.detail, row.retryAfter)
			}
			if e.Reason != "" {
				t.Errorf("ErrorFor(%v).Reason = %q, want empty", row.err, e.Reason)
			}
			if !errors.Is(e.Err, row.err) {
				t.Errorf("ErrorFor(%v).Err = %v, want the mapped error", row.err, e.Err)
			}
		})
	}
	for name, err := range map[string]error{
		"unmapped_foreign":         errors.New("foreign"),
		"unmapped_recent_auth":     access.ErrRecentAuthRequired,
		"unmapped_not_recheckable": access.ErrNotRecheckable,
		"unmapped_nil":             nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if e, ok := access.ErrorFor(err); ok {
				t.Errorf("ErrorFor(%v) = %+v, true; want false", err, e)
			}
		})
	}
}

// TestGuardErrorForHidesKeyReason: the refusals of an unknown key, an
// expired key and a previous secret past its overlap, as Authenticate
// returns them, map to one Error with an empty Reason; the audit reason
// they carry never reaches the answer.
func TestGuardErrorForHidesKeyReason(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	u := &access.User{Username: "alice", Role: access.RoleUser, Enabled: true}
	if err := store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	addKey := func(expires time.Time) (string, int64) {
		g, err := access.GenerateAPIKey("ak_")
		if err != nil {
			t.Fatal(err)
		}
		k := &access.Key{UserID: u.ID, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix, Label: "k", CreatedAt: now, ExpiresAt: expires}
		if err := store.CreateAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		return g.Plaintext.Reveal(), k.ID
	}
	expired, _ := addKey(now.Add(-time.Minute))
	retired, id := addKey(time.Time{})
	next, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	sec := access.KeySecret{KeyHash: next.Hash, KeyPrefix: next.DisplayPrefix, KeySuffix: next.DisplaySuffix, PreviousHash: access.APIKeyHash(retired), PreviousUntil: now.Add(-time.Minute)}
	if err := store.UpdateAPIKeySecret(ctx, access.KeyRef{ID: id, UserID: u.ID}, sec); err != nil {
		t.Fatal(err)
	}
	unknown, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	authn, err := access.New(store, access.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var first access.Error
	for i, key := range []string{unknown.Plaintext.Reveal(), expired, retired} {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		_, authErr := authn.Authenticate(r)
		e, ok := access.ErrorFor(authErr)
		if !ok {
			t.Fatalf("key %d: ErrorFor(%v) is unmapped", i, authErr)
		}
		e.Err = nil
		if i == 0 {
			first = e
		}
		if e != first || e.Reason != "" || e.Code != access.CodeKeyInvalid {
			t.Errorf("key %d: ErrorFor = %+v, want %+v with an empty Reason", i, e, first)
		}
	}
}
