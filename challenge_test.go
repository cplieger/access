package access_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
)

func newChallenger(t *testing.T, realm string) *access.Authenticator {
	t.Helper()
	a, err := access.New(accesstest.NewMemStore(), access.Config{Realm: realm})
	if err != nil {
		t.Fatalf("New(Realm %q): %v", realm, err)
	}
	return a
}

func challengeOf(a *access.Authenticator, code access.Code, scope string) []string {
	h := http.Header{}
	a.Challenge(h, code, scope)
	return h.Values("WWW-Authenticate")
}

// TestChallenge holds Challenge to RFC 6750: §3.1's error codes go only on a
// refused Bearer token (invalid_token) and a token lacking scope
// (insufficient_scope), and every other 401 carries the bare §3 challenge,
// since RFC 9110 §15.5.2 requires one on every 401.
func TestChallenge(t *testing.T) {
	t.Parallel()
	a := newChallenger(t, "")
	const bare = `Bearer realm="access"`
	rows := []struct {
		name  string
		code  access.Code
		scope string
		want  string
	}{
		{"rfc6750_3_1_invalid_token", "auth_key_invalid", "", `Bearer realm="access", error="invalid_token"`},
		{"rfc6750_3_1_insufficient_scope", "auth_scope_required", "admin", `Bearer realm="access", error="insufficient_scope", scope="admin"`},
		{"rfc6750_3_1_insufficient_scope_unnamed", "auth_scope_required", "", `Bearer realm="access", error="insufficient_scope"`},
		{"rfc6750_3_no_credential", "auth_required", "", bare},
		{"rfc6750_3_session_cookie_expired", "auth_session_expired", "", bare},
		{"rfc6750_3_other_credential_refused", "auth_invalid_credentials", "", bare},
		{"rfc6750_3_setup_token", "auth_setup_token_required", "", bare},
		{"rfc6750_3_link_token", "auth_token_invalid", "", bare},
		{"rfc6750_3_ceremony", "auth_ceremony_invalid", "", bare},
		{"rfc6750_3_unknown_passkey", "auth_unknown_credential", "", bare},
		{"rfc6750_3_assertion", "auth_assertion_failed", "", bare},
		{"rfc6750_3_sso", "auth_oidc_failed", "", bare},
	}
	challenged := map[access.Code]bool{}
	for _, tc := range rows {
		challenged[tc.code] = true
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := challengeOf(a, tc.code, tc.scope)
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("Challenge(%s, %q) = %q, want [%q]", tc.code, tc.scope, got, tc.want)
			}
		})
	}
	t.Run("every_401_has_a_row", func(t *testing.T) {
		t.Parallel()
		for _, sc := range specCodes {
			if sc.status == http.StatusUnauthorized && !challenged[sc.code] {
				t.Errorf("401 %s has no challenge row", sc.code)
			}
		}
	})
	t.Run("no_challenge_otherwise", func(t *testing.T) {
		t.Parallel()
		for _, sc := range specCodes {
			if challenged[sc.code] {
				continue
			}
			if got := challengeOf(a, sc.code, ""); len(got) != 0 {
				t.Errorf("Challenge(%s) = %q, want none", sc.code, got)
			}
		}
		if got := challengeOf(a, "auth_x_unknown", ""); len(got) != 0 {
			t.Errorf("Challenge(an unlisted code) = %q, want none", got)
		}
	})
	t.Run("sets_never_adds", func(t *testing.T) {
		t.Parallel()
		h := http.Header{"Www-Authenticate": {"Basic", "Bearer"}}
		a.Challenge(h, "auth_required", "")
		if got := h.Values("WWW-Authenticate"); len(got) != 1 || got[0] != bare {
			t.Errorf("WWW-Authenticate = %q, want only [%q]", got, bare)
		}
	})
	t.Run("leaves_an_unchallenged_header", func(t *testing.T) {
		t.Parallel()
		h := http.Header{"Www-Authenticate": {"Basic"}}
		a.Challenge(h, "auth_forbidden", "")
		if got := h.Values("WWW-Authenticate"); len(got) != 1 || got[0] != "Basic" {
			t.Errorf("WWW-Authenticate = %q, want [Basic] untouched", got)
		}
	})
	// RFC 6750 §3: scope = scope-token *( SP scope-token ), and a scope-token
	// is %x21 / %x23-5B / %x5D-7E, so one value never needs escaping.
	for _, scope := range []string{"a b", `a"b`, `a\b`, "a\x7f", "café"} {
		t.Run("panics_on_scope_"+strings.NewReplacer(" ", "SP", `"`, "DQUOTE", `\`, "BSLASH", "\x7f", "DEL").Replace(scope), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("Challenge(auth_scope_required, %q) did not panic", scope)
				}
			}()
			a.Challenge(http.Header{}, "auth_scope_required", scope)
		})
	}
}

// TestRealmValidation: the realm is a quoted-string (RFC 9110 §5.6.4) that
// Challenge writes unescaped, so New refuses what would need escaping or
// is not text.
func TestRealmValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, realm string }{
		{"dquote", `my"app`},
		{"backslash", `my\app`},
		{"nul", "my\x00app"},
		{"tab", "my\tapp"},
		{"newline", "my\napp"},
		{"del", "my\x7fapp"},
	} {
		t.Run("refuses_"+tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := access.New(accesstest.NewMemStore(), access.Config{Realm: tc.realm})
			if a != nil || err == nil || !strings.Contains(err.Error(), "realm") {
				t.Errorf("New(Realm %q) = (%p, %v), want a refusal naming the realm", tc.realm, a, err)
			}
		})
	}
	for _, tc := range []struct{ name, realm, want string }{
		{"empty_is_access", "", `Bearer realm="access"`},
		{"marotte", "marotte", `Bearer realm="marotte"`},
		{"spaces_and_punctuation", "My App: API", `Bearer realm="My App: API"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := challengeOf(newChallenger(t, tc.realm), "auth_required", "")
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("challenge = %q, want [%q]", got, tc.want)
			}
		})
	}
}
