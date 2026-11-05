package access

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/printcheck"
)

func TestPrincipalPrinting(t *testing.T) {
	t.Parallel()
	const (
		known  = "kn0wn-pr1nc1pal-h4sh-0451"
		marker = "4242"
	)
	p := Principal{
		User:       &User{ID: 7, Username: "alice", Role: RoleUser, PasswordHash: NewHash(known)},
		Method:     MethodAPIKey,
		KeyID:      4242,
		Scopes:     []string{"read"},
		SessionID:  "sess-1",
		credential: NewHash(known),
		source:     sourceSession,
	}
	values := map[string]any{"Principal": p, "*Principal": &p}
	// The same marker exceptions as TestRecordPrinting.
	noMarker := []string{"%T", "%q", "%x", "%X"}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			isPointer := reflect.ValueOf(v).Kind() == reflect.Pointer
			for route, got := range recordRenderings(t, v) {
				if printcheck.Leak(got, known) {
					t.Errorf("%s printed the hash: %s", route, got)
				}
				verb, nested := strings.CutPrefix(route, "[]any ")
				addressOnly := (verb == "%p" && (nested || isPointer)) || (nested && isPointer)
				if !slices.Contains(noMarker, verb) && !addressOnly && !strings.Contains(got, marker) {
					t.Errorf("%s = %s, want the principal's %s in it", route, got, marker)
				}
			}
		})
	}
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: principalFields, Types: []string{"time.Time"}}, reflect.TypeFor[*Principal]())
	})
}

// principalFields are the text fields a principal reaches that hold no
// secret: its own identifiers and enums, and its user's (recordFields).
var principalFields = []string{
	"access.Principal.Method", "access.Principal.SessionID", "access.Principal.SessionKind", "access.Principal.Scopes",
	"access.User.Username", "access.User.Email", "access.User.DisplayName", "access.User.Role",
	"access.User.WebAuthnHandle", "access.OIDCIdentity.Issuer", "access.OIDCIdentity.Subject",
}

func TestPrincipalLogValue(t *testing.T) {
	t.Parallel()
	p := Principal{
		User: &User{ID: 5}, Method: MethodPassword, SessionID: "sid", SessionKind: SessionRecovery,
		KeyID: 3, Scopes: []string{"read"}, credential: NewHash("h"),
	}
	want := map[string]any{
		"method": "password", "user_id": int64(5), "session_id": "sid", "session_kind": "recovery",
		"key_id": int64(3), "scopes": []string{"read"},
	}
	if got := logAttrs(t, p); !reflect.DeepEqual(got, want) {
		t.Errorf("LogValue() = %v, want %v", got, want)
	}
	if _, ok := logAttrs(t, Principal{Method: "custom"})["user_id"]; ok {
		t.Error("LogValue() of a principal with no user has a user_id")
	}
}

func TestPrincipalAccessors(t *testing.T) {
	t.Parallel()
	hash := NewHash("h")
	full := Principal{User: &User{ID: 1, Enabled: true}, Method: MethodPassword, credential: hash, source: sourceSession}
	recovery := full
	recovery.SessionKind = SessionRecovery
	key := Principal{User: &User{ID: 1, Enabled: true}, Method: MethodAPIKey, KeyID: 2, credential: hash, source: sourceAPIKey}
	custom := Principal{User: &User{Enabled: true}, Method: "custom", SessionID: "forged", AuthTime: time.Now()}
	customKey := Principal{User: &User{Enabled: true}, Method: MethodAPIKey, KeyID: 2, credential: hash}
	for _, tt := range []struct {
		name                string
		p                   Principal
		session, recovering bool
		tokenHash, apiKey   bool
	}{
		{name: "full session", p: full, session: true, tokenHash: true},
		{name: "recovery session", p: recovery, recovering: true, tokenHash: true},
		{name: "key", p: key, apiKey: true},
		{name: "custom filling session fields", p: custom},
		{name: "custom filling key fields", p: customKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.IsSession(); got != tt.session {
				t.Errorf("IsSession() = %v, want %v", got, tt.session)
			}
			if got := tt.p.IsRecoverySession(); got != tt.recovering {
				t.Errorf("IsRecoverySession() = %v, want %v", got, tt.recovering)
			}
			if got := tt.p.SessionTokenHash(); got.Equal(hash) != tt.tokenHash || got.IsZero() == tt.tokenHash {
				t.Errorf("SessionTokenHash() zero = %v, want zero %v", got.IsZero(), !tt.tokenHash)
			}
			if got := tt.p.IsAPIKey(); got != tt.apiKey {
				t.Errorf("IsAPIKey() = %v, want %v", got, tt.apiKey)
			}
		})
	}
	t.Run("HasScope", func(t *testing.T) {
		t.Parallel()
		p := Principal{Scopes: []string{"read", "write"}}
		if !p.HasScope("write") || p.HasScope("admin") || (Principal{}).HasScope("") {
			t.Errorf("HasScope over %v answered wrongly", p.Scopes)
		}
	})
}

type labelVerifier struct{ p Principal }

var _ Rechecker = labelVerifier{}

func (v labelVerifier) Verify(_ context.Context, r *http.Request) (Principal, bool, error) {
	if r.Header.Get("Authorization") != "Bearer label" {
		return Principal{}, false, nil
	}
	return v.p, true, nil
}

func (v labelVerifier) Recheck(context.Context, Principal) (Principal, bool, error) {
	return v.p, true, nil
}

func TestPrincipalIsAPIKey(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	label := Principal{User: &User{ID: 900, Enabled: true}, Method: MethodAPIKey, KeyID: f.keyID, Scopes: []string{"read"}}
	a := mustAuthenticator(t, f.store, Config{Verifier: labelVerifier{p: label}})
	key := mustAuthenticate(t, a, bearerRequest(f.key))
	session := mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
	custom := mustAuthenticate(t, a, bearerRequest("label"))
	bypass := mustAuthenticate(t, mustAuthenticator(t, f.store, Config{Bypass: func() bool { return true }}), bearerRequest(""))
	for name, tc := range map[string]struct {
		p    Principal
		want bool
	}{
		"key": {p: key, want: true}, "session": {p: session}, "custom_labelled_key": {p: custom}, "bypass": {p: bypass},
	} {
		if got := tc.p.IsAPIKey(); got != tc.want {
			t.Errorf("%s: IsAPIKey() = %v, want %v", name, got, tc.want)
		}
	}
	if q, err := a.Recheck(t.Context(), key); err != nil || !q.IsAPIKey() || q.KeyID != f.keyID {
		t.Errorf("Recheck(key) = %+v, %v, want the key principal again", q, err)
	}
	reads := f.store.keyReads.Load()
	q, err := a.Recheck(t.Context(), custom)
	if err != nil || q.IsAPIKey() || q.User.ID != 900 {
		t.Errorf("Recheck(custom labelled key) = %+v, %v, want its own verifier's principal", q, err)
	}
	if n := f.store.keyReads.Load() - reads; n != 0 {
		t.Errorf("Recheck(custom labelled key) made %d key reads, want 0", n)
	}
}

func TestRequireRecentAuth(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	now := time.Now()
	a := mustAuthenticator(t, f.store, Config{})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: f.session})
	session, err := a.Authenticate(r)
	if err != nil || !session.IsSession() {
		t.Fatalf("Authenticate(session) = (%+v, %v), want a session principal", session, err)
	}
	key, err := a.Authenticate(bearerRequest(f.key))
	if err != nil || key.KeyID == 0 {
		t.Fatalf("Authenticate(key) = (%+v, %v), want a key principal", key, err)
	}
	custom := Principal{User: &User{Enabled: true}, Method: "custom", SessionID: "sess-1", AuthTime: now}
	stale := session
	stale.AuthTime = now.Add(-2 * time.Minute)
	recovery := session
	recovery.SessionKind = SessionRecovery

	for _, tt := range []struct {
		name string
		p    Principal
		ok   bool
	}{
		{name: "fresh session", p: session, ok: true},
		{name: "session at exactly maxAge", p: func() Principal { s := session; s.AuthTime = now.Add(-time.Minute); return s }(), ok: true},
		{name: "stale session", p: stale},
		{name: "session at exactly now", p: func() Principal { s := session; s.AuthTime = now; return s }(), ok: true},
		{name: "session in the future", p: func() Principal { s := session; s.AuthTime = now.Add(24 * time.Hour); return s }()},
		{name: "recovery session", p: recovery},
		{name: "key", p: key},
		{name: "custom filling SessionID and AuthTime", p: custom},
		{name: "zero", p: Principal{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := RequireRecentAuth(tt.p, time.Minute, now)
			if tt.ok && err != nil {
				t.Errorf("RequireRecentAuth = %v, want nil", err)
			}
			if !tt.ok && !errors.Is(err, ErrRecentAuthRequired) {
				t.Errorf("RequireRecentAuth = %v, want ErrRecentAuthRequired", err)
			}
		})
	}
}

func TestRequestMarks(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	if IsPassive(ctx) {
		t.Error("IsPassive() = true on an unmarked context")
	}
	if !IsPassive(Passive(ctx)) {
		t.Error("IsPassive(Passive(ctx)) = false")
	}
	if IsPassive(AllowRecoverySession(ctx)) {
		t.Error("AllowRecoverySession marked the context passive")
	}
	if v, _ := AllowRecoverySession(ctx).Value(allowRecoveryKey{}).(bool); !v {
		t.Error("AllowRecoverySession(ctx) carries no mark")
	}
	if v, _ := Passive(ctx).Value(allowRecoveryKey{}).(bool); v {
		t.Error("Passive marked the context as allowing a recovery session")
	}
}
