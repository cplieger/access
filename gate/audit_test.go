package gate_test

import (
	"cmp"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

// auditLog records the events a gate's Audit hook receives.
type auditLog struct {
	mu     sync.Mutex
	events []access.AuditEvent
}

func (l *auditLog) record(_ *http.Request, e access.AuditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *auditLog) all() []access.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// httptest.NewRequest's RemoteAddr, which the default ClientAddr reads.
const testIP = "192.0.2.1"

// TestAudit is design 2.2 "The audit": one event per refusal of a
// presented credential, with its kind, reason and fields, and none for a
// request with no credential, a 503, an admitted request or a route miss.
func TestAudit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	failure := func(reason string, method access.Method, keyID int64) *access.AuditEvent {
		return &access.AuditEvent{Kind: "gate.failure", Reason: reason, Method: method, KeyID: keyID, IP: testIP}
	}
	forbidden := func(reason string, method access.Method, userID, keyID int64) *access.AuditEvent {
		return &access.AuditEvent{Kind: "gate.forbidden", Reason: reason, Method: method, UserID: userID, KeyID: keyID, IP: testIP}
	}
	for _, tc := range []struct {
		want   *access.AuditEvent
		name   string
		method string
		path   string
		creds  []cred
		bypass bool
	}{
		{name: "key_unknown", path: "/key", creds: []cred{unknownKey}, want: failure("key_unknown", access.MethodAPIKey, 0)},
		{name: "key_expired", path: "/key", creds: []cred{expiredKey}, want: failure("key_expired", access.MethodAPIKey, f.keyExpiredID)},
		{name: "key_retired", path: "/key", creds: []cred{retiredKey}, want: failure("key_retired", access.MethodAPIKey, f.keyRetiredID)},
		{name: "key_account_disabled", path: "/key", creds: []cred{disabledKey}, want: failure("account_disabled", access.MethodAPIKey, f.keyDisabledID)},
		{name: "session_expired", path: "/sess", creds: []cred{expiredCred}, want: failure("session_expired", "", 0)},
		{name: "session_unknown", path: "/sess", creds: []cred{goneCred}, want: failure("session_unknown", "", 0)},
		{name: "session_account_disabled", path: "/sess", creds: []cred{disabledCred}, want: failure("account_disabled", "", 0)},
		{name: "credential_invalid", path: "/scoped", creds: []cred{withAgent("bad")}, want: failure("credential_invalid", agentMethod, 0)},
		{name: "recovery_session", path: "/sess", creds: []cred{recoveryCred}, want: forbidden("recovery_session", "", 0, 0)},
		{name: "session_required", path: "/sess", creds: []cred{keyReadCred}, want: forbidden("session_required", access.MethodAPIKey, f.userID, f.keyID)},
		{name: "key_required", path: "/key", creds: []cred{sessionCred}, want: forbidden("key_required", "", f.userID, 0)},
		{name: "key_required_agent", path: "/key", creds: []cred{agentCred}, want: forbidden("key_required", agentMethod, 900, 0)},
		{name: "scope_required", path: "/key/read", creds: []cred{keyNoneCred}, want: forbidden("scope_required", access.MethodAPIKey, f.userID, f.keyNoneID)},
		{name: "forbidden", path: "/scoped", creds: []cred{agentCred}, want: forbidden("forbidden", agentMethod, 900, 0)},
		{name: "forbidden_bypass", path: "/scoped", bypass: true, want: forbidden("forbidden", access.MethodBypass, 0, 0)},
		{name: "cross_origin", method: http.MethodPost, path: "/sess", creds: []cred{sessionCred, crossSite}, want: forbidden("cross_origin", "", 0, 0)},
		{name: "none_no_credential", path: "/sess", creds: []cred{noCred}},
		{name: "none_store_down", path: "/sess", creds: []cred{withAgent("down")}},
		{name: "none_unmapped", path: "/sess", creds: []cred{withAgent("boom")}},
		{name: "none_admitted", path: "/sess", creds: []cred{sessionCred}},
		{name: "none_public", path: "/pub", creds: []cred{unknownKey}},
		{name: "none_not_found", path: "/nothing", creds: []cred{unknownKey}},
		{name: "none_method_not_allowed", method: http.MethodDelete, path: "/sess", creds: []cred{unknownKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log := &auditLog{}
			authn := f.authn
			if tc.bypass {
				authn = f.bypass
			}
			g := mustGate(t, gate.Config{Authenticator: authn, Audit: log.record}, classRoutes, &served{})
			method := cmp.Or(tc.method, http.MethodGet)
			a := do(t, f, g, method, tc.path, tc.creds...)
			got := log.all()
			if tc.want == nil {
				if len(got) != 0 {
					t.Errorf("%s %s = %d %q, audit %+v, want no event", method, tc.path, a.status, a.code, got)
				}
				return
			}
			if len(got) != 1 || got[0] != *tc.want {
				t.Errorf("%s %s = %d %q, audit %+v, want [%+v]", method, tc.path, a.status, a.code, got, *tc.want)
			}
		})
	}
	t.Run("before_errors", func(t *testing.T) {
		t.Parallel()
		var (
			mu  sync.Mutex
			seq []string
		)
		note := func(s string) {
			mu.Lock()
			defer mu.Unlock()
			seq = append(seq, s)
		}
		cfg := gate.Config{
			Authenticator: f.authn,
			Audit:         func(*http.Request, access.AuditEvent) { note("audit") },
			Errors: func(w http.ResponseWriter, r *http.Request, e access.Error) {
				note("errors")
				writeError(w, r, e)
			},
		}
		g := mustGate(t, cfg, classRoutes, &served{})
		do(t, f, g, http.MethodGet, "/key", unknownKey)
		do(t, f, g, http.MethodGet, "/key", sessionCred)
		mu.Lock()
		defer mu.Unlock()
		if want := []string{"audit", "errors", "audit", "errors"}; !slices.Equal(seq, want) {
			t.Errorf("calls = %q, want %q", seq, want)
		}
	})
}

// TestKeyRefusalsIdentical: an unknown key, an expired key and a previous
// secret past its overlap get byte-identical answers, so a refusal never
// tells a key holder which keys exist; only the audit event names the
// reason.
func TestKeyRefusalsIdentical(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	unstored, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	log := &auditLog{}
	g := mustGate(t, gate.Config{Authenticator: f.authn, Audit: log.record}, classRoutes, &served{})
	answers := map[string]answer{
		"key_unknown": do(t, f, g, http.MethodGet, "/key", withBearer(func(*fixture) string { return unstored.Plaintext.Reveal() })),
		"key_expired": do(t, f, g, http.MethodGet, "/key", expiredKey),
		"key_retired": do(t, f, g, http.MethodGet, "/key", retiredKey),
	}
	first := answers["key_unknown"]
	if first.status != http.StatusUnauthorized || first.code != access.CodeKeyInvalid {
		t.Fatalf("unknown key = %d %q, want 401 %s", first.status, first.code, access.CodeKeyInvalid)
	}
	for name, a := range answers {
		if a.status != first.status || a.body != first.body || !maps.EqualFunc(a.header, first.header, slices.Equal) {
			t.Errorf("%s answered %d %v %q, want the unknown key's %d %v %q", name, a.status, a.header, a.body, first.status, first.header, first.body)
		}
	}
	var reasons []string
	for _, e := range log.all() {
		reasons = append(reasons, e.Reason)
	}
	slices.Sort(reasons)
	if want := []string{"key_expired", "key_retired", "key_unknown"}; !slices.Equal(reasons, want) {
		t.Errorf("audit reasons = %q, want %q", reasons, want)
	}
	if !strings.Contains(first.body, `"reason":""`) {
		t.Errorf("body %q, want an empty reason", first.body)
	}
}
