package gate_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

var httpsRoutes = []gate.Route{
	{Name: "secret", Method: http.MethodGet, Path: "/secret", Class: gate.Session, HTTPS: true},
	{Name: "key_secret", Method: http.MethodGet, Path: "/key/secret", Class: gate.Key, HTTPS: true},
	{Name: "open", Method: http.MethodGet, Path: "/open", Class: gate.Session},
}

// TestHTTPSRow pins Route.HTTPS under PosturePerRequest: a plain request
// the class admits is refused 403 auth_https_required, with no audit event
// and no handler call; a secure one, and a plain one on a row without
// HTTPS, are served.
func TestHTTPSRow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	authn, err := access.New(f.store, access.Config{Cookie: access.CookieConfig{Posture: access.PosturePerRequest}, Logger: f.logger()})
	if err != nil {
		t.Fatal(err)
	}
	c := authn.Cookie()
	plainName := c.CookieName(false)
	plainSession := cred(func(f *fixture, r *http.Request) { r.AddCookie(&http.Cookie{Name: plainName, Value: f.plain}) })
	for _, tc := range []struct {
		name   string
		path   string
		route  string
		cred   cred
		plain  bool
		served bool
	}{
		{name: "plain_session_https_row", path: "/secret", route: "secret", cred: plainSession, plain: true},
		{name: "plain_key_https_row", path: "/key/secret", route: "key_secret", cred: keyReadCred, plain: true},
		{name: "secure_session_https_row", path: "/secret", route: "secret", cred: sessionCred, served: true},
		{name: "secure_key_https_row", path: "/key/secret", route: "key_secret", cred: keyReadCred, served: true},
		{name: "plain_session_open_row", path: "/open", route: "open", cred: plainSession, plain: true, served: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log := &auditLog{}
			g := mustGate(t, gate.Config{Authenticator: authn, Audit: log.record}, httpsRoutes, &served{})
			send := do
			if tc.plain {
				send = doPlain
			}
			a := send(t, f, g, http.MethodGet, tc.path, tc.cred)
			ran := a.body == "ok:"+tc.route
			if tc.served {
				if a.status != http.StatusOK || !ran {
					t.Errorf("GET %s = %d %q, handler ran %t; want served", tc.path, a.status, a.code, ran)
				}
				return
			}
			if a.status != http.StatusForbidden || a.code != access.CodeHTTPSRequired || ran {
				t.Errorf("GET %s = %d %q, handler ran %t; want 403 auth_https_required unserved", tc.path, a.status, a.code, ran)
			}
			if got := log.all(); len(got) != 0 {
				t.Errorf("GET %s audit = %+v, want no event", tc.path, got)
			}
		})
	}
	t.Run("codes", func(t *testing.T) {
		t.Parallel()
		for _, r := range httpsRoutes {
			if !slices.Contains(gate.Codes(r), access.CodeHTTPSRequired) {
				t.Errorf("Codes(%s) = %v, want auth_https_required listed", r.Name, gate.Codes(r))
			}
		}
	})
}

// TestPostureSecurePlain: under PostureSecure every authenticating row
// refuses a plain request 403 auth_https_required whatever it presents,
// the bypass included, with no audit event and no handler call; a Public
// row is still served.
func TestPostureSecurePlain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, who := range []struct {
		authn *access.Authenticator
		name  string
		cred  cred
	}{
		{f.authn, "none", noCred},
		{f.authn, "session", sessionCred},
		{f.authn, "plain_session", plainCred},
		{f.authn, "key", keyReadCred},
		{f.authn, "unknown_key", unknownKey},
		{f.authn, "agent", agentCred},
		{f.bypass, "bypass", noCred},
	} {
		for _, r := range classRoutes {
			t.Run(r.Name+"_"+who.name, func(t *testing.T) {
				t.Parallel()
				log := &auditLog{}
				g := mustGate(t, gate.Config{Authenticator: who.authn, Audit: log.record}, classRoutes, &served{})
				a := doPlain(t, f, g, r.Method, r.Path, who.cred)
				ran := a.body == "ok:"+r.Name
				if r.Class == gate.Public {
					if a.status != http.StatusOK || !ran {
						t.Errorf("%s %s = %d %q %q, want served", r.Method, r.Path, a.status, a.code, a.body)
					}
					return
				}
				if a.status != http.StatusForbidden || a.code != access.CodeHTTPSRequired || ran {
					t.Errorf("%s %s = %d %q, handler ran %t; want 403 auth_https_required unserved", r.Method, r.Path, a.status, a.code, ran)
				}
				if got := log.all(); len(got) != 0 {
					t.Errorf("%s %s audit = %+v, want no event", r.Method, r.Path, got)
				}
			})
		}
	}
}
