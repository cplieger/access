package accesshttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// TestStateRoute is authState's answer per posture and transport, with
// passkeys, OIDC and an HTTPS origin configured: docs/plain-http.md's
// sign-in screen states on the wire.
func TestStateRoute(t *testing.T) {
	const origin = "https://grelot.example"
	plainSession := &PlainSessionView{IdleSeconds: 1800, AbsoluteSeconds: 43200}
	for _, tc := range []struct {
		name   string
		opts   envOptions
		origin string
		want   StateResponse
		raw    []string // substrings the body must hold
		absent []string // keys the body must not hold
	}{
		{
			name: "posture_secure_secure", origin: testOrigin,
			want:   StateResponse{SSO: account.SSONameAlongside, Registration: account.RegistrationNameOff, SetupRequired: true, PasswordLogin: true, Passkeys: true, OIDC: true, Secure: true, HTTPSRequired: []account.HTTPSFeature{}},
			raw:    []string{`"https_required":[]`},
			absent: []string{`"plain_session"`, `"https_origin"`},
		},
		{
			name: "posture_secure_plain", origin: plainOrigin,
			want: StateResponse{
				SSO:           account.SSONameAlongside,
				Registration:  account.RegistrationNameOff,
				SetupRequired: true, HTTPSOrigin: origin,
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPassword, account.HTTPSSetup, account.HTTPSPasskeys, account.HTTPSOIDC},
			},
			raw:    []string{`"https_required":["password","setup","passkeys","oidc"]`, `"secure":false`, `"password_login":false`},
			absent: []string{`"plain_session"`},
		},
		{
			name: "per_request_secure", opts: perRequest, origin: testOrigin,
			want:   StateResponse{SSO: account.SSONameAlongside, Registration: account.RegistrationNameOff, SetupRequired: true, PasswordLogin: true, Passkeys: true, OIDC: true, Secure: true, HTTPSRequired: []account.HTTPSFeature{}},
			raw:    []string{`"https_required":[]`},
			absent: []string{`"plain_session"`, `"https_origin"`},
		},
		{
			name: "per_request_plain", opts: perRequest, origin: plainOrigin,
			want: StateResponse{
				SSO:           account.SSONameAlongside,
				Registration:  account.RegistrationNameOff,
				SetupRequired: true, PasswordLogin: true, PlainSession: plainSession, HTTPSOrigin: origin,
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys, account.HTTPSOIDC},
			},
			raw:    []string{`"plain_session":{"idle_seconds":1800,"absolute_seconds":43200}`, `"https_origin":"https://grelot.example"`, `"passkeys":false`, `"oidc":false`},
			absent: []string{`"temporary_password_https_only"`},
		},
		// A plain request under DisablePasswordLogin carries the
		// flag, so the plain form sends no temporary password.
		{
			name: "per_request_plain_password_login_off", opts: with(perRequest, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}), origin: plainOrigin,
			want: StateResponse{
				SSO:           account.SSONameAlongside,
				Registration:  account.RegistrationNameOff,
				SetupRequired: true, PlainSession: plainSession, HTTPSOrigin: origin, TemporaryPasswordHTTPSOnly: true,
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys, account.HTTPSOIDC},
			},
			raw: []string{`"temporary_password_https_only":true`},
		},
		{
			name: "per_request_secure_password_login_off", opts: with(perRequest, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}), origin: testOrigin,
			want:   StateResponse{SSO: account.SSONameAlongside, Registration: account.RegistrationNameOff, SetupRequired: true, Passkeys: true, OIDC: true, Secure: true, HTTPSRequired: []account.HTTPSFeature{}},
			absent: []string{`"temporary_password_https_only"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, with(passkeys, tc.opts, envOptions{rules: func(r *account.Rules) { r.HTTPSOrigin = origin }}))
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			rt := e.route(t, "authState")
			w := do(rt, requestAt(tc.origin, rt.Path, rt, ""))
			var got StateResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
				t.Fatalf("status %d body %q, want 200 StateResponse", w.Code, w.Body.String())
			}
			tc.want.PasswordLength = passwordBounds // the same on every posture and transport
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("state %+v (plain session %v), want %+v (plain session %v)", got, got.PlainSession, tc.want, tc.want.PlainSession)
			}
			for _, s := range tc.raw {
				if !bytes.Contains(w.Body.Bytes(), []byte(s)) {
					t.Errorf("body %s lacks %s", w.Body.Bytes(), s)
				}
			}
			for _, s := range tc.absent {
				if bytes.Contains(w.Body.Bytes(), []byte(s)) {
					t.Errorf("body %s holds %s", w.Body.Bytes(), s)
				}
			}
		})
	}
}

// TestSessionViewsSecure: authMe and authSessions carry each session's
// transport.
func TestSessionViewsSecure(t *testing.T) {
	for _, secure := range []bool{true, false} {
		e := newPlainWorld(t, secure)
		me := do(e.route(t, "authMe"), requestAt(e.origin, e.route(t, "authMe").Path, e.route(t, "authMe"), "", e.session))
		var got MeResponse
		if me.Code != http.StatusOK || json.Unmarshal(me.Body.Bytes(), &got) != nil || got.Session.Secure != secure {
			t.Errorf("secure %t: authMe status %d session %+v, want 200 with secure %t", secure, me.Code, got.Session, secure)
		}
		rt := e.route(t, "authSessions")
		list := do(rt, requestAt(e.origin, rt.Path, rt, "", e.session))
		var views []SessionView
		if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &views) != nil || len(views) != 1 || views[0].Secure != secure {
			t.Errorf("secure %t: authSessions status %d views %+v, want one with secure %t", secure, list.Code, views, secure)
		}
	}
}
