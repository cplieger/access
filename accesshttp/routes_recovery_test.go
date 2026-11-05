package accesshttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// startRecoveryRoute serves authRecoveryStart with an out-of-band recovery
// token for name and returns the response and its decoded body.
func (e *env) startRecoveryRoute(t *testing.T, name string) (*httptest.ResponseRecorder, RecoveryResponse) {
	t.Helper()
	issued, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, name).ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	w := do(e.route(t, "authRecoveryStart"), e.post(t, "authRecoveryStart", jsonBody(t, TokenRequest{Token: issued.Plaintext.Reveal()})))
	var resp RecoveryResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("status %d body %q, errors %+v, want 200 RecoveryResponse", w.Code, w.Body.String(), e.errs.all())
	}
	return w, resp
}

func TestRouteAuthRecoveryStart(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		w, resp := e.startRecoveryRoute(t, "alice")
		want := RecoveryResponse{Username: "alice", Methods: MethodsView{Locks: []MethodLockView{}, Password: true, PasswordLogin: true}}
		if !reflect.DeepEqual(resp, want) {
			t.Errorf("recovery %+v, want %+v", resp, want)
		}
		sessionName, deviceName := e.names()
		session := cookieNamed(w, sessionName)
		if session == nil || session.MaxAge != int(access.RecoverySessionLifetime.Seconds()) {
			t.Fatalf("session cookie %+v, want the recovery lifetime", session)
		}
		if p := e.principal(t, session); !p.IsRecoverySession() {
			t.Errorf("cookie authenticates %+v, want a recovery session", p)
		}
		if cookieNamed(w, deviceName) != nil {
			t.Errorf("a recovery start set the device cookie")
		}
	})
	t.Run("configured", func(t *testing.T) {
		var passwordOff atomic.Bool
		e := newEnv(t, with(passkeys, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = passwordOff.Load() }}))
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleUser)
		e.enrol(t, "alice")
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		passwordOff.Store(true)
		_, resp := e.startRecoveryRoute(t, "alice")
		want := RecoveryResponse{Username: "alice", Methods: MethodsView{
			Locks: []MethodLockView{}, PasskeyCount: 1, Password: true, OIDCLinked: true, OIDCAvailable: true, PasskeysAvailable: true,
		}}
		if !reflect.DeepEqual(resp, want) {
			t.Errorf("recovery %+v, want %+v", resp, want)
		}
	})
}

// requireRecovered checks that a completion answered 204, cleared the
// cookie, ended the recovery session and signed nobody in.
func (e *env) requireRecovered(t *testing.T, w *httptest.ResponseRecorder, cookie *http.Cookie) {
	t.Helper()
	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, errors %+v, want 204", res.StatusCode, e.errs.all())
	}
	sessionName, deviceName := e.names()
	var cleared bool
	for _, c := range res.Cookies() {
		switch c.Name {
		case sessionName:
			cleared = c.MaxAge < 0 && c.Value == ""
		case deviceName:
			t.Errorf("a recovery completion set the device cookie")
		}
	}
	if !cleared {
		t.Errorf("cookies %v, want the session cookie cleared and no new session", res.Cookies())
	}
	if _, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(cookie.Value)); err != nil || found {
		t.Errorf("recovery session still stored (%v, %v)", found, err)
	}
}

func TestRouteAuthRecoveryPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		cookie := e.recoveryCookie(t, "alice")
		const recovered = "recovered-horse-battery-staple-7"
		w := do(e.route(t, "authRecoveryPassword"), e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, recovered), cookie))
		e.requireRecovered(t, w, cookie)
		login := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: recovered})))
		e.requireSignedIn(t, login, "alice")
	})
}

func TestRouteAuthRecoveryPasskeyBegin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		e.createUser(t, "alice", access.RoleUser)
		id, options := e.begin(t, "authRecoveryPasskeyBegin", "", "", e.recoveryCookie(t, "alice"))
		var opts struct {
			PublicKey struct {
				User struct{ Name string } `json:"user"`
			} `json:"publicKey"`
		}
		if id == "" || json.Unmarshal(options, &opts) != nil || opts.PublicKey.User.Name != "alice" {
			t.Errorf("ceremony %q options %s, want creation options for alice", id, options)
		}
	})
}

func TestRouteAuthRecoveryPasskeyFinish(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		e.createUser(t, "alice", access.RoleUser)
		cookie := e.recoveryCookie(t, "alice")
		id, options := e.begin(t, "authRecoveryPasskeyBegin", "", "", cookie)
		dev := accesstest.NewPasskeyDevice(t)
		rt := e.route(t, "authRecoveryPasskeyFinish")
		e.requireRecovered(t, do(rt, finish(rt, id, dev.Register(options), cookie)), cookie)
		loginID, loginOptions := e.begin(t, "authLoginPasskeyBegin", "", "")
		login := e.route(t, "authLoginPasskeyFinish")
		e.requireSignedIn(t, do(login, finish(login, loginID, dev.Assert(loginOptions))), "alice")
	})
}

func TestRecoveryCookieRefusedElsewhere(t *testing.T) {
	e := newEnv(t, passkeys)
	e.createUser(t, "alice", access.RoleAdmin)
	cookie := e.recoveryCookie(t, "alice")
	var checked int
	for _, rt := range e.h.Routes() {
		if rt.Class == ClassPublic || rt.Class == ClassRecovery {
			continue
		}
		checked++
		t.Run(rt.Name, func(t *testing.T) {
			before := len(e.errs.all())
			w := do(rt, request(rt, "", cookie))
			errs := e.errs.all()[before:]
			if w.Code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != CodeSessionRequired {
				t.Errorf("status %d errors %+v, want 403 auth_session_required", w.Code, errs)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no authenticating route outside the recovery class is mounted")
	}
	t.Run("recovery_route_admits", func(t *testing.T) {
		e.begin(t, "authRecoveryPasskeyBegin", "", "", cookie)
	})
}

// recoveryFinishRecording records the options each passkey recovery
// finish passes account.
type recoveryFinishRecording struct {
	accountAPI
	opts []account.RecoverOptions
}

func (r *recoveryFinishRecording) RecoverPasskeyFinish(_ context.Context, _ access.Principal, _ string, _ io.Reader, opts account.RecoverOptions) error {
	r.opts = append(r.opts, opts)
	return nil
}

func TestRecoveryPasskeyFinishQuery(t *testing.T) {
	rec := &recoveryFinishRecording{}
	e := newEnv(t, with(passkeys, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { rec.accountAPI = s; return rec }}))
	e.createUser(t, "alice", access.RoleUser)
	cookie := e.recoveryCookie(t, "alice")
	rt := e.route(t, "authRecoveryPasskeyFinish")
	for _, tc := range []struct {
		query string
		want  account.RecoverOptions
	}{
		{"", account.RecoverOptions{}},
		{"keep_sessions=true", account.RecoverOptions{KeepSessions: true}},
		{"keep_keys=true", account.RecoverOptions{KeepKeys: true}},
		{"keep_sessions=true&keep_keys=true", account.RecoverOptions{KeepSessions: true, KeepKeys: true}},
	} {
		t.Run("q_"+tc.query, func(t *testing.T) {
			rec.opts = nil
			r := finish(rt, "any", []byte(`{}`), cookie)
			r.URL.RawQuery = tc.query
			if w := do(rt, r); w.Code != http.StatusNoContent || len(rec.opts) != 1 || rec.opts[0] != tc.want {
				t.Errorf("status %d opts %+v, want 204 and %+v", w.Code, rec.opts, tc.want)
			}
		})
	}
	for query, key := range map[string]string{"keep_keys=1": "keep_keys", "keep_sessions=false": "keep_sessions", "keep_keys=true&keep_keys=true": "keep_keys"} {
		t.Run("refused_"+query, func(t *testing.T) {
			rec.opts = nil
			r := finish(rt, "any", []byte(`{}`), cookie)
			r.URL.RawQuery = query
			before := len(e.errs.all())
			w := do(rt, r)
			errs := e.errs.all()[before:]
			if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Reason != key || len(rec.opts) != 0 {
				t.Errorf("status %d errors %+v opts %v, want 400 auth_bad_request %s and no account call", w.Code, errs, rec.opts, key)
			}
		})
	}
}
