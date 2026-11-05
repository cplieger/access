package accesshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// decoded checks that w answered status and decodes its body as T.
func decoded[T any](t testing.TB, e *env, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	var v T
	if w.Code != status {
		t.Fatalf("status %d, errors %+v, want %d", w.Code, e.errs.all(), status)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

// requireStatus checks that w answered status.
func (e *env) requireStatus(t testing.TB, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, errors %+v, want %d", w.Code, e.errs.all(), status)
	}
}

// requireRefused checks that w answered exactly one code.
func (e *env) requireRefused(t testing.TB, w *httptest.ResponseRecorder, code Code) Error {
	t.Helper()
	errs := e.errs.all()
	if len(errs) == 0 || errs[len(errs)-1].Code != code || w.Code != codeTable[codeIndex[code]].status {
		t.Fatalf("status %d, errors %+v, want %s", w.Code, errs, code)
	}
	return errs[len(errs)-1]
}

// authenticates reports whether cookie still authenticates a session.
func (e *env) authenticates(t testing.TB, cookie *http.Cookie) bool {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testOrigin+"/", http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	_, err := e.authn.Authenticate(r)
	return err == nil
}

// requireRotated checks that w set a new session cookie for before's
// session, whose old cookie no longer authenticates, signed in by method
// when method is set, and a device cookie exactly when device is set.
func (e *env) requireRotated(t testing.TB, w *httptest.ResponseRecorder, old *http.Cookie, before access.Principal, method access.Method, device bool) {
	t.Helper()
	sessionName, deviceName := e.names()
	sc := cookieNamed(w, sessionName)
	if sc == nil || sc.Value == "" || sc.Value == old.Value {
		t.Fatalf("Set-Cookie %v, want a rotated session cookie", w.Result().Cookies())
	}
	p := e.principal(t, sc)
	if p.SessionID != before.SessionID || p.User.ID != before.User.ID || !p.IsSession() {
		t.Errorf("rotated cookie authenticates %+v, want session %s of user %d", p, before.SessionID, before.User.ID)
	}
	if method != "" && p.Method != method {
		t.Errorf("rotated session method %s, want %s", p.Method, method)
	}
	if e.authenticates(t, old) {
		t.Error("the cookie before the rotation still authenticates")
	}
	if d := cookieNamed(w, deviceName); (d != nil && d.Value != "") != device {
		t.Errorf("device Set-Cookie %v, want one: %v", d, device)
	}
}

func TestRouteAuthMe(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		p := e.principal(t, cookie)
		me := decoded[MeResponse](t, e, do(e.route(t, "authMe"), e.post(t, "authMe", "", cookie)), http.StatusOK)
		want := CurrentSessionView{ID: p.SessionID, Method: access.MethodPassword, AuthTime: p.AuthTime, IdleDeadline: p.IdleDeadline, AbsoluteDeadline: p.AbsoluteDeadline}
		if !sameSessionView(me.Session, want) || me.User.Username != "alice" || !me.Methods.Password || !me.Methods.PasswordLogin || me.CanLinkOIDC {
			t.Errorf("me %+v, want alice's password session %+v", me, want)
		}
	})
}

func sameSessionView(a, b CurrentSessionView) bool {
	return a.ID == b.ID && a.Method == b.Method && a.AuthTime.Equal(b.AuthTime) &&
		a.IdleDeadline.Equal(b.IdleDeadline) && a.AbsoluteDeadline.Equal(b.AbsoluteDeadline)
}

func TestRouteAuthProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		me := decoded[MeResponse](t, e, do(e.route(t, "authProfile"), e.post(t, "authProfile", jsonBody(t, ProfileRequest{DisplayName: "Alice A."}), cookie)), http.StatusOK)
		if me.User.DisplayName != "Alice A." || me.User.Username != "alice" || !me.Methods.Password {
			t.Errorf("me %+v, want alice named Alice A.", me)
		}
		if got := e.user(t, "alice").DisplayName; got != "Alice A." {
			t.Errorf("stored display name %q", got)
		}
	})
}

// passkeyReadFails fails every passkey read an Update's transaction makes.
type passkeyReadFails struct{ account.Store }

func (s passkeyReadFails) Update(ctx context.Context, fn func(account.Tx) error) error {
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(passkeyReadFailsTx{tx}) })
}

type passkeyReadFailsTx struct{ account.Tx }

func (passkeyReadFailsTx) PasskeysByUserID(context.Context, int64) ([]access.PasskeyCredential, error) {
	return nil, errors.New("passkey read failed")
}

// TestProfileViewReadFails: authProfile's view is read in the Update that
// sets the name, so a failed read answers 503 and leaves the name unset.
func TestProfileViewReadFails(t *testing.T) {
	e := newEnv(t, envOptions{edit: func(c *account.Config) { c.Store = passkeyReadFails{c.Store} }})
	cookie := e.aliceSession(t)
	w := do(e.route(t, "authProfile"), e.post(t, "authProfile", jsonBody(t, ProfileRequest{DisplayName: "Alice A."}), cookie))
	e.requireRefused(t, w, CodeUnavailable)
	if got := e.user(t, "alice").DisplayName; got != "" {
		t.Errorf("stored display name %q after the failed update, want it unchanged", got)
	}
}

// failureNames remembers the failure-record name account reads outside
// an Update, the HMAC a test cannot derive itself.
type failureNames struct {
	account.Store
	name string
	mu   sync.Mutex
}

func (s *failureNames) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	s.mu.Lock()
	s.name = ref.Name
	s.mu.Unlock()
	return s.Store.AuthFailure(ctx, ref)
}

func (s *failureNames) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

func TestRouteAuthMethodReenable(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		spy := &failureNames{}
		e := newEnv(t, with(passkeys, envOptions{edit: func(c *account.Config) { spy.Store = c.Store; c.Store = spy }}))
		e.aliceSession(t)
		cookie := e.passkeySession(t, e.enrol(t, "alice"))
		me := func() MeResponse {
			return decoded[MeResponse](t, e, do(e.route(t, "authMe"), e.post(t, "authMe", "", cookie)), http.StatusOK)
		}
		me()
		lock := account.FailureCount{Count: account.FailureCap, Locked: true, LockedAt: time.Now().Add(-time.Hour)}
		lock.Name, lock.Method = spy.last(), access.MethodPassword
		if err := e.mem.PutAuthFailure(t.Context(), lock); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
		if got := me().Methods.Locks; len(got) != 1 || got[0] != (MethodLockView{Method: access.MethodPassword, Untrusted: true}) {
			t.Fatalf("locks %+v before the re-enable, want the seeded untrusted password lock", got)
		}
		e.requireStatus(t, do(e.route(t, "authMethodReenable"), e.at(t, "authMethodReenable", string(access.MethodPassword), "", cookie)), http.StatusNoContent)
		if got := me().Methods.Locks; len(got) != 0 {
			t.Errorf("locks %+v after the re-enable, want none", got)
		}
	})
}

func TestRouteAuthStepUpPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		w := do(e.route(t, "authStepUpPassword"), e.post(t, "authStepUpPassword", jsonBody(t, PasswordRequest{Password: testPassword}), cookie))
		e.requireStatus(t, w, http.StatusNoContent)
		if w.Body.Len() != 0 {
			t.Errorf("body %q, want none", w.Body.String())
		}
	})
}

func TestRouteAuthStepUpPasskeyBegin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		id, options := e.begin(t, "authStepUpPasskeyBegin", "", "", cookie)
		var opts struct {
			PublicKey struct {
				RPID  string            `json:"rpId"`
				Allow []json.RawMessage `json:"allowCredentials"`
			} `json:"publicKey"`
		}
		if id == "" || json.Unmarshal(options, &opts) != nil || opts.PublicKey.RPID != testRPID || len(opts.PublicKey.Allow) != 1 {
			t.Errorf("ceremony %q options %s, want request options for %s allowing alice's one passkey", id, options, testRPID)
		}
	})
}

func TestRouteAuthStepUpPasskeyFinish(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		w := do(e.route(t, "authStepUpPasskeyFinish"), e.stepUpFinish(t, cookie, e.enrol(t, "alice"), nil, nil))
		e.requireStatus(t, w, http.StatusNoContent)
	})
}

// signsIn reports whether name signs in with password.
func (e *env) signsIn(t testing.TB, name, password string) bool {
	t.Helper()
	_, err := e.svc.PasswordLogin(t.Context(), account.Client{}, account.Credentials{Username: name, Password: access.NewSecret(password)})
	return err == nil
}

func TestRouteAuthPasswordSet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		e.requireStatus(t, do(e.route(t, "authPasswordSet"), e.post(t, "authPasswordSet", passwordSetBody(t, testPassword, newPassword), cookie)), http.StatusNoContent)
		if !e.signsIn(t, "alice", newPassword) || e.signsIn(t, "alice", testPassword) {
			t.Error("after the change, want the new password to sign in and the old one refused")
		}
	})
}

// TestPasswordSetCurrentHTTP is §9.5 "Current password" through authPasswordSet.
func TestPasswordSetCurrentHTTP(t *testing.T) {
	send := func(e *env, cookie *http.Cookie, current string) *httptest.ResponseRecorder {
		return do(e.route(t, "authPasswordSet"), e.post(t, "authPasswordSet", passwordSetBody(t, current, newPassword), cookie))
	}
	t.Run("missing", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		before := e.user(t, "alice").PasswordHash
		if got := e.requireRefused(t, send(e, cookie, ""), CodeBadRequest); got.Reason != ReasonCurrentPasswordRequired {
			t.Errorf("reason %q, want %s", got.Reason, ReasonCurrentPasswordRequired)
		}
		if !e.user(t, "alice").PasswordHash.Equal(before) {
			t.Error("the stored hash changed")
		}
	})
	t.Run("wrong", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		w := send(e, cookie, "not-"+testPassword)
		e.requireRefused(t, w, CodeInvalidCredentials)
		if len(w.Result().Cookies()) != 0 || !e.authenticates(t, cookie) || !e.signsIn(t, "alice", testPassword) {
			t.Errorf("cookies %v, want none, the session kept and the password unchanged", w.Result().Cookies())
		}
	})
	t.Run("right", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		before := e.principal(t, cookie)
		w := send(e, cookie, testPassword)
		e.requireStatus(t, w, http.StatusNoContent)
		e.requireRotated(t, w, cookie, before, "", true)
	})
	t.Run("first_password", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		u := e.user(t, "alice")
		u.PasswordHash = access.Hash{}
		if err := e.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		e.requireStatus(t, send(e, cookie, ""), http.StatusNoContent)
		if !e.signsIn(t, "alice", newPassword) {
			t.Error("the first password does not sign in")
		}
	})
}

func TestRouteAuthPasswordRemove(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		e.requireStatus(t, do(e.route(t, "authPasswordRemove"), e.post(t, "authPasswordRemove", passwordRemoveBody(t, testPassword), cookie)), http.StatusNoContent)
		if !e.user(t, "alice").PasswordHash.IsZero() {
			t.Error("the password is still stored")
		}
	})
}

// TestPasswordRemoveCurrentHTTP is §9.5 "Current password" through
// authPasswordRemove, on a user holding a password and a passkey.
func TestPasswordRemoveCurrentHTTP(t *testing.T) {
	setup := func(t *testing.T) (*env, *http.Cookie) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		return e, cookie
	}
	remove := func(t *testing.T, e *env, cookie *http.Cookie, current string) *httptest.ResponseRecorder {
		return do(e.route(t, "authPasswordRemove"), e.post(t, "authPasswordRemove", passwordRemoveBody(t, current), cookie))
	}
	t.Run("missing", func(t *testing.T) {
		e, cookie := setup(t)
		if got := e.requireRefused(t, remove(t, e, cookie, ""), CodeBadRequest); got.Reason != ReasonCurrentPasswordRequired {
			t.Errorf("reason %q, want %s", got.Reason, ReasonCurrentPasswordRequired)
		}
		if e.user(t, "alice").PasswordHash.IsZero() {
			t.Fatal("the password was removed")
		}
		w := do(e.route(t, "authPasswordSet"), e.post(t, "authPasswordSet", passwordSetBody(t, "", newPassword), cookie))
		if got := e.requireRefused(t, w, CodeBadRequest); got.Reason != ReasonCurrentPasswordRequired {
			t.Errorf("set after the refused removal: reason %q, want %s", got.Reason, ReasonCurrentPasswordRequired)
		}
	})
	t.Run("wrong", func(t *testing.T) {
		e, cookie := setup(t)
		e.requireRefused(t, remove(t, e, cookie, "not-"+testPassword), CodeInvalidCredentials)
		if !e.signsIn(t, "alice", testPassword) {
			t.Error("the password no longer signs in")
		}
	})
	t.Run("right", func(t *testing.T) {
		e, cookie := setup(t)
		before := e.principal(t, cookie)
		w := remove(t, e, cookie, testPassword)
		e.requireStatus(t, w, http.StatusNoContent)
		e.requireRotated(t, w, cookie, before, "", true)
		if e.signsIn(t, "alice", testPassword) {
			t.Error("the removed password still signs in")
		}
	})
}

func TestRouteAuthPasskeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		stored, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(stored) != 1 {
			t.Fatalf("PasskeysByUserID = %d, %v", len(stored), err)
		}
		views := decoded[[]PasskeyView](t, e, do(e.route(t, "authPasskeys"), e.post(t, "authPasskeys", "", cookie)), http.StatusOK)
		if want := passkeyView(&stored[0]); len(views) != 1 || views[0].ID != want.ID || views[0].Name != want.Name || views[0].RPID != testRPID || !views[0].CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("passkeys %+v, want alice's one %+v", views, want)
		}
	})
}

// TestPasskeyViewRPID: each listed passkey carries the RP ID it was
// registered against, a stale one's included.
func TestPasskeyViewRPID(t *testing.T) {
	e := newEnv(t, passkeys)
	cookie := e.aliceSession(t)
	e.enrol(t, "alice")
	stale := &access.PasskeyCredential{
		UserID: e.user(t, "alice").ID, CredentialID: []byte("stale-credential"), PublicKey: []byte("key"),
		RPID: "old.example.com", Name: "old", CreatedAt: time.Now(),
	}
	if err := e.mem.CreatePasskey(t.Context(), stale); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	views := decoded[[]PasskeyView](t, e, do(e.route(t, "authPasskeys"), e.post(t, "authPasskeys", "", cookie)), http.StatusOK)
	var enrolledRP, staleRP string
	for _, v := range views {
		if v.Name == "old" {
			staleRP = v.RPID
		} else {
			enrolledRP = v.RPID
		}
	}
	if len(views) != 2 || enrolledRP != testRPID || staleRP != "old.example.com" {
		t.Errorf("passkeys %+v, want the enrolled one under %s and the stale one under old.example.com", views, testRPID)
	}
}

func TestRouteAuthPasskeyRegisterBegin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		id, options := e.begin(t, "authPasskeyRegisterBegin", "", "", e.aliceSession(t))
		var opts struct {
			PublicKey struct {
				RP struct{ ID string } `json:"rp"`
			} `json:"publicKey"`
		}
		if id == "" || json.Unmarshal(options, &opts) != nil || opts.PublicKey.RP.ID != testRPID {
			t.Errorf("ceremony %q options %s, want creation options for %s", id, options, testRPID)
		}
	})
}

func TestRouteAuthPasskeyRegisterFinish(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		view := decoded[PasskeyView](t, e, do(e.route(t, "authPasskeyRegisterFinish"), e.registerFinish(t, cookie, nil, nil, nil)), http.StatusCreated)
		if id := e.passkeyID(t, "alice"); view.ID != id || view.RPID != testRPID || view.Name == "" {
			t.Errorf("view %+v, want the stored passkey %d under %s", view, id, testRPID)
		}
	})
}

func TestRouteAuthPasskeyRename(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		id := e.passkeyID(t, "alice")
		e.requireStatus(t, do(e.route(t, "authPasskeyRename"), e.at(t, "authPasskeyRename", strconv.FormatInt(id, 10), jsonBody(t, NameRequest{Name: "laptop"}), cookie)), http.StatusNoContent)
		creds, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(creds) != 1 || creds[0].Name != "laptop" {
			t.Errorf("stored passkeys %+v, %v; want one named laptop", creds, err)
		}
	})
}

func TestRouteAuthPasskeyRemove(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		id := e.passkeyID(t, "alice")
		e.requireStatus(t, do(e.route(t, "authPasskeyRemove"), e.at(t, "authPasskeyRemove", strconv.FormatInt(id, 10), "", cookie)), http.StatusNoContent)
		if creds, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID); err != nil || len(creds) != 0 {
			t.Errorf("stored passkeys %+v, %v; want none", creds, err)
		}
	})
}

func TestRouteAuthWebAuthnSignals(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		sig := decoded[webauthn.Signals](t, e, do(e.route(t, "authWebAuthnSignals"), e.post(t, "authWebAuthnSignals", "", cookie)), http.StatusOK)
		if sig.CurrentUserDetails.RPID != testRPID || sig.CurrentUserDetails.Name != "alice" || sig.AllAcceptedCredentials.RPID != testRPID || len(sig.AllAcceptedCredentials.AllAcceptedCredentialIDs) != 1 {
			t.Errorf("signals %+v, want alice's details and her one credential under %s", sig, testRPID)
		}
	})
}

func TestRouteAuthSessions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		other := e.sessionCookie(t, "alice")
		views := decoded[[]SessionView](t, e, do(e.route(t, "authSessions"), e.post(t, "authSessions", "", cookie)), http.StatusOK)
		current := map[string]bool{}
		for _, v := range views {
			current[v.ID] = v.Current
		}
		if _, listed := current[e.sessionIDOf(t, other)]; len(views) != 2 || !listed || !current[e.sessionIDOf(t, cookie)] || current[e.sessionIDOf(t, other)] {
			t.Errorf("sessions %+v, want both of alice's with only the caller's current", views)
		}
	})
}

// TestSessionViewDeadlines: each listed session's deadlines are
// access.SessionDeadlines under Timeouts, a capped and a recovery session's
// included, and the current one's equal authMe's.
func TestSessionViewDeadlines(t *testing.T) {
	e := newEnv(t, envOptions{})
	cookie := e.aliceSession(t)
	e.recoveryCookie(t, "alice")
	_, hash := access.GenerateSessionToken()
	now := time.Now().Truncate(time.Millisecond)
	capped := &access.Session{
		ID: "c0ffee00c0ffee00c0ffee00c0ffee00", UserID: e.user(t, "alice").ID, TokenHash: hash, AuthMethod: access.MethodPassword,
		CreatedAt: now, LastActivity: now, AuthTime: now, IdleCap: 10 * time.Minute, AbsoluteCap: time.Hour,
	}
	if err := e.mem.CreateSession(t.Context(), capped); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	views := decoded[[]SessionView](t, e, do(e.route(t, "authSessions"), e.post(t, "authSessions", "", cookie)), http.StatusOK)
	stored, err := e.mem.SessionsByUserID(t.Context(), e.user(t, "alice").ID)
	if err != nil || len(stored) != 3 {
		t.Fatalf("SessionsByUserID = %d, %v; want 3", len(stored), err)
	}
	byID := map[string]SessionView{}
	for _, v := range views {
		byID[v.ID] = v
	}
	kinds := map[access.SessionKind]bool{}
	for i := range stored {
		s := &stored[i]
		kinds[s.Kind] = true
		idle, absolute := access.SessionDeadlines(s, e.authn.Timeouts())
		v, ok := byID[s.ID]
		if !ok || !v.IdleDeadline.Equal(idle) || !v.AbsoluteDeadline.Equal(absolute) {
			t.Errorf("session %s (kind %q, caps %v/%v): view %+v, want deadlines %v and %v", s.ID, s.Kind, s.IdleCap, s.AbsoluteCap, v, idle, absolute)
		}
	}
	if !kinds[access.SessionRecovery] {
		t.Fatal("fixture: no recovery session listed")
	}
	me := decoded[MeResponse](t, e, do(e.route(t, "authMe"), e.post(t, "authMe", "", cookie)), http.StatusOK)
	cur := byID[me.Session.ID]
	if !cur.Current || !cur.IdleDeadline.Equal(me.Session.IdleDeadline) || !cur.AbsoluteDeadline.Equal(me.Session.AbsoluteDeadline) {
		t.Errorf("current row %+v, want authMe's deadlines %+v", cur, me.Session)
	}
}

func TestRouteAuthSessionRename(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		id := e.sessionIDOf(t, cookie)
		e.requireStatus(t, do(e.route(t, "authSessionRename"), e.at(t, "authSessionRename", id, jsonBody(t, NameRequest{Name: "laptop"}), cookie)), http.StatusNoContent)
		stored, err := e.mem.SessionsByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(stored) != 1 || stored[0].Label != "laptop" {
			t.Errorf("stored sessions %+v, %v; want one labelled laptop", stored, err)
		}
	})
}

func TestRouteAuthSessionRevoke(t *testing.T) {
	t.Run("other", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		other := e.sessionCookie(t, "alice")
		w := do(e.route(t, "authSessionRevoke"), e.at(t, "authSessionRevoke", e.sessionIDOf(t, other), "", cookie))
		e.requireStatus(t, w, http.StatusNoContent)
		if len(w.Result().Cookies()) != 0 || e.authenticates(t, other) || !e.authenticates(t, cookie) {
			t.Errorf("cookies %v; want none set, the other session ended and the caller's kept", w.Result().Cookies())
		}
	})
	t.Run("own", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		w := do(e.route(t, "authSessionRevoke"), e.at(t, "authSessionRevoke", e.sessionIDOf(t, cookie), "", cookie))
		e.requireStatus(t, w, http.StatusNoContent)
		e.requireCleared(t, w)
		if e.authenticates(t, cookie) {
			t.Error("the revoked session still authenticates")
		}
	})
}

func TestRouteAuthSessionsRevokeOthers(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		other := e.sessionCookie(t, "alice")
		e.requireStatus(t, do(e.route(t, "authSessionsRevokeOthers"), e.post(t, "authSessionsRevokeOthers", "", cookie)), http.StatusNoContent)
		if e.authenticates(t, other) || !e.authenticates(t, cookie) {
			t.Error("want the other session ended and the caller's kept")
		}
	})
}

// mintKey mints a key for name out of band.
func (e *env) mintKey(t testing.TB, name string, in account.NewKey) account.CreatedKey {
	t.Helper()
	created, err := e.svc.CreateAPIKey(t.Context(), account.OutOfBand("test"), e.user(t, name).ID, in)
	if err != nil {
		t.Fatalf("CreateAPIKey(%s): %v", name, err)
	}
	return created
}

// bearer is r carrying key as its Bearer credential.
func bearer(r *http.Request, key access.Secret) *http.Request {
	r.Header.Set("Authorization", "Bearer "+key.Reveal())
	return r
}

func TestRouteAuthKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		e.createUser(t, "bob", access.RoleUser)
		own := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		e.mintKey(t, "bob", account.NewKey{Label: "bob's"})
		views := decoded[[]KeyView](t, e, do(e.route(t, "authKeys"), e.post(t, "authKeys", "", cookie)), http.StatusOK)
		if want := keyView(&own.Key, ""); len(views) != 1 || views[0].ID != want.ID || views[0].Label != "ci" || views[0].Owner != "" || views[0].Prefix != want.Prefix {
			t.Errorf("keys %+v, want alice's one %+v with no owner", views, want)
		}
	})
}

func TestRouteAuthKeyCreate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		created := decoded[KeyCreatedResponse](t, e, do(e.route(t, "authKeyCreate"), e.post(t, "authKeyCreate", jsonBody(t, NewKeyRequest{Label: "ci", ExpiresInDays: 2}), cookie)), http.StatusCreated)
		keys, err := e.mem.ListAPIKeysByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(keys) != 1 {
			t.Fatalf("stored keys %d, %v; want one", len(keys), err)
		}
		d := created.Details
		if d.ID != keys[0].ID || d.Label != "ci" || d.UserID != keys[0].UserID || !d.ExpiresAt.Equal(keys[0].ExpiresAt) || time.Until(d.ExpiresAt).Round(time.Hour) != 48*time.Hour {
			t.Errorf("details %+v, want the stored key expiring in 2 days", d)
		}
		if d.Prefix != keys[0].KeyPrefix || d.Suffix != keys[0].KeySuffix || !d.CreatedAt.Equal(keys[0].CreatedAt) || d.Owner != "" {
			t.Errorf("details %+v, want the stored key's prefix, suffix and creation time with no owner", d)
		}
	})
}

func TestRouteAuthKeyRevoke(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.aliceSession(t)
		key := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		e.requireStatus(t, do(e.route(t, "authKeyRevoke"), e.at(t, "authKeyRevoke", strconv.FormatInt(key.Key.ID, 10), "", cookie)), http.StatusNoContent)
		if keys, err := e.mem.ListAPIKeysByUserID(t.Context(), e.user(t, "alice").ID); err != nil || len(keys) != 0 {
			t.Errorf("stored keys %+v, %v; want none", keys, err)
		}
	})
}

// TestRotationSetsCookie: every rotating route sets the rotated session
// cookie in its own response, and the step-ups and credential changes the
// device cookie.
func TestRotationSetsCookie(t *testing.T) {
	cases := []struct {
		build  func(t *testing.T, e *env, cookie *http.Cookie) *http.Request
		name   string
		method access.Method
		device bool
	}{
		{name: "authStepUpPassword", method: access.MethodPassword, device: true, build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			return e.post(t, "authStepUpPassword", jsonBody(t, PasswordRequest{Password: testPassword}), c)
		}},
		{name: "authStepUpPasskeyFinish", method: access.MethodPasskey, device: true, build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			return e.stepUpFinish(t, c, e.enrol(t, "alice"), nil, nil)
		}},
		{name: "authPasswordSet", device: true, build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			return e.post(t, "authPasswordSet", passwordSetBody(t, testPassword, newPassword), c)
		}},
		{name: "authPasswordRemove", device: true, build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			e.enrol(t, "alice")
			return e.post(t, "authPasswordRemove", passwordRemoveBody(t, testPassword), c)
		}},
		{name: "authPasskeyRegisterFinish", build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			return e.registerFinish(t, c, nil, nil, nil)
		}},
		{name: "authKeyCreate", build: func(t *testing.T, e *env, c *http.Cookie) *http.Request {
			return e.post(t, "authKeyCreate", keyBody(t, "ci"), c)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, passkeys)
			cookie := e.aliceSession(t)
			before := e.principal(t, cookie)
			r := tc.build(t, e, cookie)
			w := do(e.route(t, tc.name), r)
			if w.Code/100 != 2 {
				t.Fatalf("status %d, errors %+v", w.Code, e.errs.all())
			}
			e.requireRotated(t, w, cookie, before, tc.method, tc.device)
		})
	}
}

// TestEverySpecServed: every spec row carries its handler.
func TestEverySpecServed(t *testing.T) {
	for i := range specs {
		if specs[i].serve == nil {
			t.Errorf("%s has no handler", specs[i].name)
		}
	}
}
