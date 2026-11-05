package accesshttp

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// movable is an access.Config.TimeoutSource a test moves.
type movable struct {
	v atomic.Pointer[access.SessionTimeouts]
}

func newMovable(idle time.Duration) *movable {
	m := &movable{}
	m.set(idle)
	return m
}

func (m *movable) get() access.SessionTimeouts { return *m.v.Load() }
func (m *movable) set(idle time.Duration) {
	m.v.Store(&access.SessionTimeouts{Idle: idle, Absolute: 24 * time.Hour})
}

// timeoutMove is one runtime move of the idle limit from 2h to an
// effective 1h: the source answering 1h, or answering zero over a static
// 1h.
type timeoutMove struct {
	name   string
	static time.Duration
	to     time.Duration
}

var timeoutMoves = []timeoutMove{{name: "source_1h", static: 3 * time.Hour, to: time.Hour}, {name: "zero_falls_back", static: time.Hour}}

func (m timeoutMove) options(src *movable) envOptions {
	return envOptions{authn: func(_ *env, c *access.Config) {
		c.TimeoutSource, c.IdleTimeout = src.get, m.static
	}}
}

// clock is account.Config.Now, set by hand.
type clock struct{ at atomic.Pointer[time.Time] }

func (c *clock) now() time.Time { return *c.at.Load() }
func (c *clock) advance(d time.Duration) {
	at := c.now().Add(d)
	c.at.Store(&at)
}

// TestOneSessionConfiguration is §9.5 "One session configuration": an idle
// limit moved from 2h to 1h at runtime is the verifier's, the sweep's and
// the OIDC session check's alike, a source answering zero falling back to
// the static value in all three; and the cookie a password sign-in sets is
// the one the verifier reads next, under PostureSecure and
// PosturePerRequest.
func TestOneSessionConfiguration(t *testing.T) {
	for _, mv := range timeoutMoves {
		t.Run(mv.name+"_verifier_and_sweep", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				src := newMovable(2 * time.Hour)
				e := newEnv(t, with(mv.options(src), envOptions{edit: func(c *account.Config) { c.CleanupInterval = time.Minute }}))
				e.createUser(t, "alice", access.RoleUser)
				idle90 := e.storedSession(t, "alice", 0, 90*time.Minute)
				idle30 := e.storedSession(t, "alice", 0, 30*time.Minute)
				me := e.route(t, "authMe")
				for _, c := range []*http.Cookie{idle90, idle30} {
					e.requireStatus(t, do(me, request(me, "", c)), http.StatusOK)
				}
				src.set(mv.to)
				e.requireRefused(t, do(me, request(me, "", idle90)), CodeSessionExpired)
				e.requireStatus(t, do(me, request(me, "", idle30)), http.StatusOK)
				time.Sleep(time.Minute)
				synctest.Wait()
				for c, kept := range map[*http.Cookie]bool{idle90: false, idle30: true} {
					if _, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(c.Value)); err != nil || found != kept {
						t.Errorf("after the sweep: found %v, %v; want %v", found, err, kept)
					}
				}
			})
		})
		t.Run(mv.name+"_oidc_session_check", func(t *testing.T) {
			for _, moved := range []bool{false, true} {
				t.Run(map[bool]string{false: "unmoved", true: "moved"}[moved], func(t *testing.T) {
					src, at := newMovable(2*time.Hour), &clock{}
					now := time.Now()
					at.at.Store(&now)
					e := newEnv(t, with(mv.options(src), envOptions{edit: func(c *account.Config) { c.Now = at.now }}))
					idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
					b := e.signedInBrowser(t, "alice")
					e.linkUser(t, "alice", idpIdentity(testIssuer))
					w := e.sessionFlow(t, b, idp, "authOIDCStartStepUp", "/settings", func() {
						at.advance(90 * time.Minute)
						if moved {
							src.set(mv.to)
						}
					})
					want := "/settings?oidc=stepped_up"
					if moved {
						want = "/settings?auth_error=auth_session_expired"
					}
					if loc := location(t, w); loc != want {
						t.Errorf("step-up landed on %q, want %q", loc, want)
					}
				})
			}
		})
	}
	for _, tc := range []struct {
		opts   envOptions
		name   string
		origin string
	}{
		{name: "posture_secure", origin: testOrigin},
		{name: "per_request_https", opts: perRequest(nil), origin: testOrigin},
		{name: "per_request_http", opts: perRequest(nil), origin: "http://localhost"},
	} {
		t.Run("sign_in_cookie_"+tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			e.createUser(t, "alice", access.RoleUser)
			b := newBrowserAt(t, tc.origin)
			login := e.route(t, "authLoginPassword")
			w := b.send(login, b.request(login, signInBody(t, "alice")))
			var in SignedInResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &in) != nil {
				t.Fatalf("sign-in: status %d, errors %+v", w.Code, e.errs.all())
			}
			if me := e.meOf(t, b); me.Session.ID != in.SessionID || me.User.Username != "alice" {
				t.Errorf("the next request's session %+v of %s, want %s of alice", me.Session, me.User.Username, in.SessionID)
			}
		})
	}
}
