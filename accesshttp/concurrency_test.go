package accesshttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

// TestBeginFloodBounded floods authLoginPasskeyBegin with concurrent
// requests, then finishes every admitted ceremony with alice's passkey. A
// begin the cache evicted answers auth_ceremony_invalid, so the ceremonies
// that still sign in are what the cache held once the flood ended.
func TestBeginFloodBounded(t *testing.T) {
	t.Run("one_ip", func(t *testing.T) {
		const limit, maxPending, flood = 6, 4, 64
		e, dev := floodEnv(t, limit, maxPending)
		admitted, refused := e.floodBegins(t, flood, func(int) string { return "192.0.2.1:4000" })
		if len(admitted) != limit || refused != flood-limit {
			t.Fatalf("%d begins admitted and %d refused, want %d and %d", len(admitted), refused, limit, flood-limit)
		}
		e.requireLive(t, dev, admitted, maxPending)
	})
	t.Run("many_ips", func(t *testing.T) {
		const maxPending, flood = 8, 200
		e, dev := floodEnv(t, ratelimit.DefaultConfig().Request.Limit, maxPending)
		admitted, refused := e.floodBegins(t, flood, func(i int) string { return fmt.Sprintf("198.18.0.%d:4000", i+1) })
		if len(admitted) != flood || refused != 0 {
			t.Fatalf("%d begins admitted and %d refused, want every one of %d admitted", len(admitted), refused, flood)
		}
		e.requireLive(t, dev, admitted, maxPending)
	})
}

// begun is one admitted begin: its ceremony, its options and the address
// that sent it.
type begun struct {
	id, remote string
	options    []byte
}

// floodEnv is an env whose Service holds at most maxPending ceremonies and
// whose limiter admits limit begins per IP an hour, with alice enrolled on
// the device it returns.
func floodEnv(t *testing.T, limit, maxPending int) (*env, *accesstest.PasskeyDevice) {
	t.Helper()
	e := newEnv(t, envOptions{
		passkeys: true,
		edit:     func(c *account.Config) { c.MaxPending = maxPending },
		limits:   func(c *ratelimit.Config) { c.Request = ratelimit.Rate{Limit: limit, Window: time.Hour} },
	})
	e.createUser(t, "alice", access.RoleUser)
	return e, e.enrol(t, "alice")
}

// floodBegins sends n begins at once, the i-th from remote(i), and returns
// the admitted ones and the count of refusals, each a cookieless 429 the
// ErrorWriter got as auth_rate_limited.
func (e *env) floodBegins(t *testing.T, n int, remote func(int) string) (admitted []begun, refused int) {
	t.Helper()
	rt := e.route(t, "authLoginPasskeyBegin")
	before := len(e.errs.all())
	start := make(chan struct{})
	answers := make([]*http.Response, n)
	bodies := make([][]byte, n)
	var wg sync.WaitGroup
	for i := range n {
		r := request(rt, "")
		r.RemoteAddr = remote(i)
		wg.Go(func() {
			<-start
			w := do(rt, r)
			answers[i], bodies[i] = w.Result(), w.Body.Bytes()
		})
	}
	close(start)
	wg.Wait()
	for i, res := range answers {
		switch {
		case res.StatusCode == http.StatusOK:
			var resp CeremonyResponse
			if err := json.Unmarshal(bodies[i], &resp); err != nil || resp.Ceremony == "" {
				t.Fatalf("begin %d: body %q (%v), want a ceremony", i, bodies[i], err)
			}
			admitted = append(admitted, begun{id: resp.Ceremony, remote: remote(i), options: resp.PublicKey})
		case res.StatusCode == http.StatusTooManyRequests && len(res.Cookies()) == 0:
			refused++
		default:
			t.Fatalf("begin %d = %d with Set-Cookie %v, want 200 or a cookieless 429", i, res.StatusCode, res.Cookies())
		}
	}
	errs := e.errs.all()[before:]
	if len(errs) != refused || slices.ContainsFunc(errs, func(er Error) bool { return er.Code != CodeRateLimited }) {
		t.Errorf("the ErrorWriter got %+v for %d refusals, want auth_rate_limited each", errs, refused)
	}
	return admitted, refused
}

// requireLive finishes every admitted ceremony from its own address with
// dev's assertion and requires exactly live of them to sign in, every
// other one answering auth_ceremony_invalid.
func (e *env) requireLive(t *testing.T, dev *accesstest.PasskeyDevice, admitted []begun, live int) {
	t.Helper()
	rt := e.route(t, "authLoginPasskeyFinish")
	before := len(e.errs.all())
	var signedIn, invalid int
	for _, b := range admitted {
		r := finish(rt, b.id, dev.Assert(b.options))
		r.RemoteAddr = b.remote
		switch w := do(rt, r); w.Code {
		case http.StatusOK:
			signedIn++
		case http.StatusUnauthorized:
			invalid++
		default:
			t.Fatalf("finish of %s = %d, errors %+v, want 200 or 401", b.id, w.Code, e.errs.all()[before:])
		}
	}
	if signedIn != live {
		t.Errorf("%d of %d admitted ceremonies signed in, want MaxPending %d", signedIn, len(admitted), live)
	}
	errs := e.errs.all()[before:]
	if len(errs) != invalid || slices.ContainsFunc(errs, func(er Error) bool { return er.Code != CodeCeremonyInvalid }) {
		t.Errorf("the ErrorWriter got %+v for %d refused finishes, want auth_ceremony_invalid each", errs, invalid)
	}
}
