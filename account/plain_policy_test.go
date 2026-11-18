package account_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

// plainClientOf is localClient over plain HTTP from an address no prep
// charges.
func plainClientOf() account.Client {
	c := clientAt(1 << 20)
	c.Host, c.Secure = localClient.Host, false
	return c
}

// limitsOfOne admit one request per IP and hold one attempt per IP and
// per account, so a single charge shows.
func limitsOfOne(c *ratelimit.Config) {
	one := ratelimit.Rate{Limit: 1, Window: time.Hour}
	c.IP, c.Account, c.Request = one, one, one
}

// requireUncounted fails when a call charged w's limits of one: c's IP
// request and attempt and root's and alice's account attempts must each
// still be admitted.
func requireUncounted(t *testing.T, w *opWorld, c account.Client) {
	t.Helper()
	if err := w.limiter.Request(ratelimit.IPKey(c.IP())); err != nil {
		t.Errorf("Limiter.Request(%s) after the refusal = %v, want admitted", c.IP(), err)
	}
	attempts := []ratelimit.Attempt{{IP: ratelimit.IPKey(c.IP())}}
	for _, u := range []*access.User{w.root, w.alice} {
		if u != nil {
			attempts = append(attempts, ratelimit.Attempt{Account: ratelimit.AccountKey(u.Username), OmitIP: true})
		}
	}
	for _, a := range attempts {
		res, err := w.limiter.Attempt(a)
		if err != nil {
			t.Errorf("Limiter.Attempt(%+v) after the refusal = %v, want admitted", a, err)
			continue
		}
		res.Cancel()
	}
}

// plainRefusedUnder reports whether posture refuses op over plain HTTP.
func plainRefusedUnder(op *operation, posture access.CookiePosture) bool {
	return op.transport == plainRefused || op.transport == plainPerRequest && posture == access.PostureSecure
}

func TestPlainPolicyEveryOperation(t *testing.T) {
	t.Parallel()
	for _, posture := range []access.CookiePosture{access.PosturePerRequest, access.PostureSecure} {
		t.Run(posture.String(), func(t *testing.T) {
			t.Parallel()
			for _, op := range operations() {
				t.Run(op.name, func(t *testing.T) {
					t.Parallel()
					if op.transport == transportUnset {
						t.Fatalf("catalogue row %s has no transport", op.name)
					}
					w := newOpWorld(t, worldOptions{empty: op.empty, posture: posture, limiter: limitsOfOne})
					w.client = plainClientOf()
					p := w.actorFor(t, op.class)
					p.Secure = false
					call := op.prep(t, w, p)
					w.fs.resetRecord()
					mark := len(w.events.all())
					reserved, hashed := w.counted.reserved.Load(), w.counted.hashed.Load()
					err := call.run(t.Context())
					if !plainRefusedUnder(&op, posture) {
						if err != nil {
							t.Fatalf("plain %s = %v, want it to go through as over HTTPS", op.name, err)
						}
						got := comparableEvents(t, w.events.all()[mark:])
						if want := comparableEvents(t, withAt(call.want())); !reflect.DeepEqual(got, want) {
							t.Errorf("plain %s emitted\n%+v\nwant\n%+v", op.name, got, want)
						}
						return
					}
					if !errors.Is(err, access.ErrHTTPSRequired) {
						t.Errorf("plain %s = %v, want access.ErrHTTPSRequired", op.name, err)
					}
					if calls := w.fs.recorded(); len(calls) != 0 {
						t.Errorf("plain %s made %d store calls, first %s; want none", op.name, len(calls), calls[0].name)
					}
					if r, h := w.counted.reserved.Load()-reserved, w.counted.hashed.Load()-hashed; r != 0 || h != 0 {
						t.Errorf("plain %s reserved %d hash permits and derived %d hashes, want none", op.name, r, h)
					}
					if n := len(w.events.all()) - mark; n != 0 {
						t.Errorf("plain %s emitted %d events, want none", op.name, n)
					}
					requireUncounted(t, w, w.client)
				})
			}
		})
	}
}

// TestPlainEitherHalf holds the operations taking a Client and a Principal
// to both: either one plain refuses the call.
func TestPlainEitherHalf(t *testing.T) {
	t.Parallel()
	byName := map[string]operation{}
	for _, op := range operations() {
		byName[op.name] = op
	}
	for _, name := range []string{"StepUpPassword", "StepUpPasskeyFinish", "StepUpCode", "FinishTOTP", "RemovePassword", "SetPassword"} {
		op := byName[name]
		for _, half := range []struct {
			name                    string
			client, principalSecure bool
		}{
			{name: "plain_client", principalSecure: true},
			{name: "plain_principal", client: true},
		} {
			t.Run(name+"_"+half.name, func(t *testing.T) {
				t.Parallel()
				w := newOpWorld(t, worldOptions{})
				w.client.Secure = half.client
				p := w.actorFor(t, op.class)
				p.Secure = half.principalSecure
				if err := op.prep(t, w, p).run(t.Context()); !errors.Is(err, access.ErrHTTPSRequired) {
					t.Errorf("%s with a %s = %v, want access.ErrHTTPSRequired", name, half.name, err)
				}
			})
		}
	}
}

// TestPlainPolicyOutOfBand holds the issuing operations an Actor makes to
// their out-of-band arm: no transport, never refused.
func TestPlainPolicyOutOfBand(t *testing.T) {
	t.Parallel()
	for _, posture := range []access.CookiePosture{access.PosturePerRequest, access.PostureSecure} {
		t.Run(posture.String(), func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{posture: posture})
			a := account.OutOfBand("socket")
			if _, err := w.svc.CreateAPIKey(t.Context(), a, w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}}); err != nil {
				t.Errorf("CreateAPIKey(OutOfBand) = %v, want it to go through", err)
			}
			k := w.storedKey(t, w.alice, "read")
			if _, err := w.svc.RotateAPIKey(t.Context(), a, k.ID); err != nil {
				t.Errorf("RotateAPIKey(OutOfBand) = %v, want it to go through", err)
			}
		})
	}
}
