package discovery_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access/oidc/internal/discovery"
	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

// The design's two intervals (6.6): a cached set is refreshed once it is
// 24 hours old, and refetch attempts are at least 60 seconds apart.
const (
	maxAge = 24 * time.Hour
	gate   = 60 * time.Second
)

// Design 6.6: the key set is fetched when the provider is built, which
// fails when the JWKS cannot be fetched (Discovery 1.0 §4.2: only a 200
// answer is read) or holds no usable key (RFC 7517 §5 skips the rest).
func TestNewKeySet_Refusals(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		want  error
		reply reply
	}{
		"500":                {discovery.ErrFetch, reply{status: 500, body: `{"keys":[]}`}},
		"404":                {discovery.ErrFetch, reply{status: 404}},
		"204":                {discovery.ErrFetch, reply{status: 204}},
		"transport error":    {discovery.ErrFetch, reply{err: errors.New("dial refused")}},
		"body read error":    {discovery.ErrFetch, reply{status: 200, cutBody: true}},
		"not JSON":           {discovery.ErrKeys, reply{status: 200, body: "<html>"}},
		"no keys member":     {discovery.ErrKeys, reply{status: 200, body: `{}`}},
		"empty set":          {discovery.ErrKeys, reply{status: 200, body: `{"keys":[]}`}},
		"no usable key":      {discovery.ErrKeys, reply{status: 200, body: octOnly}},
		"a private EC key":   {discovery.ErrKeys, reply{status: 200, body: jsonText(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "d": "AA"}}})}},
		"redirect":           {discovery.ErrFetch, reply{location: jwksURI}},
		"redirect to http":   {discovery.ErrFetch, reply{location: "http://idp.example/jwks"}},
		"redirect elsewhere": {discovery.ErrFetch, reply{location: "https://attacker.example/jwks"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := &jwksIdP{}
			idp.serve(tc.reply)
			ks, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI, Algs: testAlgs}, newClock().now, slog.New(&logSink{}))
			if ks != nil || !errors.Is(err, tc.want) {
				t.Fatalf("NewKeySet = %v, %v; want nil, %v", ks, err, tc.want)
			}
			if got := idp.requests(); got != 1 {
				t.Errorf("the JWKS saw %d requests, want 1: a redirect is never followed", got)
			}
		})
	}
}

// octOnly is a JWK Set whose one key is symmetric, which RFC 7517 §5 has
// skipped, so it holds no usable key.
var octOnly = jsonText(map[string]any{"keys": []any{map[string]any{"kty": "oct", "k": "c2VjcmV0"}}})

// Design 6.6: the fetch ends within the client's timeout, so a JWKS that
// never answers fails construction after 10 seconds.
func TestNewKeySet_HangingJWKS(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		idp := newJWKSIdP(t)
		release := idp.holdRequests()
		defer release()
		start := time.Now()
		ks, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI, Algs: testAlgs}, newClock().now, slog.New(&logSink{}))
		if ks != nil || !errors.Is(err, discovery.ErrFetch) {
			t.Fatalf("NewKeySet = %v, %v; want nil, ErrFetch", ks, err)
		}
		if waited := time.Since(start); waited != 10*time.Second {
			t.Errorf("NewKeySet waited %v, want the client's 10s timeout", waited)
		}
	})
}

// A fetch error never carries the jwks_uri, whose query may hold a secret
// (net/http's *url.Error prints the request URL).
func TestNewKeySet_ErrorOmitsURL(t *testing.T) {
	t.Parallel()
	idp := &jwksIdP{}
	idp.serve(reply{err: errors.New("dial refused")})
	_, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI + "?sig=query-secret", Algs: testAlgs}, newClock().now, slog.New(&logSink{}))
	if !errors.Is(err, discovery.ErrFetch) || strings.Contains(err.Error(), "query-secret") {
		t.Fatalf("NewKeySet = %v; want ErrFetch without the URL's query", err)
	}
}

// Design 6.6: every JWKS request, the first included, sends Cache-Control:
// no-cache, so a caching intermediary cannot pin a stale set (RFC 9111
// §5.2.1.4).
func TestKeySet_NoCache(t *testing.T) {
	t.Parallel()
	a, b := ecSigner(t, "a"), ecSigner(t, "b")
	f := newFixture(t, a)
	f.idp.publish(t, a, b)
	f.verifies(t, b)
	headers := f.idp.requestHeaders()
	if len(headers) != 2 {
		t.Fatalf("the JWKS saw %d requests, want 2", len(headers))
	}
	for i, h := range headers {
		if got := h.Values("Cache-Control"); !reflect.DeepEqual(got, []string{"no-cache"}) {
			t.Errorf("request %d: Cache-Control = %q, want [no-cache]", i, got)
		}
	}
}

// OpenID Connect Core 1.0 §10.1.1: a provider rotates by publishing a new
// kid, so a token under a kid the cache lacks is a miss that refetches
// once and verifies (design 6.4 step 5).
func TestKeySet_MissRefetches(t *testing.T) {
	t.Parallel()
	t.Run("new kid", func(t *testing.T) {
		t.Parallel()
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		f.idp.publish(t, a, b)
		f.verifies(t, b)
		f.wantRequests(t, 2)
		f.verifies(t, b)
		f.wantRequests(t, 2)
	})
	t.Run("new material under the same kid", func(t *testing.T) {
		t.Parallel()
		old, replaced := ecSigner(t, "k"), ecSigner(t, "k")
		f := newFixture(t, old)
		f.idp.publish(t, replaced)
		f.verifies(t, replaced)
		f.wantRequests(t, 2)
	})
	t.Run("new algorithm under the same kid", func(t *testing.T) {
		t.Parallel()
		old, replaced := ecSigner(t, "k"), edSigner(t, "k")
		f := newFixture(t, old)
		f.idp.publish(t, replaced)
		f.verifies(t, replaced)
		f.wantRequests(t, 2)
	})
	t.Run("the refetched set still lacks the kid", func(t *testing.T) {
		t.Parallel()
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		f.misses(t, b)
		f.wantRequests(t, 2)
		f.idp.publish(t, a, b)
		f.clock.advance(gate - time.Second)
		f.misses(t, b)
		f.wantRequests(t, 2)
	})
}

// Design 6.6: at most one refetch attempt per 60 seconds of Config.Now,
// and NewKeySet's own fetch does not start the gate.
func TestKeySet_Gate(t *testing.T) {
	t.Parallel()
	a, b, c := ecSigner(t, "a"), ecSigner(t, "b"), ecSigner(t, "c")
	f := newFixture(t, a)
	f.clock.advance(time.Second)
	f.idp.publish(t, b)
	f.verifies(t, b)
	f.wantRequests(t, 2)

	f.idp.publish(t, c)
	f.clock.advance(59 * time.Second)
	f.misses(t, c)
	f.wantRequests(t, 2)
	f.clock.advance(2 * time.Second)
	f.verifies(t, c)
	f.wantRequests(t, 3)

	d := ecSigner(t, "d")
	f.idp.publish(t, d)
	f.clock.advance(gate)
	f.verifies(t, d)
	f.wantRequests(t, 4)
}

// PyJWT CVE-2026-48524, CVE-2026-101917: a stream of tokens under unknown
// kids costs at most one JWKS request per 60 seconds.
func TestKeySet_UnknownKIDAmplification(t *testing.T) {
	t.Parallel()
	a := ecSigner(t, "a")
	f := newFixture(t, a)
	unknown := ecSigner(t, "unknown").token(t)
	for range 1000 {
		if _, err := f.keys.Verify(t.Context(), unknown); !errors.Is(err, jws.ErrNoKey) {
			t.Fatalf("Verify = %v, want ErrNoKey", err)
		}
		f.clock.advance(50 * time.Millisecond)
	}
	f.wantRequests(t, 2)
}

// Design 6.6: a dead JWKS endpoint costs one attempt a minute, and a miss
// while the gate is shut answers at once, without the network.
func TestKeySet_DeadEndpoint(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		release := f.idp.holdRequests()
		defer release()

		start := time.Now()
		f.misses(t, b)
		if waited := time.Since(start); waited != 10*time.Second {
			t.Errorf("the gated miss waited %v, want the client's 10s timeout", waited)
		}
		f.wantRequests(t, 2)

		f.clock.advance(time.Second)
		start = time.Now()
		f.misses(t, b)
		if waited := time.Since(start); waited != 0 {
			t.Errorf("a miss in the shut window waited %v, want 0", waited)
		}
		f.wantRequests(t, 2)

		f.clock.advance(gate)
		f.misses(t, b)
		f.wantRequests(t, 3)
		f.verifies(t, a)
	})
}

// Design 6.6 step 1: a verify that succeeds from a set whose age is due
// starts one refresh and does not wait for it.
func TestKeySet_AgeRefresh(t *testing.T) {
	t.Parallel()
	t.Run("boundary", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a := ecSigner(t, "a")
			f := newFixture(t, a)
			f.clock.advance(maxAge - time.Second)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 1)
			f.clock.advance(time.Second)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
		})
	})
	t.Run("hanging JWKS", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a := ecSigner(t, "a")
			f := newFixture(t, a)
			release := f.idp.holdRequests()
			defer release()
			f.clock.advance(maxAge)
			start := time.Now()
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			f.clock.advance(time.Second)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			if waited := time.Since(start); waited != 0 {
				t.Errorf("the age-due verifies waited %v, want 0", waited)
			}
		})
	})
	t.Run("new kid on an aged set", func(t *testing.T) {
		t.Parallel()
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		f.clock.advance(maxAge)
		f.idp.publish(t, a, b)
		f.verifies(t, b)
		f.wantRequests(t, 2)
	})
}

// Design 6.6 step 3: a miss while a refetch is in flight joins it,
// whatever started it, and verifies with the key it brings.
func TestKeySet_MissJoinsAgeRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		release := f.idp.holdRequests()
		f.clock.advance(maxAge)
		f.verifies(t, a)
		synctest.Wait()
		f.wantRequests(t, 2)

		f.idp.publish(t, a, b)
		done := make(chan error)
		go func() {
			_, err := f.keys.Verify(t.Context(), b.token(t))
			done <- err
		}()
		synctest.Wait()
		release()
		if err := <-done; err != nil {
			t.Fatalf("the joined miss = %v, want the payload", err)
		}
		f.wantRequests(t, 2)
	})
}

// Design 6.6: concurrent misses share one fetch.
func TestKeySet_ConcurrentMisses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		release := f.idp.holdRequests()
		f.idp.publish(t, a, b)
		tok := b.token(t)
		errs := make(chan error, 10)
		for range 10 {
			go func() {
				_, err := f.keys.Verify(t.Context(), tok)
				errs <- err
			}()
		}
		synctest.Wait()
		release()
		for range 10 {
			if err := <-errs; err != nil {
				t.Errorf("a coalesced miss = %v, want the payload", err)
			}
		}
		f.wantRequests(t, 2)
	})
}

// Design 6.6 and 6.9: the fetch runs under context.WithoutCancel, so the
// first waiter leaving fails only itself, and the second waiter verifies
// from the same fetch.
func TestKeySet_CancelledFirstWaiter(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		release := f.idp.holdRequests()
		f.idp.publish(t, a, b)
		tok := b.token(t)

		ctx, cancel := context.WithCancel(t.Context())
		first := make(chan error)
		go func() {
			_, err := f.keys.Verify(ctx, tok)
			first <- err
		}()
		synctest.Wait()
		second := make(chan error)
		go func() {
			_, err := f.keys.Verify(t.Context(), tok)
			second <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Errorf("the cancelled first waiter = %v, want context.Canceled", err)
		}
		release()
		if err := <-second; err != nil {
			t.Errorf("the second waiter = %v, want the payload", err)
		}
		f.wantRequests(t, 2)
	})
}

// Design 6.6: Config.Now may step back, so the gate and the age both open
// when now reads before the last attempt or the fetch.
func TestKeySet_ClockStepsBack(t *testing.T) {
	t.Parallel()
	t.Run("gate", func(t *testing.T) {
		t.Parallel()
		a, b, c := ecSigner(t, "a"), ecSigner(t, "b"), ecSigner(t, "c")
		f := newFixture(t, a)
		f.idp.publish(t, b)
		f.verifies(t, b)
		f.wantRequests(t, 2)
		f.idp.publish(t, c)
		f.clock.advance(-time.Hour)
		f.verifies(t, c)
		f.wantRequests(t, 3)
	})
	t.Run("age", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a := ecSigner(t, "a")
			f := newFixture(t, a)
			f.clock.advance(-time.Hour)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
		})
	})
	// Design 6.6, one fetch at a time: a step back while the age refresh is
	// in flight opens the age and the gate, and starts no second fetch.
	t.Run("refresh in flight", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a := ecSigner(t, "a")
			f := newFixture(t, a)
			release := f.idp.holdRequests()
			f.clock.advance(maxAge)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			f.clock.advance(-2 * maxAge)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			release()
			synctest.Wait()
		})
	})
}

// Design 6.6: a failed refetch keeps the last good set and logs one WARN.
func TestKeySet_FailedRefetchKeepsSet(t *testing.T) {
	t.Parallel()
	for name, rep := range map[string]reply{
		"500":             {status: 500},
		"redirect":        {location: jwksURI},
		"transport error": {err: errors.New("dial refused")},
		"body read error": {status: 200, cutBody: true},
		"not JSON":        {status: 200, body: "{"},
		"no usable key":   {status: 200, body: octOnly},
		"a private key":   {status: 200, body: jsonText(map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AA", "d": "AA"}}})},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := ecSigner(t, "a"), ecSigner(t, "b")
			f := newFixture(t, a)
			f.idp.serve(rep)
			f.misses(t, b)
			f.wantRequests(t, 2)
			f.verifies(t, a)
			if got := f.log.warns(); len(got) != 1 {
				t.Errorf("WARNs = %q, want one", got)
			}
		})
	}
}

// The refetch WARN names the provider's JWKS host, never the URL's query.
func TestKeySet_WarnOmitsQuery(t *testing.T) {
	t.Parallel()
	a, b := ecSigner(t, "a"), ecSigner(t, "b")
	idp := newJWKSIdP(t, a)
	sink := &logSink{}
	ks, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI + "?sig=query-secret", Algs: testAlgs}, newClock().now, slog.New(sink))
	if err != nil {
		t.Fatalf("NewKeySet = %v", err)
	}
	idp.serve(reply{err: errors.New("dial refused")})
	if _, err := ks.Verify(t.Context(), b.token(t)); !errors.Is(err, jws.ErrNoKey) {
		t.Fatalf("Verify = %v, want ErrNoKey", err)
	}
	warns := sink.warns()
	if len(warns) != 1 || strings.Contains(warns[0], "query-secret") || !strings.Contains(warns[0], "idp.example") {
		t.Errorf("WARNs = %q, want one naming idp.example without the query", warns)
	}
}

// Config.Logger's nil means slog.Default() when the WARN is written.
func TestKeySet_NilLoggerUsesDefault(t *testing.T) {
	a, b := ecSigner(t, "a"), ecSigner(t, "b")
	idp := newJWKSIdP(t, a)
	ks, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI, Algs: testAlgs}, newClock().now, nil)
	if err != nil {
		t.Fatalf("NewKeySet = %v", err)
	}
	sink := &logSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })
	idp.serve(reply{status: 500})
	if _, err := ks.Verify(t.Context(), b.token(t)); !errors.Is(err, jws.ErrNoKey) {
		t.Fatalf("Verify = %v, want ErrNoKey", err)
	}
	if got := sink.warns(); len(got) != 1 {
		t.Errorf("slog.Default() WARNs = %q, want one", got)
	}
}

// RFC 7517 §4.5: two keys may share a kid. When both fit one of the
// provider's algorithms both are tried, and the fetch logs a WARN; keys
// of different types sharing a kid are told apart by the header's alg.
func TestKeySet_SharedKID(t *testing.T) {
	t.Parallel()
	t.Run("one algorithm", func(t *testing.T) {
		t.Parallel()
		first, second := ecSigner(t, "k"), ecSigner(t, "k")
		f := newFixture(t, first, second)
		if got := f.log.warns(); len(got) != 1 || !strings.Contains(got[0], "k") {
			t.Errorf("WARNs = %q, want one naming kid k", got)
		}
		f.verifies(t, second)
		f.verifies(t, first)
		f.wantRequests(t, 1)
	})
	t.Run("different algorithms", func(t *testing.T) {
		t.Parallel()
		ec, ed := ecSigner(t, "k"), edSigner(t, "k")
		f := newFixture(t, ec, ed)
		if got := f.log.warns(); len(got) != 0 {
			t.Errorf("WARNs = %q, want none", got)
		}
		f.verifies(t, ec)
		f.verifies(t, ed)
		f.wantRequests(t, 1)
	})
	t.Run("an algorithm outside the provider's set", func(t *testing.T) {
		t.Parallel()
		first, second := ecSigner(t, "k"), ecSigner(t, "k")
		idp := newJWKSIdP(t, first, second)
		sink := &logSink{}
		_, err := discovery.NewKeySet(t.Context(), idp.client(), discovery.Document{JWKSURI: jwksURI, Algs: []jwk.Alg{jwk.EdDSA}}, newClock().now, slog.New(sink))
		if err != nil {
			t.Fatalf("NewKeySet = %v", err)
		}
		if got := sink.warns(); len(got) != 0 {
			t.Errorf("WARNs = %q, want none: no accepted token can name both keys", got)
		}
	})
}

// Design 6.6 and OpenID Connect Core 1.0 §10.1.1: a key the provider
// retires verifies from the cache until the first successful refetch after
// the age is due, or an earlier miss's refetch; a failed refresh keeps it.
func TestKeySet_RetiredKey(t *testing.T) {
	t.Parallel()
	t.Run("age refresh drops it", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a, b := ecSigner(t, "a"), ecSigner(t, "b")
			f := newFixture(t, a)
			f.idp.publish(t, b)
			f.clock.advance(maxAge - time.Second)
			f.verifies(t, a)
			f.clock.advance(time.Second)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			f.misses(t, a)
			f.wantRequests(t, 2)
		})
	})
	t.Run("failed age refresh keeps it", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			a := ecSigner(t, "a")
			f := newFixture(t, a)
			f.idp.serve(reply{status: 503})
			f.clock.advance(maxAge)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			f.clock.advance(gate - time.Second)
			f.verifies(t, a)
			synctest.Wait()
			f.wantRequests(t, 2)
			if got := f.log.warns(); len(got) != 1 {
				t.Errorf("WARNs = %q, want one", got)
			}
		})
	})
	t.Run("a miss's refetch drops it", func(t *testing.T) {
		t.Parallel()
		a, b := ecSigner(t, "a"), ecSigner(t, "b")
		f := newFixture(t, a)
		f.idp.publish(t, b)
		f.verifies(t, b)
		f.misses(t, a)
		f.wantRequests(t, 2)
	})
}

// Design 6.6: no long-lived goroutine. Once an age refresh has ended,
// nothing the KeySet started is left running, and it has nothing to stop.
func TestKeySet_NoGoroutineLeft(t *testing.T) {
	for _, name := range []string{"Stop", "Close", "Shutdown"} {
		if _, ok := reflect.TypeFor[*discovery.KeySet]().MethodByName(name); ok {
			t.Errorf("KeySet has a %s method; it is an immutable value never stopped", name)
		}
	}
	baseline := runtime.NumGoroutine()
	a := ecSigner(t, "a")
	f := newFixture(t, a)
	f.clock.advance(maxAge)
	f.verifies(t, a)
	deadline := time.Now().Add(5 * time.Second)
	for f.idp.requests() < 2 || runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("after the age refresh: %d requests, %d goroutines; want 2 and at most the baseline %d", f.idp.requests(), runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
