package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
	"golang.org/x/sync/singleflight"
)

const (
	// maxAge is how old the cached set grows before a verify that succeeds
	// from it refreshes it, which bounds how long a retired key verifies.
	maxAge = 24 * time.Hour
	// gateInterval spaces refetch attempts, whatever starts them and
	// whatever their outcome, so unknown kids or a dead endpoint cost at
	// most one request a minute (PyJWT CVE-2026-48524, CVE-2026-101917).
	gateInterval = time.Minute
)

// ErrKeys is the error NewKeySet wraps when the fetched JWK Set is refused
// or holds no usable key.
var ErrKeys = errors.New("discovery: JWK Set refused")

// KeySet is a provider's JWK Set, fetched from its jwks_uri and cached. A
// miss refetches, an aged set refreshes, and every refetch passes one gate
// and is shared by every verify that waits for it. It starts no goroutine
// that outlives a fetch, so it is never stopped.
type KeySet struct {
	// attempted is the last refetch attempt's time. NewKeySet's fetch
	// leaves it zero, so a key rotated just after start refetches at once.
	attempted time.Time
	group     singleflight.Group
	cur       atomic.Pointer[snapshot]
	client    *http.Client
	logger    *slog.Logger
	now       func() time.Time
	uri       string
	logURI    string
	algs      []jwk.Alg
	mu        sync.Mutex
	// inflight is true from a refetch's start until after it stores its
	// set. The call clears it and forgets its key in one k.mu section, so
	// a DoChan under k.mu joins a running call exactly when inflight is
	// true, and a miss that sees it false sees the set the call stored.
	inflight bool
}

type snapshot struct {
	fetched time.Time
	keys    jwk.Set
}

// NewKeySet fetches doc.JWKSURI through a copy of client that follows no
// redirect; client's Timeout bounds every fetch. It fails with ErrFetch or
// ErrKeys. now is the provider's clock, which the set's age and the gate
// read; logger, nil meaning slog.Default() at each call, receives the
// WARNs for a failed refetch and for two keys of one kid that fit one of
// doc.Algs.
func NewKeySet(ctx context.Context, client *http.Client, doc Document, now func() time.Time, logger *slog.Logger) (*KeySet, error) {
	k := &KeySet{client: client, logger: logger, now: now, uri: doc.JWKSURI, logURI: withoutQuery(doc.JWKSURI), algs: slices.Clone(doc.Algs)}
	s, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	k.cur.Store(s)
	return k, nil
}

// Verify returns t's payload under the first key of the set that fits it
// and verifies its signature (jws.Token.Verify), refetching the set once,
// through the gate, on a miss. It returns jws.ErrNoKey when no key
// verifies after that, or ctx's error when ctx ends while it waits.
func (k *KeySet) Verify(ctx context.Context, t *jws.Token) ([]byte, error) {
	seen := k.cur.Load()
	if p, err := t.Verify(seen.keys); err == nil {
		k.refreshIfAged(ctx, seen.fetched)
		return p, nil
	}
	for {
		newer, wait := k.afterMiss(ctx, seen)
		switch {
		case newer != nil:
			if p, err := t.Verify(newer.keys); err == nil {
				return p, nil
			}
			seen = newer
		case wait != nil:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
			}
			return t.Verify(k.cur.Load().keys)
		default:
			return nil, jws.ErrNoKey
		}
	}
}

// afterMiss decides what a miss under seen does next, in this order: a set
// stored since seen is returned to re-verify against; a refetch in flight
// is joined, whatever started it; otherwise an open gate starts one. Both
// nil means the miss is final.
func (k *KeySet) afterMiss(ctx context.Context, seen *snapshot) (newer *snapshot, wait <-chan singleflight.Result) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cur := k.cur.Load(); cur != seen {
		return cur, nil
	}
	if k.inflight {
		return nil, k.group.DoChan("", k.refetch(ctx))
	}
	now := k.now()
	if !due(now, k.attempted, gateInterval) {
		return nil, nil
	}
	return nil, k.start(ctx, now)
}

// refreshIfAged starts a refetch, not waited for, when a set fetched at
// fetched is due its refresh and the gate is open.
func (k *KeySet) refreshIfAged(ctx context.Context, fetched time.Time) {
	now := k.now()
	if !due(now, fetched, maxAge) {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if due(now, k.attempted, gateInterval) {
		k.start(ctx, now)
	}
}

// start runs one refetch, or joins the one in flight, with k.mu held. Its
// result channel has room for the result, so a caller may drop it.
func (k *KeySet) start(ctx context.Context, now time.Time) <-chan singleflight.Result {
	k.attempted, k.inflight = now, true
	return k.group.DoChan("", k.refetch(ctx))
}

// refetch is the shared call. It runs under context.WithoutCancel, so the
// waiter that started it leaving fails no other waiter.
func (k *KeySet) refetch(ctx context.Context) func() (any, error) {
	return func() (any, error) {
		s, err := k.fetch(context.WithoutCancel(ctx))
		if err == nil {
			k.cur.Store(s)
		} else {
			k.log().Warn("access/oidc: JWKS refetch failed; the cached key set stays in use", "jwks", k.logURI, "err", err)
		}
		k.mu.Lock()
		k.inflight = false
		k.group.Forget("")
		k.mu.Unlock()
		return nil, nil
	}
}

func (k *KeySet) fetch(ctx context.Context) (*snapshot, error) {
	body, err := get(ctx, k.client, k.uri)
	if err != nil {
		return nil, err
	}
	keys, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeys, err)
	}
	if keys.Len() == 0 {
		return nil, fmt.Errorf("%w: no usable key", ErrKeys)
	}
	for _, kid := range k.sharedKIDs(keys) {
		k.log().Warn("access/oidc: two JWKS keys share a kid and fit one algorithm; both are tried", "jwks", k.logURI, "kid", kid)
	}
	return &snapshot{keys: keys, fetched: k.now()}, nil
}

// sharedKIDs is each kid two keys carry while both fit one of the
// provider's rows (RFC 7517 §4.5 allows a shared kid).
func (k *KeySet) sharedKIDs(keys jwk.Set) []string {
	all := slices.Collect(keys.All())
	var kids []string
	for i, a := range all {
		kid, ok := a.KeyID()
		if !ok || slices.Contains(kids, kid) {
			continue
		}
		if slices.ContainsFunc(all[i+1:], func(b jwk.Key) bool {
			other, ok := b.KeyID()
			return ok && other == kid && k.fitTogether(a, b)
		}) {
			kids = append(kids, kid)
		}
	}
	return kids
}

func (k *KeySet) fitTogether(a, b jwk.Key) bool {
	return slices.ContainsFunc(k.algs, func(alg jwk.Alg) bool { return a.Fits(alg) && b.Fits(alg) })
}

func (k *KeySet) log() *slog.Logger {
	if k.logger != nil {
		return k.logger
	}
	return slog.Default()
}

// due reports whether interval has passed since then, or now reads before
// then: the provider's clock may carry no monotonic reading, so a clock
// that steps back opens the age and the gate rather than shutting them for
// the length of the step.
func due(now, then time.Time, interval time.Duration) bool {
	return now.Sub(then) >= interval || now.Before(then)
}

// withoutQuery is the URL a WARN names: a jwks_uri's query may carry a
// secret.
func withoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}
