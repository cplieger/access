package access

import (
	"strings"
	"testing"
	"time"
)

// mustAuthenticator builds an Authenticator and fails the test if the
// configuration is rejected. Tests of a rejected config call New directly. It
// takes testing.TB so benchmarks can use it too.
func mustAuthenticator(tb testing.TB, store AuthenticatorStore, cfg Config) *Authenticator {
	tb.Helper()
	a, err := New(store, cfg)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return a
}

// TestNewRefusesNil pins one nil rule over both interface inputs: a nil
// interface, or one holding a nil pointer, map, slice, func or chan.
func TestNewRefusesNil(t *testing.T) {
	t.Parallel()
	store := newFakeSessionStore()
	for _, tt := range []struct {
		store AuthenticatorStore
		cfg   Config
		name  string
		input string
	}{
		{name: "nil store", input: "AuthenticatorStore"},
		{name: "typed-nil store", store: (*fakeSessionStore)(nil), input: "AuthenticatorStore"},
		{name: "typed-nil recording store", store: (*recordingStore)(nil), input: "AuthenticatorStore"},
		{name: "typed-nil pointer verifier", store: store, cfg: Config{Verifier: (*agentVerifier)(nil)}, input: "Verifier"},
		{name: "nil func verifier", store: store, cfg: Config{Verifier: verifierFunc(nil)}, input: "Verifier"},
		{name: "nil map verifier", store: store, cfg: Config{Verifier: verifierMap(nil)}, input: "Verifier"},
		{name: "nil slice verifier", store: store, cfg: Config{Verifier: verifierSlice(nil)}, input: "Verifier"},
		{name: "nil chan verifier", store: store, cfg: Config{Verifier: verifierChan(nil)}, input: "Verifier"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, err := New(tt.store, tt.cfg)
			if a != nil {
				t.Errorf("New = %p, want a nil *Authenticator", a)
			}
			if err == nil || !strings.Contains(err.Error(), "nil "+tt.input) {
				t.Errorf("New error = %v, want one naming the nil %s", err, tt.input)
			}
		})
	}
	t.Run("nil verifier is none", func(t *testing.T) {
		t.Parallel()
		a, err := New(store, Config{Verifier: nil})
		if err != nil || a == nil {
			t.Fatalf("New(valid store, nil Verifier) = (%p, %v), want an Authenticator", a, err)
		}
		if len(a.chain) != 2 {
			t.Errorf("chain holds %d verifiers, want the 2 built-in ones", len(a.chain))
		}
	})
}

func TestNewRefusesUnusableConfig(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "throttle equal to idle", cfg: Config{IdleTimeout: time.Hour, ActivityThrottle: time.Hour}, want: "must be less than the idle timeout"},
		{name: "throttle at the default idle", cfg: Config{ActivityThrottle: DefaultIdleTimeout}, want: "must be less than the idle timeout"},
		{name: "negative throttle", cfg: Config{ActivityThrottle: -time.Second}, want: "activity throttle must not be negative"},
		{name: "negative absolute timeout", cfg: Config{AbsTimeout: -time.Hour}, want: "absolute timeout must be positive"},
		// A negative idle timeout survives the zero-only default and would
		// expire every session at once.
		{name: "negative idle timeout", cfg: Config{IdleTimeout: -time.Second}, want: "idle timeout must be positive"},
		// Browsers refuse a __Host- cookie with a Domain.
		{name: "invalid cookie", cfg: Config{Cookie: CookieConfig{Domain: "example.com"}}, want: "CookieConfig.Domain must be empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, err := New(newFakeSessionStore(), tt.cfg)
			if err == nil || a != nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("New = (%p, %v), want (nil, an error containing %q)", a, err, tt.want)
			}
		})
	}
	t.Run("throttle just below idle", func(t *testing.T) {
		t.Parallel()
		if _, err := New(newFakeSessionStore(), Config{IdleTimeout: time.Hour, ActivityThrottle: time.Hour - time.Nanosecond}); err != nil {
			t.Errorf("New error = %v, want nil", err)
		}
	})
}
