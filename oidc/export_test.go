package oidc

import (
	"net/http"
	"testing"
	"time"
)

// SetDefaultHTTPTimeout shortens the timeout a client without one gets, until
// t's cleanup. The caller must not run in parallel with a test that builds a
// Provider.
func SetDefaultHTTPTimeout(t testing.TB, d time.Duration) {
	old := defaultHTTPTimeout
	defaultHTTPTimeout = d
	t.Cleanup(func() { defaultHTTPTimeout = old })
}

// ProviderHTTPClient returns the client p makes its outbound calls with.
func ProviderHTTPClient(p *Provider) *http.Client { return p.cfg.HTTPClient }

// ErrResponseTooLarge is the body cap's error.
var ErrResponseTooLarge = errResponseTooLarge
