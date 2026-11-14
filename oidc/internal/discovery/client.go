package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// noRedirect copies c with a CheckRedirect that hands back every redirect
// unfollowed, so the caller's policy is never asked and the answer is
// refused as a non-200. The transport, and with it the caller's body cap,
// guard and dialer, is kept.
func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// get fetches target through a no-redirect copy of c. Only a 200 answer's
// body is read (Discovery 1.0 §4.2); every error wraps ErrFetch.
func get(ctx context.Context, c *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	resp, err := noRedirect(c).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: answer %d, want 200", ErrFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	return body, nil
}
