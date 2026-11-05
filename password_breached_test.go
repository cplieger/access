package access

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/cplieger/access/internal/capture"
)

// hibpFake stands up the Have I Been Pwned range endpoint on httptest's
// in-memory network (Go 1.27). Its client routes the hardcoded
// https://api.pwnedpasswords.com/range/... URL straight to the handler with
// the Host, path and headers intact, so the handler sees the request the
// library built.
type hibpFake struct {
	respByPrefix  map[string]string
	gotHost       string
	gotPath       string
	gotAddPadding string
}

func newHibpFake(t *testing.T, respByPrefix map[string]string) (*http.Client, *hibpFake) {
	t.Helper()
	f := &hibpFake{respByPrefix: respByPrefix}
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotHost, f.gotPath = r.Host, r.URL.Path
		f.gotAddPadding = r.Header.Get("Add-Padding")
		body, ok := f.respByPrefix[strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/range/"))]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	return srv.Client(), f
}

func hibpRange(password string) (prefix, suffix string) {
	hexStr := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	return hexStr[:5], hexStr[5:]
}

func TestCheckBreachedPassword_sets_add_padding_header(t *testing.T) {
	t.Parallel()
	prefix, _ := hibpRange("anything")
	client, fake := newHibpFake(t, map[string]string{prefix: ""})

	_, _ = CheckBreachedPassword(t.Context(), client, "anything")

	if fake.gotAddPadding != "true" {
		t.Errorf("Add-Padding = %q, want %q", fake.gotAddPadding, "true")
	}
	// Only the 5-hex-character prefix may leave the process, never the full SHA-1.
	if fake.gotHost != "api.pwnedpasswords.com" {
		t.Errorf("outbound Host = %q, want %q", fake.gotHost, "api.pwnedpasswords.com")
	}
	if want := "/range/" + prefix; fake.gotPath != want {
		t.Errorf("outbound path = %q, want %q (only the 5-char prefix, never the full hash)", fake.gotPath, want)
	}
}

func TestCheckBreachedPassword_filters_zero_count_padding(t *testing.T) {
	t.Parallel()
	password := "MySecretPassword!"
	prefix, suffix := hibpRange(password)

	body := suffix + ":0\nDEADBEEF" + strings.Repeat("0", len(suffix)-8) + ":7\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("count=0 treated as breach")
	}
}

func TestCheckBreachedPassword_real_hit(t *testing.T) {
	t.Parallel()
	password := "Password123!"
	prefix, suffix := hibpRange(password)

	client, _ := newHibpFake(t, map[string]string{prefix: suffix + ":42\n"})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Error("real hit not detected")
	}
}

func TestCheckBreachedPassword_normalizesToNFC(t *testing.T) {
	t.Parallel()
	composed := strings.Repeat("caf\u00e9", 4)
	prefix, suffix := hibpRange(composed)
	client, _ := newHibpFake(t, map[string]string{prefix: suffix + ":9\n"})

	for _, password := range []string{composed, strings.Repeat("cafe\u0301", 4)} {
		breached, err := CheckBreachedPassword(t.Context(), client, password)
		if err != nil || !breached {
			t.Errorf("CheckBreachedPassword(%q) = (%v, %v), want (true, nil)", password, breached, err)
		}
	}
}

func TestCheckBreachedPassword_no_match(t *testing.T) {
	t.Parallel()
	password := "UntestedPassword99"
	prefix, _ := hibpRange(password)

	body := "DEADBEEFCAFE0000111122223333444455556666:5\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("no-match treated as breach")
	}
}

func TestCheckBreachedPassword_skipsMalformedCountLine(t *testing.T) {
	t.Parallel()
	password := "Some-Password-99"
	prefix, suffix := hibpRange(password)

	for _, count := range []string{"not-a-number", "-1"} {
		t.Run(count, func(t *testing.T) {
			t.Parallel()
			client, _ := newHibpFake(t, map[string]string{prefix: suffix + ":" + count + "\n"})

			breached, err := CheckBreachedPassword(t.Context(), client, password)
			if err != nil {
				t.Fatalf("CheckBreachedPassword error = %v, want nil", err)
			}
			if breached {
				t.Errorf("count %q treated as a breach, want not-breached", count)
			}
		})
	}
}

// TestCheckBreachedPassword_bodyAtCap reads a range response of exactly
// 2 MiB whose only hit is its last line, so a cap that truncated or refused
// it would miss the breach.
func TestCheckBreachedPassword_bodyAtCap(t *testing.T) {
	t.Parallel()
	password := "Body-At-The-Cap-Password"
	prefix, suffix := hibpRange(password)
	hit := suffix + ":3\n"
	pad := strings.Repeat("0", len(suffix)) + ":0\n"
	var b strings.Builder
	for b.Len()+len(pad) <= hibpMaxBody-len(hit) {
		b.WriteString(pad)
	}
	b.WriteString(strings.Repeat("\n", hibpMaxBody-len(hit)-b.Len()))
	b.WriteString(hit)
	if b.Len() != hibpMaxBody {
		t.Fatalf("fixture body is %d bytes, want %d", b.Len(), hibpMaxBody)
	}
	client, _ := newHibpFake(t, map[string]string{prefix: b.String()})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil || !breached {
		t.Fatalf("CheckBreachedPassword(2 MiB body) = (%v, %v), want (true, nil)", breached, err)
	}
}

func TestCheckBreachedPassword_doesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		header := http.Header{"Location": {"https://redirect.invalid/capture"}}
		return &http.Response{StatusCode: http.StatusFound, Header: header, Body: http.NoBody, Request: r}, nil
	})}

	breached, err := CheckBreachedPassword(t.Context(), client, "redirected-check-password")

	if breached || !errors.Is(err, ErrBreachCheckUnavailable) || !strings.Contains(err.Error(), "status 302") {
		t.Errorf("CheckBreachedPassword(302) = (%v, %v), want (false, an ErrBreachCheckUnavailable naming status 302)", breached, err)
	}
	if len(requests) != 1 {
		t.Errorf("requests = %q, want only the range request", requests)
	}
	if client.CheckRedirect != nil {
		t.Error("CheckBreachedPassword set CheckRedirect on the caller's client")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func blockUntilDone(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func newStatusClient(t *testing.T, status int, body string) *http.Client {
	t.Helper()
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	return srv.Client()
}

// TestCheckBreachedPassword holds every arm that gets no verdict. Each
// returns false and ErrBreachCheckUnavailable, its error text names its cause
// and neither the API's URL nor the password's hash prefix, and nothing is
// logged. The capture swaps the process logger, so the cases run serially.
func TestCheckBreachedPassword(t *testing.T) {
	const password = "unavailable-check-password"
	prefix, _ := hibpRange(password)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	cases := []struct {
		name   string
		client func(t *testing.T) *http.Client
		ctx    func(t *testing.T) context.Context
		cause  string
	}{
		{
			name:   "nil client",
			client: func(*testing.T) *http.Client { return nil },
			cause:  "no HTTP client",
		},
		{
			name:   "context deadline",
			client: func(*testing.T) *http.Client { return &http.Client{Transport: roundTripFunc(blockUntilDone)} },
			ctx:    func(t *testing.T) context.Context { return timeoutCtx(t, 20*time.Millisecond) },
			cause:  "request timed out",
		},
		{
			name: "client timeout",
			client: func(*testing.T) *http.Client {
				return &http.Client{Timeout: 20 * time.Millisecond, Transport: roundTripFunc(blockUntilDone)}
			},
			cause: "request timed out",
		},
		{
			name:   "context cancelled",
			client: func(*testing.T) *http.Client { return &http.Client{Transport: roundTripFunc(blockUntilDone)} },
			ctx:    func(*testing.T) context.Context { return cancelled },
			cause:  "request failed",
		},
		{
			name: "transport error",
			client: func(*testing.T) *http.Client {
				return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("dial tcp: connection refused")
				})}
			},
			cause: "request failed",
		},
		{
			name: "transport timeout",
			client: func(*testing.T) *http.Client {
				return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, timeoutNetError{}
				})}
			},
			cause: "request timed out",
		},
		{
			name:   "500 status",
			client: func(t *testing.T) *http.Client { return newStatusClient(t, http.StatusInternalServerError, "") },
			cause:  "unexpected status 500",
		},
		{
			name:   "429 status",
			client: func(t *testing.T) *http.Client { return newStatusClient(t, http.StatusTooManyRequests, "") },
			cause:  "unexpected status 429",
		},
		{
			name: "body over 2 MiB",
			client: func(t *testing.T) *http.Client {
				return newStatusClient(t, http.StatusOK, strings.Repeat("0", hibpMaxBody+1))
			},
			cause: "response over 2 MiB",
		},
		{
			name:   "read error",
			client: func(*testing.T) *http.Client { return bodyErrClient(errors.New("connection reset by peer")) },
			cause:  "reading the response failed",
		},
		{
			name:   "body read timeout",
			client: func(*testing.T) *http.Client { return bodyErrClient(timeoutNetError{}) },
			cause:  "reading the response timed out",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := capture.Default(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}

			breached, err := CheckBreachedPassword(ctx, tc.client(t), password)

			if breached {
				t.Error("breached = true, want false")
			}
			if !errors.Is(err, ErrBreachCheckUnavailable) {
				t.Fatalf("err = %v, want ErrBreachCheckUnavailable", err)
			}
			if !strings.Contains(err.Error(), tc.cause) {
				t.Errorf("err = %q, want it to name %q", err, tc.cause)
			}
			for _, leak := range []string{"pwnedpasswords", "/range/", prefix} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("err = %q, holds %q", err, leak)
				}
			}
			if n := rec.CountMsg(""); n != 0 {
				t.Errorf("CheckBreachedPassword logged %d records, want none", n)
			}
		})
	}
}

// TestBreachErrorWrapsContext checks that the error wraps the caller's
// context error exactly when that context ended, whichever step it ended in,
// and that a non-200 body is drained up to 4 KiB before it is closed.
func TestBreachErrorWrapsContext(t *testing.T) {
	t.Parallel()
	const password = "context-check-password"
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	blocking := func(*testing.T) *http.Client { return &http.Client{Transport: roundTripFunc(blockUntilDone)} }
	noCtx := func(t *testing.T) context.Context { return t.Context() }

	cases := []struct {
		name    string
		client  func(t *testing.T) *http.Client
		ctx     func(t *testing.T) context.Context
		wantCtx error // nil: the error wraps neither context error
	}{
		{"cancelled context", blocking, func(*testing.T) context.Context { return cancelled }, context.Canceled},
		{"expired deadline", blocking, func(t *testing.T) context.Context { return timeoutCtx(t, 20*time.Millisecond) }, context.DeadlineExceeded},
		{"deadline during the body read", func(*testing.T) *http.Client {
			return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := io.NopCloser(blockingReader{r.Context()})
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
			})}
		}, func(t *testing.T) context.Context { return timeoutCtx(t, 20*time.Millisecond) }, context.DeadlineExceeded},
		{"client timeout", func(*testing.T) *http.Client {
			return &http.Client{Timeout: 20 * time.Millisecond, Transport: roundTripFunc(blockUntilDone)}
		}, noCtx, nil},
		{"transport timeout", func(*testing.T) *http.Client {
			return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutNetError{} })}
		}, noCtx, nil},
		{"500 status", func(t *testing.T) *http.Client { return newStatusClient(t, http.StatusInternalServerError, "") }, noCtx, nil},
		{"body over 2 MiB", func(t *testing.T) *http.Client {
			return newStatusClient(t, http.StatusOK, strings.Repeat("0", hibpMaxBody+1))
		}, noCtx, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := CheckBreachedPassword(tc.ctx(t), tc.client(t), password)

			if !errors.Is(err, ErrBreachCheckUnavailable) {
				t.Fatalf("err = %v, want ErrBreachCheckUnavailable", err)
			}
			for _, ctxErr := range []error{context.Canceled, context.DeadlineExceeded} {
				if got, want := errors.Is(err, ctxErr), ctxErr == tc.wantCtx; got != want {
					t.Errorf("errors.Is(%q, %v) = %v, want %v", err, ctxErr, got, want)
				}
			}
			for _, leak := range []string{"https://", "pwnedpasswords", "/range/"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("err = %q, holds %q", err, leak)
				}
			}
		})
	}

	t.Run("a non-200 body is drained up to 4 KiB", func(t *testing.T) {
		t.Parallel()
		body := &countingBody{r: strings.NewReader(strings.Repeat("x", 64<<10))}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: body, Header: make(http.Header)}, nil
		})}

		_, err := CheckBreachedPassword(t.Context(), client, password)

		if !errors.Is(err, ErrBreachCheckUnavailable) {
			t.Errorf("err = %v, want ErrBreachCheckUnavailable", err)
		}
		if body.read != 4<<10 {
			t.Errorf("read %d bytes of the 500's body, want the 4096-byte drain", body.read)
		}
		if !body.closed {
			t.Error("the 500's body was not closed")
		}
	})
}

// blockingReader blocks a body read until ctx ends, then returns its error.
type blockingReader struct{ ctx context.Context }

func (b blockingReader) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

type countingBody struct {
	r      io.Reader
	read   int
	closed bool
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error {
	c.closed = true
	return nil
}

// timeoutNetError is a timeout with no Is(context.DeadlineExceeded), as
// net/http's TLS handshake timeout is.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "net/http: TLS handshake timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func bodyErrClient(err error) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := io.NopCloser(iotest.ErrReader(err))
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})}
}

func timeoutCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}
