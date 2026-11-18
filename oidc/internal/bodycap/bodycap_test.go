package bodycap

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

// stubTransport answers every request with its body and declared length.
type stubTransport struct {
	body   []byte
	length int64
}

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(s.body)), ContentLength: s.length}, nil
}

type stalledTransport struct{}

func (stalledTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&stalledBody{left: MaxBytes}), ContentLength: -1}, nil
}

type stalledBody struct{ left int }

func (s *stalledBody) Read(p []byte) (int, error) {
	n := min(len(p), s.left)
	s.left -= n
	return n, nil
}

// countingBody counts the bytes read through the cap from the body below it.
type countingBody struct {
	io.ReadCloser
	n *int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	*c.n += int64(n)
	return n, err
}

func TestTransport(t *testing.T) {
	t.Parallel()
	// open returns a body through the cap and the count of bytes the cap has
	// pulled from the body below it.
	open := func(t *testing.T, body []byte, length int64) (io.ReadCloser, *int64) {
		t.Helper()
		resp, err := Transport{Next: stubTransport{body: body, length: length}}.RoundTrip(&http.Request{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		pulled := new(int64)
		capped := resp.Body.(*cappedBody)
		capped.rc = countingBody{ReadCloser: capped.rc, n: pulled}
		return capped, pulled
	}
	// get reads a body through the cap, under a consumer's own 1 MiB limit
	// when limited (cappedBody.Read).
	get := func(t *testing.T, body []byte, length int64, limited bool) (got []byte, pulled int64, err error) {
		t.Helper()
		rc, n := open(t, body, length)
		var r io.Reader = rc
		if limited {
			r = io.LimitReader(r, MaxBytes)
		}
		got, err = io.ReadAll(r)
		return got, *n, err
	}
	big := bytes.Repeat([]byte{'x'}, 2<<20)
	for _, tc := range []struct {
		name    string
		length  int64
		limited bool
	}{
		{name: "declared_over_cap", length: int64(len(big))},
		{name: "undeclared_over_cap", length: -1},
		{name: "declared_over_cap_under_consumer_limit", length: int64(len(big)), limited: true},
		{name: "undeclared_over_cap_under_consumer_limit", length: -1, limited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, pulled, err := get(t, big, tc.length, tc.limited)
			if !errors.Is(err, ErrTooLarge) {
				t.Errorf("reading a 2 MiB body = %v, want ErrTooLarge", err)
			}
			if len(got) > MaxBytes {
				t.Errorf("handed out %d bytes, want at most %d", len(got), MaxBytes)
			}
			if pulled > MaxBytes+1 {
				t.Errorf("pulled %d bytes from the transport, want at most %d", pulled, MaxBytes+1)
			}
		})
	}
	t.Run("empty_reads_at_cap_under_consumer_limit", func(t *testing.T) {
		t.Parallel()
		resp, err := Transport{Next: stalledTransport{}}.RoundTrip(&http.Request{})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes)); !errors.Is(err, io.ErrNoProgress) {
			t.Errorf("a body that answers nothing at the cap = %v, want io.ErrNoProgress", err)
		}
	})
	t.Run("verdict_sticky", func(t *testing.T) {
		t.Parallel()
		for _, size := range []int{MaxBytes + 1, MaxBytes + 3} {
			body, pulled := open(t, big[:size], -1)
			if _, err := io.ReadAll(body); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("reading a %d-byte body = %v, want ErrTooLarge", size, err)
			}
			for i := range 3 {
				if n, err := body.Read(make([]byte, 8)); n != 0 || !errors.Is(err, ErrTooLarge) {
					t.Errorf("a %d-byte body, read %d after the refusal = %d, %v; want 0, ErrTooLarge", size, i+1, n, err)
				}
			}
			if *pulled != MaxBytes+1 {
				t.Errorf("a %d-byte body: pulled %d bytes from the transport, want %d", size, *pulled, MaxBytes+1)
			}
		}
	})
	t.Run("at_cap", func(t *testing.T) {
		t.Parallel()
		for _, length := range []int64{MaxBytes, -1} {
			for _, limited := range []bool{false, true} {
				got, _, err := get(t, big[:MaxBytes], length, limited)
				if err != nil || len(got) != MaxBytes {
					t.Errorf("a 1 MiB body declared %d, limited %t: read %d bytes, %v; want all of it", length, limited, len(got), err)
				}
			}
		}
	})
}
