// Package bodycap caps every response body an http.Client reads at
// MaxBytes, whatever length the response declares.
package bodycap

import (
	"errors"
	"io"
	"net/http"
)

// MaxBytes is the most a capped body hands out.
const MaxBytes = 1 << 20

// ErrTooLarge is the error a capped body fails with once it holds a byte
// past MaxBytes.
var ErrTooLarge = errors.New("oidc: response body larger than 1 MiB")

// Transport caps the response body, not the dial, so it sits outside an
// SSRF-guarding transport without weakening it.
type Transport struct{ Next http.RoundTripper }

// RoundTrip answers Next's response with its body capped.
func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body}
	return resp, nil
}

// cappedBody hands out at most MaxBytes and fails with ErrTooLarge once the body
// holds a byte beyond them, reading at most that one byte past the cap. The
// error that ends the body at the cap is returned by every later Read.
type cappedBody struct {
	rc  io.ReadCloser
	err error
	n   int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if room := MaxBytes - b.n; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.rc.Read(p)
	b.n += int64(n)
	if b.n == MaxBytes {
		if err == nil {
			// x/oauth2 reads the token body through its own 1 MiB limit and
			// never asks for the byte past the cap, so it is looked for now:
			// https://github.com/golang/oauth2/blob/v0.37.0/internal/token.go#L263
			err = b.pastCap()
		}
		b.err = err
	}
	return n, err
}

// pastCap reads one byte past the cap: ErrTooLarge when there is one, else
// the body's own end or error, or io.ErrNoProgress after maxEmptyReads
// reads of no byte and no error.
func (b *cappedBody) pastCap() error {
	var one [1]byte
	for range maxEmptyReads {
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return ErrTooLarge
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

// maxEmptyReads bounds pastCap's consecutive empty reads, so a body that
// answers no byte and no error forever cannot hang the read.
const maxEmptyReads = 100

func (b *cappedBody) Close() error { return b.rc.Close() }
