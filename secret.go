package access

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Secret holds a plaintext credential. Every printing route (fmt verbs,
// slog, encoding/json, reflection) renders "[redacted]", masked bytes or an
// address, or "" for the zero value; only Reveal returns the text. The
// plaintext is never held in clear, so a printer walking any holder's
// fields by reflection (%p of a struct value, go-cmp, go-spew) finds only
// masked bytes. == does not compile on a Secret. A Secret is not a wire or
// storage type and has no decoder: a caller converts at its seam, with
// NewSecret on a decoded string and Reveal on the way out.
type Secret struct {
	_ [0]func()
	p *masked
}

// NewSecret wraps plaintext. NewSecret("") is the zero Secret.
func NewSecret(plaintext string) Secret { return Secret{p: mask(plaintext)} }

// Reveal returns the plaintext, or "" for the zero value.
func (s Secret) Reveal() string { return s.p.open() }

// IsZero reports whether s holds no plaintext.
func (s Secret) IsZero() bool { return s.p == nil }

func (s Secret) render() string {
	if s.IsZero() {
		return ""
	}
	return redacted
}

// Format writes "[redacted]", or nothing for the zero value, for every verb
// fmt routes to it.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.render())
}

// LogValue returns the redacted rendering as a string value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.render()) }

// MarshalJSON encodes the redacted rendering as a JSON string, which
// nothing decodes.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.render()) }
