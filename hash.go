package access

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Hash holds a stored credential hash: a PHC Argon2id string, or the hex
// SHA-256 of a session token, an API key or a one-time token. Every printing
// route (fmt verbs, slog, encoding/json, reflection) renders "[redacted]",
// masked bytes or an address, or "" for the zero value; only Reveal returns
// the text. == does not compile on a Hash: compare with Equal, and key an
// in-memory map on Key. Hash has no decoder: a store writes Reveal() and
// reads with NewHash.
type Hash struct {
	_ [0]func()
	h *masked
}

// NewHash wraps encoded. NewHash("") is the zero Hash.
func NewHash(encoded string) Hash { return Hash{h: mask(encoded)} }

// Reveal returns the text, or "" for the zero value.
func (h Hash) Reveal() string { return h.h.open() }

// IsZero reports whether h holds no text.
func (h Hash) IsZero() bool { return h.h == nil }

// Equal reports, in constant time for any two values, whether h and o hold
// the same text: it compares two fixed-size 32-byte tags, never the texts.
// Two zero values are equal, and a zero value equals no other.
func (h Hash) Equal(o Hash) bool { return maskedEqual(h.h, o.h) }

// HashKey is a Hash's comparable form: equal texts give equal keys within
// the process, so it is a valid map key, and == on it is a fixed-size
// compare. It reveals nothing a reflective printer of the Hash does not
// already show. A non-zero key is valid only in the process that made it: a
// durable index keys on Reveal().
type HashKey [32]byte

// Key returns h's HashKey, the masked value's tag; the zero Hash gives the
// zero HashKey.
func (h Hash) Key() HashKey { return h.h.tag() }

func (h Hash) render() string {
	if h.IsZero() {
		return ""
	}
	return redacted
}

// Format writes "[redacted]", or nothing for the zero value, for every verb
// fmt routes to it.
func (h Hash) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, h.render()) }

// LogValue returns the redacted rendering as a string value.
func (h Hash) LogValue() slog.Value { return slog.StringValue(h.render()) }

// MarshalJSON encodes the redacted rendering as a JSON string.
func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.render()) }
