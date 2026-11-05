package access

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/cplieger/access/internal/printcheck"
)

// secretHolder is a plain struct with no printing methods of its own.
type secretHolder struct {
	Label  string
	Value  Secret
	hidden Secret
}

func TestSecretPrinting(t *testing.T) {
	t.Parallel()
	const known = "pl41n-v4lue-0451"
	s := NewSecret(known)
	h := secretHolder{Label: "lbl", Value: s, hidden: s}
	values := map[string]any{
		"value":            s,
		"pointer":          &s,
		"array":            [1]Secret{s},
		"field":            h,
		"pointer_to_field": &h,
	}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkMasked(t, v, known)
		})
	}
	t.Run("masked_bytes", func(t *testing.T) {
		t.Parallel()
		checkMaskedBytes(t, s, known)
	})
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: []string{"access.secretHolder.Label"}}, reflect.TypeFor[*secretHolder]())
	})
	session, sessionHash := GenerateSessionToken()
	opaque, opaqueHash := GenerateOpaqueToken()
	for name, tok := range map[string]Secret{"session_token": session, "opaque_token": opaque} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text := tok.Reveal()
			checkMasked(t, tok, text)
			checkMasked(t, &tok, text)
			checkMaskedBytes(t, tok, text)
		})
	}
	for name, h := range map[string]Hash{"session_hash": sessionHash, "opaque_hash": opaqueHash} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text := h.Reveal()
			checkMasked(t, h, text)
			checkMasked(t, &h, text)
			checkMaskedBytes(t, h, text)
		})
	}

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		var zero Secret
		for _, verb := range maskedVerbs {
			if got := fmt.Sprintf(verb, zero); got != "" {
				t.Errorf("Sprintf(%s, zero) = %q, want empty", verb, got)
			}
			if got := fmt.Sprintf(verb, &zero); got != "" {
				t.Errorf("Sprintf(%s, &zero) = %q, want empty", verb, got)
			}
		}
		if got := zero.LogValue().String(); got != "" {
			t.Errorf("zero.LogValue() = %q, want empty", got)
		}
		var text bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("msg", "v", zero)
		if got := text.String(); !strings.Contains(got, ` v=""`) {
			t.Errorf("slog.TextHandler = %s, want v=\"\"", got)
		}
		var js bytes.Buffer
		slog.New(slog.NewJSONHandler(&js, nil)).Info("msg", "v", zero)
		if got := js.String(); !strings.Contains(got, `"v":""`) {
			t.Errorf("slog.JSONHandler = %s, want \"v\":\"\"", got)
		}
		b, err := json.Marshal(zero)
		if err != nil {
			t.Fatalf("json.Marshal(zero) error = %v", err)
		}
		if got := string(b); got != `""` {
			t.Errorf("json.Marshal(zero) = %s, want \"\"", got)
		}
	})
}

func TestSecretReveal(t *testing.T) {
	t.Parallel()
	const known = "pl41n-v4lue-0451"
	s := NewSecret(known)
	if got := s.Reveal(); got != known {
		t.Errorf("Reveal() = %q, want %q", got, known)
	}
	if s.IsZero() {
		t.Error("IsZero() = true for a non-empty plaintext, want false")
	}
	for name, z := range map[string]Secret{"literal": {}, "empty": NewSecret("")} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !z.IsZero() {
				t.Error("IsZero() = false, want true")
			}
			if got := z.Reveal(); got != "" {
				t.Errorf("Reveal() = %q, want empty", got)
			}
		})
	}
}

func TestSecretHasNoDecoder(t *testing.T) {
	t.Parallel()
	t.Run("interfaces", func(t *testing.T) {
		t.Parallel()
		codecs := []reflect.Type{
			reflect.TypeFor[json.Unmarshaler](),
			reflect.TypeFor[encoding.TextMarshaler](),
			reflect.TypeFor[encoding.TextUnmarshaler](),
		}
		for _, typ := range []reflect.Type{
			reflect.TypeFor[Secret](), reflect.TypeFor[*Secret](),
			reflect.TypeFor[Hash](), reflect.TypeFor[*Hash](),
		} {
			for _, codec := range codecs {
				if typ.Implements(codec) {
					t.Errorf("%s implements %s", typ, codec)
				}
			}
		}
	})
	t.Run("secret", func(t *testing.T) {
		t.Parallel()
		checkNotDecoded[Secret](t, "pl41n-v4lue-0451")
	})
	t.Run("hash", func(t *testing.T) {
		t.Parallel()
		checkNotDecoded[Hash](t, "kn0wn-st0red-h4sh-0451")
	})
}

// checkNotDecoded requires that json.Unmarshal refuses a JSON string holding
// known into a T, with an error naming T and holding none of known, and that
// null and an object leave the T zero.
func checkNotDecoded[T interface{ IsZero() bool }](t *testing.T, known string) {
	t.Helper()
	name := reflect.TypeFor[T]().String()
	var v T
	err := json.Unmarshal([]byte(`"`+known+`"`), &v)
	switch {
	case err == nil:
		t.Errorf("json.Unmarshal(string) into %s error = nil, want an error", name)
	case strings.Contains(err.Error(), known):
		t.Errorf("json.Unmarshal(string) into %s error %q holds the input", name, err)
	case !strings.Contains(err.Error(), name):
		t.Errorf("json.Unmarshal(string) into %s error %q does not name the type", name, err)
	}
	if !v.IsZero() {
		t.Errorf("json.Unmarshal(string) set the %s", name)
	}
	for _, in := range []string{"null", `{"p":"` + known + `","h":"` + known + `"}`} {
		var z T
		if err := json.Unmarshal([]byte(in), &z); err != nil {
			t.Errorf("json.Unmarshal(%s) into %s error = %v", in, name, err)
		}
		if !z.IsZero() {
			t.Errorf("json.Unmarshal(%s) set the %s, want it left zero", in, name)
		}
	}
}
