package accesshttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

// maxBodyBytes caps every JSON body (WebAuthn finish bodies have their own
// cap, webauthn.MaxResponseBytes).
const maxBodyBytes = 4 << 10

// secretFields are the request keys that hold a password or a token. The
// decoder never reports them missing: the handler wraps each in a Secret,
// and an empty one is account's or the handler's refusal to name.
var secretFields = map[string]bool{"password": true, "token": true, "current_password": true}

// decodeJSON decodes r's body strictly into a T. Its errors are a
// *http.MaxBytesError or a requestError whose reason names a field, never
// encoding/json's text, which quotes a mistyped value.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var v T
	data, err := readBody(w, r, maxBodyBytes)
	if err != nil {
		return v, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&v); err != nil {
		return v, decodeRefusal(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return v, badRequest(ReasonTrailingData)
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(data, &present); err != nil {
		return v, badRequest(ReasonMalformedJSON)
	}
	return v, checkFields(reflect.TypeFor[T](), present)
}

// readBody reads r's JSON body whole, refusing another Content-Type and a
// body past limit with its *http.MaxBytesError.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, badRequest(ReasonContentType)
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			return nil, err
		}
		return nil, badRequest(ReasonBody)
	}
	return data, nil
}

// readCredential reads a WebAuthn finish body before account sees it, so an
// overlong one is refused before its ceremony is spent or anything parses.
func readCredential(w http.ResponseWriter, r *http.Request) (io.Reader, error) {
	data, err := readBody(w, r, webauthn.MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// decodeRefusal names what the decoder refused without its error text.
func decodeRefusal(err error) error {
	if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		if te.Field == "" {
			return badRequest(ReasonBody)
		}
		return badRequest(te.Field)
	}
	return badRequest(ReasonMalformedJSON)
}

// checkFields refuses a key that is not exactly a field's JSON name (the
// decoder matches names case-insensitively) and a missing required field:
// one without omitempty that is not a secret field.
func checkFields(t reflect.Type, present map[string]json.RawMessage) error {
	names := make(map[string]string, t.NumField())
	for f := range t.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		names[name] = opts
	}
	for key := range present {
		if _, ok := names[key]; !ok {
			return badRequest(ReasonUnknownField)
		}
	}
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if _, ok := present[name]; !ok && !strings.Contains(names[name], "omitempty") && !secretFields[name] {
			return badRequest(name)
		}
	}
	return nil
}

// requireSecret wraps a decoded password or token field; an empty one is
// the missing field named by key.
func requireSecret(key, value string) (access.Secret, error) {
	if value == "" {
		return access.Secret{}, badRequest(key)
	}
	return access.NewSecret(value), nil
}

// sessionIDLen is a session ID's length: 128 random bits in lowercase hex.
const sessionIDLen = 32

// pathValues parses s's path value into c, or refuses it.
func pathValues(s *routeSpec, r *http.Request, c *call) error {
	key := s.pathID.key()
	switch s.pathID {
	case pathInt:
		id, ok := positiveDecimal(r.PathValue(key))
		if !ok {
			return badRequest(key)
		}
		c.id = id
	case pathSession:
		id := r.PathValue(key)
		if len(id) != sessionIDLen || strings.Trim(id, "0123456789abcdef") != "" {
			return badRequest(key)
		}
		c.sessionID = id
	case pathMethod:
		switch m := access.Method(r.PathValue(key)); m {
		case access.MethodPassword, access.MethodPasskey, access.MethodOIDC:
			c.method = m
		default:
			return badRequest(key)
		}
	default:
	}
	return nil
}
