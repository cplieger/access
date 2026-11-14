// Package jsonmember reads JSON documents member by member, by each
// member's JSON kind (RFC 8259).
//
// Object decodes with encoding/json/v2 at its defaults, which refuses
// duplicate names and invalid UTF-8 at every depth, unread members
// included, and bounds the nesting (RFC 8259 §4, §8.1). A member is then
// read by its kind, never by decoding into a Go type, since json/v2 decodes
// null into a string, number or bool as the zero value with no error. So a
// null member is the wrong kind; a caller that reads null as absent checks
// for it itself.
package jsonmember

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
)

// Object decodes data as one JSON object, its members' values kept as JSON
// text. Any other document, null included, is an error.
func Object(data []byte) (map[string]jsontext.Value, error) {
	if jsontext.Value(data).Kind() != '{' {
		return nil, errors.New("jsonmember: not a JSON object")
	}
	var m map[string]jsontext.Value
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Array reads v, a value from Object, as a JSON array; ok is false for any
// other kind.
func Array(v jsontext.Value) (vals []jsontext.Value, ok bool) {
	if v.Kind() != '[' || json.Unmarshal(v, &vals) != nil {
		return nil, false
	}
	return vals, true
}

// String reads member name of m as a JSON string; ok is false when it is
// absent or of another kind, null included.
func String(m map[string]jsontext.Value, name string) (s string, ok bool) {
	v, found := m[name]
	if !found || v.Kind() != '"' || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// Strings reads v as a JSON array whose every entry is a string; ok is
// false for any other value, an array holding a null included.
func Strings(v jsontext.Value) ([]string, bool) {
	vals, ok := Array(v)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(vals))
	for _, e := range vals {
		var s string
		if e.Kind() != '"' || json.Unmarshal(e, &s) != nil {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
