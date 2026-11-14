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
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"time"
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

// String reads v as a JSON string; ok is false for any other kind, null
// included, and for an absent member's nil value.
func String(v jsontext.Value) (s string, ok bool) {
	if v.Kind() != '"' || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// Bool reads v as a JSON true or false; ok is false for any other value.
func Bool(v jsontext.Value) (b, ok bool) {
	if k := v.Kind(); (k != 't' && k != 'f') || !v.IsValid() {
		return false, false
	}
	return v.Kind() == 't', true
}

// NumericDate reads v as a NumericDate (RFC 7519 §2): a JSON number of
// seconds since the epoch, in [0, maxNumericDate], its fraction dropped. ok
// is false for any other value, null and a string included.
func NumericDate(v jsontext.Value) (t time.Time, ok bool) {
	if v.Kind() != '0' || !v.IsValid() {
		return time.Time{}, false
	}
	sec, ok := wholeSeconds(string(bytes.TrimSpace(v)))
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// maxNumericDate is 9999-12-31T23:59:59Z, the last second time.Time
// formats with a four-digit year (RFC 3339 §5.6).
const maxNumericDate = 253402300799

// wholeSeconds floors num, a valid JSON number (RFC 8259 §6), when it lies
// in [0, maxNumericDate]. The range is judged on the decimal text itself,
// since a float64 rounds -1e-400 to -0 and 253402300799.00001 to the bound.
func wholeSeconds(num string) (int64, bool) {
	neg := strings.HasPrefix(num, "-")
	mant, exp, _ := strings.Cut(strings.ToLower(strings.TrimPrefix(num, "-")), "e")
	intPart, frac, _ := strings.Cut(mant, ".")
	all := intPart + frac
	digits := strings.TrimLeft(all, "0")
	// The value is 0.digits × 10^point.
	point := len(intPart) - (len(all) - len(digits))
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		return 0, true
	}
	if exp != "" {
		// Past ±limit the outcome no longer depends on the exponent, and
		// clamping keeps point from overflowing.
		limit := int64(len(num) + maxNumericDateDigits + 1)
		e, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			e = limit
			if exp[0] == '-' {
				e = -limit
			}
		}
		point += int(min(max(e, -limit), limit))
	}
	switch {
	case neg || point > maxNumericDateDigits:
		return 0, false
	case point <= 0:
		return 0, true
	}
	whole := (digits + strings.Repeat("0", max(0, point-len(digits))))[:point]
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || n > maxNumericDate || n == maxNumericDate && len(digits) > point {
		return 0, false
	}
	return n, true
}

// maxNumericDateDigits is the number of digits in maxNumericDate.
const maxNumericDateDigits = 12

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
