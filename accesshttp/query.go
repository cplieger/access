package accesshttp

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
)

// This file holds accesshttp's only reads of a request's query: a handler
// receives its route's decoded Query struct and cannot read an undeclared
// key.

// mediationConditional is the one mediation value authLoginPasskeyBegin
// accepts.
const mediationConditional = "conditional"

// queryValues lists the only values a declared string key accepts.
var queryValues = map[string][]string{
	"mediation": {mediationConditional},
}

// signInRedirect is the one query key the sign-in start repairs to "/".
const signInRedirect = "redirect"

// decodeQuery decodes r's query into a new value of s.query, or returns a
// nil Value for a route that accepts none. A token route refuses a token
// in its query: a URL is logged and kept in history, a body is not.
func decodeQuery(s *routeSpec, r *http.Request) (reflect.Value, error) {
	pairs := queryPairs(r.URL.RawQuery)
	if s.tokenBody && slices.ContainsFunc(pairs, func(p queryPair) bool { return p.names("token") }) {
		return reflect.Value{}, badRequest(ReasonTokenInQuery)
	}
	if s.query == nil {
		return reflect.Value{}, nil
	}
	out := reflect.New(s.query).Elem()
	for i := range s.query.NumField() {
		f := s.query.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		vals, malformed := valuesOf(pairs, key)
		if s.redirect {
			setLenient(s, key, vals, malformed, out.Field(i))
			continue
		}
		if malformed || len(vals) > 1 || (len(vals) == 1 && !setStrict(key, vals[0], out.Field(i))) {
			return reflect.Value{}, badRequest(key)
		}
	}
	return out, nil
}

// queryPair is one '&'-separated pair of a raw query. url.ParseQuery drops
// a pair that fails to unescape or holds ';' without an error, which would
// turn a malformed key=%ZZ into an absent key; a malformed pair is kept
// here, with every key it may name.
type queryPair struct {
	key, value string
	keys       []string // malformed only: each ';' segment's raw and unescaped key
	malformed  bool
}

func queryPairs(raw string) []queryPair {
	var pairs []queryPair
	for part := range strings.SplitSeq(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		key, keyErr := url.QueryUnescape(k)
		value, valueErr := url.QueryUnescape(v)
		if keyErr == nil && valueErr == nil && !strings.Contains(part, ";") {
			pairs = append(pairs, queryPair{key: key, value: value})
			continue
		}
		p := queryPair{malformed: true}
		for seg := range strings.SplitSeq(part, ";") {
			rawKey, _, _ := strings.Cut(seg, "=")
			p.keys = append(p.keys, rawKey)
			if unescaped, err := url.QueryUnescape(rawKey); err == nil {
				p.keys = append(p.keys, unescaped)
			}
		}
		pairs = append(pairs, p)
	}
	return pairs
}

// names reports whether p is, or may be, a pair for key.
func (p queryPair) names(key string) bool {
	if p.malformed {
		return slices.Contains(p.keys, key)
	}
	return p.key == key
}

// valuesOf returns key's well-formed values in order, and whether any pair
// that may name key is malformed.
func valuesOf(pairs []queryPair, key string) (vals []string, malformed bool) {
	for _, p := range pairs {
		switch {
		case !p.names(key):
		case p.malformed:
			malformed = true
		default:
			vals = append(vals, p.value)
		}
	}
	return vals, malformed
}

// setStrict sets a JSON route's declared key, reporting false for a value
// it refuses.
func setStrict(key, raw string, field reflect.Value) bool {
	switch field.Kind() {
	case reflect.Bool:
		if raw != "true" {
			return false
		}
		field.SetBool(true)
	case reflect.Int64:
		n, ok := positiveDecimal(raw)
		if !ok {
			return false
		}
		field.SetInt(n)
	case reflect.String:
		if allowed, listed := queryValues[key]; listed && !slices.Contains(allowed, raw) {
			return false
		}
		field.SetString(raw)
	default:
		return false
	}
	return true
}

// setLenient sets a redirect route's key, which refuses nothing: the
// callback takes each key's first well-formed value so Finish clears the
// flow cookie on every outcome, and the sign-in start falls back to "/".
func setLenient(s *routeSpec, key string, vals []string, malformed bool, field reflect.Value) {
	if s.name == routeOIDCStartSignIn && key == signInRedirect {
		if len(vals) > 0 || malformed {
			field.SetString(signInTarget(vals, malformed))
		}
		return
	}
	if len(vals) > 0 {
		field.SetString(vals[0])
	}
}

// signInTarget is the sign-in start's redirect: one well-formed value that
// ValidateRedirectURI keeps and that fits oidc.MaxRedirectBytes, else "/".
func signInTarget(vals []string, malformed bool) string {
	if malformed || len(vals) != 1 || len(vals[0]) > oidc.MaxRedirectBytes {
		return "/"
	}
	return access.ValidateRedirectURI(vals[0])
}

// positiveDecimal parses a canonical positive decimal int64: digits only,
// no sign and no leading zero.
func positiveDecimal(s string) (int64, bool) {
	if s == "" || s[0] == '0' || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
