package accesshttp

import (
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// The callback's markers (§7.2): the query key each sets.
const (
	markerOIDC  = "oidc"
	markerError = "auth_error"
)

// withMarker is target with key=value as its only oidc or auth_error pair,
// built on target's bytes: url.URL.String would rebuild a non-canonical path
// such as /%2Fevil.com/| as //evil.com/%7C, which leaves the origin. The
// path ends at the first '?' or '#', the query at the next '#'.
func withMarker(target, key, value string) string {
	path, rest := target, ""
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		path, rest = target[:i], target[i:]
	}
	query, fragment := "", rest
	if strings.HasPrefix(rest, "?") {
		query, fragment = rest[1:], ""
		if j := strings.IndexByte(query, '#'); j >= 0 {
			query, fragment = query[:j], query[j:]
		}
	}
	var pairs []string
	if query != "" {
		for pair := range strings.SplitSeq(query, "&") {
			k, _, _ := strings.Cut(pair, "=")
			if name, err := url.QueryUnescape(k); err == nil && (name == markerOIDC || name == markerError) {
				continue
			}
			pairs = append(pairs, pair)
		}
	}
	pairs = append(pairs, key+"="+value)
	return path + "?" + strings.Join(pairs, "&") + fragment
}

// redirect sends the browser to location unchanged but for each byte >= 0x80,
// percent-escaped: a Location is an ASCII URI-reference (RFC 9110 section
// 10.2.2). http.Redirect escapes the same bytes but also runs path.Clean
// before the first '?', a fragment included, so "/settings#/../../admin"
// would land on "/admin", not the validated target.
func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", escapeNonASCII(location))
	w.WriteHeader(http.StatusFound)
}

func escapeNonASCII(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c < utf8.RuneSelf {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}
