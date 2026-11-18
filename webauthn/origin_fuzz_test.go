package webauthn

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzParseOrigin_roundtrip pins the properties the origin binding rests on:
// the parser never panics on an attacker-controlled header, a parsed origin
// re-parses to itself, and its String is the input origin's RFC 6454 §6.2
// serialization. clientDataJSON's origin is compared byte for byte with that
// String (verifyClientData), so a parser that repairs its input, stripping a
// trailing dot, binds an origin the browser never sends.
func FuzzParseOrigin_roundtrip(f *testing.F) {
	for _, seed := range []string{
		"https://example.com",
		"https://example.com:443",
		"https://example.com:8443",
		"http://localhost:8374",
		"HTTPS://EXAMPLE.COM",
		"https://example.com/",
		"https://[::1]:8443",
		"https://[0:0:0:0:0:0:0:1]",
		"null",
		"https://example.com.",
		"https://sub..example.com",
		"https://ex%C3%A4mple.com",
		"https://u:p@example.com",
		"https://example.com:99999",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		o, err := ParseOrigin(raw)
		if err != nil {
			if !o.IsZero() {
				t.Fatalf("ParseOrigin(%q) = %v with error %v, want the zero Origin on refusal", raw, o, err)
			}
			return
		}
		again, err := ParseOrigin(o.String())
		if err != nil {
			t.Fatalf("ParseOrigin(%q).String() = %q does not re-parse: %v", raw, o.String(), err)
		}
		if again != o {
			t.Fatalf("ParseOrigin(%q) = %+v, re-parsed as %+v, want a stable round trip", raw, o, again)
		}
		if want := rfc6454Serialization(t, raw); o.String() != want {
			t.Fatalf("ParseOrigin(%q).String() = %q, want the input's serialization %q; the parser repaired something", raw, o.String(), want)
		}
	})
}

// rfc6454Serialization is the ASCII serialization of raw's origin
// (RFC 6454 §4 and §6.2): the scheme and host lowercased, the scheme's
// default port omitted.
func rfc6454Serialization(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) = %v for an accepted origin", raw, err)
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		port = ""
	}
	if port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}
