package accesshttp

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

// browserNormalised is loc as a browser reads a Location (WHATWG URL
// parsing): leading C0 controls and spaces stripped, tab, LF and CR
// removed, and '\' read as '/'.
func browserNormalised(loc string) string {
	loc = strings.TrimLeftFunc(loc, func(r rune) bool { return r <= ' ' })
	loc = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(loc)
	return strings.ReplaceAll(loc, `\`, "/")
}

// asciiLocation is target as an RFC 3986 URI-reference carries it: each byte
// >= 0x80 written as %XX, every other byte unchanged.
func asciiLocation(target string) string {
	var b strings.Builder
	for _, c := range []byte(target) {
		if c >= 0x80 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FuzzCallbackLocation holds the callback's emission to the origin: for any
// input, the Location written for ValidateRedirectURI's answer, with each
// marker, is that target with only its non-ASCII bytes percent-escaped, and
// a path-absolute reference that resolves on the app's origin.
func FuzzCallbackLocation(f *testing.F) {
	for _, seed := range []string{"/%2Fevil.com/|", "/%2f</@", "/%2F%2Fevil.com x", "/a#x?y", "/settings#/../../admin", "/caf\u00e9#\u00e9", "/a\xff"} {
		f.Add(seed)
	}
	app, err := url.Parse("https://app.example/")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sealed := access.ValidateRedirectURI(s)
		for _, target := range []string{
			sealed,
			withMarker(sealed, markerOIDC, "linked"),
			withMarker(sealed, markerOIDC, "stepped_up"),
			withMarker(sealed, markerError, "x"),
		} {
			w := httptest.NewRecorder()
			redirect(w, target)
			loc := w.Header().Get("Location")
			if want := asciiLocation(target); loc != want {
				t.Fatalf("input %q: Location %q, want %q", s, loc, want)
			}
			n := browserNormalised(loc)
			if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") {
				t.Fatalf("input %q: Location %q is not one path-absolute reference", s, loc)
			}
			if ref, err := url.Parse(n); err == nil {
				if got := app.ResolveReference(ref); got.Scheme != "https" || got.Host != "app.example" {
					t.Fatalf("input %q: Location %q resolves to %s", s, loc, got)
				}
			}
		}
	})
}
