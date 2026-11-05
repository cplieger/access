package accesshttp

import (
	"net/http"
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

// FuzzCallbackLocation holds the callback's emission to the origin: for any
// input, the Location written for ValidateRedirectURI's answer, with each
// marker, is a path-absolute reference that resolves on the app's origin.
func FuzzCallbackLocation(f *testing.F) {
	for _, seed := range []string{"/%2Fevil.com/|", "/%2f</@", "/%2F%2Fevil.com x", "/a#x?y"} {
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
			redirect(w, httptest.NewRequest(http.MethodGet, "https://app.example/api/auth/oidc/callback", nil), target)
			loc := w.Header().Get("Location")
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
