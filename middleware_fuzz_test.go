package access

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func FuzzValidateRedirectURI(f *testing.F) {
	f.Add("/")
	f.Add("/dashboard")
	f.Add("//evil.com")
	f.Add("https://evil.com")
	f.Add("")
	f.Add("/path?q=1#frag")
	f.Add("javascript:alert(1)")
	f.Add("/\\evil.com")
	f.Add("/path\\to\\file")
	f.Add("/%zz")
	f.Add("/" + strings.Repeat("a", 2048))

	f.Fuzz(func(t *testing.T, uri string) {
		result := ValidateRedirectURI(uri)
		if result == "" {
			t.Error("returned empty string")
		}
		if len(result) > 0 && result[0] != '/' {
			t.Errorf("result %q does not start with /", result)
		}
		if len(result) > 1 && result[1] == '/' {
			t.Errorf("result %q starts with // (open redirect)", result)
		}
		if len(result) > 2048 {
			t.Errorf("result is %d bytes, want at most 2048", len(result))
		}
		// A non-root result is the input accepted unchanged and must never
		// carry an open-redirect vector: no backslash (browsers fold "/\" to
		// "//") and no scheme separator.
		if result != "/" {
			if result != uri {
				t.Errorf("ValidateRedirectURI(%q) = %q, want either \"/\" or the input unchanged", uri, result)
			}
			if strings.Contains(result, "\\") {
				t.Errorf("accepted redirect %q contains a backslash (open-redirect vector)", result)
			}
			if strings.Contains(result, "://") {
				t.Errorf("accepted redirect %q contains a scheme separator", result)
			}
		}
	})
}

// bearerShape is the header grammar the API-key verifier reads: the Bearer
// scheme in any case, one or more spaces, then a value that starts with no
// space (RFC 9110 §11.4, RFC 6750 §2.1).
var bearerShape = regexp.MustCompile(`(?i)^bearer +[^ ]`)

// FuzzBearerHeader pins that only a Bearer header is read: such a value is
// refused as an unknown key, and every other header is not the verifier's
// credential and reaches no store.
func FuzzBearerHeader(f *testing.F) {
	for _, seed := range []string{
		"Bearer ak_x", "bearer ak_x", "BEARER ak_x", "bEaReR ak_x", "Bearer  ak_x",
		"Bearer", "Bearer ", "Bearer   ", "Bearer\tak_x", "Bearerak_x", " Bearer ak_x",
		"Basic dXNlcjpwYXNz", "Token ak_x", "", "Bearer \xff", "Bearer\xa0ak_x",
	} {
		f.Add(seed)
	}
	store := newRecordingStore()
	a := mustAuthenticator(f, store, Config{})
	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header["Authorization"] = []string{header}
		before := store.keyReads.Load()
		_, err := a.Authenticate(r)
		read := errors.Is(err, ErrInvalidCredential)
		if want := bearerShape.MatchString(header); read != want {
			t.Fatalf("Authorization %q: read = %v (error %v), want %v", header, read, err, want)
		}
		if !read && (err != ErrUnauthenticated || store.keyReads.Load() != before) { //nolint:errorlint // bare: no verifier claimed the header
			t.Fatalf("Authorization %q: error = %v with a key read, want bare ErrUnauthenticated and none", header, err)
		}
	})
}
