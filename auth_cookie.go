package access

import (
	"net/http"
	"strings"
)

// IsBrowserRequest reports whether the request appears to come from a
// browser: its Accept header contains text/html and it carries no
// Authorization header, whatever its scheme or value.
func IsBrowserRequest(r *http.Request) bool {
	if len(r.Header.Values("Authorization")) > 0 {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
