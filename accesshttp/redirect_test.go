package accesshttp

import "testing"

func TestWithMarker(t *testing.T) {
	for _, tc := range []struct {
		name, target, want string
	}{
		{"path_only", "/p", "/p?oidc=linked"},
		{"query_and_fragment", "/p?a=1#f", "/p?a=1&oidc=linked#f"},
		{"empty_query_before_fragment", "/p?#f", "/p?oidc=linked#f"},
		{"query_only", "?a=1", "?a=1&oidc=linked"},
		{"fragment_only", "#f", "?oidc=linked#f"},
		{"old_markers_replaced", "/p?oidc=x&a=1&auth%5Ferror=y", "/p?a=1&oidc=linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := withMarker(tc.target, markerOIDC, "linked"); got != tc.want {
				t.Errorf("withMarker(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}
