package access

import (
	"net/http"
	"testing"
)

func TestIsBrowserRequest_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		accept        string
		authorization string
		want          bool
	}{
		{"browser html", "text/html,application/xhtml+xml", "", true},
		{"browser with wildcard", "text/html, */*", "", true},
		{"api client json", "application/json", "", false},
		{"api key overrides browser", "text/html", "Bearer ak_abc123", false},
		{"empty accept", "", "", false},
		{"api key with empty accept", "", "Bearer ak_abc123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if tt.authorization != "" {
				r.Header.Set("Authorization", tt.authorization)
			}
			got := IsBrowserRequest(r)
			if got != tt.want {
				t.Errorf("IsBrowserRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBrowserRequestAuthorization(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		value []string
		want  bool
	}{
		{"no Authorization header", nil, true},
		{"Bearer", []string{"Bearer ak_abc123"}, false},
		{"Basic from a proxy", []string{"Basic dXNlcjpwYXNz"}, false},
		{"unknown scheme", []string{"Negotiate abc"}, false},
		{"empty value", []string{""}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "text/html")
			for _, v := range tt.value {
				r.Header.Add("Authorization", v)
			}
			if got := IsBrowserRequest(r); got != tt.want {
				t.Errorf("IsBrowserRequest(Authorization %q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
