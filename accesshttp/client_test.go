package accesshttp

import (
	"strings"
	"testing"
)

func TestSanitizeUserAgent(t *testing.T) {
	atCap := strings.Repeat("a", maxUserAgentBytes)
	for _, tc := range []struct {
		name, in, want string
	}{
		{"plain_kept", "Mozilla/5.0 (X11)", "Mozilla/5.0 (X11)"},
		{"controls_dropped", "a\x00b\nc\u200ed\u2028e\u2029f", "abcdef"},
		{"invalid_utf8_dropped", "a\xffb", "ab"},
		{"exactly_the_cap_kept", atCap, atCap},
		{"one_past_the_cap_cut", atCap + "b", atCap},
		{"rune_straddling_the_cap_cut", atCap[1:] + "é", atCap[1:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeUserAgent(tc.in); got != tc.want {
				t.Errorf("sanitizeUserAgent(%q) = %q (%d bytes), want %q (%d bytes)", tc.in, got, len(got), tc.want, len(tc.want))
			}
		})
	}
}
