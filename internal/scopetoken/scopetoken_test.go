package scopetoken

import "testing"

// TestValid follows RFC 6750 §3's scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
func TestValid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		s    string
		want bool
	}{
		{"word", "admin", true},
		{"punctuation", "read:all/v1.x-y_z!#[]{}~", true},
		{"lowest_0x21", "!", true},
		{"highest_0x7e", "~", true},
		{"either_side_of_dquote", "\x21\x23", true},
		{"either_side_of_backslash", "\x5b\x5d", true},
		{"empty", "", false},
		{"space_separates_tokens", "read write", false},
		{"dquote", `a"b`, false},
		{"backslash", `a\b`, false},
		{"control", "a\x1fb", false},
		{"del", "a\x7f", false},
		{"non_ascii", "caf\u00e9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Valid(tc.s); got != tc.want {
				t.Errorf("Valid(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
