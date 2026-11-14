// Package scopetoken holds the one rule for a key scope's characters, so
// every scope access accepts quotes unescaped in a WWW-Authenticate scope
// attribute.
package scopetoken

// Valid reports whether s is one RFC 6750 §3 scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ).
func Valid(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
