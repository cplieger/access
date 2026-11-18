package totp

import (
	"strings"
	"testing"
)

// sixDigits is RFC 4226 §5.3's six-digit value after removing ASCII spaces.
func sixDigits(raw string) bool {
	s := strings.ReplaceAll(raw, " ", "")
	if len(s) != 6 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// FuzzMatch_malformed checks that Match never panics, answers Malformed
// exactly for input that is not six ASCII digits after removing spaces, and
// answers a well-formed input the same with or without spaces between digits.
func FuzzMatch_malformed(f *testing.F) {
	for _, s := range []string{"", "123456", "123 456", " 123456 ", "12345", "1234567", "١٢٣٤٥٦", "１２３４５６", "123\t456", "12\u00a03456", "\xff\xfe12345", "287082"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		step, r := Match(rfcSecret, raw, windowNow, 0)
		if (r == Malformed) == sixDigits(raw) {
			t.Fatalf("Match(%q) = %v, but six ASCII digits after spaces = %v", raw, r, sixDigits(raw))
		}
		if r == Malformed {
			return
		}
		bare := strings.ReplaceAll(raw, " ", "")
		if s2, r2 := Match(rfcSecret, bare, windowNow, 0); s2 != step || r2 != r {
			t.Fatalf("Match(%q) = %d, %v but Match(%q) = %d, %v", raw, step, r, bare, s2, r2)
		}
	})
}

// FuzzURI_roundtrip checks that every issuer and account parses back with
// net/url to one label pair, with colons mapped to "_", and one of each
// parameter with issuer equal to the label prefix.
func FuzzURI_roundtrip(f *testing.F) {
	f.Add("Example", "alice@google.com")
	f.Add("ACME Co", "john.doe@email.com")
	f.Add("a:b", "c:d%3Ae")
	f.Add("R&D", "x&secret=AAAA&issuer=evil")
	f.Add("", "")
	f.Add("\xff", "日本#?/+")
	f.Fuzz(func(t *testing.T, issuer, account string) {
		p := parseURI(t, URI(issuer, account, wikiSecret))
		wantIssuer, wantAccount := strings.ReplaceAll(issuer, ":", "_"), strings.ReplaceAll(account, ":", "_")
		if p.labelIssuer != wantIssuer || p.account != wantAccount {
			t.Fatalf("label = %q:%q, want %q:%q", p.labelIssuer, p.account, wantIssuer, wantAccount)
		}
		checkParams(t, p, wikiSecret)
	})
}
