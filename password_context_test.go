package access

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/access/internal/blocklist"
	"golang.org/x/text/unicode/norm"
	"pgregory.net/rapid"
)

// TestPasswordNormalizationFacts pins, over every rune, the Unicode facts
// that make the separators of blocklist.Fold(s) those of s, so the core
// ValidatePasswordContext strips from the folded form is the input's.
func TestPasswordNormalizationFacts(t *testing.T) {
	t.Parallel()
	for r := range rune(unicode.MaxRune + 1) {
		if !utf8.ValidRune(r) {
			continue
		}
		nfd := []rune(norm.NFD.String(string(r)))
		folded := []rune(blocklist.Fold(string(r)))
		if len(folded) == 0 {
			t.Errorf("%U folds to nothing", r)
		}
		if slices.ContainsFunc(folded, func(f rune) bool { return isPasswordSeparator(f) != isPasswordSeparator(r) }) {
			t.Errorf("%U folds to %q, changing its separator class", r, folded)
		}
		if len(nfd) > 1 && slices.ContainsFunc(nfd, isPasswordSeparator) {
			t.Errorf("%U decomposes to %q, which holds a separator", r, nfd)
		}
		if isPasswordSeparator(r) && norm.NFC.PropertiesString(string(r)).CCC() != 0 {
			t.Errorf("separator %U has combining class %d, so marks can reorder before it", r, norm.NFC.PropertiesString(string(r)).CCC())
		}
	}
}

func TestValidatePasswordContext(t *testing.T) {
	t.Parallel()
	const (
		ok        PasswordRejection = ""
		username                    = PasswordContainsUsername
		forbidden                   = PasswordContainsForbiddenWord
	)
	cases := []struct {
		name           string
		password       string
		username       string
		forbiddenWords []string
		want           PasswordRejection
	}{
		{"clean", "correct horse battery staple", "alice", []string{"subflux"}, ok},
		{"equal to the username", "alice", "alice", nil, username},
		{"the username plus digits", "alice2024", "alice", nil, username},
		{"digits and punctuation around the username", "  2024-alice!! ", "alice", nil, username},
		{"the username repeated", "alicealicealice", "alice", nil, username},
		{"the username repeated with separators", "alice-alice 2024alice", "alice", nil, username},
		{"case folded", "ALICE", "Alice", nil, username},
		{"full case folding", "STRAßE1", "strasse", nil, username},
		{"NFC on both sides", "cafe\u0301cafe\u0301", "caf\u00e9", nil, username},
		{"surrounding separators of the username stripped", "alice", "alice99", nil, username},
		{"equal to a forbidden word", "Subflux123", "alice", []string{"subflux"}, forbidden},
		{"a forbidden word repeated", "subflux.subflux", "alice", []string{"subflux"}, forbidden},
		{"a substring of a forbidden word is accepted", "my subflux library passphrase", "alice", []string{"subflux"}, ok},
		{"a substring of the username is accepted", "alice-secret-passphrase", "alice", nil, ok},
		{"letters between the copies", "alice1bob", "alice", nil, ok},
		{"a partial repeat", "alicealic", "alice", nil, ok},
		{"the username inside a word", "malice", "alice", nil, ok},
		{"a three-rune username is not compared", "bob123", "bob", nil, ok},
		{"a two-rune six-byte username is not compared", "日本日本", "日本", nil, ok},
		{"a four-rune username is compared", "日本語名2024", "日本語名", nil, username},
		{"a username of three runes after NFC is not compared", "abe\u0301", "abe\u0301", nil, ok},
		{"a username NFC expands to four runes is compared", "\u0958\u09582024", "\u0958\u0958", nil, username},
		{"empty username", "a-perfectly-fine-passphrase", "", nil, ok},
		{"empty forbidden word ignored", "!!!", "", []string{""}, ok},
		{"a forbidden word of digits and punctuation refuses only itself", "2024", "", []string{"20-24"}, ok},
		{"equal to a forbidden word of digits and punctuation", "20-24", "", []string{"20-24"}, forbidden},
		{"equal to an all-digit username", "123456789012345", "123456789012345", nil, username},
		{"an all-digit username plus digits is accepted", "1234567890123456", "123456789012345", nil, ok},
		{"a word starting with a combining mark, repeated with a separator", "\u0301abcdefghijklmne-\u0301abcdefghijklmne", "", []string{"\u0301abcdefghijklmne"}, forbidden},
		{"a join NFC composes across is no repeat", "\u0301abcdefghijklmne\u0301abcdefghijklmne", "", []string{"\u0301abcdefghijklmne"}, ok},
		{"a join NFC reorders across is no repeat", "\u0316x\u0301\u0316x\u0301", "", []string{"\u0316x\u0301"}, ok},
		{"a join NFC composes into the word's own form", "e\u0301e\u0301", "", []string{"\u00e9"}, forbidden},
		{"a forbidden word holding punctuation, repeated", "foo-barfoo-bar2024", "", []string{"Foo-Bar"}, forbidden},
		{"a symbol-wrapped forbidden word is accepted", "💡subflux💡", "alice", []string{"subflux"}, ok},
		{"a NUL-wrapped forbidden word is accepted", "\x00subflux\x00", "alice", []string{"subflux"}, ok},
		{"a symbol-wrapped username is accepted", "+alice+", "alice", nil, ok},
		{"tabs and newlines around a forbidden word", "\tsubflux\n", "alice", []string{"subflux"}, forbidden},
		{"punctuation around a forbidden word", "¡¿subflux?!", "alice", []string{"subflux"}, forbidden},
		{"non-ASCII digits around the username", "alice٢٠٢٤", "alice", nil, username},
		{"a forbidden word holding a symbol", "Sub💡flux2024", "alice", []string{"sub💡flux"}, forbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePasswordContext(tc.password, PasswordContext{Username: tc.username, ForbiddenWords: tc.forbiddenWords})
			if tc.want == ok {
				if err != nil {
					t.Errorf("ValidatePasswordContext(%q, {%q, %q}) = %v, want nil", tc.password, tc.username, tc.forbiddenWords, err)
				}
				return
			}
			var pe *PasswordError
			if !errors.As(err, &pe) {
				t.Fatalf("ValidatePasswordContext(%q, {%q, %q}) = %v, want a *PasswordError", tc.password, tc.username, tc.forbiddenWords, err)
			}
			if pe.Reason != tc.want || pe.Min != 0 || pe.Max != 0 {
				t.Errorf("ValidatePasswordContext(%q, {%q, %q}) = %+v, want Reason %q and zero bounds", tc.password, tc.username, tc.forbiddenWords, *pe, tc.want)
			}
		})
	}
}

// TestContextVerdictFormIndependent checks that a password's NFC and NFD
// spellings get its own verdict. The runes are ones NFC composes or
// reorders (combining marks, Hangul jamo), placed around and between copies
// of the word; a word that starts with a mark or a vowel jamo and ends with
// a base or a leading jamo composes across the join of two copies.
func TestContextVerdictFormIndependent(t *testing.T) {
	t.Parallel()
	leads := []rune{'\u0301', '\u0316', '\u0327', '\u1161', '\u11a8'}
	tails := []rune{'a', 'e', 'x', '\u1100', '\uac00'}
	runes := rapid.SampledFrom(append(append([]rune{'\u00e9'}, leads...), tails...))
	separators := rapid.SampledFrom([]string{"-", "1", " ", "\u0662"})
	joining := rapid.Custom(func(t *rapid.T) string {
		lead, tail := rapid.SampledFrom(leads).Draw(t, "lead"), rapid.SampledFrom(tails).Draw(t, "tail")
		return string(lead) + rapid.StringOfN(runes, 0, 3, -1).Draw(t, "middle") + string(tail)
	})
	rapid.Check(t, func(t *rapid.T) {
		word := rapid.OneOf(joining, rapid.StringOfN(runes, 1, 5, -1)).Draw(t, "word")
		pieces := rapid.SliceOfN(rapid.OneOf(
			rapid.Just(word),
			rapid.Just(word+word),
			separators,
			rapid.Map(runes, func(r rune) string { return string(r) }),
		), 1, 6).Draw(t, "pieces")
		password := strings.Join(pieces, "")
		pctx := PasswordContext{ForbiddenWords: []string{word}}
		if rapid.Bool().Draw(t, "as username") {
			pctx = PasswordContext{Username: word}
		}

		want := contextRejection(t, password, pctx)
		for _, form := range []string{norm.NFC.String(password), norm.NFD.String(password)} {
			if got := contextRejection(t, form, pctx); got != want {
				t.Fatalf("ValidatePasswordContext(%+q) = %q, but %q for its normal form %+q", password, want, got, form)
			}
		}
	})
}
