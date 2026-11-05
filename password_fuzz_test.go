package access

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// FuzzPasswordValidators checks both validators on any input, invalid UTF-8
// included. The input and its NFC and NFD forms get one length verdict and
// one context verdict. A password of four runes or more after NFC is
// refused as its own username, and a non-empty word refuses itself. A valid
// UTF-8 word with a core also refuses itself plus digits and itself twice
// around a hyphen, because a separator is a starter NFC never composes or
// reorders across (TestPasswordNormalizationFacts); joined invalid bytes can
// fuse into a new rune, so only valid words are extended.
func FuzzPasswordValidators(f *testing.F) {
	f.Add("short", "alice")
	f.Add(strings.Repeat("e\u0301", 8), "cafe\u0301")
	f.Add(strings.Repeat("e\u0301", 15), "Stra\u00dfe")
	f.Add(strings.Repeat("\u0958", 8), "\u0958\u0958\u0958\u0958")
	f.Add(strings.Repeat("あ", 129), "日本語名")
	f.Add("pass\x00word\x00null", "--subflux--")
	f.Add("123456789012345", "20-24")
	f.Add("abc", "\u0301abcdefghijklmne")
	f.Add("\u0301abcdefghijklmne\u0301abcdefghijklmne", "\u0301abcdefghijklmne")
	f.Add("abc", "\u0316x\u0301")
	f.Add("\xff\xfe", "\xff")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, pw, word string) {
		pctx := PasswordContext{ForbiddenWords: []string{word}}
		wantLength, wantContext := lengthVerdict(t, pw), contextRejection(t, pw, pctx)
		for _, form := range []string{norm.NFC.String(pw), norm.NFD.String(pw)} {
			if got := lengthVerdict(t, form); got != wantLength {
				t.Errorf("ValidatePasswordLength verdict %q for %q, %q for its normal form %q", wantLength, pw, got, form)
			}
			if got := contextRejection(t, form, pctx); got != wantContext {
				t.Errorf("ValidatePasswordContext verdict %q for %q, %q for its normal form %q", wantContext, pw, got, form)
			}
		}

		err := ValidatePasswordContext(pw, PasswordContext{Username: pw, ForbiddenWords: []string{word}})
		if utf8.RuneCountInString(norm.NFC.String(pw)) >= contextMinUsernameRunes {
			var pe *PasswordError
			if !errors.As(err, &pe) || (pe.Reason != PasswordContainsUsername && pe.Reason != PasswordContainsForbiddenWord) {
				t.Errorf("ValidatePasswordContext(%q, username %q) = %v, want a username or forbidden-word refusal", pw, pw, err)
			}
		}

		var refused []string
		if word != "" {
			refused = append(refused, word)
		}
		if utf8.ValidString(word) && hasCore(word) {
			refused = append(refused, word+"2024", word+"-"+word)
		}
		for _, derived := range refused {
			var pe *PasswordError
			err := ValidatePasswordContext(derived, pctx)
			if !errors.As(err, &pe) || pe.Reason != PasswordContainsForbiddenWord {
				t.Errorf("ValidatePasswordContext(%q, forbidden %q) = %v, want contains_forbidden_word", derived, word, err)
			}
		}
	})
}

// hasCore reports a rune the context check keeps after stripping
// separators, so s cannot strip to nothing.
func hasCore(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return !isPasswordSeparator(r) }) >= 0
}

// contextRejection takes a *testing.T or a *rapid.T, which has no Helper.
func contextRejection(t interface{ Fatalf(string, ...any) }, pw string, pctx PasswordContext) PasswordRejection {
	err := ValidatePasswordContext(pw, pctx)
	if err == nil {
		return ""
	}
	var pe *PasswordError
	if !errors.As(err, &pe) {
		t.Fatalf("ValidatePasswordContext(%q) = %v, want nil or a *PasswordError", pw, err)
	}
	return pe.Reason
}

func lengthVerdict(t *testing.T, pw string) PasswordRejection {
	t.Helper()
	err := ValidatePasswordLength(pw)
	if err == nil {
		return ""
	}
	var pe *PasswordError
	if !errors.As(err, &pe) || pe.Min != PasswordMinLength || pe.Max != PasswordMaxLength {
		t.Fatalf("ValidatePasswordLength(%q) = %v, want a *PasswordError with Min 15, Max 128", pw, err)
	}
	return pe.Reason
}

func FuzzHasherVerify(f *testing.F) {
	f.Add("test-password-long-enough")
	f.Add("short")
	f.Add("")
	f.Add("caf\u0065\u0301")
	f.Add("\xff\xfe")

	h := mustHasher(f, HasherConfig{})
	f.Fuzz(func(t *testing.T, pw string) {
		hash := mustHash(t, h, pw)
		ok, needsRehash, err := h.Verify(t.Context(), pw, hash)
		if err != nil || !ok || needsRehash {
			t.Fatalf("Verify(correct) = (%v, %v, %v), want (true, false, nil)", ok, needsRehash, err)
		}
		ok, _, err = h.Verify(t.Context(), pw+"x", hash)
		if err != nil || ok {
			t.Fatalf("Verify(wrong) = (%v, %v), want (false, nil)", ok, err)
		}
	})
}

func FuzzParsePHC(f *testing.F) {
	canonical := "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32
	seeds := []string{
		canonical,
		"$argon2id$v=19$m=4194304,t=100,p=16$" + strings.Repeat("A", 86) + "$" + strings.Repeat("A", 86),
		"$argon2id$v=19$m=019456,t=2,p=1$" + phcSalt16 + "$" + phcKey32,
		"$argon2id$v=19$m=+19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32,
		"$argon2id$v=019$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32,
		"$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16[:21] + "B$" + phcKey32,
		"$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "==$" + phcKey32,
		"$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16[:10] + "\n" + phcSalt16[10:] + "$" + phcKey32,
		"x" + canonical,
		"$argon2id$v=19$m=1024,t=38,p=1$" + phcSalt16 + "$" + phcKey32,
		"$argon2id$v=19$m=19455,t=2,p=1$" + phcSalt16 + "$" + phcKey32,
		"$argon2id$v=19$m=19456,t=2,p=17$" + phcSalt16 + "$" + phcKey32,
		"",
		"$",
		"$$$$$$",
		"not-a-hash",
		"$argon2id$v=99$m=19456,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAA$BBBB",
		"$argon2id$v=19$m=-1,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 10000) + "$" + phcKey32,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		p, err := parsePHC(encoded)
		if err != nil {
			return
		}
		if got := p.format(); got != encoded {
			t.Errorf("parsePHC(%q) accepted text whose canonical form is %q", encoded, got)
		}
		if err := p.params.Validate(); err != nil {
			t.Errorf("parsePHC(%q) accepted out-of-bounds params: %v", encoded, err)
		}
		if int(p.params.SaltLength) != len(p.salt) || int(p.params.KeyLength) != len(p.key) {
			t.Errorf("parsePHC(%q) lengths %d/%d disagree with salt %d and key %d bytes", encoded, p.params.SaltLength, p.params.KeyLength, len(p.salt), len(p.key))
		}
		if cost := HashCost(p.params); cost > argonMaxMemory*1024 {
			t.Errorf("parsePHC(%q) accepted a cost of %d bytes, over 4 GiB", encoded, cost)
		}
	})
}
