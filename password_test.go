package access

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestProperty_PasswordHashRoundTrip(t *testing.T) {
	t.Parallel()
	h := mustHasher(t, HasherConfig{})
	ctx := t.Context()
	rapid.Check(t, func(t *rapid.T) {
		password := rapid.StringN(8, 128, -1).Draw(t, "password")

		hash, err := h.Hash(ctx, password)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		ok, _, err := h.Verify(ctx, password, hash)
		if err != nil || !ok {
			t.Fatalf("Verify(same) = (%v, %v), want (true, nil)", ok, err)
		}
		ok, _, err = h.Verify(ctx, password+"x", hash)
		if err != nil || ok {
			t.Fatalf("Verify(different) = (%v, %v), want (false, nil)", ok, err)
		}
	})
}

func TestProperty_UniqueSaltPerHash(t *testing.T) {
	t.Parallel()
	h := mustHasher(t, HasherConfig{})
	ctx := t.Context()
	rapid.Check(t, func(t *rapid.T) {
		password := rapid.StringN(1, 128, -1).Draw(t, "password")

		hash1, err1 := h.Hash(ctx, password)
		hash2, err2 := h.Hash(ctx, password)
		if err1 != nil || err2 != nil {
			t.Fatalf("Hash: %v, %v", err1, err2)
		}
		if hash1.Equal(hash2) {
			t.Fatalf("two hashes identical (salt reuse)")
		}
	})
}

func TestValidatePasswordLength(t *testing.T) {
	t.Parallel()
	const accepted PasswordRejection = ""
	cases := []struct {
		name     string
		password string
		want     PasswordRejection
	}{
		{"empty", "", PasswordTooShort},
		{"14 runes", strings.Repeat("a", 14), PasswordTooShort},
		{"15 runes", strings.Repeat("a", 15), accepted},
		{"128 runes", strings.Repeat("a", 128), accepted},
		{"129 runes", strings.Repeat("a", 129), PasswordTooLong},
		{"128 three-byte runes", strings.Repeat("日", 128), accepted},
		{"15 combining sequences compose to 15 runes", strings.Repeat("e\u0301", 15), accepted},
		{"14 combining sequences compose to 14 runes", strings.Repeat("e\u0301", 14), PasswordTooShort},
		{"128 combining sequences compose to 128 runes", strings.Repeat("e\u0301", 128), accepted},
		{"129 combining sequences compose to 129 runes", strings.Repeat("e\u0301", 129), PasswordTooLong},
		// U+0958 is excluded from composition, so NFC writes it as two runes.
		{"8 runes NFC expands to 16", strings.Repeat("\u0958", 8), accepted},
		{"65 runes NFC expands to 130", strings.Repeat("\u0958", 65), PasswordTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePasswordLength(tc.password)
			if tc.want == accepted {
				if err != nil {
					t.Errorf("ValidatePasswordLength(%q) = %v, want nil", tc.password, err)
				}
				return
			}
			var pe *PasswordError
			if !errors.As(err, &pe) {
				t.Fatalf("ValidatePasswordLength(%q) = %v, want a *PasswordError", tc.password, err)
			}
			if pe.Reason != tc.want || pe.Min != PasswordMinLength || pe.Max != PasswordMaxLength {
				t.Errorf("ValidatePasswordLength(%q) = %+v, want Reason %q, Min 15, Max 128", tc.password, *pe, tc.want)
			}
			bound := pe.Min
			if tc.want == PasswordTooLong {
				bound = pe.Max
			}
			if !strings.Contains(pe.Error(), strconv.Itoa(bound)) {
				t.Errorf("Error() = %q, want it to name the bound %d", pe.Error(), bound)
			}
		})
	}
}

func TestValidatePasswordCommon(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		password string
		refused  bool
	}{
		{"listed", "qazwsxedcrfvtgb", true},
		{"upper case", "QAZWSXEDCRFVTGB", true},
		{"mixed case", "QazWsxEdcRfvTgb", true},
		{"long s folds to s", "qazw\u017Fxedcrfvtgb", true},
		{"Kelvin sign normalizes to K", "a\u212Asjdlasdakj89879", true},
		{"unlisted 15 runes", "unlisted-horse7", false},
		{"listed plus a rune", "qazwsxedcrfvtgb!", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePasswordCommon(tc.password)
			if !tc.refused {
				if err != nil {
					t.Errorf("ValidatePasswordCommon(%q) = %v, want nil", tc.password, err)
				}
				return
			}
			var pe *PasswordError
			if !errors.As(err, &pe) || pe.Reason != "common" || pe.Min != 0 || pe.Max != 0 {
				t.Errorf("ValidatePasswordCommon(%q) = %v, want a *PasswordError with Reason common", tc.password, err)
			}
		})
	}
}
