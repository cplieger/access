package access

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestPasswordRejections pins the list to the wire values and to this
// package's validators: each validator rejection is listed, and each listed
// value but breached, which account produces, comes from a validator.
func TestPasswordRejections(t *testing.T) {
	t.Parallel()
	want := []PasswordRejection{"too_short", "too_long", "contains_username", "contains_forbidden_word", "common", "breached"}
	if got := PasswordRejections(); !slices.Equal(got, want) {
		t.Fatalf("PasswordRejections() = %v, want %v", got, want)
	}
	produced := map[PasswordRejection]error{
		PasswordTooShort:              ValidatePasswordLength("short"),
		PasswordTooLong:               ValidatePasswordLength(strings.Repeat("a", PasswordMaxLength+1)),
		PasswordContainsUsername:      ValidatePasswordContext("alice-the-admin", PasswordContext{Username: "alice-the-admin"}),
		PasswordContainsForbiddenWord: ValidatePasswordContext("examplecorp2026", PasswordContext{ForbiddenWords: []string{"examplecorp"}}),
		PasswordCommon:                ValidatePasswordCommon("qazwsxedcrfvtgb"),
	}
	for _, r := range want[:len(want)-1] {
		t.Run(string(r), func(t *testing.T) {
			t.Parallel()
			pe, ok := errors.AsType[*PasswordError](produced[r])
			if !ok || pe.Reason != r {
				t.Errorf("the %s producer returned %v, want a *PasswordError with that Reason", r, produced[r])
			}
		})
	}
	if len(produced) != len(want)-1 {
		t.Errorf("%d producers for %d validator rejections", len(produced), len(want)-1)
	}
}
