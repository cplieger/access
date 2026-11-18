package access

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestPasswordRejections pins the list to the wire values and to this
// package's validators: each validator rejection is listed, and each listed
// value but the last two, breached and is_temporary_password, which
// account produces, comes from a validator.
func TestPasswordRejections(t *testing.T) {
	t.Parallel()
	want := []PasswordRejection{"too_short", "too_long", "contains_username", "contains_forbidden_word", "common", "breached", "is_temporary_password"}
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
	validators := want[:len(want)-2]
	for _, r := range validators {
		t.Run(string(r), func(t *testing.T) {
			t.Parallel()
			pe, ok := errors.AsType[*PasswordError](produced[r])
			if !ok || pe.Reason != r {
				t.Errorf("the %s producer returned %v, want a *PasswordError with that Reason", r, produced[r])
			}
		})
	}
	if len(produced) != len(validators) {
		t.Errorf("%d producers for %d validator rejections", len(produced), len(validators))
	}
}
