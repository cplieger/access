package access

import (
	"errors"
	"fmt"

	"golang.org/x/text/secure/precis"
)

// Sentinel errors returned by [NormalizeUsername].
var (
	// ErrUsernameEmpty reports that the username is empty, or normalized to
	// empty. RFC 8265 §3.1 requires a non-empty result.
	ErrUsernameEmpty = errors.New("username must not be empty")

	// ErrUsernameInvalid reports that the username contains a code point the
	// PRECIS IdentifierClass disallows. The wrapped error carries the detail
	// from golang.org/x/text and is not part of this library's contract.
	ErrUsernameInvalid = errors.New("username contains a disallowed character")
)

// NormalizeUsername returns the canonical form of a username, so two names
// with the same form are one account: apply it to the unique-username index
// key and again to the login input. The rule is RFC 8265 §3.3's
// UsernameCaseMapped profile, which case-folds all of Unicode ("Müller" is
// "MÜLLER") without transliterating ("straße" stays apart from "strasse") and
// refuses spaces. It bounds no length and refuses no confusable: the consumer
// owns both policies. It returns ErrUsernameEmpty for an empty result and
// ErrUsernameInvalid, wrapping the profile's cause, for a refused name.
func NormalizeUsername(username string) (string, error) {
	normalized, err := precis.UsernameCaseMapped.String(username)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUsernameInvalid, err)
	}
	// RFC 8265 §3.1 requires a non-empty result, which the profile does not
	// enforce (https://github.com/golang/go/issues/64531). Checking the result
	// also refuses input the profile's mapping reduces to nothing.
	if normalized == "" {
		return "", ErrUsernameEmpty
	}
	return normalized, nil
}
