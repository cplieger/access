package account

import (
	"context"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/access"
)

// countedMethods are the methods with failure records: a creating Update
// deletes the new name's records of each.
var countedMethods = []access.Method{access.MethodPassword}

// canonicalUsername is the shared username rule of every creation path,
// run before any limiter call or hash: access.NormalizeUsername, then
// MaxUsernameLength runes.
func canonicalUsername(name string) (string, error) {
	canonical, err := access.NormalizeUsername(name)
	switch {
	case errors.Is(err, access.ErrUsernameEmpty):
		return "", &UsernameError{Reason: ReasonEmpty}
	case err != nil:
		return "", &UsernameError{Reason: ReasonDisallowedCharacter}
	case utf8.RuneCountInString(canonical) > MaxUsernameLength:
		return "", &UsernameError{Reason: ReasonTooLong}
	}
	return canonical, nil
}

// checkPassword is the shared password rule of every set path: length, the
// context of username and Rules.ForbiddenWords, the common-password list,
// then the breach check per r.Breach. A caller whose ctx ended during the
// breach check gets that context's error under either mode, with no WARN:
// fail-open covers only the breach service failing to answer.
func (s *Service) checkPassword(ctx context.Context, r Rules, username string, pw access.Secret) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	text := pw.Reveal()
	if err := access.ValidatePasswordLength(text); err != nil {
		return err
	}
	if err := access.ValidatePasswordContext(text, access.PasswordContext{Username: username, ForbiddenWords: r.ForbiddenWords}); err != nil {
		return err
	}
	if err := access.ValidatePasswordCommon(text); err != nil {
		return err
	}
	if r.Breach == BreachOff {
		return nil
	}
	breached, err := access.CheckBreachedPassword(ctx, s.breach, text)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("account: password check ended: %w", ctxErr)
	}
	switch {
	case breached:
		return &access.PasswordError{Reason: access.PasswordBreached}
	case err == nil:
		return nil
	case r.Breach == BreachFailOpen:
		s.logger().Warn("account: breached-password check unavailable; the password is accepted", "err", err)
		return nil
	default:
		return err
	}
}

// checkLine is the display-text rule: valid UTF-8 of at most maxRunes runes
// on one line, holding no character lineBreaking reports.
func checkLine(field, text string, maxRunes int) error {
	if !utf8.ValidString(text) {
		return &TextError{Field: field, Reason: ReasonDisallowedCharacter}
	}
	for _, r := range text {
		if lineBreaking(r) {
			return &TextError{Field: field, Reason: ReasonDisallowedCharacter}
		}
	}
	if utf8.RuneCountInString(text) > maxRunes {
		return &TextError{Field: field, Reason: ReasonTooLong}
	}
	return nil
}

// lineBreaking reports a character that breaks a displayed line or reorders
// it: a control (tab and newline included), a bidi control, or a line or
// paragraph separator.
func lineBreaking(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control, unicode.Zl, unicode.Zp)
}
