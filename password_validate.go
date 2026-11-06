package access

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 required by HIBP k-anonymity API (not for security)
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/access/internal/blocklist"
	"golang.org/x/text/unicode/norm"
)

// PasswordMinLength is the shortest password [ValidatePasswordLength]
// accepts, in runes after NFC. A password is always a sole sufficient
// factor here, so the floor never drops below NIST's 15 (SP 800-63B-4
// §3.1.1.2).
const PasswordMinLength = 15

// PasswordMaxLength is the longest password [ValidatePasswordLength]
// accepts, in runes after NFC: an upper bound NIST SP 800-63B-4 §3.1.1.2
// permits (it asks for at least 64). It is not a DoS guard, because Argon2
// first hashes the password into its 64-byte H0 (RFC 9106 §3.2), so the
// length barely changes a derivation's cost.
const PasswordMaxLength = 128

// hibpRequestTimeout bounds each request even when the caller's client has
// no Timeout.
const hibpRequestTimeout = 5 * time.Second

const hibpMaxBody = 2 << 20

// hibpDrainMax bounds the read of a non-200 body, drained before it is
// closed so the transport can reuse the connection.
const hibpDrainMax = 4 << 10

const contextMinUsernameRunes = 4

// PasswordRejection names why a password was refused; PasswordRejections
// lists every value, each stable data for UIs.
type PasswordRejection string

// The rejections, in PasswordRejections order. This package's validators
// return the first five; PasswordBreached is for a caller that refuses a
// password [CheckBreachedPassword] reports breached.
const (
	PasswordTooShort              PasswordRejection = "too_short"
	PasswordTooLong               PasswordRejection = "too_long"
	PasswordContainsUsername      PasswordRejection = "contains_username"
	PasswordContainsForbiddenWord PasswordRejection = "contains_forbidden_word"
	PasswordCommon                PasswordRejection = "common"
	PasswordBreached              PasswordRejection = "breached"
)

// PasswordRejections returns every PasswordRejection, in a stable order.
func PasswordRejections() []PasswordRejection {
	return []PasswordRejection{PasswordTooShort, PasswordTooLong, PasswordContainsUsername, PasswordContainsForbiddenWord, PasswordCommon, PasswordBreached}
}

// PasswordError reports a policy refusal. Min and Max carry the length
// bounds for "too_short" and "too_long" and are zero for every other Reason.
type PasswordError struct {
	Reason   PasswordRejection
	Min, Max int
}

// Error describes the refusal without the password.
func (e *PasswordError) Error() string {
	switch e.Reason {
	case PasswordTooShort:
		return fmt.Sprintf("access: password must be at least %d characters", e.Min)
	case PasswordTooLong:
		return fmt.Sprintf("access: password must be at most %d characters", e.Max)
	}
	return "access: password refused: " + string(e.Reason)
}

// ErrBreachCheckUnavailable reports that [CheckBreachedPassword] got no
// verdict.
var ErrBreachCheckUnavailable = errors.New("access: breached-password check unavailable")

// ValidatePasswordLength refuses a password shorter than [PasswordMinLength]
// or longer than [PasswordMaxLength] runes after NFC, with a
// *[PasswordError] whose Reason is "too_short" or "too_long".
func ValidatePasswordLength(password string) error {
	n := utf8.RuneCountInString(norm.NFC.String(password))
	switch {
	case n > PasswordMaxLength:
		return &PasswordError{Reason: PasswordTooLong, Min: PasswordMinLength, Max: PasswordMaxLength}
	case n < PasswordMinLength:
		return &PasswordError{Reason: PasswordTooShort, Min: PasswordMinLength, Max: PasswordMaxLength}
	}
	return nil
}

// PasswordContext carries the user-specific values a candidate password must
// not be. A field-named struct keeps the password and the username from
// being swapped silently as adjacent same-typed parameters.
//
// WARNING: the zero value FAILS OPEN: an empty Username and an empty
// ForbiddenWords compare against nothing, so a partial literal silently
// validates less. Populate every field the account has.
type PasswordContext struct {
	// Username is compared only when it has at least four runes after NFC.
	Username string
	// ForbiddenWords are app-specific words (site name, product name) the
	// password must not be; an entry of only digits, spaces and punctuation
	// refuses only a password equal to it.
	ForbiddenWords []string
}

// ValidatePasswordContext refuses a password that is one of pctx's words or a
// simple derivative of one, with a *[PasswordError] whose Reason is
// "contains_forbidden_word" or "contains_username". Both sides are NFC and
// case-folded, as [Hasher] hashes. It refuses the word itself, or the word's
// core once or repeated with only digits, spaces and punctuation around and
// between the copies (a core strips those from both ends). A password that only
// contains a word is accepted (NIST SP 800-63B-4 §3.1.1.2).
func ValidatePasswordContext(password string, pctx PasswordContext) error {
	folded := blocklist.Fold(password)
	for _, word := range pctx.ForbiddenWords {
		if word != "" && matchesWord(folded, blocklist.Fold(word)) {
			return &PasswordError{Reason: PasswordContainsForbiddenWord}
		}
	}
	if utf8.RuneCountInString(norm.NFC.String(pctx.Username)) >= contextMinUsernameRunes && matchesWord(folded, blocklist.Fold(pctx.Username)) {
		return &PasswordError{Reason: PasswordContainsUsername}
	}
	return nil
}

// matchesWord reports whether the folded password is the folded word, or its
// core is the word's core repeated with only separators between the copies.
// The whole-value comparison catches a word whose core is empty.
func matchesWord(password, word string) bool {
	if password == word {
		return true
	}
	core := strings.TrimFunc(word, isPasswordSeparator)
	if core == "" {
		return false
	}
	rest := strings.TrimFunc(password, isPasswordSeparator)
	for {
		var ok bool
		if rest, ok = strings.CutPrefix(rest, core); !ok {
			return false
		}
		if rest == "" {
			return true
		}
		rest = strings.TrimLeftFunc(rest, isPasswordSeparator)
	}
}

func isPasswordSeparator(r rune) bool {
	return unicode.IsDigit(r) || unicode.IsSpace(r) || unicode.IsPunct(r)
}

// ValidatePasswordCommon refuses a password on the embedded list of common
// passwords (NIST SP 800-63B-4 §3.1.1.2), with a *[PasswordError] whose
// Reason is "common". The list holds SecLists' most frequent passwords that
// reach [PasswordMinLength] runes after NFC and case folding, the form the
// comparison uses; a shorter password is [ValidatePasswordLength]'s to
// refuse.
func ValidatePasswordCommon(password string) error {
	if blocklist.Contains(password) {
		return &PasswordError{Reason: PasswordCommon}
	}
	return nil
}

// CheckBreachedPassword reports whether the Have I Been Pwned Passwords API
// lists the password, sending only the first five hex characters of the SHA-1
// of its NFC form (k-anonymity). It never logs or follows a redirect. A nil
// client, a failed request, a non-200 status, a failed read or a body over 2 MiB
// returns false and an error wrapping [ErrBreachCheckUnavailable], naming the
// cause but not the URL, and also wrapping ctx.Err() once ctx has ended.
func CheckBreachedPassword(ctx context.Context, client *http.Client, password string) (bool, error) {
	if client == nil {
		return false, breachUnavailable(ctx, "no HTTP client")
	}
	hash := sha1.Sum([]byte(norm.NFC.String(password))) //nolint:gosec // SHA-1 required by HIBP k-anonymity API
	hexHash := fmt.Sprintf("%X", hash)
	prefix := hexHash[:5]
	suffix := hexHash[5:]

	reqCtx, cancel := context.WithTimeout(ctx, hibpRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		"https://api.pwnedpasswords.com/range/"+prefix, http.NoBody)
	if err != nil {
		return false, breachUnavailable(ctx, "building the request failed")
	}
	req.Header.Set("User-Agent", "Auth-Library")
	req.Header.Set("Add-Padding", "true")

	// A followed redirect would send the hash prefix wherever the response
	// points; the copy leaves the caller's client as it was.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return false, breachUnavailable(ctx, failureCause("request", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, hibpDrainMax))
		return false, breachUnavailable(ctx, "unexpected status "+strconv.Itoa(resp.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, hibpMaxBody+1))
	if err != nil {
		return false, breachUnavailable(ctx, failureCause("reading the response", err))
	}
	if len(body) > hibpMaxBody {
		return false, breachUnavailable(ctx, "response over 2 MiB")
	}

	for line := range strings.SplitSeq(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], suffix) {
			continue
		}
		count, convErr := strconv.Atoi(strings.TrimSpace(parts[1]))
		if convErr != nil || count <= 0 {
			continue
		}
		return true, nil
	}

	return false, nil
}

// breachUnavailable wraps ErrBreachCheckUnavailable with cause, and with
// ctx's error once ctx has ended. Callers pass a fixed cause, never a
// transport error's text: the *url.Error net/http returns names the URL.
func breachUnavailable(ctx context.Context, cause string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %s: %w", ErrBreachCheckUnavailable, cause, ctxErr)
	}
	return fmt.Errorf("%w: %s", ErrBreachCheckUnavailable, cause)
}

// failureCause names a failed step as timed out or failed.
func failureCause(step string, err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return step + " timed out"
	}
	return step + " failed"
}
