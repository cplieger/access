package account_test

import (
	"encoding/base32"
	"strconv"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/totp"
)

// testIssuer is the TOTPConfig.Issuer every TOTP fixture wires.
const testIssuer = "Example"

// sealTOTP stores a fresh TOTP record for u, its secret sealed at rest
// under sealer with design 4.3's purpose "totp:" + the user's ID, and
// returns the secret.
func sealTOTP(t testing.TB, s account.Store, sealer *access.Sealer, u *access.User) []byte {
	t.Helper()
	secret := totp.NewSecret()
	sealed, err := sealer.SealAtRest("totp:"+strconv.FormatInt(u.ID, 10), secret)
	if err != nil {
		t.Fatalf("SealAtRest: %v", err)
	}
	created := time.Now().Add(-time.Minute) // before any enrolment the test then begins
	if err := s.SetTOTP(t.Context(), access.TOTP{UserID: u.ID, Sealed: sealed, CreatedAt: created}); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	return secret
}

// codeAt is secret's code for the RFC 6238 §4.2 step of at.
func codeAt(secret []byte, at time.Time) string { return totp.Code(secret, totp.Step(at)) }

// codeNow is secret's code for the current step.
func codeNow(secret []byte) string { return codeAt(secret, time.Now()) }

// secretOf decodes an enrolment's text key, RFC 4648 §6 base32 without
// padding, back to the secret.
func secretOf(t testing.TB, e account.TOTPEnrolment) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Text.Reveal())
	if err != nil {
		t.Fatalf("the enrolment's text key %q is not RFC 4648 base32: %v", e.Text.Reveal(), err)
	}
	return b
}

// totpRecord is u's stored TOTP record.
func totpRecord(t testing.TB, s account.Store, userID int64) (access.TOTP, bool) {
	t.Helper()
	rec, found, err := s.TOTPByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("TOTPByUserID: %v", err)
	}
	return rec, found
}

// totpFailures is u's TOTP failure record in one trust context.
func totpFailures(t testing.TB, s account.Store, svc *account.Service, name string, trusted bool) (account.FailureCount, bool) {
	t.Helper()
	rec, found, err := s.AuthFailure(t.Context(), account.FailureRef{Name: account.FailureName(svc, name), Method: access.MethodTOTP, Trusted: trusted})
	if err != nil {
		t.Fatalf("AuthFailure: %v", err)
	}
	return rec, found
}
