package account_test

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// shownCode is design 4.6's displayed form: 16 Crockford symbols in four
// groups of four (crockford.com/base32.html, no I L O U).
var shownCode = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

// requireIssued checks shown is a recovery code in its displayed form whose
// salted hash, and only that, is u's stored record (NIST SP 800-63B-4
// §4.2.1.1: at least 64 bits, stored hashed).
func requireIssued(t *testing.T, f *sfFixture, u *access.User, shown access.Secret) {
	t.Helper()
	code := shown.Reveal()
	if !shownCode.MatchString(code) {
		t.Fatalf("recovery code %q is not XXXX-XXXX-XXXX-XXXX in Crockford symbols", code)
	}
	if bits := 5 * len(strings.ReplaceAll(code, "-", "")); bits < 64 {
		t.Errorf("recovery code holds %d bits, want at least 64", bits)
	}
	rec, found, err := f.mem.RecoveryCodeByUserID(t.Context(), u.ID)
	if err != nil || !found {
		t.Fatalf("RecoveryCodeByUserID = %t, %v; want the issued code stored", found, err)
	}
	if strings.Contains(rec.Hash.Reveal(), strings.ReplaceAll(code, "-", "")) {
		t.Error("the record holds the code in clear")
	}
	ok, _, err := f.hasher.Verify(t.Context(), strings.ReplaceAll(code, "-", ""), rec.Hash)
	if err != nil || !ok {
		t.Errorf("the stored hash verifies the code = %t, %v; want true", ok, err)
	}
}

// requireNoCode checks the answer carried no recovery code and none is
// stored but the one before.
func requireNoCode(t *testing.T, f *sfFixture, u *access.User, shown access.Secret, before bool) {
	t.Helper()
	if !shown.IsZero() {
		t.Errorf("the answer carries recovery code %q, want none", shown.Reveal())
	}
	if _, found, err := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); err != nil || found != before {
		t.Errorf("a recovery code stored = %t, %v; want %t", found, err, before)
	}
	if n := len(eventsOf(f.events, account.EventRecoveryCodeIssued)); n != 0 {
		t.Errorf("recovery_code_issued events = %d, want 0", n)
	}
}

// registerWith registers dev for pr's user with proof and returns the
// answer.
func registerWith(t *testing.T, f *sfFixture, pr access.Principal, dev *accesstest.PasskeyDevice, proof account.SecondFactorProof) (account.Registered, error) {
	t.Helper()
	pc, err := f.svc.PasskeyRegisterBegin(t.Context(), localClient, pr, f.origin, proof)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin = %v", err)
	}
	return f.svc.PasskeyRegisterFinish(t.Context(), pr, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
}

// TestRecoveryCodeIssueRule is design 4.6 and 4.50: an Update that adds a
// password or a second factor issues a recovery code when the user then
// holds a password, a usable second factor and no code, carried once in
// that Update's answer.
func TestRecoveryCodeIssueRule(t *testing.T) {
	t.Parallel()
	t.Run("totp_enrolment", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		e, err := f.svc.BeginTOTP(t.Context(), pr)
		if err != nil {
			t.Fatalf("BeginTOTP = %v", err)
		}
		done, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secretOf(t, e))})
		if err != nil {
			t.Fatalf("FinishTOTP = %v", err)
		}
		requireIssued(t, f, u, done.RecoveryCode)
		if evs := eventsOf(f.events, account.EventRecoveryCodeIssued); len(evs) != 1 || evs[0].UserID != u.ID || evs[0].Actor.SessionID != pr.SessionID {
			t.Errorf("recovery_code_issued events = %+v, want one by the session", evs)
		}
	})
	// Design 4.6: a code is issued once; a binding while one is held
	// issues none.
	t.Run("totp_replacement_keeps_the_code", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		old := sealTOTP(t, f.mem, f.sealer, u)
		storeRecoveryCode(t, f.mem, u)
		e, err := f.svc.BeginTOTP(t.Context(), pr)
		if err != nil {
			t.Fatalf("BeginTOTP = %v", err)
		}
		done, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secretOf(t, e)), CurrentCode: codeNow(old)})
		if err != nil {
			t.Fatalf("FinishTOTP = %v", err)
		}
		requireNoCode(t, f, u, done.RecoveryCode, true)
	})
	// Design 4.50: a password user's first usable passkey under the rule is
	// a second factor; a second passkey finds the code held.
	t.Run("first_usable_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		first := accesstest.NewPasskeyDevice(t)
		reg, err := registerWith(t, f, f.sessionPrincipal(t, u, time.Now()), first, account.SecondFactorProof{})
		if err != nil {
			t.Fatalf("PasskeyRegisterFinish = %v", err)
		}
		requireIssued(t, f, u, reg.RecoveryCode)
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		proof := account.ProofPasskey(pc.ID, first.Assert(browserJSON(t, pc.Assertion)))
		again, err := registerWith(t, f, pr, accesstest.NewPasskeyDevice(t), proof)
		if err != nil {
			t.Fatalf("the second PasskeyRegisterFinish = %v", err)
		}
		if !again.RecoveryCode.IsZero() {
			t.Errorf("the second passkey answers recovery code %q, want none", again.RecoveryCode.Reveal())
		}
		if n := len(eventsOf(f.events, account.EventRecoveryCodeIssued)); n != 1 {
			t.Errorf("recovery_code_issued events = %d, want the first passkey's one", n)
		}
	})
	// Design 4.4: password and a passkey is a second factor only under the
	// rule, so with it off the passkey issues nothing.
	t.Run("passkey_without_the_rule", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		reg, err := registerWith(t, f, f.sessionPrincipal(t, u, time.Now()), accesstest.NewPasskeyDevice(t), account.SecondFactorProof{})
		if err != nil {
			t.Fatalf("PasskeyRegisterFinish = %v", err)
		}
		requireNoCode(t, f, u, reg.RecoveryCode, false)
	})
	// Design 4.50, 4.4: a passkey the app's MethodUsable refuses is not a
	// usable second factor.
	t.Run("passkey_not_usable", func(t *testing.T) {
		t.Parallel()
		refusesPasskeys := func(_ context.Context, _ account.Tx, _ *access.User, m access.Method) bool {
			return m != access.MethodPasskey
		}
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		f.set(account.Rules{RequireSecondFactor: true, MethodUsable: refusesPasskeys})
		pc, err := f.svc.PasskeyRegisterBegin(t.Context(), localClient, pr, f.origin, account.SecondFactorProof{})
		if err != nil {
			t.Fatalf("PasskeyRegisterBegin = %v", err)
		}
		reg, err := f.svc.PasskeyRegisterFinish(t.Context(), pr, pc.ID, bytes.NewReader(accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))))
		if err != nil {
			t.Fatalf("PasskeyRegisterFinish = %v", err)
		}
		requireNoCode(t, f, u, reg.RecoveryCode, false)
	})
	// Design 4.50: a passkey user's first password under the rule leaves
	// password and passkey held.
	t.Run("first_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		addPasskey(t, f.mem, u, rpID)
		set, err := f.svc.SetPassword(t.Context(), localClient, f.sessionPrincipal(t, u, time.Now()), access.Secret{}, access.NewSecret(newPassword))
		if err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		requireIssued(t, f, u, set.RecoveryCode)
		if set.Issued.Token.IsZero() {
			t.Error("SetPassword answered no rotated session")
		}
	})
	t.Run("first_password_with_a_code_held", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		addPasskey(t, f.mem, u, rpID)
		storeRecoveryCode(t, f.mem, u)
		set, err := f.svc.SetPassword(t.Context(), localClient, f.sessionPrincipal(t, u, time.Now()), access.Secret{}, access.NewSecret(newPassword))
		if err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		requireNoCode(t, f, u, set.RecoveryCode, true)
	})
	// Design 4.4: a passkey under an old relying-party ID is not usable.
	t.Run("first_password_beside_an_old_rp_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		addPasskey(t, f.mem, u, "old.example.com")
		set, err := f.svc.SetPassword(t.Context(), localClient, f.sessionPrincipal(t, u, time.Now()), access.Secret{}, access.NewSecret(newPassword))
		if err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		requireNoCode(t, f, u, set.RecoveryCode, false)
	})
	t.Run("changed_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sealTOTP(t, f.mem, f.sealer, u)
		set, err := f.svc.SetPassword(t.Context(), localClient, f.sessionPrincipal(t, u, time.Now()), access.NewSecret(goodPassword), access.NewSecret(newPassword))
		if err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		if !set.RecoveryCode.IsZero() {
			t.Errorf("a changed password answers recovery code %q, want none", set.RecoveryCode.Reveal())
		}
	})
}

// TestRegenerateRecoveryCode is design 4.6's replacement on request.
func TestRegenerateRecoveryCode(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*sfFixture, *access.User, access.Principal, []byte) {
		t.Helper()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		storeRecoveryCode(t, f.mem, u)
		return f, u, f.sessionPrincipal(t, u, time.Now()), secret
	}
	t.Run("replaces_with_a_code", func(t *testing.T) {
		t.Parallel()
		f, u, pr, secret := setup(t)
		before, _, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID)
		code := codeNow(secret)
		shown, err := f.svc.RegenerateRecoveryCode(t.Context(), clientAt(1), pr, account.ProofCode(code))
		if err != nil {
			t.Fatalf("RegenerateRecoveryCode = %v", err)
		}
		requireIssued(t, f, u, shown)
		if after, _, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); after.Hash.Equal(before.Hash) {
			t.Error("the old code's hash is still stored")
		}
		if evs := eventsOf(f.events, account.EventRecoveryCodeReplaced); len(evs) != 1 || evs[0].Actor.SessionID != pr.SessionID {
			t.Errorf("recovery_code_replaced events = %+v, want one by the session", evs)
		}
		// RFC 6238 §5.2: the proof's code is spent.
		if _, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, code); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the proof's code at step-up = %v, want code_reused", err)
		}
	})
	t.Run("with_a_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		f.enrol(t, u, dev)
		sealTOTP(t, f.mem, f.sealer, u)
		storeRecoveryCode(t, f.mem, u)
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		shown, err := f.svc.RegenerateRecoveryCode(t.Context(), clientAt(1), pr, account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion))))
		if err != nil {
			t.Fatalf("RegenerateRecoveryCode with a passkey = %v", err)
		}
		requireIssued(t, f, u, shown)
	})
	refusals := []struct {
		name  string
		want  error
		proof func(secret []byte) account.SecondFactorProof
		edit  func(t *testing.T, f *sfFixture, u *access.User, pr *access.Principal)
	}{
		{name: "no_proof", want: account.ErrSecondFactorProofRequired, proof: func([]byte) account.SecondFactorProof { return account.SecondFactorProof{} }},
		{name: "wrong_code", want: account.ErrCodeInvalid, proof: func(s []byte) account.SecondFactorProof {
			return account.ProofCode(codeAt(s, time.Now().Add(-time.Hour)))
		}},
		{name: "plain", want: access.ErrHTTPSRequired, edit: func(_ *testing.T, _ *sfFixture, _ *access.User, pr *access.Principal) { pr.Secure = false }},
		{name: "not_recent", want: access.ErrRecentAuthRequired, edit: func(t *testing.T, f *sfFixture, u *access.User, pr *access.Principal) {
			*pr = f.sessionPrincipal(t, u, time.Now().Add(-time.Hour))
		}},
		{name: "no_code_held", want: account.ErrNotFound, edit: func(t *testing.T, f *sfFixture, u *access.User, _ *access.Principal) {
			if err := f.mem.DeleteRecoveryCode(t.Context(), u.ID); err != nil {
				t.Fatalf("DeleteRecoveryCode: %v", err)
			}
		}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, u, pr, secret := setup(t)
			if tc.edit != nil {
				tc.edit(t, f, u, &pr)
			}
			proof := account.ProofCode(codeNow(secret))
			if tc.proof != nil {
				proof = tc.proof(secret)
			}
			before, held, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID)
			if _, err := f.svc.RegenerateRecoveryCode(t.Context(), clientAt(1), pr, proof); !errors.Is(err, tc.want) {
				t.Fatalf("RegenerateRecoveryCode = %v, want %v", err, tc.want)
			}
			if after, found, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); found != held || !after.Hash.Equal(before.Hash) {
				t.Error("a refused regeneration changed the stored code")
			}
		})
	}
}

// TestMethodsRecoveryCode is MethodsView.recovery_code (design 4.12).
func TestMethodsRecoveryCode(t *testing.T) {
	t.Parallel()
	f := newSF(t, account.Rules{}, pwOptions{})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	pr := f.sessionPrincipal(t, u, time.Now())
	if me, err := f.svc.Me(t.Context(), pr); err != nil || me.Methods.RecoveryCode {
		t.Fatalf("Me = %t, %v; want recovery_code false with none held", me.Methods.RecoveryCode, err)
	}
	storeRecoveryCode(t, f.mem, u)
	if me, err := f.svc.Me(t.Context(), pr); err != nil || !me.Methods.RecoveryCode {
		t.Errorf("Me = %t, %v; want recovery_code true", me.Methods.RecoveryCode, err)
	}
}
