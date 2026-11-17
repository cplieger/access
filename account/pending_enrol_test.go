package account_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

// knownRecoveryCode is a recovery code's 16 Crockford symbols
// (crockford.com/base32.html: 80 bits, no I L O U), and knownRecoveryShown
// its displayed form.
const (
	knownRecoveryCode  = "7K3M9QW2XZ8R4T6V"
	knownRecoveryShown = "7K3M-9QW2-XZ8R-4T6V"
)

// storeKnownRecoveryCode gives u knownRecoveryCode, stored as its salted
// hash the way the Service stores one (NIST SP 800-63B-4 §3.1.2).
func storeKnownRecoveryCode(t testing.TB, f *sfFixture, u *access.User) {
	t.Helper()
	h, err := f.hasher.Hash(t.Context(), knownRecoveryCode)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := f.mem.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: u.ID, Hash: h}); err != nil {
		t.Fatalf("SetRecoveryCode: %v", err)
	}
}

// recoveryTicket gives a password user alice a sealed TOTP record and
// knownRecoveryCode, and answers her pending sign-in from c, with the
// record's secret.
func recoveryTicket(t *testing.T, f *sfFixture, c account.Client) (*access.User, access.Secret, []byte) {
	t.Helper()
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	secret := sealTOTP(t, f.mem, f.sealer, u)
	storeKnownRecoveryCode(t, f, u)
	out, err := f.step1(t.Context(), c, "alice", goodPassword)
	return u, pending(t, out, err, account.NextSecondFactor, access.MethodTOTP, access.MethodRecoveryCode).Ticket, secret
}

// recovered requires out to be design 4.6's answer to a matched recovery
// code: a NextEnrol ticket marked Recovered listing methods, and no session.
func recovered(t testing.TB, out account.LoginResult, err error, methods ...access.Method) *account.Pending {
	t.Helper()
	p := pending(t, out, err, account.NextEnrol, methods...)
	if !p.Recovered {
		t.Fatal("the recovery code's NextEnrol is not marked recovered (design 4.6)")
	}
	return p
}

// pendingEnrolTOTP runs the pending TOTP enrolment on ticket from c and answers
// its finish.
func pendingEnrolTOTP(t *testing.T, f *sfFixture, c account.Client, ticket access.Secret) (account.SignedIn, []byte, error) {
	t.Helper()
	e, err := f.svc.PendingTOTPBegin(t.Context(), c, ticket)
	if err != nil {
		t.Fatalf("PendingTOTPBegin = %v", err)
	}
	secret := secretOf(t, account.TOTPEnrolment{URI: e.URI, Text: e.Text})
	out, err := f.svc.PendingTOTPFinish(t.Context(), c, ticket, codeNow(secret))
	return signedInOf(t, out), secret, err
}

// pendingEnrolPasskey registers dev on ticket's pending enrolment from c and
// answers its finish.
func pendingEnrolPasskey(t *testing.T, f *sfFixture, c account.Client, ticket access.Secret, dev *accesstest.PasskeyDevice) (account.SignedIn, error) {
	t.Helper()
	pc, err := f.svc.PendingPasskeyBegin(t.Context(), c, ticket, f.origin)
	if err != nil {
		t.Fatalf("PendingPasskeyBegin = %v", err)
	}
	out, err := f.svc.PendingPasskeyFinish(t.Context(), c, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
	return signedInOf(t, out), err
}

// signedInOf is out's sign-in; a finish that made its account wait fails
// the test.
func signedInOf(t testing.TB, out account.EnrolmentResult) account.SignedIn {
	t.Helper()
	if out.Waiting != nil {
		t.Fatalf("the finish made %q wait for approval, want a sign-in", out.Waiting.User.Username)
	}
	return out.SignedIn
}

// recoveryFailures is u's recovery-code failure record in one trust context.
func recoveryFailures(t testing.TB, f *sfFixture, name string, trusted bool) (account.FailureCount, bool) {
	t.Helper()
	rec, found, err := f.mem.AuthFailure(t.Context(), account.FailureRef{Name: account.FailureName(f.svc, name), Method: access.MethodRecoveryCode, Trusted: trusted})
	if err != nil {
		t.Fatalf("AuthFailure: %v", err)
	}
	return rec, found
}

// TestSignInWithRecoveryCode is design 4.6's recovery-code step: NIST SP
// 800-63B-4 §4.2.1.1's saved recovery code, used once after the password.
func TestSignInWithRecoveryCode(t *testing.T) {
	t.Parallel()
	// Design 4.6: the step commits nothing but the count and answers a
	// recovered NextEnrol, never a session.
	t.Run("answers_a_recovered_enrolment", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		p := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
		if live(f, ticket) {
			t.Error("the second-factor ticket outlived its replacement (design 4.4)")
		}
		got, ok := account.TicketOf(f.svc, p.Ticket)
		if !ok || !got.Recovered || got.UserID != u.ID {
			t.Errorf("the replacement = %+v, %t; want alice's recovered ticket", got, ok)
		}
		if _, found := totpRecord(t, f.mem, u.ID); !found {
			t.Error("the step deleted the TOTP record; only the enrolment finish does")
		}
		if _, found, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); !found {
			t.Error("the step spent the recovery code; only the enrolment finish does")
		}
		if sessions, _ := f.mem.SessionsByUserID(t.Context(), u.ID); len(sessions) != 0 {
			t.Errorf("the step created %d sessions, want none", len(sessions))
		}
		if rec, _ := recoveryFailures(t, f, "alice", false); rec.Count != 1 {
			t.Errorf("recovery-code failure count = %d, want the step's one count", rec.Count)
		}
		if n := len(eventsOf(f.events, account.EventRecoveryCodeUsed)); n != 0 {
			t.Errorf("recovery_code_used events = %d, want 0 before the finish", n)
		}
	})
	// Design 4.6: Crockford's decode table on input, ASCII only.
	for name, typed := range map[string]string{
		"lower_case":       "7k3m9qw2xz8r4t6v",
		"spaces":           "7K3M 9QW2 XZ8R 4T6V",
		"no_dashes":        knownRecoveryCode,
		"mixed_separators": " 7k3m-9qw2 xz8r-4t6v ",
	} {
		t.Run("normalises_"+name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{})
			_, ticket, _ := recoveryTicket(t, f, clientAt(1))
			out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, typed)
			recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
		})
	}
	// crockford.com/base32.html: O and o read as 0, I i L l as 1.
	t.Run("normalises_look_alikes", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sealTOTP(t, f.mem, f.sealer, u)
		h, err := f.hasher.Hash(t.Context(), "0011K3M9QW2XZ8R4")
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if err := f.mem.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: u.ID, Hash: h}); err != nil {
			t.Fatalf("SetRecoveryCode: %v", err)
		}
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		ticket := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP, access.MethodRecoveryCode).Ticket
		out, err = f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, "oOiL-k3m9-qw2x-z8r4")
		recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
	})
	// Design 4.4 step 0 and 4.6: Go and JavaScript case mapping disagree on
	// ß and ı, so neither reads as a letter; a malformed code counts nothing.
	for name, typed := range map[string]string{
		"sharp_s":        "7K3M-9QW2-XZ8R-4Tß",
		"dotless_i":      "ı" + knownRecoveryCode[1:],
		"fullwidth":      "７" + knownRecoveryCode[1:],
		"fifteen":        knownRecoveryCode[1:],
		"seventeen":      knownRecoveryCode + "0",
		"excluded_u":     "U" + knownRecoveryCode[1:],
		"empty":          "",
		"padding_symbol": knownRecoveryCode[:15] + "=",
	} {
		t.Run("malformed_"+name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{limiter: ipLimit(1)})
			_, ticket, _ := recoveryTicket(t, f, clientAt(1))
			_, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(2), ticket, typed)
			var me *account.MalformedError
			if !errors.As(err, &me) || me.Field != "code" {
				t.Fatalf("SignInWithRecoveryCode(%q) = %v, want a MalformedError on code", typed, err)
			}
			if _, found := recoveryFailures(t, f, "alice", false); found {
				t.Error("a malformed code was counted")
			}
			if !live(f, ticket) {
				t.Error("a malformed code ended the ticket")
			}
			out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(2), ticket, knownRecoveryShown)
			recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
		})
	}
	// NIST SP 800-63B-4 §3.1.2.1: a look-up secret is throttled; design 4.6
	// on (username, recovery_code), the ticket kept for a retry.
	t.Run("wrong_code", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		for range 2 {
			_, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, "0000-0000-0000-0000")
			if codeReason(err) != account.ReasonCodeInvalid {
				t.Fatalf("a wrong code = %v, want code_invalid", err)
			}
		}
		if !live(f, ticket) {
			t.Fatal("a wrong code ended the ticket")
		}
		if rec, _ := recoveryFailures(t, f, "alice", false); rec.Count != 2 {
			t.Errorf("recovery-code failure count = %d, want 2", rec.Count)
		}
		evs := eventsOf(f.events, account.EventSecondFactorFailed)
		if len(evs) != 1 || evs[0].Method != access.MethodRecoveryCode || evs[0].UserID != u.ID {
			t.Errorf("second_factor_failed = %+v, want one recovery_code entry for alice (design 4.4)", evs)
		}
	})
	t.Run("locked", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, _ := recoveryTicket(t, f, clientAt(1))
		ref := account.FailureRef{Name: account.FailureName(f.svc, "alice"), Method: access.MethodRecoveryCode}
		if err := f.mem.PutAuthFailure(t.Context(), account.FailureCount{FailureRef: ref, Count: account.FailureCap, Locked: true}); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
		_, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		if codeReason(err) != account.ReasonMethodLocked {
			t.Errorf("the right code on a locked method = %v, want method_locked", err)
		}
	})
	// Design 4.6: refused over plain before the code is read.
	t.Run("plain_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		plain := clientAt(1)
		plain.Secure = false
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sealTOTP(t, f.mem, f.sealer, u)
		storeKnownRecoveryCode(t, f, u)
		out, err := f.step1(t.Context(), plain, "alice", goodPassword)
		ticket := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP).Ticket
		if _, err := f.svc.SignInWithRecoveryCode(t.Context(), plain, ticket, "not even a code"); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a plain recovery step = %v, want access.ErrHTTPSRequired", err)
		}
		if !live(f, ticket) {
			t.Error("a plain ticket refused on its own transport was dropped (design 4.4)")
		}
	})
	t.Run("ticket_not_listing_it", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, _ := codeTicket(t, f, clientAt(1))
		if _, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a recovery step on a totp-only ticket = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Design 4.4 step 5: a record deleted between the steps ends the ticket.
	t.Run("code_gone", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		if err := f.mem.DeleteRecoveryCode(t.Context(), u.ID); err != nil {
			t.Fatalf("DeleteRecoveryCode: %v", err)
		}
		if _, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("a step after the code went = %v, want access.ErrTokenInvalid", err)
		}
		if live(f, ticket) {
			t.Error("the ticket outlived its record")
		}
	})
	// Design 4.4's ticket-method tests: with DisableTOTP on, a
	// password-and-passkey user under the rule is asked for a passkey or
	// the recovery code, and the recovery step answers NextEnrol [passkey].
	t.Run("disable_totp_enrols_a_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true, DisableTOTP: true}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		f.enrol(t, u, accesstest.NewPasskeyDevice(t))
		storeKnownRecoveryCode(t, f, u)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		ticket := pending(t, out, err, account.NextSecondFactor, access.MethodPasskey, access.MethodRecoveryCode).Ticket
		out, err = f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		recovered(t, out, err, access.MethodPasskey)
	})
	// Design 4.4: a hook refusing passkeys gets no passkey at the
	// recovery-code replacement.
	t.Run("hook_refusing_passkeys", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{edit: allowOnly(access.MethodPassword)})
		_, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		recovered(t, out, err, access.MethodTOTP)
	})
	// Design 4.4: an empty enrolment set at the replacement is
	// no_usable_method, and the replaced ticket ends.
	t.Run("no_usable_method", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{edit: allowOnly(access.MethodPassword)})
		_, ticket, _ := recoveryTicket(t, f, clientAt(1))
		f.set(account.Rules{DisableTOTP: true})
		if _, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown); !errors.Is(err, account.ErrNoUsableMethod) {
			t.Fatalf("a recovery whose enrolment set is empty = %v, want ErrNoUsableMethod", err)
		}
		if live(f, ticket) {
			t.Error("the replaced ticket outlived no_usable_method")
		}
	})
}

// TestRecoveryCompletes is design 4.6's enrolment finish committing the
// recovery: NIST SP 800-63B-4 §4.2.1.1, a saved recovery code is used once
// and the CSP SHALL issue a new one.
func TestRecoveryCompletes(t *testing.T) {
	t.Parallel()
	t.Run("by_totp", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, oldSecret := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		next := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey).Ticket
		in, newSecret, err := pendingEnrolTOTP(t, f, clientAt(1), next)
		if err != nil || in.User == nil || in.User.ID != u.ID {
			t.Fatalf("PendingTOTPFinish = %v, want alice signed in", err)
		}
		if sess := storedSession(t, f.mem, u.ID, in.Session.ID); sess.AuthMethod != access.MethodPassword {
			t.Errorf("session method = %s, want password (design 4.4 step 3)", sess.AuthMethod)
		}
		requireIssued(t, f, u, in.RecoveryCode)
		if in.RecoveryCode.Reveal() == knownRecoveryShown {
			t.Error("the finish issued the code it spent")
		}
		if bytes.Equal(newSecret, oldSecret) {
			t.Error("the enrolment drew the lost secret again")
		}
		if live(f, next) {
			t.Error("the enrolment ticket outlived its sign-in")
		}
		if _, found := recoveryFailures(t, f, "alice", false); found {
			t.Error("the recovery left the recovery code's failure record (design 4.6)")
		}
		removed := eventsOf(f.events, account.EventTOTPRemoved)
		if len(removed) != 1 || removed[0].UserID != u.ID {
			t.Errorf("totp_removed = %+v, want the lost TOTP's one entry", removed)
		}
		for _, kind := range []account.EventKind{account.EventRecoveryCodeUsed, account.EventTOTPAdded, account.EventRecoveryCodeIssued} {
			evs := eventsOf(f.events, kind)
			if len(evs) != 1 || evs[0].UserID != u.ID || evs[0].Actor.UserID != u.ID {
				t.Errorf("%s = %+v, want one entry by alice", kind, evs)
			}
		}
		// The old code is spent: alice's next sign-in refuses it.
		ticket = again(t, f, clientAt(1))
		if _, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown); codeReason(err) != account.ReasonCodeInvalid {
			t.Errorf("the spent code = %v, want code_invalid", err)
		}
	})
	t.Run("by_passkey_under_the_rule", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		next := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey).Ticket
		in, err := pendingEnrolPasskey(t, f, clientAt(1), next, accesstest.NewPasskeyDevice(t))
		if err != nil || in.User == nil {
			t.Fatalf("PendingPasskeyFinish = %v, want alice signed in", err)
		}
		requireIssued(t, f, u, in.RecoveryCode)
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the recovery kept the lost TOTP")
		}
		if n := len(eventsOf(f.events, account.EventPasskeyAdded)); n != 1 {
			t.Errorf("passkey_added events = %d, want 1", n)
		}
	})
	// Design 4.6's issue rule: with the rule off a password and a passkey
	// hold no second factor (4.4), so the finish issues no code.
	t.Run("by_passkey_rule_off_issues_none", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		next := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey).Ticket
		in, err := pendingEnrolPasskey(t, f, clientAt(1), next, accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("PendingPasskeyFinish = %v", err)
		}
		requireNoCode(t, f, u, in.RecoveryCode, false)
		if n := len(eventsOf(f.events, account.EventRecoveryCodeUsed)); n != 1 {
			t.Errorf("recovery_code_used events = %d, want 1", n)
		}
	})
	// Design 4.6: an abandoned recovery leaves the old code and TOTP.
	t.Run("abandoned", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, secret := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		next := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey).Ticket
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), next); err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		ticket = again(t, f, clientAt(1))
		if live(f, next) {
			t.Error("a new step 1 left the abandoned enrolment's ticket")
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
			t.Fatalf("the old TOTP after an abandoned recovery = %v, want a sign-in", err)
		}
		if _, found, _ := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); !found {
			t.Error("an abandoned recovery spent the code")
		}
	})
	// The code that matched must still be the user's at the finish: one
	// replaced meanwhile ends the ticket and nothing is written.
	t.Run("code_replaced_between", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		next := recovered(t, out, err, access.MethodTOTP, access.MethodPasskey).Ticket
		e, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), next)
		if err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		storeRecoveryCode(t, f.mem, u)
		secret := secretOf(t, account.TOTPEnrolment{Text: e.Text})
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), next, codeNow(secret)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("a finish after the code changed = %v, want access.ErrTokenInvalid", err)
		}
		if live(f, next) {
			t.Error("the ticket outlived its spent proof")
		}
		if n := len(eventsOf(f.events, account.EventRecoveryCodeUsed)); n != 0 {
			t.Errorf("recovery_code_used events = %d, want 0", n)
		}
	})
}

// TestPendingEnrolment is design 4.4's and 4.8's NextEnrol for an existing
// user under Rules.RequireSecondFactor, from a known device.
func TestPendingEnrolment(t *testing.T) {
	t.Parallel()
	enrolTicket := func(t *testing.T, f *sfFixture) (*access.User, access.Secret) {
		t.Helper()
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		c := clientAt(1)
		c.Device = f.knownDevice("alice")
		out, err := f.step1(t.Context(), c, "alice", goodPassword)
		p := pending(t, out, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		if p.Recovered {
			t.Fatal("a first enrolment is marked recovered")
		}
		return u, p.Ticket
	}
	rule := account.Rules{RequireSecondFactor: true}
	t.Run("totp", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		u, ticket := enrolTicket(t, f)
		in, secret, err := pendingEnrolTOTP(t, f, clientAt(1), ticket)
		if err != nil || in.User == nil || in.User.ID != u.ID {
			t.Fatalf("PendingTOTPFinish = %v, want alice signed in", err)
		}
		if in.DeviceCookie.IsZero() {
			t.Error("a completed sign-in answered no device cookie")
		}
		requireIssued(t, f, u, in.RecoveryCode)
		rec, found := totpRecord(t, f.mem, u.ID)
		if !found {
			t.Fatal("the enrolment stored no TOTP record")
		}
		// RFC 6238 §5.2: the confirming code is spent.
		ticket = again(t, f, clientAt(1))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the confirming code replayed at sign-in = %v, want code_reused (LastStep %d)", err, rec.LastStep)
		}
		if n := len(eventsOf(f.events, account.EventRecoveryCodeUsed)); n != 0 {
			t.Errorf("recovery_code_used events = %d, want 0 for a first enrolment", n)
		}
	})
	t.Run("passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		u, ticket := enrolTicket(t, f)
		in, err := pendingEnrolPasskey(t, f, clientAt(1), ticket, accesstest.NewPasskeyDevice(t))
		if err != nil || in.User == nil || in.User.ID != u.ID {
			t.Fatalf("PendingPasskeyFinish = %v, want alice signed in", err)
		}
		requireIssued(t, f, u, in.RecoveryCode)
		if pks, _ := f.mem.PasskeysByUserID(t.Context(), u.ID); len(pks) != 1 {
			t.Errorf("passkeys = %d, want the one enrolled", len(pks))
		}
	})
	t.Run("wrong_code_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, ticket := enrolTicket(t, f)
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket); err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, "000000"); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("a wrong code = %v, want code_invalid", err)
		}
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, "12345"); !errors.Is(err, account.ErrCodeMalformed) {
			t.Fatalf("a five-digit code = %v, want ErrCodeMalformed", err)
		}
		if !live(f, ticket) {
			t.Error("a refused code ended the enrolment ticket")
		}
	})
	// NIST SP 800-63B-4 §3.2.2: the finish is rate-limited like its begin,
	// so a spent IP request budget refuses a well-formed wrong code.
	t.Run("finish_limited", func(t *testing.T) {
		t.Parallel()
		limited := func(err error) bool { _, ok := errors.AsType[*ratelimit.RefusedError](err); return ok }
		f := newSF(t, rule, pwOptions{limiter: func(c *ratelimit.Config) { c.Request = ratelimit.Rate{Limit: 1, Window: time.Hour} }})
		_, ticket := enrolTicket(t, f)
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket); err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, "000000"); !limited(err) {
			t.Errorf("a wrong code with the IP request budget spent = %v, want a *ratelimit.RefusedError", err)
		}
		if !live(f, ticket) {
			t.Error("the limiter's refusal ended the enrolment ticket")
		}
	})
	t.Run("finish_before_begin", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, ticket := enrolTicket(t, f)
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, "000000"); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a finish with no secret drawn = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Design 4.5's mirror: a second begin replaces the secret, so only the
	// newest shown secret binds.
	t.Run("begin_again_replaces_the_secret", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, ticket := enrolTicket(t, f)
		first, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket)
		if err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket); err != nil {
			t.Fatalf("PendingTOTPBegin again = %v", err)
		}
		old := secretOf(t, account.TOTPEnrolment{Text: first.Text})
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, codeNow(old)); codeReason(err) != account.ReasonCodeInvalid {
			t.Errorf("the replaced secret's code = %v, want code_invalid", err)
		}
	})
	// Design 4.7: under DisableTOTP the pending TOTP begin and finish answer
	// ErrTOTPDisabled and keep the ticket.
	t.Run("disable_totp", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, ticket := enrolTicket(t, f)
		f.set(account.Rules{RequireSecondFactor: true, DisableTOTP: true})
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("PendingTOTPBegin = %v, want ErrTOTPDisabled", err)
		}
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, "000000"); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("PendingTOTPFinish = %v, want ErrTOTPDisabled", err)
		}
		if !live(f, ticket) {
			t.Error("auth_totp_disabled ended the ticket (design 4.39)")
		}
		if _, err := pendingEnrolPasskey(t, f, clientAt(1), ticket, accesstest.NewPasskeyDevice(t)); err != nil {
			t.Errorf("the ticket's passkey enrolment after the switch = %v", err)
		}
	})
	// Design 4.4: a ticket finishes only on its own transport, and a
	// secure ticket sent in clear is dropped.
	t.Run("plain_drops_the_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{posture: access.PosturePerRequest})
		_, ticket := enrolTicket(t, f)
		plain := clientAt(1)
		plain.Secure = false
		if _, err := f.svc.PendingTOTPBegin(t.Context(), plain, ticket); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a plain enrolment = %v, want access.ErrHTTPSRequired", err)
		}
		if live(f, ticket) {
			t.Error("the secure ticket that crossed in clear was kept")
		}
	})
	t.Run("second_factor_ticket_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, _ := codeTicket(t, f, clientAt(1))
		if _, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("an enrolment on a second-factor ticket = %v, want access.ErrTokenInvalid", err)
		}
		if _, err := f.svc.PendingPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a passkey enrolment on a second-factor ticket = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Design 4.4 step 1: the finish re-checks what step 1 verified.
	t.Run("password_changed_between", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		u, ticket := enrolTicket(t, f)
		e, err := f.svc.PendingTOTPBegin(t.Context(), clientAt(1), ticket)
		if err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		h, err := f.hasher.Hash(t.Context(), "another password entirely")
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		stored := storedUser(t, f.mem, u.ID)
		stored.PasswordHash = h
		if err := f.mem.UpdateUser(t.Context(), stored); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		secret := secretOf(t, account.TOTPEnrolment{Text: e.Text})
		if _, err := f.svc.PendingTOTPFinish(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("a finish after the password changed = %v, want access.ErrTokenInvalid", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("a refused finish stored a TOTP record")
		}
	})
	t.Run("passkey_ceremony_once", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, ticket := enrolTicket(t, f)
		pc, err := f.svc.PendingPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin)
		if err != nil {
			t.Fatalf("PendingPasskeyBegin = %v", err)
		}
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if _, err := f.svc.PendingPasskeyFinish(t.Context(), clientAt(1), pc.ID, bytes.NewReader(body)); err != nil {
			t.Fatalf("first finish = %v", err)
		}
		if _, err := f.svc.PendingPasskeyFinish(t.Context(), clientAt(1), pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("the finish replayed = %v, want ErrCeremonyInvalid", err)
		}
	})
}
