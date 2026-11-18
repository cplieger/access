package account_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/totp"
	"github.com/cplieger/access/webauthn"
)

// enrolTOTP runs BeginTOTP and FinishTOTP for pr's user with the new
// secret's current code, and returns the secret.
func enrolTOTP(t *testing.T, f *sfFixture, pr access.Principal) []byte {
	t.Helper()
	e, err := f.svc.BeginTOTP(t.Context(), pr)
	if err != nil {
		t.Fatalf("BeginTOTP = %v", err)
	}
	secret := secretOf(t, e)
	if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}); err != nil {
		t.Fatalf("FinishTOTP = %v", err)
	}
	return secret
}

// TestBeginTOTP checks the enrolment start and the Key Uri Format.
func TestBeginTOTP(t *testing.T) {
	t.Parallel()
	t.Run("answers_the_uri_and_key", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		e, err := f.svc.BeginTOTP(t.Context(), f.sessionPrincipal(t, u, time.Now()))
		if err != nil {
			t.Fatalf("BeginTOTP = %v", err)
		}
		if secret := secretOf(t, e); len(secret) != totp.SecretBytes {
			t.Errorf("secret = %d bytes, want %d (RFC 4226 §4 R6)", len(secret), totp.SecretBytes)
		}
		uri, err := url.Parse(e.URI.Reveal())
		if err != nil {
			t.Fatalf("the URI does not parse: %v", err)
		}
		q := uri.Query()
		if uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Path != "/"+testIssuer+":alice" || q.Get("issuer") != testIssuer || q.Get("secret") != e.Text.Reveal() {
			t.Errorf("URI = %s, want otpauth://totp/%s:alice with the issuer and the text key (Key Uri Format)", e.URI.Reveal(), testIssuer)
		}
		if e.Ticket.IsZero() {
			t.Error("no enrolment ticket")
		}
	})
	refusals := []struct {
		name  string
		rules account.Rules
		want  error
		user  func(t *testing.T, f *sfFixture) access.Principal
	}{
		{name: "not_recent", want: access.ErrRecentAuthRequired, user: func(t *testing.T, f *sfFixture) access.Principal {
			return f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "alice", goodPassword), time.Now().Add(-time.Hour))
		}},
		{name: "plain", want: access.ErrHTTPSRequired, user: func(t *testing.T, f *sfFixture) access.Principal {
			p := f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "alice", goodPassword), time.Now())
			p.Secure = false
			return p
		}},
		{name: "disable_totp", rules: account.Rules{DisableTOTP: true}, want: account.ErrTOTPDisabled, user: func(t *testing.T, f *sfFixture) access.Principal {
			return f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "alice", goodPassword), time.Now())
		}},
		// A passkey-only user has no password for a code to
		// protect.
		{name: "no_password", want: account.ErrPasswordRequired, user: func(t *testing.T, f *sfFixture) access.Principal {
			u := passwordUser(t, f.mem, nil, "alice", "")
			addPasskey(t, f.mem, u, rpID)
			return f.sessionPrincipal(t, u, time.Now())
		}},
		// A dormant user adds no TOTP.
		{name: "dormant", want: account.ErrSSOOnly, user: func(t *testing.T, f *sfFixture) access.Principal {
			mustOwner(t, f.mem, "root")
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			linkIdentity(t, f.mem, u, access.OIDCIdentity{Issuer: "https://idp.example", Subject: "alice"})
			if err := f.mem.Update(t.Context(), func(tx account.Tx) error { return tx.SetSSOMode(t.Context(), account.SSOForLinked) }); err != nil {
				t.Fatalf("SetSSOMode: %v", err)
			}
			return f.sessionPrincipal(t, u, time.Now())
		}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{})
			pr := tc.user(t, f)
			before := account.PendingOf(f.svc).Len()
			if _, err := f.svc.BeginTOTP(t.Context(), pr); !errors.Is(err, tc.want) {
				t.Fatalf("BeginTOTP = %v, want %v", err, tc.want)
			}
			if n := account.PendingOf(f.svc).Len(); n != before {
				t.Errorf("pending entries %d to %d: a refused begin drew a secret", before, n)
			}
		})
	}
	// TOTP unwired answers ErrTOTPDisabled.
	t.Run("unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if _, err := f.svc.BeginTOTP(t.Context(), f.sessionPrincipal(t, u, time.Now())); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("BeginTOTP with TOTP unwired = %v, want ErrTOTPDisabled", err)
		}
	})
}

// TestFinishTOTP checks the enrolment and replacement.
func TestFinishTOTP(t *testing.T) {
	t.Parallel()
	begin := func(t *testing.T, f *sfFixture, pr access.Principal) (account.TOTPEnrolment, []byte) {
		t.Helper()
		e, err := f.svc.BeginTOTP(t.Context(), pr)
		if err != nil {
			t.Fatalf("BeginTOTP = %v", err)
		}
		return e, secretOf(t, e)
	}
	t.Run("enrols_with_the_step_spent", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		e, secret := begin(t, f, pr)
		code := codeNow(secret)
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: code}); err != nil {
			t.Fatalf("FinishTOTP = %v", err)
		}
		rec, found := totpRecord(t, f.mem, u.ID)
		if !found || rec.LastStep != totp.Step(time.Now()) {
			t.Fatalf("record = %+v, %t, want one whose LastStep is the confirming step", rec, found)
		}
		opened, current, err := f.sealer.OpenAtRest("totp:"+strconv.FormatInt(u.ID, 10), rec.Sealed)
		if err != nil || !current || !bytes.Equal(opened, secret) {
			t.Errorf("the stored secret opens as %v, %t, %v; want the enrolled secret under the first key", opened, current, err)
		}
		if strings.Contains(rec.Sealed, e.Text.Reveal()) {
			t.Error("the record holds the secret in clear")
		}
		if evs := eventsOf(f.events, account.EventTOTPAdded); len(evs) != 1 || evs[0].UserID != u.ID || evs[0].Actor.SessionID != pr.SessionID {
			t.Errorf("totp_added events = %+v, want one by the session", evs)
		}
		if _, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, code); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the confirming code at step-up = %v, want code_reused (RFC 6238 §5.2)", err)
		}
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: code}); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the spent ticket again = %v, want access.ErrTokenInvalid", err)
		}
	})
	t.Run("wrong_code_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		e, secret := begin(t, f, pr)
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeAt(secret, time.Now().Add(-5*totp.Period))}); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("a wrong code = %v, want code_invalid", err)
		}
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: "12 34"}); func() bool {
			me, ok := errors.AsType[*account.MalformedError](err)
			return !ok || me.Field != "code"
		}() {
			t.Errorf("a malformed code = %v, want a MalformedError for code", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Fatal("a refused finish stored a record")
		}
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}); err != nil {
			t.Errorf("the right code after a wrong one = %v", err)
		}
	})
	// A ticket from another session is refused.
	t.Run("other_session", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		e, secret := begin(t, f, f.sessionPrincipal(t, u, time.Now()))
		other := f.sessionPrincipal(t, u, time.Now())
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), other, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("another session's finish = %v, want access.ErrTokenInvalid", err)
		}
	})
	// LibreChat GHSA-45fp-6q26-wfgq: replacement needs the old secret's code.
	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		old := enrolTOTP(t, f, pr)
		e, secret := begin(t, f, pr)
		in := account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, in); !errors.Is(err, account.ErrSecondFactorProofRequired) {
			t.Fatalf("a replacement with no current code = %v, want ErrSecondFactorProofRequired", err)
		}
		in.CurrentCode = codeAt(old, time.Now().Add(-5*totp.Period))
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, in); codeReason(err) != account.ReasonCurrentCodeInvalid {
			t.Fatalf("a wrong current code = %v, want current_code_invalid", err)
		}
		in.CurrentCode = "x"
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, in); func() bool {
			me, ok := errors.AsType[*account.MalformedError](err)
			return !ok || me.Field != "current_code"
		}() {
			t.Errorf("a malformed current code = %v, want a MalformedError for current_code", err)
		}
		if rec, _ := totpFailures(t, f.mem, f.svc, "alice", false); rec.Count != 1 {
			t.Errorf("TOTP failures = %d, want the one wrong current code", rec.Count)
		}
		f.nextStep()
		in.CurrentCode = codeAt(old, f.now())
		in.Code = codeAt(secret, f.now())
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, in); err != nil {
			t.Fatalf("a replacement with the current code = %v", err)
		}
		if evs := eventsOf(f.events, account.EventTOTPReplaced); len(evs) != 1 {
			t.Errorf("totp_replaced events = %d, want 1", len(evs))
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("the replacement left the old secret's failures")
		}
		f.nextStep()
		if _, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, codeAt(old, f.now())); codeReason(err) != account.ReasonCodeInvalid {
			t.Errorf("the old secret after the replacement = %v, want code_invalid", err)
		}
	})
	// An older enrolment ticket cannot overwrite a newer device.
	t.Run("older_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		stale, staleSecret := begin(t, f, pr)
		time.Sleep(2 * time.Millisecond) // the records' CreatedAt is at the millisecond (rule 11)
		fresh := enrolTOTP(t, f, pr)
		f.nextStep()
		in := account.TOTPFinish{Ticket: stale.Ticket, Code: codeAt(staleSecret, f.now()), CurrentCode: codeAt(fresh, f.now())}
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, in); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a ticket older than the record = %v, want access.ErrTokenInvalid", err)
		}
	})
	// A password removed mid-enrolment refuses the finish
	// inside its Update.
	t.Run("password_removed_during_the_finish", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSF(t, account.Rules{}, pwOptions{store: fs})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		e, secret := begin(t, f, pr)
		var once sync.Once
		fs.onUpdate(func(ctx context.Context, _ int) {
			once.Do(func() {
				cur := storedUser(t, f.mem, u.ID)
				cur.PasswordHash = access.Hash{}
				if err := f.mem.UpdateUser(ctx, cur); err != nil {
					t.Errorf("UpdateUser: %v", err)
				}
			})
		})
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}); !errors.Is(err, account.ErrPasswordRequired) {
			t.Fatalf("FinishTOTP after the password went = %v, want ErrPasswordRequired", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the refused finish stored a TOTP record")
		}
	})
	t.Run("disable_totp_between", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pr := f.sessionPrincipal(t, u, time.Now())
		e, secret := begin(t, f, pr)
		f.set(account.Rules{DisableTOTP: true})
		if _, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeNow(secret)}); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("FinishTOTP under DisableTOTP = %v, want ErrTOTPDisabled", err)
		}
	})
}

// TestRemoveTOTP checks the removal, its proof and its guard.
func TestRemoveTOTP(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, r account.Rules) (*sfFixture, *access.User, access.Principal, []byte) {
		t.Helper()
		f := newSF(t, r, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		return f, u, f.sessionPrincipal(t, u, time.Now()), secret
	}
	t.Run("with_a_code", func(t *testing.T) {
		t.Parallel()
		f, u, pr, secret := setup(t, account.Rules{})
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, account.ProofCode(codeNow(secret))); err != nil {
			t.Fatalf("RemoveTOTP = %v", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the record is still stored")
		}
		if evs := eventsOf(f.events, account.EventTOTPRemoved); len(evs) != 1 || evs[0].Actor.SessionID != pr.SessionID {
			t.Errorf("totp_removed events = %+v, want one by the session", evs)
		}
	})
	// snipe-it GHSA-mr8g-2mj4-pcq2, FileRise GHSA-84hw-8g73-v3f8: no factor
	// change without the current factor.
	t.Run("no_proof", func(t *testing.T) {
		t.Parallel()
		f, u, pr, _ := setup(t, account.Rules{})
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, account.SecondFactorProof{}); !errors.Is(err, account.ErrSecondFactorProofRequired) {
			t.Fatalf("RemoveTOTP with no proof = %v, want ErrSecondFactorProofRequired", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); !found {
			t.Error("the refused removal deleted the record")
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("a missing proof was counted (decided before any count)")
		}
	})
	t.Run("wrong_code", func(t *testing.T) {
		t.Parallel()
		f, u, pr, secret := setup(t, account.Rules{})
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, account.ProofCode(codeAt(secret, time.Now().Add(-5*totp.Period)))); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("RemoveTOTP with a wrong code = %v, want code_invalid", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); !found {
			t.Error("the refused removal deleted the record")
		}
	})
	t.Run("with_a_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		f.enrol(t, u, dev)
		sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		proof := account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion)))
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, proof); err != nil {
			t.Fatalf("RemoveTOTP with a passkey = %v", err)
		}
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, proof); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("RemoveTOTP again = %v, want ErrNotFound", err)
		}
	})
	t.Run("assertion_spent_once", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		f.enrol(t, u, dev)
		sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		proof := account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion)))
		if _, err := f.svc.StepUpPasskeyFinish(t.Context(), clientAt(1), pr, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion)))); err != nil {
			t.Fatalf("StepUpPasskeyFinish = %v", err)
		}
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), f.sessionPrincipal(t, u, time.Now()), proof); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("a proof whose ceremony a step-up spent = %v, want ErrCeremonyInvalid", err)
		}
	})
	t.Run("none_held", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), f.sessionPrincipal(t, u, time.Now()), account.ProofCode("123456")); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("RemoveTOTP with no record = %v, want ErrNotFound", err)
		}
	})
	// Under the rule, a user cannot remove TOTP while their
	// passkey is unusable.
	t.Run("last_second_factor", func(t *testing.T) {
		t.Parallel()
		f, u, pr, secret := setup(t, account.Rules{RequireSecondFactor: true})
		addPasskey(t, f.mem, u, "old.example.com")
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, account.ProofCode(codeNow(secret))); !errors.Is(err, account.ErrLastSecondFactor) || !errors.Is(err, account.ErrLastMethod) {
			t.Fatalf("RemoveTOTP of the last usable factor = %v, want ErrLastSecondFactor", err)
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("the guard's refusal counted the code")
		}
		me, err := f.svc.Me(t.Context(), pr)
		if err != nil || me.Methods.TOTP.Removable || !me.Methods.TOTP.Usable {
			t.Errorf("Me totp = %+v, %v; want usable and not removable", me.Methods.TOTP, err)
		}
		addPasskey(t, f.mem, u, rpID)
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, account.ProofCode(codeNow(secret))); err != nil {
			t.Errorf("RemoveTOTP with a usable passkey kept = %v", err)
		}
	})
	// A record TOTP no longer reads is removed with no
	// proof, any proof ignored, but only by a recent session.
	t.Run("dormant_record", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name  string
			proof account.SecondFactorProof
		}{{name: "empty"}, {name: "with_a_code", proof: account.ProofCode("000000")}} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f, u, pr, _ := setup(t, account.Rules{DisableTOTP: true})
				old := f.sessionPrincipal(t, u, time.Now().Add(-time.Hour))
				if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), old, tc.proof); !errors.Is(err, access.ErrRecentAuthRequired) {
					t.Fatalf("a non-recent removal of a dormant record = %v, want access.ErrRecentAuthRequired", err)
				}
				if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), pr, tc.proof); err != nil {
					t.Fatalf("a recent removal of a dormant record = %v, want it removed", err)
				}
				if _, found := totpRecord(t, f.mem, u.ID); found {
					t.Error("the dormant record is still stored")
				}
			})
		}
	})
	// With TOTP unwired, a stored record is removed
	// by the dormant arm.
	t.Run("unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sealTOTP(t, f.mem, access.NewEphemeralSealer(), u)
		if err := f.svc.RemoveTOTP(t.Context(), clientAt(1), f.sessionPrincipal(t, u, time.Now()), account.SecondFactorProof{}); err != nil {
			t.Fatalf("RemoveTOTP with TOTP unwired = %v, want the dormant arm", err)
		}
		if _, found := totpRecord(t, f.mem, u.ID); found {
			t.Error("the record is still stored")
		}
	})
}

// TestStepUpCode checks the step-up by code.
func TestStepUpCode(t *testing.T) {
	t.Parallel()
	t.Run("rotates_to_totp", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now().Add(-time.Hour))
		code := codeNow(secret)
		is, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, code)
		if err != nil {
			t.Fatalf("StepUpCode = %v", err)
		}
		if is.Session.AuthMethod != access.MethodTOTP || time.Since(is.Session.AuthTime) > time.Minute || is.Session.ID != pr.SessionID {
			t.Errorf("session = %+v, want p's session at AuthTime now by totp", is.Session)
		}
		if is.Token.IsZero() || is.DeviceCookie.IsZero() {
			t.Error("a step-up answered no token or no device cookie")
		}
		if evs := eventsOf(f.events, account.EventSteppedUp); len(evs) != 1 || evs[0].Method != access.MethodTOTP {
			t.Errorf("stepped_up events = %+v, want one by totp", evs)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), again(t, f, clientAt(1)), code); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the step-up's code at sign-in = %v, want code_reused", err)
		}
	})
	t.Run("101_step_ups_never_lock", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now())
		for i := range 101 {
			is, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, codeAt(secret, f.nextStep()))
			if err != nil {
				t.Fatalf("step-up %d = %v", i+1, err)
			}
			pr = f.principal(t, is.Token)
		}
		if rec, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Errorf("record after 101 step-ups = %+v, want none", rec)
		}
	})
	// RFC 6238 §5.2: the proof sites share the code step's commit, so a
	// record replaced since the count takes no step of the old secret.
	t.Run("record_replaced_since_the_count", func(t *testing.T) {
		t.Parallel()
		var (
			f *sfFixture
			u *access.User
		)
		o := pwOptions{}
		o.hooks.CodeCounted = func(context.Context) { replaceTOTP(t, f.mem, f.sealer, u) }
		f = newSF(t, account.Rules{}, o)
		u = passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now().Add(-time.Hour))
		if _, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, codeNow(secret)); codeReason(err) != account.ReasonCodeInvalid {
			t.Errorf("the old secret's code = %v, want code_invalid", err)
		}
		if evs := eventsOf(f.events, account.EventSteppedUp); len(evs) != 0 {
			t.Errorf("stepped_up events = %d, want none", len(evs))
		}
		if rec, _ := totpRecord(t, f.mem, u.ID); rec.LastStep != 0 {
			t.Errorf("the new record's LastStep = %d, want 0", rec.LastStep)
		}
	})
	for _, tc := range []struct {
		name  string
		rules account.Rules
		plain bool
		none  bool
		want  error
	}{
		{name: "disable_totp", rules: account.Rules{DisableTOTP: true}, want: account.ErrTOTPDisabled},
		{name: "plain", plain: true, want: access.ErrHTTPSRequired},
		{name: "no_record", none: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			code := "123456"
			if !tc.none {
				code = codeNow(sealTOTP(t, f.mem, f.sealer, u))
			}
			c := clientAt(1)
			c.Secure = !tc.plain
			_, err := f.svc.StepUpCode(t.Context(), c, f.sessionPrincipal(t, u, time.Now()), code)
			switch {
			case tc.none && codeReason(err) != account.ReasonCodeInvalid:
				t.Errorf("StepUpCode with no record = %v, want code_invalid", err)
			case !tc.none && !errors.Is(err, tc.want):
				t.Errorf("StepUpCode = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestStepUpPasswordWhileHeld: a password never steps up a
// user who holds a second factor, and nothing is counted for the try.
func TestStepUpPasswordWhileHeld(t *testing.T) {
	t.Parallel()
	one := func(c *ratelimit.Config) { c.Account = ratelimit.Rate{Limit: 1, Window: time.Hour} }
	f := newSF(t, account.Rules{}, pwOptions{limiter: one})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	sealTOTP(t, f.mem, f.sealer, u)
	pr := f.sessionPrincipal(t, u, time.Now())
	reserved := f.counted.reserved.Load()
	_, err := f.svc.StepUpPassword(t.Context(), clientAt(1), pr, access.NewSecret(goodPassword))
	if !errors.Is(err, account.ErrSecondFactorHeld) || !errors.Is(err, account.ErrSecondFactorRequired) {
		t.Fatalf("StepUpPassword while a factor is held = %v, want ErrSecondFactorHeld", err)
	}
	if n := f.counted.reserved.Load() - reserved; n != 0 {
		t.Errorf("hash permits reserved = %d, want none", n)
	}
	if _, found := record(t, f.mem, f.svc, "alice", false); found {
		t.Error("the refusal wrote a password failure record")
	}
	res, err := f.limiter.Attempt(ratelimit.Attempt{OmitIP: true, Account: ratelimit.AccountKey("alice")})
	if err != nil {
		t.Errorf("the account's one attempt after the refusal = %v, want admitted: the refusal charged the limiter", err)
	} else {
		res.Cancel()
	}
	if got := storedSession(t, f.mem, u.ID, pr.SessionID); got.AuthTime.After(pr.AuthTime) {
		t.Error("the refused step-up refreshed the session")
	}
	bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
	if _, err := f.svc.StepUpPassword(t.Context(), clientAt(1), f.sessionPrincipal(t, bob, time.Now()), access.NewSecret(goodPassword)); err != nil {
		t.Errorf("a user with no factor stepping up by password = %v", err)
	}
}

// TestPasskeyChangesNeedAFactor: while a second
// factor is held, adding or removing a passkey takes a current one
// (Keycloak CVE-2026-3429).
func TestPasskeyChangesNeedAFactor(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, r account.Rules) (*sfFixture, *access.User, *accesstest.PasskeyDevice, access.PasskeyCredential, []byte) {
		t.Helper()
		f := newSF(t, r, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		pk := f.enrol(t, u, dev)
		return f, u, dev, pk, sealTOTP(t, f.mem, f.sealer, u)
	}
	t.Run("register_begin", func(t *testing.T) {
		t.Parallel()
		f, u, _, _, secret := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.SecondFactorProof{}); !errors.Is(err, account.ErrSecondFactorProofRequired) {
			t.Fatalf("PasskeyRegisterBegin with no proof = %v, want ErrSecondFactorProofRequired", err)
		}
		code := codeNow(secret)
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(code)); err != nil {
			t.Fatalf("PasskeyRegisterBegin with a code = %v", err)
		}
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(code)); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the proof's code again = %v, want code_reused", err)
		}
	})
	// The ceremony's place is held before the proof is spent, so a full
	// list refuses the begin and the same code still proves once a place
	// frees (RFC 6238 §5.2: a code is accepted once).
	t.Run("register_begin_full_list_spends_no_code", func(t *testing.T) {
		t.Parallel()
		f, u, _, _, secret := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		cache := account.PendingOf(f.svc)
		cache.SetMax(account.PurposeAddPasskey, 1)
		other := mustPut(t, cache, account.PurposeAddPasskey, access.User{ID: 999}, time.Now())
		code := codeNow(secret)
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(code)); !isRefused(err) {
			t.Fatalf("PasskeyRegisterBegin with the list full = %v, want refused", err)
		}
		if rec, _ := totpRecord(t, f.mem, u.ID); rec.LastStep != 0 {
			t.Errorf("LastStep after the refused begin = %d, want 0: the proof's code was spent", rec.LastStep)
		}
		cache.Drop(other)
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(code)); err != nil {
			t.Errorf("the same code once a place freed = %v, want the ceremony", err)
		}
	})
	t.Run("register_begin_full_list_keeps_the_step_up", func(t *testing.T) {
		t.Parallel()
		f, u, dev, _, _ := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		cache := account.PendingOf(f.svc)
		cache.SetMax(account.PurposeAddPasskey, 2)
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		other := mustPut(t, cache, account.PurposeAddPasskey, access.User{ID: 999}, time.Now())
		proof := account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion)))
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, proof); !isRefused(err) {
			t.Fatalf("PasskeyRegisterBegin with the list full = %v, want refused", err)
		}
		cache.Drop(other)
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, proof); err != nil {
			t.Errorf("the same assertion once a place freed = %v, want the ceremony: the refused begin spent its step-up", err)
		}
	})
	// The relying party checks the origin before the proof is read, so a
	// begin it refuses spends no code (RFC 6238 §5.2: a code is accepted
	// once) and no step-up ceremony (WebAuthn L3 §7.1: the origin is the
	// relying party's to refuse).
	t.Run("register_begin_rejected_origin_spends_no_code", func(t *testing.T) {
		t.Parallel()
		f, u, _, _, secret := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		code := codeNow(secret)
		var oe *webauthn.OriginError
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, rejectedOrigin(t), account.ProofCode(code)); !errors.As(err, &oe) {
			t.Fatalf("PasskeyRegisterBegin at a rejected origin = %v, want *webauthn.OriginError", err)
		}
		if rec, _ := totpRecord(t, f.mem, u.ID); rec.LastStep != 0 {
			t.Errorf("LastStep after the rejected origin = %d, want 0: the proof's code was spent", rec.LastStep)
		}
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(code)); err != nil {
			t.Errorf("the same code at the relying party's origin = %v, want the ceremony", err)
		}
	})
	t.Run("register_begin_rejected_origin_keeps_the_step_up", func(t *testing.T) {
		t.Parallel()
		f, u, dev, _, _ := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		proof := account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion)))
		var oe *webauthn.OriginError
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, rejectedOrigin(t), proof); !errors.As(err, &oe) {
			t.Fatalf("PasskeyRegisterBegin at a rejected origin = %v, want *webauthn.OriginError", err)
		}
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, proof); err != nil {
			t.Errorf("the same assertion at the relying party's origin = %v, want the ceremony: the rejected begin spent its step-up", err)
		}
	})
	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		f, u, _, pk, secret := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		if err := f.svc.RemovePasskey(t.Context(), clientAt(1), pr, pk.ID, account.SecondFactorProof{}); !errors.Is(err, account.ErrSecondFactorProofRequired) {
			t.Fatalf("RemovePasskey with no proof = %v, want ErrSecondFactorProofRequired", err)
		}
		if err := f.svc.RemovePasskey(t.Context(), clientAt(1), pr, pk.ID, account.ProofCode(codeNow(secret))); err != nil {
			t.Fatalf("RemovePasskey with a code = %v", err)
		}
	})
	// The passkey being removed may prove itself.
	t.Run("remove_with_its_own_assertion", func(t *testing.T) {
		t.Parallel()
		f, u, dev, pk, _ := setup(t, account.Rules{})
		pr := f.sessionPrincipal(t, u, time.Now())
		pc, err := f.svc.StepUpPasskeyBegin(t.Context(), pr, f.origin)
		if err != nil {
			t.Fatalf("StepUpPasskeyBegin = %v", err)
		}
		if err := f.svc.RemovePasskey(t.Context(), clientAt(1), pr, pk.ID, account.ProofPasskey(pc.ID, dev.Assert(browserJSON(t, pc.Assertion)))); err != nil {
			t.Errorf("RemovePasskey with its own assertion = %v", err)
		}
	})
	// Under the rule, the last passkey of a user with no usable
	// TOTP is refused, and its row is not removable.
	t.Run("last_second_factor", func(t *testing.T) {
		t.Parallel()
		f, u, _, pk, _ := setup(t, account.Rules{RequireSecondFactor: true, DisableTOTP: true})
		pr := f.sessionPrincipal(t, u, time.Now())
		listed, err := f.svc.Passkeys(t.Context(), pr)
		if err != nil || len(listed) != 1 || listed[0].Removable {
			t.Fatalf("Passkeys = %+v, %v; want one passkey that is not removable", listed, err)
		}
		if err := f.svc.RemovePasskey(t.Context(), clientAt(1), pr, pk.ID, account.SecondFactorProof{}); !errors.Is(err, account.ErrLastSecondFactor) {
			t.Errorf("RemovePasskey of the last usable factor = %v, want ErrLastSecondFactor", err)
		}
	})
	t.Run("removable_without_a_factor", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		pk := f.enrol(t, u, accesstest.NewPasskeyDevice(t))
		pr := f.sessionPrincipal(t, u, time.Now())
		if listed, err := f.svc.Passkeys(t.Context(), pr); err != nil || len(listed) != 1 || !listed[0].Removable {
			t.Fatalf("Passkeys = %+v, %v; want one removable passkey", listed, err)
		}
		if err := f.svc.RemovePasskey(t.Context(), clientAt(1), pr, pk.ID, account.SecondFactorProof{}); err != nil {
			t.Errorf("RemovePasskey with no factor held = %v", err)
		}
	})
}

// TestMeTOTP is MethodsView.totp's four fields.
func TestMeTOTP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                        string
		rules                       account.Rules
		record, stale               bool
		enrolled, usable, removable bool
	}{
		{name: "none"},
		{name: "usable", record: true, enrolled: true, usable: true, removable: true},
		{name: "disable_totp", rules: account.Rules{DisableTOTP: true}, record: true, enrolled: true, removable: true},
		{name: "rule_on_old_rp_passkey", rules: account.Rules{RequireSecondFactor: true}, record: true, stale: true, enrolled: true, usable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			if tc.record {
				sealTOTP(t, f.mem, f.sealer, u)
			}
			if tc.stale {
				addPasskey(t, f.mem, u, "old.example.com")
			}
			me, err := f.svc.Me(t.Context(), f.sessionPrincipal(t, u, time.Now()))
			if err != nil {
				t.Fatalf("Me = %v", err)
			}
			got := me.Methods.TOTP
			if got.Enrolled != tc.enrolled || got.Usable != tc.usable || got.Removable != tc.removable || got.Since.IsZero() == tc.record {
				t.Errorf("totp = %+v, want enrolled %t, usable %t, removable %t", got, tc.enrolled, tc.usable, tc.removable)
			}
		})
	}
}

// TestRemovePasswordDropsSecondFactors: with no password,
// TOTP and the recovery code protect nothing.
func TestRemovePasswordDropsSecondFactors(t *testing.T) {
	t.Parallel()
	f := newSF(t, account.Rules{}, pwOptions{})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	f.enrol(t, u, accesstest.NewPasskeyDevice(t))
	sealTOTP(t, f.mem, f.sealer, u)
	storeRecoveryCode(t, f.mem, u)
	pr := f.sessionPrincipal(t, u, time.Now())
	if _, err := f.svc.RemovePassword(t.Context(), clientAt(1), pr, access.NewSecret(goodPassword)); err != nil {
		t.Fatalf("RemovePassword = %v", err)
	}
	if _, found := totpRecord(t, f.mem, u.ID); found {
		t.Error("the TOTP record outlived the password")
	}
	if _, found, err := f.mem.RecoveryCodeByUserID(t.Context(), u.ID); err != nil || found {
		t.Errorf("the recovery code outlived the password (%v)", err)
	}
	if evs := eventsOf(f.events, account.EventTOTPRemoved); len(evs) != 1 || evs[0].Actor.SessionID != pr.SessionID {
		t.Errorf("totp_removed events = %+v, want one by the session", evs)
	}
}

// TestResealTOTP checks the re-sealing and its return contract: the
// counts so far, stopping at the first store error.
func TestResealTOTP(t *testing.T) {
	t.Parallel()
	oldKey, newKey := access.GenerateSealerKey(), access.GenerateSealerKey()
	sealer := func(t *testing.T, keys ...[]byte) *access.Sealer {
		t.Helper()
		s, err := access.NewSealer(keys...)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		return s
	}
	t.Run("four_arms", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSFSealed(t, sealer(t, newKey, oldKey), account.Rules{}, pwOptions{store: fs})
		users := make([]*access.User, 4)
		for i, name := range []string{"aold", "bcurrent", "clost", "dgone"} {
			users[i] = passwordUser(t, f.mem, f.hasher, name, goodPassword)
		}
		oldSecret := sealTOTP(t, f.mem, sealer(t, oldKey), users[0])
		rec, _ := totpRecord(t, f.mem, users[0].ID)
		rec.LastStep = 42
		if err := f.mem.SetTOTP(t.Context(), rec); err != nil {
			t.Fatalf("SetTOTP: %v", err)
		}
		sealTOTP(t, f.mem, sealer(t, newKey), users[1])
		current, _ := totpRecord(t, f.mem, users[1].ID)
		sealTOTP(t, f.mem, access.NewEphemeralSealer(), users[2])
		sealTOTP(t, f.mem, sealer(t, oldKey), users[3])
		var once sync.Once
		fs.onUpdate(func(ctx context.Context, _ int) {
			once.Do(func() {
				if err := f.mem.Update(ctx, func(tx account.Tx) error { return tx.DeleteTOTP(ctx, users[3].ID) }); err != nil {
					t.Errorf("DeleteTOTP: %v", err)
				}
			})
		})
		resealed, unopenable, err := f.svc.ResealTOTP(t.Context())
		if err != nil || resealed != 1 || unopenable != 1 {
			t.Fatalf("ResealTOTP = %d, %d, %v; want 1 resealed and 1 unopenable", resealed, unopenable, err)
		}
		after, _ := totpRecord(t, f.mem, users[0].ID)
		opened, cur, err := sealer(t, newKey).OpenAtRest("totp:"+strconv.FormatInt(users[0].ID, 10), after.Sealed)
		if err != nil || !cur || !bytes.Equal(opened, oldSecret) || after.LastStep != 42 {
			t.Errorf("the resealed record opens as %v, %t, %v with LastStep %d; want the secret under the new key alone, LastStep 42", opened, cur, err, after.LastStep)
		}
		if kept, _ := totpRecord(t, f.mem, users[1].ID); kept.Sealed != current.Sealed {
			t.Error("a record already under the first key was rewritten")
		}
		if errorLogs(f.logs) == 0 {
			t.Error("the unopenable record logged nothing at ERROR")
		}
	})
	t.Run("pages", func(t *testing.T) {
		t.Parallel()
		f := newSFSealed(t, sealer(t, newKey, oldKey), account.Rules{}, pwOptions{})
		old := sealer(t, oldKey)
		n := account.MaxSweepBatch + 1
		for id := int64(1); id <= int64(n); id++ {
			sealed, err := old.SealAtRest("totp:"+strconv.FormatInt(id, 10), totp.NewSecret())
			if err != nil {
				t.Fatalf("SealAtRest: %v", err)
			}
			if err := f.mem.SetTOTP(t.Context(), access.TOTP{UserID: id, Sealed: sealed, CreatedAt: time.Now()}); err != nil {
				t.Fatalf("SetTOTP: %v", err)
			}
		}
		if resealed, unopenable, err := f.svc.ResealTOTP(t.Context()); err != nil || resealed != n || unopenable != 0 {
			t.Errorf("ResealTOTP over two pages = %d, %d, %v; want %d, 0", resealed, unopenable, err, n)
		}
	})
	t.Run("stops_at_a_store_error", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSFSealed(t, sealer(t, newKey, oldKey), account.Rules{}, pwOptions{store: fs})
		for _, name := range []string{"a", "b", "c"} {
			sealTOTP(t, f.mem, sealer(t, oldKey), passwordUser(t, f.mem, f.hasher, name, goodPassword))
		}
		fs.failCallNth("SetTOTP", 2)
		resealed, unopenable, err := f.svc.ResealTOTP(t.Context())
		if !errors.Is(err, access.ErrAuthBackend) || resealed != 1 || unopenable != 0 {
			t.Errorf("ResealTOTP with the second write failing = %d, %d, %v; want 1, 0 and the store's error", resealed, unopenable, err)
		}
	})
	// A sign-in setting LastStep during the walk is kept.
	t.Run("keeps_a_concurrent_last_step", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSFSealed(t, sealer(t, newKey, oldKey), account.Rules{}, pwOptions{store: fs})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, sealer(t, oldKey), u)
		ticket := again(t, f, clientAt(1))
		type walk struct{}
		var once sync.Once
		fs.onUpdate(func(ctx context.Context, _ int) {
			if ctx.Value(walk{}) == nil {
				return
			}
			once.Do(func() {
				if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
					t.Errorf("the sign-in during the walk = %v", err)
				}
			})
		})
		if _, _, err := f.svc.ResealTOTP(context.WithValue(t.Context(), walk{}, true)); err != nil {
			t.Fatalf("ResealTOTP = %v", err)
		}
		if rec, _ := totpRecord(t, f.mem, u.ID); rec.LastStep != totp.Step(time.Now()) {
			t.Errorf("LastStep after the walk = %d, want the sign-in's %d: a burned code would match again", rec.LastStep, totp.Step(time.Now()))
		}
	})
	t.Run("unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		if _, _, err := f.svc.ResealTOTP(t.Context()); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("ResealTOTP with TOTP unwired = %v, want ErrTOTPDisabled", err)
		}
	})
}
