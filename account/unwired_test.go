package account_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// unwiredWorld is a Service with passkeys wired and TOTP unwired, under
// RequireSecondFactor, and alice holding a password, a usable passkey, a
// recovery code and a TOTP record sealed under a sealer the Service never
// holds, so opening the record cannot succeed.
type unwiredWorld struct {
	*pkFixture
	alice  *access.User
	pr     access.Principal
	secret []byte
	stored access.TOTP
}

func newUnwiredWorld(t *testing.T) *unwiredWorld {
	t.Helper()
	f := newPK(t, pwOptions{rules: func() account.Rules { return account.Rules{RequireSecondFactor: true} }})
	mustOwner(t, f.mem, "root")
	alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	f.enrol(t, alice, accesstest.NewPasskeyDevice(t))
	storeRecoveryCode(t, f.mem, alice)
	secret := sealTOTP(t, f.mem, access.NewEphemeralSealer(), alice)
	stored, _ := totpRecord(t, f.mem, alice.ID)
	return &unwiredWorld{pkFixture: f, alice: alice, pr: f.sessionPrincipal(t, alice, time.Now()), secret: secret, stored: stored}
}

// untouched requires alice's TOTP record as stored and no TOTP failure
// counted, the dormant record's state.
func (w *unwiredWorld) untouched(t *testing.T) {
	t.Helper()
	if rec, found := totpRecord(t, w.mem, w.alice.ID); !found || rec != w.stored {
		t.Errorf("TOTP record = %+v, %t; want it as stored, %+v", rec, found, w.stored)
	}
	for _, trusted := range []bool{false, true} {
		if n, found := totpFailures(t, w.mem, w.svc, "alice", trusted); found {
			t.Errorf("a TOTP failure was counted (trusted %t): %+v", trusted, n)
		}
	}
}

// TestTOTPUnwired is design 4.46's census for Config.TOTP unset: every
// operation that verifies a code, enrols or reseals answers
// ErrTOTPDisabled and writes nothing, a stored record is dormant and never
// opened, and the operations on stored records keep working (RULINGS M1
// addendum 2).
func TestTOTPUnwired(t *testing.T) {
	t.Parallel()
	ticket := access.NewSecret("any-ticket")
	for _, tc := range []struct {
		name string
		call func(t *testing.T, w *unwiredWorld) error
	}{
		{"SignInWithCode", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.SignInWithCode(t.Context(), localClient, ticket, codeNow(w.secret))
			return err
		}},
		{"StepUpCode", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.StepUpCode(t.Context(), localClient, w.pr, codeNow(w.secret))
			return err
		}},
		{"BeginTOTP", func(t *testing.T, w *unwiredWorld) error {
			before := account.PendingOf(w.svc).Len()
			_, err := w.svc.BeginTOTP(t.Context(), w.pr)
			if n := account.PendingOf(w.svc).Len(); n != before {
				t.Errorf("pending entries %d to %d: a refused begin drew a secret", before, n)
			}
			return err
		}},
		{"FinishTOTP", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.FinishTOTP(t.Context(), localClient, w.pr, account.TOTPFinish{Ticket: ticket, Code: "123456", CurrentCode: codeNow(w.secret)})
			return err
		}},
		{"PendingTOTPBegin", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.PendingTOTPBegin(t.Context(), localClient, ticket)
			return err
		}},
		{"PendingTOTPFinish", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.PendingTOTPFinish(t.Context(), localClient, ticket, "123456")
			return err
		}},
		{"ResealTOTP", func(t *testing.T, w *unwiredWorld) error {
			_, _, err := w.svc.ResealTOTP(t.Context())
			return err
		}},
		{"RegenerateRecoveryCode_code_proof", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.RegenerateRecoveryCode(t.Context(), localClient, w.pr, account.ProofCode(codeNow(w.secret)))
			return err
		}},
		{"PasskeyRegisterBegin_code_proof", func(t *testing.T, w *unwiredWorld) error {
			_, err := w.svc.PasskeyRegisterBegin(t.Context(), localClient, w.pr, w.origin, account.ProofCode(codeNow(w.secret)))
			return err
		}},
		{"RemovePasskey_code_proof", func(t *testing.T, w *unwiredWorld) error {
			extra := addPasskey(t, w.mem, w.alice, rpID) // a second one, so the removal passes its guards
			return w.svc.RemovePasskey(t.Context(), localClient, w.pr, extra.ID, account.ProofCode(codeNow(w.secret)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newUnwiredWorld(t)
			if err := tc.call(t, w); !errors.Is(err, account.ErrTOTPDisabled) {
				t.Errorf("%s with TOTP unwired = %v, want ErrTOTPDisabled", tc.name, err)
			}
			w.untouched(t)
		})
	}
	t.Run("RemoveTOTP_dormant_arm", func(t *testing.T) {
		t.Parallel()
		w := newUnwiredWorld(t)
		if err := w.svc.RemoveTOTP(t.Context(), localClient, w.pr, account.SecondFactorProof{}); err != nil {
			t.Fatalf("RemoveTOTP with TOTP unwired = %v, want the dormant arm", err)
		}
		if _, found := totpRecord(t, w.mem, w.alice.ID); found {
			t.Error("the record is still stored")
		}
	})
	t.Run("ResetSecondFactor", func(t *testing.T) {
		t.Parallel()
		w := newUnwiredWorld(t)
		if err := w.svc.ResetSecondFactor(t.Context(), account.OutOfBand("cli"), w.alice.ID); err != nil {
			t.Fatalf("ResetSecondFactor with TOTP unwired = %v, want nil", err)
		}
		if !secondFactorGone(t, w.mem, w.alice) {
			t.Error("the reset left alice's TOTP record or recovery code")
		}
	})
	t.Run("readers", func(t *testing.T) {
		t.Parallel()
		w := newUnwiredWorld(t)
		st, err := w.svc.State(t.Context(), localClient)
		if err != nil || st.TOTP {
			t.Errorf("State = %+v, %v; want TOTP false", st, err)
		}
		me, err := w.svc.Me(t.Context(), w.pr)
		if got := me.Methods.TOTP; err != nil || !got.Enrolled || got.Usable || !got.Removable {
			t.Errorf("Me TOTP = %+v, %v; want enrolled, not usable, removable", got, err)
		}
		w.untouched(t)
	})
}

// TestTOTPUnwiredRecordReadsAbsent is design 4.46's one predicate: with
// TOTP unwired a stored record holds no second factor, so a password user
// with no passkey signs in by password alone and steps up by password.
func TestTOTPUnwiredRecordReadsAbsent(t *testing.T) {
	t.Parallel()
	f := newPK(t, pwOptions{})
	bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
	stored := access.TOTP{UserID: bob.ID, Sealed: "sealed", CreatedAt: time.Now()}
	if err := f.mem.SetTOTP(t.Context(), stored); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	signedIn, err := f.login(t.Context(), clientAt(1), "bob", goodPassword)
	if err != nil {
		t.Fatalf("password sign-in of a user with an unwired TOTP record = %v, want signed in", err)
	}
	pr, err := f.authenticate(t.Context(), signedIn.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	me, err := f.svc.Me(t.Context(), pr)
	if err != nil || me.Methods.SecondFactorHeld || !me.Methods.PasswordStepUp {
		t.Errorf("Me = %+v, %v; want no second factor held and password step-up offered", me.Methods, err)
	}
	if _, err := f.stepUp(t.Context(), clientAt(1), pr, goodPassword); err != nil {
		t.Errorf("StepUpPassword = %v, want nil", err)
	}
	if rec, _ := totpRecord(t, f.mem, bob.ID); rec != stored {
		t.Errorf("TOTP record = %+v, want it as stored", rec)
	}
}

// TestRequireSecondFactorNeedsAWiredFactor is design 4.46's refusal of
// RequireSecondFactor with neither TOTP nor passkeys wired, at every
// operation after a reload and at CheckRules, as New refuses it.
func TestRequireSecondFactorNeedsAWiredFactor(t *testing.T) {
	t.Parallel()
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		var re *account.RulesError
		if !errors.Is(err, account.ErrRulesInvalid) || !errors.As(err, &re) || re.Field != "RequireSecondFactor" {
			t.Errorf("%s = %v, want a *RulesError for RequireSecondFactor", what, err)
		}
	}
	ruleOn := account.Rules{RequireSecondFactor: true}
	t.Run("nothing_wired", func(t *testing.T) {
		t.Parallel()
		var r atomic.Pointer[account.Rules]
		r.Store(&account.Rules{})
		f := newPW(t, pwOptions{rules: func() account.Rules { return *r.Load() }})
		passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		refused(t, "CheckRules", f.svc.CheckRules(t.Context(), ruleOn))
		r.Store(&ruleOn)
		_, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		refused(t, "PasswordLogin after a reload", err)
	})
	t.Run("passkeys_wired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		if err := f.svc.CheckRules(t.Context(), ruleOn); err != nil {
			t.Errorf("CheckRules with passkeys wired and TOTP unwired = %v, want nil", err)
		}
	})
}
