package account_test

import (
	"context"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// storeFailure stores f as name's record.
func storeFailure(t testing.TB, s account.Store, svc *account.Service, f account.FailureCount, name string) {
	t.Helper()
	f.Name = account.FailureName(svc, name)
	if err := s.PutAuthFailure(t.Context(), f); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
}

// failureOf is name's record of method in one trust context.
func failureOf(t testing.TB, s account.Store, svc *account.Service, name string, m access.Method, trusted bool) (account.FailureCount, bool) {
	t.Helper()
	rec, found, err := s.AuthFailure(t.Context(), account.FailureRef{Name: account.FailureName(svc, name), Method: m, Trusted: trusted})
	if err != nil {
		t.Fatalf("AuthFailure: %v", err)
	}
	return rec, found
}

// sweepOnce arms hk to run the failure sweep once, as the cleanup loop
// would between a count and its success.
func sweepOnce(t *testing.T, hk *armed, svc *account.Service) {
	hk.arm(func(ctx context.Context) {
		hk.disarm()
		if err := account.SweepFailures(ctx, svc); err != nil {
			t.Errorf("SweepFailures: %v", err)
		}
	})
}

// requireReenabled requires the sweep's one method_locked of m and then
// one method_reenabled of m in the untrusted context by actor, and m's
// record gone.
func requireReenabled(t *testing.T, f *sfFixture, u *access.User, m access.Method, actor account.EventActor) {
	t.Helper()
	if evs := eventsOf(f.events, account.EventMethodLocked); len(evs) != 1 || evs[0].Method != m {
		t.Fatalf("method_locked events = %+v, want the sweep's one for %s", evs, m)
	}
	evs := eventsOf(f.events, account.EventMethodReenabled)
	if len(evs) != 1 || evs[0].Method != m || evs[0].Trusted || evs[0].UserID != u.ID || evs[0].Actor != actor {
		t.Errorf("method_reenabled events = %+v, want one of %s, untrusted, for user %d by %+v", evs, m, u.ID, actor)
	}
	if rec, found := failureOf(t, f.mem, f.svc, "alice", m, false); found {
		t.Errorf("%s record after the success = %+v, want the lock its own count set gone", m, rec)
	}
}

// requireKeptLock requires m's untrusted record to hold the lock at
// lockedAt at Count 0 and no method_reenabled.
func requireKeptLock(t *testing.T, f *sfFixture, m access.Method, lockedAt time.Time) {
	t.Helper()
	rec, found := failureOf(t, f.mem, f.svc, "alice", m, false)
	if !found || !rec.Locked || rec.Count != 0 || !rec.LockedAt.Equal(lockedAt) {
		t.Errorf("%s record after the success = %+v (found %t), want the other attempt's lock at %v kept at Count 0", m, rec, found, lockedAt)
	}
	if evs := eventsOf(f.events, account.EventMethodReenabled); len(evs) != 0 {
		t.Errorf("method_reenabled events = %+v, want none for a lock the success did not set", evs)
	}
}

// requireOwnRecordsOnly requires no recorded call to read or write a
// failure record of the untrusted context, nor to delete both contexts.
func requireOwnRecordsOnly(t *testing.T, fs *faultStore) {
	t.Helper()
	for _, c := range fs.recorded() {
		switch c.name {
		case "DeleteAuthFailures":
			t.Errorf("the trusted success called DeleteAuthFailures(%s), which removes both trust contexts", c.arg)
		case "AuthFailure", "PutAuthFailure", "DeleteAuthFailure":
			if !c.ref.Trusted {
				t.Errorf("the trusted success called %s(%+v) on the untrusted context", c.name, c.ref)
			}
		}
	}
}

// otherLock is a lock another concurrent attempt set, earlier than any
// lock the step's own count could stamp.
var otherLock = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// TestOwnContextReset checks that a correct secret clears only its own
// trust context's record, every counted method alike: device cookies count
// untrusted clients apart, so the holder's success never refills a guesser's
// budget (OWASP, "Slow Down Online Guessing Attacks with Device Cookies").
// It clears its own count, or the lock that count set, journalling
// method_reenabled once the sweep had reported it; another attempt's lock
// stays at Count 0.
func TestOwnContextReset(t *testing.T) {
	t.Parallel()
	t.Run("sign_in_code_clears_its_reported_lock", func(t *testing.T) {
		t.Parallel()
		var hk armed
		o := pwOptions{}
		o.hooks.CodeCounted = hk.hook
		f := newSF(t, account.Rules{}, o)
		u, ticket, secret := codeTicket(t, f, clientAt(1))
		storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodTOTP, Count: account.FailureCap - 1}, "alice")
		sweepOnce(t, &hk, f.svc)
		out, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret))
		if err != nil || out.Pending != nil {
			t.Fatalf("the right code at FailureCap-1 = %+v, %v; want a sign-in", out, err)
		}
		requireReenabled(t, f, u, access.MethodTOTP, account.EventActor{UserID: u.ID, SessionID: out.SignedIn.Session.ID})
	})
	t.Run("step_up_code_clears_its_reported_lock", func(t *testing.T) {
		t.Parallel()
		var hk armed
		o := pwOptions{}
		o.hooks.CodeCounted = hk.hook
		f := newSF(t, account.Rules{}, o)
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now().Add(-time.Hour))
		storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodTOTP, Count: account.FailureCap - 1}, "alice")
		sweepOnce(t, &hk, f.svc)
		if _, err := f.svc.StepUpCode(t.Context(), clientAt(1), pr, codeNow(secret)); err != nil {
			t.Fatalf("StepUpCode with the right code at FailureCap-1 = %v", err)
		}
		requireReenabled(t, f, u, access.MethodTOTP, account.EventActor{UserID: u.ID, SessionID: pr.SessionID})
	})
	t.Run("proof_code_clears_its_reported_lock", func(t *testing.T) {
		t.Parallel()
		var hk armed
		o := pwOptions{}
		o.hooks.CodeCounted = hk.hook
		f := newSF(t, account.Rules{}, o)
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		pr := f.sessionPrincipal(t, u, time.Now())
		storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodTOTP, Count: account.FailureCap - 1}, "alice")
		sweepOnce(t, &hk, f.svc)
		if _, err := f.svc.PasskeyRegisterBegin(t.Context(), clientAt(1), pr, f.origin, account.ProofCode(codeNow(secret))); err != nil {
			t.Fatalf("PasskeyRegisterBegin with the right proof code at FailureCap-1 = %v", err)
		}
		requireReenabled(t, f, u, access.MethodTOTP, account.EventActor{UserID: u.ID, SessionID: pr.SessionID})
	})
	t.Run("recovery_code_clears_its_reported_lock", func(t *testing.T) {
		t.Parallel()
		var hk armed
		o := pwOptions{}
		o.hooks.CodeCounted = hk.hook
		f := newSF(t, account.Rules{}, o)
		u, ticket, _ := recoveryTicket(t, f, clientAt(1))
		storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodRecoveryCode, Count: account.FailureCap - 1}, "alice")
		sweepOnce(t, &hk, f.svc)
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
		requireReenabled(t, f, u, access.MethodRecoveryCode, account.EventActor{UserID: u.ID})
	})
	t.Run("code_keeps_another_attempts_lock", func(t *testing.T) {
		t.Parallel()
		var f *sfFixture
		o := pwOptions{}
		o.hooks.CodeCounted = func(context.Context) {
			storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodTOTP, Count: account.FailureCap, Locked: true, LockedAt: otherLock}, "alice")
		}
		f = newSF(t, account.Rules{}, o)
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
			t.Fatalf("the right code counted before another attempt locked = %v, want a sign-in", err)
		}
		requireKeptLock(t, f, access.MethodTOTP, otherLock)
	})
	t.Run("recovery_code_keeps_another_attempts_lock", func(t *testing.T) {
		t.Parallel()
		var f *sfFixture
		o := pwOptions{}
		o.hooks.CodeCounted = func(context.Context) {
			storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodRecoveryCode, Count: account.FailureCap, Locked: true, LockedAt: otherLock}, "alice")
		}
		f = newSF(t, account.Rules{}, o)
		_, ticket, _ := recoveryTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithRecoveryCode(t.Context(), clientAt(1), ticket, knownRecoveryShown)
		recovered(t, out, err, access.MethodTOTP, access.MethodPasskey)
		requireKeptLock(t, f, access.MethodRecoveryCode, otherLock)
	})
	t.Run("trusted_password_keeps_the_untrusted_count", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", 5)
		if _, err := p.login(t.Context(), trusted, "alice", goodPassword); err != nil {
			t.Fatalf("trusted right password = %v, want a sign-in", err)
		}
		if rec, found := record(t, p.mem, p.svc, "alice", false); !found || rec.Count != 5 || rec.Locked {
			t.Errorf("untrusted record after the trusted success = %+v (found %t), want its count of 5 kept", rec, found)
		}
	})
	t.Run("guard:untrusted_code_keeps_the_trusted_count", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		storeFailure(t, f.mem, f.svc, account.FailureCount{Method: access.MethodTOTP, Trusted: true, Count: 5}, "alice")
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
			t.Fatalf("SignInWithCode = %v", err)
		}
		if rec, found := failureOf(t, f.mem, f.svc, "alice", access.MethodTOTP, true); !found || rec.Count != 5 || rec.Locked {
			t.Errorf("trusted TOTP record after an untrusted success = %+v (found %t), want its count of 5 kept", rec, found)
		}
	})
	t.Run("touches_only_its_own_context", func(t *testing.T) {
		t.Parallel()
		for _, m := range []access.Method{access.MethodPassword, access.MethodTOTP, access.MethodRecoveryCode} {
			t.Run(string(m), func(t *testing.T) {
				t.Parallel()
				fs := newFaultStore()
				f := newSF(t, account.Rules{}, pwOptions{store: fs})
				u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
				trusted := clientAt(1)
				trusted.Device = f.knownDevice("alice")
				for _, isTrusted := range []bool{false, true} {
					storeFailure(t, f.mem, f.svc, account.FailureCount{Method: m, Trusted: isTrusted, Count: 5}, "alice")
				}
				var run func() error
				switch m {
				case access.MethodPassword:
					run = func() error { _, err := f.login(t.Context(), trusted, "alice", goodPassword); return err }
				case access.MethodTOTP:
					secret := sealTOTP(t, f.mem, f.sealer, u)
					ticket := pending(t, mustStep1(t, f, trusted), nil, account.NextSecondFactor, access.MethodTOTP).Ticket
					run = func() error {
						_, err := f.svc.SignInWithCode(t.Context(), trusted, ticket, codeNow(secret))
						return err
					}
				default:
					sealTOTP(t, f.mem, f.sealer, u)
					storeKnownRecoveryCode(t, f, u)
					ticket := pending(t, mustStep1(t, f, trusted), nil, account.NextSecondFactor, access.MethodTOTP, access.MethodRecoveryCode).Ticket
					run = func() error {
						_, err := f.svc.SignInWithRecoveryCode(t.Context(), trusted, ticket, knownRecoveryShown)
						return err
					}
				}
				fs.resetRecord()
				if err := run(); err != nil {
					t.Fatalf("the trusted %s step = %v, want it to pass", m, err)
				}
				requireOwnRecordsOnly(t, fs)
				if rec, found := failureOf(t, f.mem, f.svc, "alice", m, true); found {
					t.Errorf("trusted %s record after its success = %+v, want it gone", m, rec)
				}
				if rec, found := failureOf(t, f.mem, f.svc, "alice", m, false); !found || rec.Count != 5 {
					t.Errorf("untrusted %s record after the trusted success = %+v (found %t), want its count of 5 kept", m, rec, found)
				}
			})
		}
	})
}

// mustStep1 is alice's step 1 from c with the right password.
func mustStep1(t *testing.T, f *sfFixture, c account.Client) account.LoginResult {
	t.Helper()
	out, err := f.step1(t.Context(), c, "alice", goodPassword)
	if err != nil {
		t.Fatalf("step 1 = %v", err)
	}
	return out
}
