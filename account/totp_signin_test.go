package account_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/totp"
)

// codeTicket gives a password user alice a sealed TOTP record and answers
// her pending sign-in from c, with the record's secret.
func codeTicket(t *testing.T, f *sfFixture, c account.Client) (*access.User, access.Secret, []byte) {
	t.Helper()
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	secret := sealTOTP(t, f.mem, f.sealer, u)
	out, err := f.step1(t.Context(), c, "alice", goodPassword)
	return u, pending(t, out, err, account.NextSecondFactor, access.MethodTOTP).Ticket, secret
}

// again is alice's next pending sign-in from c.
func again(t *testing.T, f *sfFixture, c account.Client) access.Secret {
	t.Helper()
	out, err := f.step1(t.Context(), c, "alice", goodPassword)
	if err != nil || out.Pending == nil {
		t.Fatalf("step 1 = %v, want a pending sign-in", err)
	}
	return out.Pending.Ticket
}

// codeReason is err's CodeError Reason, "" for none.
func codeReason(err error) string {
	if ce, ok := errors.AsType[*account.CodeError](err); ok {
		return ce.Reason
	}
	return ""
}

func live(f *sfFixture, ticket access.Secret) bool {
	_, ok := account.TicketOf(f.svc, ticket)
	return ok
}

// TestSignInWithCode is design 4.4's code step against RFC 6238.
func TestSignInWithCode(t *testing.T) {
	t.Parallel()
	t.Run("signs_in", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, secret := codeTicket(t, f, clientAt(1))
		out, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret))
		if err != nil || out.Pending != nil || out.SignedIn.User == nil || out.SignedIn.User.ID != u.ID {
			t.Fatalf("SignInWithCode = %+v, %v, want alice signed in", out.Pending, err)
		}
		if sess := storedSession(t, f.mem, u.ID, out.SignedIn.Session.ID); sess.AuthMethod != access.MethodPassword {
			t.Errorf("session method = %s, want password (design 4.4 step 3)", sess.AuthMethod)
		}
		if out.SignedIn.DeviceCookie.IsZero() {
			t.Error("a completed sign-in answered no device cookie")
		}
		if live(f, ticket) {
			t.Error("the ticket outlived the sign-in it completed")
		}
		if rec, _ := totpRecord(t, f.mem, u.ID); rec.LastStep != totp.Step(time.Now()) {
			t.Errorf("LastStep = %d, want the matched step %d (RFC 6238 §5.2: accepted once)", rec.LastStep, totp.Step(time.Now()))
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("a matched code left its failure record")
		}
		if n := len(eventsOf(f.events, account.EventSignedIn)); n != 1 {
			t.Errorf("signed_in events = %d, want 1", n)
		}
	})
	// RFC 6238 §5.2 and §6: one step of drift either side; Keycloak
	// CVE-2024-7318 records the previous step's code as accepted on purpose.
	for _, tc := range []struct {
		name   string
		offset time.Duration
		ok     bool
	}{
		{name: "previous_step", offset: -totp.Period, ok: true},
		{name: "next_step", offset: totp.Period, ok: true},
		{name: "two_steps_back", offset: -2 * totp.Period},
		{name: "two_steps_ahead", offset: 2 * totp.Period},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{})
			now := time.Now()
			f.at.Store(&now)
			_, ticket, secret := codeTicket(t, f, clientAt(1))
			_, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeAt(secret, now.Add(tc.offset)))
			switch {
			case tc.ok && err != nil:
				t.Errorf("a code %s off = %v, want a sign-in", tc.offset, err)
			case !tc.ok && codeReason(err) != account.ReasonCodeInvalid:
				t.Errorf("a code %s off = %v, want code_invalid", tc.offset, err)
			}
		})
	}
	t.Run("wrong_code_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("a wrong code = %v, want code_invalid", err)
		}
		if !live(f, ticket) {
			t.Fatal("a wrong code ended the ticket (design 4.4: a wrong code leaves it usable)")
		}
		if rec, _ := totpFailures(t, f.mem, f.svc, "alice", false); rec.Count != 1 {
			t.Errorf("TOTP failure count = %d, want 1", rec.Count)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
			t.Fatalf("the right code after a wrong one = %v", err)
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("the success left the failure record")
		}
	})
	// NIST SP 800-63B-4 §3.2.2 counts failed attempts against the
	// subscriber's own authenticator: a ticket whose step 1 no longer holds
	// is ended at the count, so its wrong codes never reach the user's lock.
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *sfFixture, u *access.User)
	}{
		{name: "mode_made_dormant", change: func(t *testing.T, f *sfFixture, _ *access.User) { storeMode(t, f.mem, account.SSOOnly) }},
		{name: "password_changed", change: func(t *testing.T, f *sfFixture, u *access.User) {
			hash, err := f.hasher.Hash(t.Context(), goodPassword)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			u.PasswordHash = hash
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{name: "disabled", change: func(t *testing.T, f *sfFixture, u *access.User) {
			u.Enabled = false
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
	} {
		t.Run("wrong_code_after_"+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{})
			u, ticket, secret := codeTicket(t, f, clientAt(1))
			tc.change(t, f, storedUser(t, f.mem, u.ID))
			wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong); !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("a wrong code on the stale ticket = %v, want access.ErrTokenInvalid", err)
			}
			if live(f, ticket) {
				t.Error("the stale ticket outlived its refused step")
			}
			if rec, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
				t.Errorf("the stale ticket's wrong code wrote a failure record %+v", rec)
			}
		})
	}
	// logto GHSA-6wj7-c66m-6c82: a used code was accepted again in its window.
	t.Run("replay_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		code := codeNow(secret)
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, code); err != nil {
			t.Fatalf("first use = %v", err)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), again(t, f, clientAt(1)), code); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the replay = %v, want code_reused", err)
		}
	})
	// OpenBao GHSA-rxp7-9q75-vj3p: a spaced code is the same code for the
	// replay check and the count.
	t.Run("spaced_code_is_the_same_code", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		code := codeNow(secret)
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, code[:3]+" "+code[3:]); err != nil {
			t.Fatalf("a spaced code = %v, want a sign-in", err)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), again(t, f, clientAt(1)), code); codeReason(err) != account.ReasonCodeReused {
			t.Errorf("the unspaced replay = %v, want code_reused", err)
		}
	})
	// Design 4.4 step 0: a malformed code is refused before anything counts.
	t.Run("malformed", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: ipLimit(2)})
		_, ticket, _ := codeTicket(t, f, clientAt(1))
		for _, raw := range []string{"", "12345", "1234567", "١٢٣٤٥٦", "123-456", "12345\t6", "abcdef"} {
			_, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, raw)
			if me, ok := errors.AsType[*account.MalformedError](err); !ok || me.Field != "code" {
				t.Errorf("SignInWithCode(%q) = %v, want a MalformedError for code", raw, err)
			}
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("a malformed code was counted")
		}
		if !live(f, ticket) {
			t.Error("a malformed code ended the ticket")
		}
	})
	// Design 4.7: the switch refuses the code step and keeps the ticket.
	t.Run("disable_totp_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		f.set(account.Rules{DisableTOTP: true})
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Fatalf("SignInWithCode under DisableTOTP = %v, want ErrTOTPDisabled", err)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), access.NewSecret("unknown"), "123456"); !errors.Is(err, account.ErrTOTPDisabled) {
			t.Errorf("an unknown ticket under DisableTOTP = %v, want ErrTOTPDisabled with no ticket condition (4.38)", err)
		}
		f.set(account.Rules{})
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); err != nil {
			t.Errorf("the kept ticket once TOTP is back = %v", err)
		}
	})
	t.Run("unknown_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), access.NewSecret("unknown"), "123456"); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("an unknown ticket = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Design 4.4 step 5 and step 1's re-check (cal.com GHSA-9r3w-4j8q-pw98).
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *sfFixture, u *access.User)
	}{
		{name: "record_gone", change: func(t *testing.T, f *sfFixture, u *access.User) {
			if err := f.mem.Update(t.Context(), func(tx account.Tx) error { return tx.DeleteTOTP(t.Context(), u.ID) }); err != nil {
				t.Fatalf("DeleteTOTP: %v", err)
			}
		}},
		{name: "password_changed", change: func(t *testing.T, f *sfFixture, u *access.User) {
			cur := storedUser(t, f.mem, u.ID)
			h, err := f.hasher.Hash(t.Context(), "another-long-password")
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			cur.PasswordHash = h
			if err := f.mem.UpdateUser(t.Context(), cur); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{name: "user_disabled", change: func(t *testing.T, f *sfFixture, u *access.User) {
			cur := storedUser(t, f.mem, u.ID)
			cur.Enabled = false
			if err := f.mem.UpdateUser(t.Context(), cur); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
	} {
		t.Run(tc.name+"_ends_the_ticket", func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{})
			u, ticket, secret := codeTicket(t, f, clientAt(1))
			tc.change(t, f, u)
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("SignInWithCode = %v, want access.ErrTokenInvalid", err)
			}
			if live(f, ticket) {
				t.Error("the refused ticket is still live")
			}
			if n := len(sessionsOf(t, f.mem, u.ID)); n != 0 {
				t.Errorf("sessions = %d, want none", n)
			}
		})
	}
	// Design 4.3: a record no key opens answers 503 and is never a wrong code.
	t.Run("unopenable", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, access.NewEphemeralSealer(), u)
		ticket := again(t, f, clientAt(1))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, account.ErrSecondFactorUnavailable) {
			t.Fatalf("SignInWithCode on an unopenable record = %v, want ErrSecondFactorUnavailable", err)
		}
		if _, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Error("an unopenable record counted the code")
		}
		if !live(f, ticket) {
			t.Error("an unopenable record ended the ticket")
		}
		if errorLogs(f.logs) == 0 {
			t.Error("an unopenable record logged nothing at ERROR")
		}
	})
	// Design 4.4 "Security log": the first refused step journals once.
	t.Run("first_refusal_journals_once", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u, ticket, secret := codeTicket(t, f, clientAt(1))
		wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
		for range 2 {
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong); codeReason(err) != account.ReasonCodeInvalid {
				t.Fatalf("a wrong code = %v", err)
			}
		}
		evs := eventsOf(f.events, account.EventSecondFactorFailed)
		if len(evs) != 1 || evs[0].UserID != u.ID || evs[0].Method != access.MethodTOTP {
			t.Fatalf("second_factor_failed events = %+v, want one for alice's totp", evs)
		}
		var entry *account.LogEntry
		for _, e := range logOf(t, f.mem) {
			if e.Event.Kind == account.EventSecondFactorFailed {
				entry = &e
			}
		}
		if entry == nil || entry.Class != account.LogClassSession || entry.Detail != account.ReasonCodeInvalid || entry.ActorUserAgent != clientAt(1).UserAgent || !entry.IP.IsValid() {
			t.Errorf("log entry = %+v, want a session entry with the reason, the user agent and the IP", entry)
		}
	})
	// Design 4.4 "Every ticket is bound to its transport".
	t.Run("plain_ticket_on_https", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		plain := clientAt(1)
		plain.Secure = false
		_, ticket, secret := codeTicket(t, f, plain)
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("a plain ticket over HTTPS = %v, want access.ErrTokenInvalid", err)
		}
		if live(f, ticket) {
			t.Error("the plain ticket presented over HTTPS was kept")
		}
	})
	t.Run("secure_ticket_on_plain", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		plain := clientAt(1)
		plain.Secure = false
		if _, err := f.svc.SignInWithCode(t.Context(), plain, ticket, codeNow(secret)); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a secure ticket over plain HTTP = %v, want access.ErrHTTPSRequired", err)
		}
		if live(f, ticket) {
			t.Error("the secure ticket that crossed in clear was kept")
		}
	})
	t.Run("plain_ticket_on_plain", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		plain := clientAt(1)
		plain.Secure = false
		_, ticket, secret := codeTicket(t, f, plain)
		out, err := f.svc.SignInWithCode(t.Context(), plain, ticket, codeNow(secret))
		if err != nil || out.SignedIn.Session.Secure {
			t.Errorf("a plain code step = %v, secure %t; want a plain session (design 4.4: the code step is allowed over plain)", err, out.SignedIn.Session.Secure)
		}
	})
	// snipe-it GHSA-mr8g-2mj4-pcq2 and runtipi GHSA-v6gf-frxm-567w: the code
	// step meets FailureCap.
	t.Run("locks_at_the_cap", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		ref := account.FailureRef{Name: account.FailureName(f.svc, "alice"), Method: access.MethodTOTP}
		if err := f.mem.PutAuthFailure(t.Context(), account.FailureCount{FailureRef: ref, Count: account.FailureCap - 1}); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
		wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("the hundredth wrong code = %v", err)
		}
		if rec, _ := totpFailures(t, f.mem, f.svc, "alice", false); !rec.Locked || !rec.Unreported {
			t.Fatalf("record after the hundredth wrong code = %+v, want an unreported lock", rec)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); codeReason(err) != account.ReasonMethodLocked {
			t.Errorf("the right code on a locked method = %v, want method_locked", err)
		}
	})
	t.Run("limited", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: ipLimit(3)})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
		var err error
		for range 4 {
			_, err = f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong)
		}
		if _, limited := errors.AsType[*ratelimit.RefusedError](err); !limited {
			t.Errorf("the fourth wrong code from one IP under a limit of three = %v, want a *ratelimit.RefusedError", err)
		}
	})
	// Listmonk GHSA-p42g-4rv2-xg2f: each new password step 1 reset the code
	// step's count, so every sign-in bought fresh guesses.
	t.Run("count_survives_a_new_step_one", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		wrong := codeAt(secret, time.Now().Add(-10*totp.Period))
		for i := range 2 {
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong); codeReason(err) != account.ReasonCodeInvalid {
				t.Fatalf("wrong code %d = %v, want code_invalid", i+1, err)
			}
			ticket = again(t, f, clientAt(1))
		}
		if rec, found := totpFailures(t, f.mem, f.svc, "alice", false); !found || rec.Count != 2 {
			t.Errorf("the code step's record after two wrong codes, each followed by a new step 1 = %+v, want a count of 2", rec)
		}
	})
	// Vault GHSA-w8f3-r2q9-xr6w: a pending sign-in completed past its
	// lifetime. Design 4.4: a ticket lives ten minutes on the Service clock.
	for name, tc := range map[string]struct {
		after time.Duration
		live  bool
	}{
		"ticket_within_its_lifetime": {10*time.Minute - time.Second, true},
		"ticket_past_its_lifetime":   {10 * time.Minute, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{}, pwOptions{})
			start := time.Now()
			f.at.Store(&start)
			_, ticket, secret := codeTicket(t, f, clientAt(1))
			late := start.Add(tc.after)
			f.at.Store(&late)
			_, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeAt(secret, late))
			if tc.live && err != nil {
				t.Errorf("the right code %v after step 1 = %v, want a sign-in", tc.after, err)
			}
			if !tc.live && !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("the right code %v after step 1 = %v, want access.ErrTokenInvalid", tc.after, err)
			}
		})
	}
	// Gitea GHSA-gx3v-q759-g323: two parallel submissions of one code.
	t.Run("parallel_steps_pass_once", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSF(t, account.Rules{}, pwOptions{store: fs})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		code := codeNow(secret)
		type key struct{}
		var mu sync.Mutex
		seen := map[any]int{}
		bothCounted := make(chan struct{})
		counted := 0
		fs.onUpdate(func(ctx context.Context, _ int) {
			id := ctx.Value(key{})
			if id == nil {
				return
			}
			mu.Lock()
			seen[id]++
			second := seen[id] == 2
			if second {
				if counted++; counted == 2 {
					close(bothCounted)
				}
			}
			mu.Unlock()
			if second {
				select {
				case <-bothCounted:
				case <-time.After(10 * time.Second):
				}
			}
		})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				ctx := context.WithValue(t.Context(), key{}, i)
				_, errs[i] = f.svc.SignInWithCode(ctx, clientAt(1), ticket, code)
			})
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if codeReason(err) != account.ReasonCodeReused {
				t.Errorf("the losing step = %v, want code_reused", err)
			}
		}
		if ok != 1 {
			t.Errorf("parallel code steps that signed in = %d, want exactly 1 (errors %v)", ok, errs)
		}
	})
	// Vikunja GHSA-fgfv-pv97-6cmj: the count commits before the match, so a
	// success Update that rolls back leaves it.
	t.Run("count_survives_a_rolled_back_success", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newSF(t, account.Rules{}, pwOptions{store: fs})
		_, ticket, secret := codeTicket(t, f, clientAt(1))
		fs.failCall("CreateSession")
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeNow(secret)); !errors.Is(err, access.ErrAuthBackend) {
			t.Fatalf("SignInWithCode with a failing session write = %v, want access.ErrAuthBackend", err)
		}
		if rec, _ := totpFailures(t, f.mem, f.svc, "alice", false); rec.Count != 1 {
			t.Errorf("TOTP failure count after the rolled-back success = %d, want the committed 1", rec.Count)
		}
	})
	// Step 1 of a two-step sign-in rewrites an old-parameter password hash.
	t.Run("rehashed_at_step_one", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		u.PasswordHash = doubleCostHash(t, goodPassword)
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		secret := sealTOTP(t, f.mem, f.sealer, u)
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), again(t, f, clientAt(1)), codeNow(secret)); err != nil {
			t.Fatalf("the code step after a rehashing step 1 = %v", err)
		}
		if f.hasher.NeedsRehash(storedUser(t, f.mem, u.ID).PasswordHash) {
			t.Error("the stored hash is still at the old parameters")
		}
	})
}

// TestCodeStepNeverLocksGoodSignIns is design 4.15's two lock tests.
func TestCodeStepNeverLocksGoodSignIns(t *testing.T) {
	t.Parallel()
	t.Run("101_good_sign_ins", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		for i := range 101 {
			at := f.nextStep()
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), again(t, f, clientAt(1)), codeAt(secret, at)); err != nil {
				t.Fatalf("good two-step sign-in %d = %v", i+1, err)
			}
		}
		if rec, found := totpFailures(t, f.mem, f.svc, "alice", false); found {
			t.Errorf("TOTP record after 101 good sign-ins = %+v, want none", rec)
		}
	})
	t.Run("typo_success_then_99_typos", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := sealTOTP(t, f.mem, f.sealer, u)
		wrong := func(at time.Time) string { return codeAt(secret, at.Add(-10*totp.Period)) }
		at := f.nextStep()
		ticket := again(t, f, clientAt(1))
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong(at)); codeReason(err) != account.ReasonCodeInvalid {
			t.Fatalf("the typo = %v", err)
		}
		if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, codeAt(secret, at)); err != nil {
			t.Fatalf("the success = %v", err)
		}
		ticket = again(t, f, clientAt(1))
		for range 99 {
			if _, err := f.svc.SignInWithCode(t.Context(), clientAt(1), ticket, wrong(at)); codeReason(err) != account.ReasonCodeInvalid {
				t.Fatalf("a typo = %v, want code_invalid", err)
			}
		}
		if rec, _ := totpFailures(t, f.mem, f.svc, "alice", false); rec.Locked || rec.Count != 99 {
			t.Errorf("record = %+v, want 99 and no lock", rec)
		}
	})
}

// TestSecondFactorPasskey is design 4.4's passkey second step.
func TestSecondFactorPasskey(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*sfFixture, *access.User, *accesstest.PasskeyDevice, access.Secret) {
		t.Helper()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		dev := accesstest.NewPasskeyDevice(t)
		f.enrol(t, u, dev)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		return f, u, dev, pending(t, out, err, account.NextSecondFactor, access.MethodPasskey, access.MethodRecoveryCode).Ticket
	}
	finish := func(t *testing.T, f *sfFixture, ticket access.Secret, dev *accesstest.PasskeyDevice) (account.LoginResult, error) {
		t.Helper()
		pc, err := f.svc.SecondFactorPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin)
		if err != nil {
			t.Fatalf("SecondFactorPasskeyBegin = %v", err)
		}
		return f.svc.SecondFactorPasskeyFinish(t.Context(), clientAt(1), pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
	}
	t.Run("signs_in", func(t *testing.T) {
		t.Parallel()
		f, u, dev, ticket := setup(t)
		out, err := finish(t, f, ticket, dev)
		if err != nil || out.SignedIn.User == nil || out.SignedIn.User.ID != u.ID {
			t.Fatalf("SecondFactorPasskeyFinish = %v, want alice signed in", err)
		}
		if sess := storedSession(t, f.mem, u.ID, out.SignedIn.Session.ID); sess.AuthMethod != access.MethodPassword {
			t.Errorf("session method = %s, want password (design 4.4 step 3)", sess.AuthMethod)
		}
		if live(f, ticket) {
			t.Error("the ticket outlived its sign-in")
		}
	})
	t.Run("other_device_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f, u, _, ticket := setup(t)
		if _, err := finish(t, f, ticket, accesstest.NewPasskeyDevice(t)); err == nil {
			t.Fatal("an assertion by a device alice never registered signed in")
		}
		if !live(f, ticket) {
			t.Error("a refused assertion ended the ticket")
		}
		if evs := eventsOf(f.events, account.EventSecondFactorFailed); len(evs) != 1 || evs[0].Method != access.MethodPasskey || evs[0].UserID != u.ID {
			t.Errorf("second_factor_failed events = %+v, want one passkey entry for alice", evs)
		}
	})
	t.Run("ceremony_once", func(t *testing.T) {
		t.Parallel()
		f, _, dev, ticket := setup(t)
		pc, err := f.svc.SecondFactorPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin)
		if err != nil {
			t.Fatalf("SecondFactorPasskeyBegin = %v", err)
		}
		body := dev.Assert(browserJSON(t, pc.Assertion))
		if _, err := f.svc.SecondFactorPasskeyFinish(t.Context(), clientAt(1), pc.ID, bytes.NewReader(body)); err != nil {
			t.Fatalf("first finish = %v", err)
		}
		if _, err := f.svc.SecondFactorPasskeyFinish(t.Context(), clientAt(1), pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("the finish replayed = %v, want ErrCeremonyInvalid", err)
		}
	})
	// Logto GHSA-f78f-ghjf-hrx2: a passkey verified for another account
	// completed the sign-in. Bob's registered passkey on alice's step signs
	// no one in.
	t.Run("another_users_passkey", func(t *testing.T) {
		t.Parallel()
		f, alice, _, ticket := setup(t)
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		bobs := accesstest.NewPasskeyDevice(t)
		f.enrol(t, bob, bobs)
		before := len(sessionsOf(t, f.mem, alice.ID)) + len(sessionsOf(t, f.mem, bob.ID))
		if out, err := finish(t, f, ticket, bobs); err == nil || out.SignedIn.User != nil {
			t.Fatalf("bob's passkey on alice's second step = %v, signed in %t, want a refusal", err, out.SignedIn.User != nil)
		}
		if after := len(sessionsOf(t, f.mem, alice.ID)) + len(sessionsOf(t, f.mem, bob.ID)); after != before {
			t.Errorf("sessions of alice and bob = %d after the refusal, want the %d before it", after, before)
		}
	})
	// Design 4.4: the passkey step needs HTTPS, and a secure ticket sent in
	// clear is dropped.
	t.Run("plain_drops_the_ticket", func(t *testing.T) {
		t.Parallel()
		f, _, _, ticket := setup(t)
		plain := clientAt(1)
		plain.Secure = false
		if _, err := f.svc.SecondFactorPasskeyBegin(t.Context(), plain, ticket, f.origin); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a plain passkey step = %v, want access.ErrHTTPSRequired", err)
		}
		if live(f, ticket) {
			t.Error("the secure ticket that crossed in clear was kept")
		}
	})
	t.Run("ticket_not_listing_passkey", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, ticket, _ := codeTicket(t, f, clientAt(1))
		if _, err := f.svc.SecondFactorPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a passkey step on a totp-only ticket = %v, want access.ErrTokenInvalid", err)
		}
	})
	// The begin re-checks the ticket's user as every step does: a password
	// changed or a mode made dormant since step 1 ends the ticket before a
	// ceremony starts.
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *sfFixture, u *access.User)
	}{
		{name: "password_changed", change: func(t *testing.T, f *sfFixture, u *access.User) {
			hash, err := f.hasher.Hash(t.Context(), goodPassword)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			u.PasswordHash = hash
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{name: "mode_made_dormant", change: func(t *testing.T, f *sfFixture, _ *access.User) { storeMode(t, f.mem, account.SSOOnly) }},
	} {
		t.Run("begin_after_"+tc.name, func(t *testing.T) {
			t.Parallel()
			f, u, _, ticket := setup(t)
			tc.change(t, f, storedUser(t, f.mem, u.ID))
			if _, err := f.svc.SecondFactorPasskeyBegin(t.Context(), clientAt(1), ticket, f.origin); !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("SecondFactorPasskeyBegin on the stale ticket = %v, want access.ErrTokenInvalid", err)
			}
			if live(f, ticket) {
				t.Error("the stale ticket outlived its refused begin")
			}
		})
	}
}

// TestOIDCSignInNeverAskedForTheCode is Vikunja GHSA-8jvc-mcx6-r4cg's
// regression by decision (design 4.4's table): an SSO sign-in of a TOTP
// user signs in, the provider owning its factors.
func TestOIDCSignInNeverAskedForTheCode(t *testing.T) {
	t.Parallel()
	sealer := access.NewEphemeralSealer()
	f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{
		edit:  func(c *account.Config) { c.TOTP = account.TOTPConfig{Sealer: sealer, Issuer: testIssuer} },
		rules: rulesWith(func(r *account.Rules) { r.RequireSecondFactor = true }),
	})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	sealTOTP(t, f.mem, sealer, u)
	linkIdentity(t, f.mem, u, f.rig.identity())
	flow, claims := f.rig.signInFlow(t)
	out, err := f.complete(t, localClient, flow, claims)
	if err != nil || out.Kind != account.OutcomeSignedIn {
		t.Fatalf("OIDCComplete for a TOTP user = %+v, %v; want a session", out, err)
	}
}
