package account_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// regRules is Rules with registration in mode and the rule as given.
func regRules(mode account.RegistrationMode, rule bool) account.Rules {
	return account.Rules{Registration: mode, RequireSecondFactor: rule, SetupTokenRequired: tokenless}
}

// newcomer is a registration of name with goodPassword.
func newcomer(name string) account.Registration {
	return account.Registration{Username: name, Password: access.NewSecret(goodPassword)}
}

// registerPasskey registers name with dev from c and answers the finish.
func registerPasskey(t *testing.T, f *sfFixture, c account.Client, name string, dev *accesstest.PasskeyDevice) (account.EnrolmentResult, error) {
	t.Helper()
	pc, err := f.svc.RegisterPasskeyBegin(t.Context(), c, account.RegistrationPasskey{Username: name, Origin: f.origin})
	if err != nil {
		t.Fatalf("RegisterPasskeyBegin = %v", err)
	}
	return f.svc.RegisterPasskeyFinish(t.Context(), c, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
}

// requireWaiting fails unless w is name's account, stored disabled and
// waiting for approval, a regular user and no owner, with no session.
func requireWaiting(t *testing.T, f *sfFixture, w *account.Waiting, name string) *access.User {
	t.Helper()
	if w == nil || w.User == nil || w.User.Username != name {
		t.Fatalf("the answer = %+v, want %q waiting for approval (design 4.17)", w, name)
	}
	u := storedUser(t, f.mem, w.User.ID)
	if u.Enabled || !u.WaitingApproval || u.Role != access.RoleUser || u.Owner {
		t.Errorf("the stored account = enabled %t, waiting %t, role %s, owner %t; want a disabled regular user waiting (design 4.17)", u.Enabled, u.WaitingApproval, u.Role, u.Owner)
	}
	if ss := sessionsOf(t, f.mem, u.ID); len(ss) != 0 {
		t.Errorf("a waiting account holds %d sessions, want none (design 4.17, 4.31)", len(ss))
	}
	return u
}

// requireRegular fails unless in signed name in as an enabled regular user
// by method.
func requireRegular(t *testing.T, f *sfFixture, in account.SignedIn, name string, m access.Method) {
	t.Helper()
	if in.User == nil || in.User.Username != name || in.Token.IsZero() {
		t.Fatalf("the answer = %+v, want %q signed in (design 4.17)", in.User, name)
	}
	u := storedUser(t, f.mem, in.User.ID)
	if !u.Enabled || u.WaitingApproval || u.Role != access.RoleUser || u.Owner {
		t.Errorf("the stored account = enabled %t, waiting %t, role %s, owner %t; want an enabled regular user (design 4.17)", u.Enabled, u.WaitingApproval, u.Role, u.Owner)
	}
	if sess := storedSession(t, f.mem, u.ID, in.Session.ID); sess.AuthMethod != m {
		t.Errorf("session method = %s, want %s", sess.AuthMethod, m)
	}
}

// TestRegistrationModes is design 4.17's table of the two modes and the
// rule, by password and by passkey.
func TestRegistrationModes(t *testing.T) {
	t.Parallel()
	t.Run("off_refuses", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOff, false), pwOptions{})
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.Is(err, account.ErrRegistrationClosed) {
			t.Errorf("RegisterPassword = %v, want ErrRegistrationClosed", err)
		}
		if _, err := f.svc.RegisterPasskeyBegin(t.Context(), localClient, account.RegistrationPasskey{Username: "newcomer", Origin: f.origin}); !errors.Is(err, account.ErrRegistrationClosed) {
			t.Errorf("RegisterPasskeyBegin = %v, want ErrRegistrationClosed", err)
		}
		requireNoUsers(t, f.mem)
	})
	t.Run("open_rule_off_signs_in", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
		if err != nil || out.Pending != nil || out.Waiting != nil {
			t.Fatalf("RegisterPassword = %+v, %v; want a sign-in", out, err)
		}
		requireRegular(t, f, out.SignedIn, "newcomer", access.MethodPassword)
		if evs := eventsOf(f.events, account.EventUserCreated); len(evs) != 1 || evs[0].Role != access.RoleUser {
			t.Errorf("user_created = %+v, want one of a regular user", evs)
		}
	})
	t.Run("approval_rule_off_waits", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationApproval, false), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
		if err != nil || out.Pending != nil || out.SignedIn.User != nil || !out.SignedIn.Token.IsZero() || !out.SignedIn.DeviceCookie.IsZero() {
			t.Fatalf("RegisterPassword = %+v, %v; want a waiting answer with no session or device cookie", out, err)
		}
		requireWaiting(t, f, out.Waiting, "newcomer")
		if !out.Waiting.RecoveryCode.IsZero() {
			t.Error("a password registration with no second factor issued a recovery code (design 4.6)")
		}
		if _, err := f.login(t.Context(), localClient, "newcomer", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the waiting account's sign-in = %v, want ErrInvalidCredentials (ui-contract part 4: fails like a wrong password)", err)
		}
	})
	t.Run("open_rule_on_drafts_then_signs_in", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, true), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
		p := pending(t, account.LoginResult{Pending: out.Pending}, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		if got, ok := account.TicketOf(f.svc, p.Ticket); !ok || got.Draft != account.ViaRegistration || got.UserID != 0 {
			t.Fatalf("the ticket = %+v, %t; want a registration's draft with no user", got, ok)
		}
		requireNoUsers(t, f.mem)
		in, _, err := pendingEnrolTOTP(t, f, localClient, p.Ticket)
		if err != nil {
			t.Fatalf("PendingTOTPFinish = %v", err)
		}
		requireRegular(t, f, in, "newcomer", access.MethodPassword)
		if in.RecoveryCode.IsZero() {
			t.Error("the finish bound a password and a second factor and issued no recovery code (design 4.6)")
		}
	})
	t.Run("approval_rule_on_end_to_end", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationApproval, true), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
		p := pending(t, account.LoginResult{Pending: out.Pending}, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		e, err := f.svc.PendingTOTPBegin(t.Context(), localClient, p.Ticket)
		if err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		done, err := f.svc.PendingTOTPFinish(t.Context(), localClient, p.Ticket, codeNow(secretOf(t, account.TOTPEnrolment{URI: e.URI, Text: e.Text})))
		if err != nil || done.SignedIn.User != nil || !done.SignedIn.Token.IsZero() {
			t.Fatalf("PendingTOTPFinish = %+v, %v; want a waiting answer and no session (design 4.31)", done, err)
		}
		u := requireWaiting(t, f, done.Waiting, "newcomer")
		if done.Waiting.RecoveryCode.IsZero() {
			t.Error("the waiting answer carried no recovery code; it is the code's one show (design 4.31)")
		}
		if _, held := totpRecord(t, f.mem, u.ID); !held {
			t.Error("the waiting account's TOTP was not bound")
		}
		if live(f, p.Ticket) {
			t.Error("the finish kept its ticket")
		}
		for _, ev := range f.events.all() {
			if ev.Kind == account.EventSignedIn || ev.Actor.SessionID != "" {
				t.Errorf("event %s names a session (%q); a waiting account holds none", ev.Kind, ev.Actor.SessionID)
			}
		}
	})
	for _, rule := range []bool{false, true} {
		t.Run(fmt.Sprintf("passkey_open_rule_%t", rule), func(t *testing.T) {
			t.Parallel()
			f := newSF(t, regRules(account.RegistrationOpen, rule), pwOptions{})
			out, err := registerPasskey(t, f, localClient, "newcomer", accesstest.NewPasskeyDevice(t))
			if err != nil || out.Waiting != nil {
				t.Fatalf("RegisterPasskeyFinish (rule %t) = %+v, %v; want a sign-in, since a passkey meets the rule", rule, out, err)
			}
			requireRegular(t, f, out.SignedIn, "newcomer", access.MethodPasskey)
			if pks, _ := f.mem.PasskeysByUserID(t.Context(), out.SignedIn.User.ID); len(pks) != 1 {
				t.Errorf("passkeys = %d, want the one registered", len(pks))
			}
		})
		t.Run(fmt.Sprintf("passkey_approval_rule_%t", rule), func(t *testing.T) {
			t.Parallel()
			f := newSF(t, regRules(account.RegistrationApproval, rule), pwOptions{})
			out, err := registerPasskey(t, f, localClient, "newcomer", accesstest.NewPasskeyDevice(t))
			if err != nil || out.SignedIn.User != nil {
				t.Fatalf("RegisterPasskeyFinish (rule %t) = %+v, %v; want a waiting answer", rule, out, err)
			}
			u := requireWaiting(t, f, out.Waiting, "newcomer")
			if pks, _ := f.mem.PasskeysByUserID(t.Context(), u.ID); len(pks) != 1 {
				t.Errorf("passkeys = %d, want the one registered", len(pks))
			}
		})
	}
}

// TestRegistrationRefusals is design 4.17's refusals: transport, the
// password rule, a taken name, the SSO mode, the Policy, and the waiting
// cap and a closed mode at the draft's finish.
func TestRegistrationRefusals(t *testing.T) {
	t.Parallel()
	t.Run("plain_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		if _, err := f.svc.RegisterPassword(t.Context(), plainClientOf(), newcomer("newcomer")); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("RegisterPassword over plain HTTP = %v, want access.ErrHTTPSRequired (design 4.17, as invite acceptance)", err)
		}
		if _, err := f.svc.RegisterPasskeyBegin(t.Context(), plainClientOf(), account.RegistrationPasskey{Username: "newcomer", Origin: f.origin}); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("RegisterPasskeyBegin over plain HTTP = %v, want access.ErrHTTPSRequired", err)
		}
		if _, err := f.svc.RegisterPasskeyFinish(t.Context(), plainClientOf(), "none", bytes.NewReader(nil)); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("RegisterPasskeyFinish over plain HTTP = %v, want access.ErrHTTPSRequired", err)
		}
		requireNoUsers(t, f.mem)
	})
	// NIST SP 800-63B-4 §3.1.1.2: a password of at least 15 characters.
	t.Run("short_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		in := account.Registration{Username: "newcomer", Password: access.NewSecret("fourteen-chars")}
		var pe *access.PasswordError
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, in); !errors.As(err, &pe) || pe.Reason != access.PasswordTooShort {
			t.Errorf("RegisterPassword with 14 characters = %v, want too_short", err)
		}
		requireNoUsers(t, f.mem)
	})
	t.Run("password_against_username", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, true), pwOptions{})
		in := account.Registration{Username: "longnewcomername", Password: access.NewSecret("longnewcomername-2024")}
		var pe *access.PasswordError
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, in); !errors.As(err, &pe) || pe.Reason != access.PasswordContainsUsername {
			t.Errorf("RegisterPassword with the username and digits as the password = %v, want contains_username (design 4.17: checkPassword with that username)", err)
		}
	})
	t.Run("taken_username", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("alice")); !errors.Is(err, account.ErrUsernameTaken) {
			t.Errorf("RegisterPassword of a taken name = %v, want ErrUsernameTaken (design 4.17)", err)
		}
		if _, err := registerPasskey(t, f, localClient, "alice", accesstest.NewPasskeyDevice(t)); !errors.Is(err, account.ErrUsernameTaken) {
			t.Errorf("RegisterPasskeyFinish of a taken name = %v, want ErrUsernameTaken", err)
		}
	})
	t.Run("sso_only", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		setMode(t, f.mem, account.SSOOnly)
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.Is(err, account.ErrSSOOnly) {
			t.Errorf("RegisterPassword under SSOOnly = %v, want ErrSSOOnly (design 4.17, 5.3)", err)
		}
		if _, err := f.svc.RegisterPasskeyBegin(t.Context(), localClient, account.RegistrationPasskey{Username: "newcomer", Origin: f.origin}); !errors.Is(err, account.ErrSSOOnly) {
			t.Errorf("RegisterPasskeyBegin under SSOOnly = %v, want ErrSSOOnly", err)
		}
		requireNoUsers(t, f.mem)
	})
	t.Run("sso_only_since_the_begin", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{})
		pc, err := f.svc.RegisterPasskeyBegin(t.Context(), localClient, account.RegistrationPasskey{Username: "newcomer", Origin: f.origin})
		if err != nil {
			t.Fatalf("RegisterPasskeyBegin = %v", err)
		}
		setMode(t, f.mem, account.SSOOnly)
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if _, err := f.svc.RegisterPasskeyFinish(t.Context(), localClient, pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrSSOOnly) {
			t.Errorf("RegisterPasskeyFinish after ApplySSO(only) = %v, want ErrSSOOnly", err)
		}
		requireNoUsers(t, f.mem)
	})
	t.Run("policy_refuses", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, false), pwOptions{edit: func(c *account.Config) { c.Policy = refuseRegistration{} }})
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("RegisterPassword under a Policy refusing ViaRegistration = %v, want ErrPolicyRefused (design 4.17)", err)
		}
		requireNoUsers(t, f.mem)
	})
	t.Run("waiting_cap", func(t *testing.T) {
		t.Parallel()
		r := regRules(account.RegistrationApproval, false)
		r.MaxWaitingRegistrations = 1
		f := newSF(t, r, pwOptions{})
		if out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("first")); err != nil || out.Waiting == nil {
			t.Fatalf("the first registration = %+v, %v; want it waiting", out, err)
		}
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("second")); !errors.Is(err, account.ErrRegistrationFull) {
			t.Errorf("a registration at the cap = %v, want ErrRegistrationFull (design 4.17)", err)
		}
		if _, err := f.svc.RegisterPasskeyBegin(t.Context(), localClient, account.RegistrationPasskey{Username: "second", Origin: f.origin}); !errors.Is(err, account.ErrRegistrationFull) {
			t.Errorf("a passkey registration at the cap = %v, want ErrRegistrationFull", err)
		}
		if usernameTakenIn(t, f.mem, "second") {
			t.Error("a registration at the cap created its account")
		}
	})
	t.Run("default_cap_is_50", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationApproval, false), pwOptions{})
		for i := range account.DefaultMaxWaitingRegistrations {
			u := mustUser(t, f.mem, "waiting"+string(rune('a'+i/26))+string(rune('a'+i%26)), access.RoleUser)
			u.Enabled, u.WaitingApproval = false, true
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}
		if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.Is(err, account.ErrRegistrationFull) {
			t.Errorf("a registration beside 50 waiting accounts = %v, want ErrRegistrationFull (design 4.17: default 50)", err)
		}
	})
	t.Run("cap_reached_since_the_draft", func(t *testing.T) {
		t.Parallel()
		r := regRules(account.RegistrationApproval, true)
		r.MaxWaitingRegistrations = 1
		f := newSF(t, r, pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("drafted"))
		p := pending(t, account.LoginResult{Pending: out.Pending}, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		if _, err := registerPasskey(t, f, localClient, "other", accesstest.NewPasskeyDevice(t)); err != nil {
			t.Fatalf("the passkey registration filling the cap = %v", err)
		}
		if err := pendingEnrolTOTPRaw(t, f, localClient, p.Ticket); !errors.Is(err, account.ErrRegistrationFull) {
			t.Errorf("the draft's finish at the cap = %v, want ErrRegistrationFull (design 4.17: the cap is re-checked there)", err)
		}
		if usernameTakenIn(t, f.mem, "drafted") || live(f, p.Ticket) {
			t.Error("a finish refused at the cap created the account or kept its ticket")
		}
	})
	t.Run("closed_since_the_draft", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, true), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("drafted"))
		p := pending(t, account.LoginResult{Pending: out.Pending}, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		f.set(regRules(account.RegistrationOff, true))
		if err := pendingEnrolTOTPRaw(t, f, localClient, p.Ticket); !errors.Is(err, account.ErrRegistrationClosed) {
			t.Errorf("the draft's finish after the mode went off = %v, want ErrRegistrationClosed (design 4.17)", err)
		}
		requireNoUsers(t, f.mem)
		if live(f, p.Ticket) {
			t.Error("a finish refused as closed kept its ticket")
		}
	})
	t.Run("approval_since_the_draft", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, regRules(account.RegistrationOpen, true), pwOptions{})
		out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("drafted"))
		p := pending(t, account.LoginResult{Pending: out.Pending}, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		f.set(regRules(account.RegistrationApproval, true))
		done, err := pendingEnrolPasskeyRaw(t, f, localClient, p.Ticket, accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("PendingPasskeyFinish = %v", err)
		}
		requireWaiting(t, f, done.Waiting, "drafted")
	})
}

// refuseRegistration is RolePolicy refusing every ViaRegistration creation.
type refuseRegistration struct{ account.RolePolicy }

func (p refuseRegistration) Authorize(ctx context.Context, d account.Decision) error {
	if d.Via == account.ViaRegistration {
		return &account.PolicyError{Op: d.Op, Reason: "no_sign_ups"}
	}
	return p.RolePolicy.Authorize(ctx, d)
}

// pendingEnrolTOTPRaw is pendingEnrolTOTP answering the finish's error as
// it is.
func pendingEnrolTOTPRaw(t *testing.T, f *sfFixture, c account.Client, ticket access.Secret) error {
	t.Helper()
	e, err := f.svc.PendingTOTPBegin(t.Context(), c, ticket)
	if err != nil {
		t.Fatalf("PendingTOTPBegin = %v", err)
	}
	secret := secretOf(t, account.TOTPEnrolment{URI: e.URI, Text: e.Text})
	_, err = f.svc.PendingTOTPFinish(t.Context(), c, ticket, codeNow(secret))
	return err
}

// pendingEnrolPasskeyRaw is pendingEnrolPasskey answering the finish as it
// is.
func pendingEnrolPasskeyRaw(t *testing.T, f *sfFixture, c account.Client, ticket access.Secret, dev *accesstest.PasskeyDevice) (account.EnrolmentResult, error) {
	t.Helper()
	pc, err := f.svc.PendingPasskeyBegin(t.Context(), c, ticket, f.origin)
	if err != nil {
		t.Fatalf("PendingPasskeyBegin = %v", err)
	}
	return f.svc.PendingPasskeyFinish(t.Context(), c, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
}

// TestRegistrationUnderSingleUser is design 4.17's and "Across the parts"'
// static refusal: under a single-user Policy checkRules refuses either mode
// at every operation, so a reloaded value cannot turn registration on.
func TestRegistrationUnderSingleUser(t *testing.T) {
	t.Parallel()
	for _, mode := range []account.RegistrationMode{account.RegistrationOpen, account.RegistrationApproval} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			f := newSF(t, regRules(account.RegistrationOff, false), pwOptions{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
			st, err := f.svc.State(t.Context(), localClient)
			if err != nil || st.Registration != account.RegistrationOff {
				t.Fatalf("State with registration off = %+v, %v", st, err)
			}
			f.set(regRules(mode, false))
			var re *account.RulesError
			if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.As(err, &re) || re.Field != "Registration" {
				t.Errorf("RegisterPassword after the reload = %v, want a RulesError on Registration", err)
			}
			if _, err := f.svc.State(t.Context(), localClient); !errors.As(err, &re) || re.Field != "Registration" {
				t.Errorf("State after the reload = %v, want the same refusal at every operation", err)
			}
			if err := f.svc.CheckRules(t.Context(), regRules(mode, false)); !errors.As(err, &re) || re.Field != "Registration" {
				t.Errorf("CheckRules = %v, want a RulesError on Registration", err)
			}
			requireNoUsers(t, f.mem)
		})
	}
}

// TestCheckRulesRegistration is design 5.3's mode rule: CheckRules refuses
// either registration mode while the stored mode is SSOOnly; a value
// published anyway leaves the owner's sign-in working while registration
// refuses at use.
func TestCheckRulesRegistration(t *testing.T) {
	t.Parallel()
	f := newSF(t, regRules(account.RegistrationOff, false), pwOptions{})
	passwordOwner(t, f.pwFixture, "root")
	for _, mode := range []account.RegistrationMode{account.RegistrationOpen, account.RegistrationApproval} {
		if err := f.svc.CheckRules(t.Context(), regRules(mode, false)); err != nil {
			t.Errorf("CheckRules(%s) under alongside = %v, want nil", mode, err)
		}
	}
	setMode(t, f.mem, account.SSOOnly)
	for _, mode := range []account.RegistrationMode{account.RegistrationOpen, account.RegistrationApproval} {
		var re *account.RulesError
		if err := f.svc.CheckRules(t.Context(), regRules(mode, false)); !errors.As(err, &re) || re.Field != "Registration" || !errors.Is(err, account.ErrRulesInvalid) {
			t.Errorf("CheckRules(%s) under only = %v, want a RulesError on Registration", mode, err)
		}
	}
	if err := f.svc.CheckRules(t.Context(), regRules(account.RegistrationOff, false)); err != nil {
		t.Errorf("CheckRules(off) under only = %v, want nil", err)
	}
	f.set(regRules(account.RegistrationOpen, false))
	if _, err := f.login(t.Context(), localClient, "root", goodPassword); err != nil {
		t.Errorf("the owner's sign-in under a published registration mode = %v, want it to work", err)
	}
	if _, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer")); !errors.Is(err, account.ErrSSOOnly) {
		t.Errorf("RegisterPassword under only = %v, want ErrSSOOnly", err)
	}
	if st, err := f.svc.State(t.Context(), localClient); err != nil || st.Registration != account.RegistrationOff {
		t.Errorf("State.Registration under only = %v, %v; want off, since every registration is refused", st.Registration, err)
	}
}

// TestSSOOnlyRefusedWhileRegistrationOn is design 5.3: CheckSSOReady, and
// so ApplySSO, refuses SSOOnly while Rules has either registration mode,
// with ReasonRegistrationEnabled, and the other modes are not refused for
// it.
func TestSSOOnlyRefusedWhileRegistrationOn(t *testing.T) {
	t.Parallel()
	for _, mode := range []account.RegistrationMode{account.RegistrationOpen, account.RegistrationApproval} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			r := regRules(mode, false)
			f, _ := modeFixture(t, pwOptions{rules: func() account.Rules { return r }})
			checkStateRefusal(t, f, socket, account.SSOOnly, account.ErrPolicyRefused, account.ReasonRegistrationEnabled)
			if err := f.svc.ApplySSO(t.Context(), socket, account.SSOForLinked); err != nil {
				t.Errorf("ApplySSO(for_linked) with registration on = %v, want nil", err)
			}
		})
	}
}

// TestStateRegistration is design 4.17's StateResponse.registration: the
// mode, on a plain request too, since the screen reads secure itself.
func TestStateRegistration(t *testing.T) {
	t.Parallel()
	for _, mode := range []account.RegistrationMode{account.RegistrationOff, account.RegistrationOpen, account.RegistrationApproval} {
		f := newSF(t, regRules(mode, false), pwOptions{})
		for _, c := range []account.Client{localClient, plainClientOf()} {
			if st, err := f.svc.State(t.Context(), c); err != nil || st.Registration != mode {
				t.Errorf("State.Registration (secure %t) = %v, %v; want %v", c.Secure, st.Registration, err, mode)
			}
		}
	}
}

// TestApproveRegistration is design 4.17's approval: enabling a waiting
// account clears WaitingApproval and journals user_approved in place of
// user_enabled; enabling an account an admin disabled stays user_enabled.
func TestApproveRegistration(t *testing.T) {
	t.Parallel()
	f := newSF(t, regRules(account.RegistrationApproval, false), pwOptions{})
	root := mustOwner(t, f.mem, "root")
	admin := f.sessionPrincipal(t, root, time.Now())
	out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
	if err != nil || out.Waiting == nil {
		t.Fatalf("RegisterPassword = %+v, %v", out, err)
	}
	enabled := true
	got, err := f.svc.UpdateUser(t.Context(), admin, out.Waiting.User.ID, account.UserChange{Enabled: &enabled})
	if err != nil || !got.Enabled || got.WaitingApproval {
		t.Fatalf("UpdateUser(enable) = %+v, %v; want the account enabled and no longer waiting", got, err)
	}
	if u := storedUser(t, f.mem, got.ID); !u.Enabled || u.WaitingApproval {
		t.Errorf("stored = enabled %t, waiting %t; want approved", u.Enabled, u.WaitingApproval)
	}
	if evs := eventsOf(f.events, account.EventUserApproved); len(evs) != 1 || evs[0].UserID != got.ID || evs[0].Actor.UserID != root.ID {
		t.Errorf("user_approved = %+v, want one by root", evs)
	}
	if evs := eventsOf(f.events, account.EventUserEnabled); len(evs) != 0 {
		t.Errorf("user_enabled = %+v, want none for an approval", evs)
	}
	if _, err := f.login(t.Context(), localClient, "newcomer", goodPassword); err != nil {
		t.Errorf("the approved account's sign-in = %v", err)
	}
	disabled := false
	if _, err := f.svc.UpdateUser(t.Context(), admin, got.ID, account.UserChange{Enabled: &disabled}); err != nil {
		t.Fatalf("UpdateUser(disable) = %v", err)
	}
	if _, err := f.svc.UpdateUser(t.Context(), admin, got.ID, account.UserChange{Enabled: &enabled}); err != nil {
		t.Fatalf("UpdateUser(enable) = %v", err)
	}
	if evs := eventsOf(f.events, account.EventUserEnabled); len(evs) != 1 {
		t.Errorf("user_enabled = %+v, want one for re-enabling an account an admin disabled", evs)
	}
}

// TestWaitingFieldDropped is design 4.17: a store that drops
// WaitingApproval shows a waiting account as disabled, which still cannot
// sign in.
func TestWaitingFieldDropped(t *testing.T) {
	t.Parallel()
	f := newSF(t, regRules(account.RegistrationApproval, false), pwOptions{})
	out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("newcomer"))
	if err != nil || out.Waiting == nil {
		t.Fatalf("RegisterPassword = %+v, %v", out, err)
	}
	u := storedUser(t, f.mem, out.Waiting.User.ID)
	u.WaitingApproval = false
	if err := f.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if _, err := f.login(t.Context(), localClient, "newcomer", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("sign-in of the account as such a store reads it = %v, want ErrInvalidCredentials", err)
	}
}

// TestSweepRegistrations is design 4.17's sweep leg: a waiting account
// older than 30 days is deleted through DeleteUser's cascade, journalling
// registration_expired and freeing its name; a younger one, and an old
// account no longer waiting, stay.
func TestSweepRegistrations(t *testing.T) {
	t.Parallel()
	f := newSF(t, regRules(account.RegistrationApproval, false), pwOptions{})
	now := time.Now()
	waitingSince := func(name string, age time.Duration, waiting bool) *access.User {
		u := mustUser(t, f.mem, name, access.RoleUser)
		u.CreatedAt, u.Enabled, u.WaitingApproval = now.Add(-age), !waiting, waiting
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		return u
	}
	old := waitingSince("old", 31*24*time.Hour, true)
	if err := f.mem.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: old.ID, Hash: access.NewHash("recovery-hash"), CreatedAt: now}); err != nil {
		t.Fatalf("SetRecoveryCode: %v", err)
	}
	young := waitingSince("young", 29*24*time.Hour, true)
	approved := waitingSince("approved", 60*24*time.Hour, false)
	f.at.Store(&now)
	if n := account.SweepRegistrations(t.Context(), f.svc); n != 1 {
		t.Errorf("SweepRegistrations = %d, want 1", n)
	}
	if usernameTakenIn(t, f.mem, "old") {
		t.Error("a 31-day-old waiting account survived the sweep")
	}
	if _, found, err := f.mem.RecoveryCodeByUserID(t.Context(), old.ID); err != nil || found {
		t.Errorf("the expired account's recovery code: found %t, %v; want DeleteUser's cascade", found, err)
	}
	for _, u := range []*access.User{young, approved} {
		if !usernameTakenIn(t, f.mem, u.Username) {
			t.Errorf("the sweep deleted %s", u.Username)
		}
	}
	if evs := eventsOf(f.events, account.EventRegistrationExpired); len(evs) != 1 || evs[0].UserID != old.ID {
		t.Errorf("registration_expired = %+v, want one for old", evs)
	}
	if out, err := f.svc.RegisterPassword(t.Context(), localClient, newcomer("old")); err != nil || out.Waiting == nil {
		t.Errorf("registering the freed name = %+v, %v; want it waiting", out, err)
	}
}
