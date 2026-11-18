package account_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/totp"
)

// sfFixture is a pkFixture with TOTP wired and Rules a test changes between
// calls.
type sfFixture struct {
	*pkFixture
	sealer *access.Sealer // Config.TOTP.Sealer
	rules  atomic.Pointer[account.Rules]
	// at is Config.Now when set, so a test can reach a later TOTP step;
	// nil runs on time.Now.
	at atomic.Pointer[time.Time]
}

func newSF(t testing.TB, r account.Rules, o pwOptions) *sfFixture {
	t.Helper()
	return newSFSealed(t, access.NewEphemeralSealer(), r, o)
}

// newSFSealed is newSF with sealer as Config.TOTP.Sealer.
func newSFSealed(t testing.TB, sealer *access.Sealer, r account.Rules, o pwOptions) *sfFixture {
	t.Helper()
	f := &sfFixture{sealer: sealer}
	f.rules.Store(&r)
	o.rules = func() account.Rules { return *f.rules.Load() }
	edit := o.edit
	o.edit = func(c *account.Config) {
		c.TOTP = account.TOTPConfig{Sealer: f.sealer, Issuer: testIssuer}
		c.Now = f.now
		if edit != nil {
			edit(c)
		}
	}
	f.pkFixture = newPK(t, o)
	return f
}

func (f *sfFixture) set(r account.Rules) { f.rules.Store(&r) }

// now is the Service's clock.
func (f *sfFixture) now() time.Time {
	if at := f.at.Load(); at != nil {
		return *at
	}
	return time.Now()
}

// nextStep moves the Service's clock one TOTP period on and returns it.
func (f *sfFixture) nextStep() time.Time {
	next := f.now().Add(totp.Period)
	f.at.Store(&next)
	return next
}

// knownDevice is a device cookie for name sealed by a secure sign-in.
func (f *sfFixture) knownDevice(name string) access.Secret {
	return f.limiter.DeviceCookie(ratelimit.AccountKey(name), access.Secret{}, true)
}

// storeTOTP gives u a TOTP record; nothing here opens it.
func storeTOTP(t testing.TB, s account.Store, u *access.User) {
	t.Helper()
	if err := s.SetTOTP(t.Context(), access.TOTP{UserID: u.ID, Sealed: "sealed", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
}

// storeRecoveryCode gives u a recovery code record.
func storeRecoveryCode(t testing.TB, s account.Store, u *access.User) {
	t.Helper()
	if err := s.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: u.ID, Hash: access.NewHash("recovery"), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SetRecoveryCode: %v", err)
	}
}

// pending requires out to be a pending sign-in of next with methods.
func pending(t testing.TB, out account.LoginResult, err error, next account.Next, methods ...access.Method) *account.Pending {
	t.Helper()
	switch {
	case err != nil:
		t.Fatalf("PasswordLogin = %v, want a pending %s", err, next)
	case out.Pending == nil:
		t.Fatalf("PasswordLogin signed in, want a pending %s", next)
	}
	p := out.Pending
	if p.Next != next || !slices.Equal(p.Methods, methods) {
		t.Fatalf("pending = %s %v, want %s %v", p.Next, p.Methods, next, methods)
	}
	if p.Ticket.IsZero() {
		t.Fatal("a pending sign-in carries no ticket")
	}
	if !out.SignedIn.Token.IsZero() || !out.SignedIn.DeviceCookie.IsZero() || out.SignedIn.User != nil {
		t.Error("a pending answer carries a session, a device cookie or a user")
	}
	return p
}

// TestStepOnePends checks the pend table and its ticket-method
// function, for a password first factor.
func TestStepOnePends(t *testing.T) {
	t.Parallel()
	rule := account.Rules{RequireSecondFactor: true}
	type user struct{ totp, passkey, staleKey, recovery bool }
	cases := []struct {
		name    string
		rules   account.Rules
		has     user
		plain   bool
		known   bool
		refuse  func(*account.Config) // MethodUsable
		next    account.Next          // "" signs in
		methods []access.Method
		err     error
	}{
		{name: "no_factor_rule_off_signs_in"},
		{name: "passkeys_rule_off_signs_in", has: user{passkey: true}},
		{name: "totp", has: user{totp: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP}},
		{name: "totp_and_passkey", has: user{totp: true, passkey: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP, access.MethodPasskey}},
		{name: "totp_and_recovery_code", has: user{totp: true, recovery: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP, access.MethodRecoveryCode}},
		{name: "passkey_rule_on", rules: rule, has: user{passkey: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodPasskey}},
		{name: "passkey_and_recovery_rule_on", rules: rule, has: user{passkey: true, recovery: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodPasskey, access.MethodRecoveryCode}},
		{name: "neither_rule_on_known_device", rules: rule, known: true, next: account.NextEnrol, methods: []access.Method{access.MethodTOTP, access.MethodPasskey}},
		{name: "neither_rule_on_new_device", rules: rule, err: account.ErrEnrolNeedsKnownDevice},
		// A ticket's Methods follow its transport.
		{name: "plain_totp_lists_totp_only", has: user{totp: true, passkey: true, recovery: true}, plain: true, next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP}},
		{name: "plain_passkey_rule_on", rules: rule, has: user{passkey: true}, plain: true, err: access.ErrHTTPSRequired},
		{name: "plain_enrol", rules: rule, plain: true, known: true, err: access.ErrHTTPSRequired},
		// One function decides a ticket's Methods.
		{name: "hook_without_totp_keeps_totp", has: user{totp: true, recovery: true}, refuse: allowOnly(access.MethodPassword, access.MethodPasskey, access.MethodOIDC), next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP, access.MethodRecoveryCode}},
		{name: "hook_refusing_passkeys", has: user{totp: true, passkey: true}, refuse: allowOnly(access.MethodPassword), next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP}},
		{name: "hook_refusing_passkeys_enrol", rules: rule, known: true, refuse: allowOnly(access.MethodPassword), next: account.NextEnrol, methods: []access.Method{access.MethodTOTP}},
		{name: "disable_totp_rule_on_recovery_kept", rules: account.Rules{RequireSecondFactor: true, DisableTOTP: true}, has: user{passkey: true, recovery: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodPasskey, access.MethodRecoveryCode}},
		{name: "disable_totp_rule_on_no_passkeys", rules: account.Rules{RequireSecondFactor: true, DisableTOTP: true}, known: true, refuse: allowOnly(access.MethodPassword), err: account.ErrNoUsableMethod},
		{name: "recovery_code_without_enrolment", rules: account.Rules{RequireSecondFactor: true, DisableTOTP: true}, has: user{passkey: true, recovery: true}, refuse: allowOnly(access.MethodPassword), err: account.ErrNoUsableMethod},
		{name: "stale_passkey_with_totp", has: user{totp: true, staleKey: true}, next: account.NextSecondFactor, methods: []access.Method{access.MethodTOTP}},
		{name: "stale_passkey_rule_on_is_neither", rules: rule, has: user{staleKey: true}, known: true, next: account.NextEnrol, methods: []access.Method{access.MethodTOTP, access.MethodPasskey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{posture: access.PosturePerRequest, edit: tc.refuse})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			if tc.has.totp {
				storeTOTP(t, f.mem, u)
			}
			if tc.has.passkey {
				addPasskey(t, f.mem, u, f.rp.ID())
			}
			if tc.has.staleKey {
				addPasskey(t, f.mem, u, "old.example.com")
			}
			if tc.has.recovery {
				storeRecoveryCode(t, f.mem, u)
			}
			c := clientAt(1)
			c.Secure = !tc.plain
			if tc.known {
				c.Device = f.knownDevice("alice")
			}
			out, err := f.step1(t.Context(), c, "alice", goodPassword)
			switch {
			case tc.err != nil:
				if !errors.Is(err, tc.err) || out.Pending != nil {
					t.Fatalf("PasswordLogin = %+v, %v, want %v and no ticket", out.Pending, err, tc.err)
				}
				if !out.SignedIn.DeviceCookie.IsZero() {
					t.Error("a refused step 1 answered a device cookie")
				}
			case tc.next == "":
				if err != nil || out.Pending != nil || out.SignedIn.Token.IsZero() {
					t.Fatalf("PasswordLogin = %+v, %v, want a session", out.Pending, err)
				}
			default:
				p := pending(t, out, err, tc.next, tc.methods...)
				got, ok := account.TicketOf(f.svc, p.Ticket)
				if !ok || got.UserID != u.ID || got.Next != tc.next || got.Secure != c.Secure || !slices.Equal(got.Methods, tc.methods) {
					t.Errorf("cached ticket = %+v, %t, want user %d, %s, secure %t", got, ok, u.ID, tc.next, c.Secure)
				}
				if got.Digest != storedUser(t, f.mem, u.ID).PasswordHash.Key() {
					t.Error("the ticket's digest is not the stored PasswordHash's")
				}
			}
		})
	}
}

// allowOnly is a Config edit whose Rules.MethodUsable allows only methods.
func allowOnly(methods ...access.Method) func(*account.Config) {
	return func(c *account.Config) {
		rules := c.Rules
		c.Rules = func() account.Rules {
			r := rules()
			r.MethodUsable = func(_ context.Context, _ account.Tx, _ *access.User, m access.Method) bool {
				return slices.Contains(methods, m)
			}
			return r
		}
	}
}

// TestStepOneDisableTOTP: a held factor is a usable one. With DisableTOTP
// on, a TOTP-only user's record reads as absent.
func TestStepOneDisableTOTP(t *testing.T) {
	t.Parallel()
	off := account.Rules{DisableTOTP: true}
	f := newSF(t, off, pwOptions{})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	storeTOTP(t, f.mem, u)
	in, err := f.login(t.Context(), clientAt(1), "alice", goodPassword)
	if err != nil {
		t.Fatalf("rule off: PasswordLogin = %v, want a session", err)
	}
	pr, err := f.authenticate(t.Context(), in.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	me, err := f.svc.Me(t.Context(), pr)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.Methods.SecondFactorHeld || !me.Methods.PasswordStepUp {
		t.Errorf("Me methods: second_factor_held %t, password_step_up %t, want false and true", me.Methods.SecondFactorHeld, me.Methods.PasswordStepUp)
	}
	f.set(account.Rules{DisableTOTP: true, RequireSecondFactor: true})
	c := clientAt(2)
	c.Device = f.knownDevice("alice")
	out, err := f.step1(t.Context(), c, "alice", goodPassword)
	pending(t, out, err, account.NextEnrol, access.MethodPasskey)
}

// TestMethodsSecondFactorHeld is MeResponse.methods.second_factor_held and
// password_step_up.
func TestMethodsSecondFactorHeld(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name               string
		rules              account.Rules
		totp, passkey      bool
		held, passwordStep bool
	}{
		{name: "nothing", passwordStep: true},
		{name: "totp", totp: true, held: true},
		{name: "totp_disabled", rules: account.Rules{DisableTOTP: true}, totp: true, passwordStep: true},
		{name: "passkey_rule_off", passkey: true, passwordStep: true},
		{name: "passkey_rule_on", rules: account.Rules{RequireSecondFactor: true}, passkey: true, held: true},
		{name: "password_login_off", rules: account.Rules{DisablePasswordLogin: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			if tc.totp {
				storeTOTP(t, f.mem, u)
			}
			if tc.passkey {
				addPasskey(t, f.mem, u, f.rp.ID())
			}
			me, err := f.svc.Me(t.Context(), f.sessionPrincipal(t, u, time.Now()))
			if err != nil {
				t.Fatalf("Me: %v", err)
			}
			if me.Methods.SecondFactorHeld != tc.held || me.Methods.PasswordStepUp != tc.passwordStep {
				t.Errorf("second_factor_held %t, password_step_up %t, want %t and %t", me.Methods.SecondFactorHeld, me.Methods.PasswordStepUp, tc.held, tc.passwordStep)
			}
		})
	}
	t.Run("no_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		addPasskey(t, f.mem, u, f.rp.ID())
		if me, err := f.svc.Me(t.Context(), f.sessionPrincipal(t, u, time.Now())); err != nil || me.Methods.PasswordStepUp {
			t.Errorf("Me = %v, password_step_up %t, want false for a user with no password", err, me.Methods.PasswordStepUp)
		}
	})
}

// TestStepOneSettles: step 1 settles the password attempt, and the limiter
// has two settle outcomes and one minter.
func TestStepOneSettles(t *testing.T) {
	t.Parallel()
	totpUser := func(t *testing.T, f *sfFixture) *access.User {
		t.Helper()
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		return u
	}
	t.Run("pending_resets_the_failure_count", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		totpUser(t, f)
		f.failN(t, clientAt(1), "alice", 3)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		if rec, found := record(t, f.mem, f.svc, "alice", false); found {
			t.Errorf("password record after a pending step 1 = %+v, want none: an abandoned second step costs the password nothing", rec)
		}
	})
	t.Run("refusal_resets_the_failure_count", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		f.failN(t, clientAt(1), "alice", 3)
		if _, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword); !errors.Is(err, account.ErrEnrolNeedsKnownDevice) {
			t.Fatalf("PasswordLogin = %v, want ErrEnrolNeedsKnownDevice", err)
		}
		if _, found := record(t, f.mem, f.svc, "alice", false); found {
			t.Error("a refusal after a correct password left the failure record")
		}
	})
	t.Run("no_session_before_the_second_step", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := totpUser(t, f)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		if ss := sessionsOf(t, f.mem, u.ID); len(ss) != 0 {
			t.Errorf("sessions after a pending step 1 = %d, want none (ZITADEL GHSA-9993-rfwp-rhwf)", len(ss))
		}
		if n := len(eventsOf(f.events, account.EventSignedIn)); n != 0 {
			t.Errorf("signed_in events = %d, want none", n)
		}
	})
	t.Run("two_fresh_posts_both_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
		passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		for i := range 2 {
			out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
			if !errors.Is(err, account.ErrEnrolNeedsKnownDevice) || !errors.Is(err, account.ErrSecondFactorRequired) || !out.SignedIn.DeviceCookie.IsZero() {
				t.Fatalf("post %d = %v, cookie %t, want ErrEnrolNeedsKnownDevice and no device cookie", i+1, err, !out.SignedIn.DeviceCookie.IsZero())
			}
		}
	})
	t.Run("pending_leaves_the_ip_budget_whole", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: ipLimit(10)})
		totpUser(t, f)
		for range 10 {
			out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
			pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		}
		f.failN(t, clientAt(1), "alice", 10)
		if _, err := f.step1(t.Context(), clientAt(1), "alice", wrongPassword); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("the 11th wrong post after ten pending = %v, want the IP budget full", err)
		}
	})
	t.Run("pending_leaves_the_device_budget_whole", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: func(c *ratelimit.Config) { c.Device = ratelimit.Rate{Limit: 10, Window: time.Hour} }})
		totpUser(t, f)
		c := clientAt(1)
		c.Device = f.knownDevice("alice")
		for range 10 {
			out, err := f.step1(t.Context(), c, "alice", goodPassword)
			pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		}
		f.failN(t, c, "alice", 10)
		if _, err := f.step1(t.Context(), c, "alice", wrongPassword); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("the 11th wrong post after ten pending = %v, want the device budget full", err)
		}
	})
	t.Run("pending_keeps_earlier_untrusted_failures", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: func(c *ratelimit.Config) { c.Account = ratelimit.Rate{Limit: 3, Window: time.Hour} }})
		totpUser(t, f)
		f.failN(t, clientAt(1), "alice", 2)
		out, err := f.step1(t.Context(), clientAt(2), "alice", goodPassword)
		pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		f.failN(t, clientAt(3), "alice", 1)
		var refused *ratelimit.RefusedError
		if _, err := f.step1(t.Context(), clientAt(4), "alice", goodPassword); !errors.As(err, &refused) || refused.Dimension != "account" {
			t.Errorf("after two failures, a pending step 1 and a third failure = %v, want the account bucket full", err)
		}
	})
	t.Run("wrong_passwords_fill_the_ip_budget", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{limiter: ipLimit(10)})
		totpUser(t, f)
		f.failN(t, clientAt(1), "alice", 10)
		if _, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("after ten wrong passwords = %v, want the IP budget full", err)
		}
	})
	t.Run("plain_https_refusal_warns", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{posture: access.PosturePerRequest})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		addPasskey(t, f.mem, u, f.rp.ID())
		c := clientAt(1)
		c.Secure = false
		if _, err := f.step1(t.Context(), c, "alice", goodPassword); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("PasswordLogin = %v, want ErrHTTPSRequired", err)
		}
		named := 0
		for _, r := range f.logs.Records("") {
			if r.Level == slog.LevelWarn && strings.Contains(r.Message, "RequireSecondFactor") {
				named++
			}
		}
		if n := warnings(f.logs); n != 1 || named != 1 {
			t.Errorf("WARN lines = %d, %d naming RequireSecondFactor, want one", n, named)
		}
	})
}

// TestEveryFirstFactorUnderTheRule is the Keycloak CVE-2026-114438
// regression: under RequireSecondFactor no password sign-in completes in
// one step, whatever the user holds.
func TestEveryFirstFactorUnderTheRule(t *testing.T) {
	t.Parallel()
	for name, give := range map[string]func(t *testing.T, f *sfFixture, u *access.User){
		"nothing":  func(*testing.T, *sfFixture, *access.User) {},
		"totp":     func(t *testing.T, f *sfFixture, u *access.User) { storeTOTP(t, f.mem, u) },
		"passkey":  func(t *testing.T, f *sfFixture, u *access.User) { addPasskey(t, f.mem, u, f.rp.ID()) },
		"stale":    func(t *testing.T, f *sfFixture, u *access.User) { addPasskey(t, f.mem, u, "old.example.com") },
		"recovery": func(t *testing.T, f *sfFixture, u *access.User) { storeRecoveryCode(t, f.mem, u) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			give(t, f, u)
			for _, known := range []bool{false, true} {
				c := clientAt(1)
				if known {
					c.Device = f.knownDevice("alice")
				}
				out, err := f.step1(t.Context(), c, "alice", goodPassword)
				if err == nil && out.Pending == nil {
					t.Fatalf("known device %t: a password alone signed in under the rule", known)
				}
			}
		})
	}
}

// TestKnownDeviceAtStepOne checks the known-device rule: only a cookie a
// secure sign-in sealed lets an existing account enrol its first factor.
func TestKnownDeviceAtStepOne(t *testing.T) {
	t.Parallel()
	f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
	passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	secure := f.deviceCookie(t, clientAt(1), "alice", goodPassword)
	plain := clientAt(2)
	plain.Secure, plain.Device = false, secure
	demoted := f.deviceCookie(t, plain, "alice", goodPassword)
	plainOnly := clientAt(3)
	plainOnly.Secure = false
	fromPlain := f.deviceCookie(t, plainOnly, "alice", goodPassword)

	f.set(account.Rules{RequireSecondFactor: true})
	for name, tc := range map[string]struct {
		cookie access.Secret
		known  bool
	}{
		"sealed_on_a_secure_sign_in":   {secure, true},
		"re_sealed_on_a_plain_sign_in": {demoted, false},
		"sealed_on_a_plain_sign_in":    {fromPlain, false},
	} {
		c := clientAt(4)
		c.Device = tc.cookie
		out, err := f.step1(t.Context(), c, "alice", goodPassword)
		if tc.known {
			pending(t, out, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
			continue
		}
		if !errors.Is(err, account.ErrEnrolNeedsKnownDevice) {
			t.Errorf("%s: PasswordLogin = %+v, %v, want ErrEnrolNeedsKnownDevice", name, out.Pending, err)
		}
	}
}

// TestTicketsEnd: a ticket dies with the credential that earned it, and the
// Keycloak CVE-2026-94218 regression.
func TestTicketsEnd(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*sfFixture, *access.User, *account.Pending) {
		t.Helper()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		storeTOTP(t, f.mem, u)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		return f, u, pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
	}
	gone := func(t *testing.T, f *sfFixture, p *account.Pending) {
		t.Helper()
		if _, ok := account.TicketOf(f.svc, p.Ticket); ok {
			t.Error("the pending sign-in's ticket outlived the change")
		}
	}
	t.Run("step_1_again", func(t *testing.T) {
		t.Parallel()
		f, _, old := setup(t)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		fresh := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		gone(t, f, old)
		if _, ok := account.TicketOf(f.svc, fresh.Ticket); !ok {
			t.Error("the new step 1's ticket is not live")
		}
	})
	t.Run("set_password", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		pr := f.sessionPrincipal(t, u, time.Now())
		if _, err := f.svc.SetPassword(t.Context(), clientAt(2), pr, access.NewSecret(goodPassword), access.NewSecret("another-horse-battery-9")); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("remove_password", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		addPasskey(t, f.mem, u, f.rp.ID())
		pr := f.sessionPrincipal(t, u, time.Now())
		if _, err := f.svc.RemovePassword(t.Context(), clientAt(2), pr, access.NewSecret(goodPassword)); err != nil {
			t.Fatalf("RemovePassword: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("disable", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		off := false
		if _, err := f.svc.UpdateUser(t.Context(), f.sessionPrincipal(t, storedByName(t, f.mem, "root"), time.Now()), u.ID, account.UserChange{Enabled: &off}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("delete", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		if err := f.svc.DeleteUser(t.Context(), f.sessionPrincipal(t, storedByName(t, f.mem, "root"), time.Now()), u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("temporary_password", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("test"), u.ID, account.TemporaryPasswordOptions{}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("second_factor_reset", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		if err := f.svc.ResetSecondFactor(t.Context(), account.OutOfBand("test"), u.ID); err != nil {
			t.Fatalf("ResetSecondFactor: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("admin_unlink", func(t *testing.T) {
		t.Parallel()
		f, u, p := setup(t)
		u.OIDC = access.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "alice"}
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.OutOfBand("test"), u.ID); err != nil {
			t.Fatalf("AdminUnlinkOIDC: %v", err)
		}
		gone(t, f, p)
	})
	// A change that leaves a user's local methods dormant drops the user's
	// pending sign-ins with the sessions it ends.
	dormant := func(t *testing.T, mode account.SSOMode, owner bool) (*sfFixture, *oidcRig, *access.User, *account.Pending) {
		t.Helper()
		rig := rigFor(t, "subject-a")
		f := newSF(t, account.Rules{}, pwOptions{edit: rig.withOIDC})
		passwordOwner(t, f.pwFixture, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if owner {
			u.Role, u.Owner = access.RoleAdmin, true
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}
		storeTOTP(t, f.mem, u)
		if mode != account.SSOAlongside {
			storeMode(t, f.mem, mode)
		}
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		return f, rig, storedUser(t, f.mem, u.ID), pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
	}
	t.Run("apply_sso_only", func(t *testing.T) {
		t.Parallel()
		f, _, _, p := dormant(t, account.SSOAlongside, false)
		if err := f.svc.ApplySSO(t.Context(), socket, account.SSOOnly); err != nil {
			t.Fatalf("ApplySSO: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("migrate_sso_only", func(t *testing.T) {
		t.Parallel()
		f, _, _, p := dormant(t, account.SSOAlongside, false)
		if err := f.svc.MigrateSSO(t.Context(), account.SSOOnly); err != nil {
			t.Fatalf("MigrateSSO: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("set_owner_false_under_sso_only", func(t *testing.T) {
		t.Parallel()
		f, _, u, p := dormant(t, account.SSOOnly, true)
		if _, err := f.svc.SetOwner(t.Context(), socket, u.ID, false); err != nil {
			t.Fatalf("SetOwner(false): %v", err)
		}
		gone(t, f, p)
	})
	t.Run("link_intent_under_for_linked", func(t *testing.T) {
		t.Parallel()
		f, rig, u, p := dormant(t, account.SSOForLinked, false)
		sess := putSession(t, f.mem, liveSession(t, u))
		flow, claims := rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
		if out, err := f.svc.OIDCComplete(t.Context(), localClient, flow, claims); err != nil || out.Kind != account.OutcomeLinked {
			t.Fatalf("OIDCComplete = %+v, %v; want Linked", out, err)
		}
		gone(t, f, p)
	})
	t.Run("link_pending_under_for_linked", func(t *testing.T) {
		t.Parallel()
		f, rig, u, p := dormant(t, account.SSOForLinked, false)
		pr, _ := f.signedInVia(t, u, access.MethodPassword)
		if _, _, err := f.svc.LinkPendingOIDC(t.Context(), pr, account.PendingLink{Identity: rig.identity()}); err != nil {
			t.Fatalf("LinkPendingOIDC: %v", err)
		}
		gone(t, f, p)
	})
	t.Run("link_under_alongside_keeps_the_ticket", func(t *testing.T) {
		t.Parallel()
		f, rig, u, p := dormant(t, account.SSOAlongside, false)
		pr, _ := f.signedInVia(t, u, access.MethodPassword)
		if _, _, err := f.svc.LinkPendingOIDC(t.Context(), pr, account.PendingLink{Identity: rig.identity()}); err != nil {
			t.Fatalf("LinkPendingOIDC: %v", err)
		}
		if _, ok := account.TicketOf(f.svc, p.Ticket); !ok {
			t.Error("a link that left the password usable ended the pending sign-in")
		}
	})
}

// TestRehashAtStepOne checks the rehash rule: derived only unless the
// SSO mode refuses the sign-in, and written by a step 1 that pends.
func TestRehashAtStepOne(t *testing.T) {
	t.Parallel()
	seed := func(t *testing.T, f *sfFixture) *access.User {
		t.Helper()
		u := passwordUser(t, f.mem, nil, "alice", "")
		u.PasswordHash = doubleCostHash(t, goodPassword)
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		return u
	}
	t.Run("pending_migrates_the_hash", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := seed(t, f)
		storeTOTP(t, f.mem, u)
		out, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword)
		p := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		stored := storedUser(t, f.mem, u.ID).PasswordHash
		if f.hasher.NeedsRehash(stored) {
			t.Error("a pending step 1 left the old-parameter hash")
		}
		if got, _ := account.TicketOf(f.svc, p.Ticket); got.Digest != stored.Key() {
			t.Error("the ticket digests a hash other than the one step 1 left stored")
		}
	})
	t.Run("mode_refused_derives_none", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		u := seed(t, f)
		if err := f.mem.Update(t.Context(), func(tx account.Tx) error { return tx.SetSSOMode(t.Context(), account.SSOOnly) }); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		if _, err := f.step1(t.Context(), clientAt(1), "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("PasswordLogin = %v, want ErrInvalidCredentials", err)
		}
		if n := f.counted.hashed.Load(); n != 0 {
			t.Errorf("rehash derivations = %d, want none for a sign-in the mode refuses", n)
		}
		if storedUser(t, f.mem, u.ID).PasswordHash.Reveal() != u.PasswordHash.Reveal() {
			t.Error("a mode-refused sign-in changed the stored hash")
		}
	})
}

// TestCountedMethods checks the census: every method with a failure record
// is counted, so user creation and Me cover it.
func TestCountedMethods(t *testing.T) {
	t.Parallel()
	want := []access.Method{access.MethodPassword, access.MethodTOTP, access.MethodRecoveryCode}
	if got := account.CountedMethods(); !slices.Equal(got, want) {
		t.Errorf("countedMethods = %v, want %v", got, want)
	}
	f := newFixture(t, options{})
	name := account.FailureName(f.svc, "alice")
	for _, m := range want {
		if err := f.mem.PutAuthFailure(t.Context(), account.FailureCount{Name: name, Method: m, Count: 3}); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
	if _, err := f.svc.CreateUser(t.Context(), account.OutOfBand("test"), account.NewUser{Username: "alice", Role: access.RoleUser}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, m := range want {
		if _, found, _ := f.mem.AuthFailure(t.Context(), account.FailureRef{Name: name, Method: m}); found {
			t.Errorf("the new user's %s failure record survived its creation", m)
		}
	}
}
