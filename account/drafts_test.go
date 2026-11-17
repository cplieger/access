package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// ruleOn is Rules.RequireSecondFactor with setup asking for no token.
var ruleOn = account.Rules{RequireSecondFactor: true, SetupTokenRequired: tokenless}

// refusePasskeys is a Rules.MethodUsable that refuses passkeys alone.
func refusePasskeys(_ context.Context, _ account.Tx, _ *access.User, m access.Method) bool {
	return m != access.MethodPasskey
}

// setupDraft is a password setup of owner from c, required to answer a
// draft's NextEnrol listing methods.
func setupDraft(t *testing.T, f *sfFixture, c account.Client, in account.SetupPassword, methods ...access.Method) access.Secret {
	t.Helper()
	out, err := f.svc.SetupWithPassword(t.Context(), c, in)
	p := pending(t, out, err, account.NextEnrol, methods...)
	got, ok := account.TicketOf(f.svc, p.Ticket)
	if !ok || got.Draft != account.ViaSetup || got.UserID != 0 || got.Username != canonicalOf(t, in.Username) {
		t.Fatalf("the ticket = %+v, %t; want setup's draft of %q with no user", got, ok, in.Username)
	}
	return p.Ticket
}

// canonicalOf is name as access stores it.
func canonicalOf(t testing.TB, name string) string {
	t.Helper()
	n, err := access.NormalizeUsername(name)
	if err != nil {
		t.Fatalf("NormalizeUsername(%q): %v", name, err)
	}
	return n
}

func setupIn(name string) account.SetupPassword {
	return account.SetupPassword{Username: name, Password: access.NewSecret(goodPassword)}
}

// requireNoUsers fails when a draft created anyone.
func requireNoUsers(t *testing.T, s account.Store) {
	t.Helper()
	if n, err := s.UserCount(t.Context()); err != nil || n != 0 {
		t.Fatalf("users = %d, %v; a draft creates no account before its finish", n, err)
	}
}

// tokenLive reports whether the token hash names is stored and unexpired.
func tokenLive(t testing.TB, s account.Store, hash access.Hash) bool {
	t.Helper()
	tok, found, err := s.OneTimeTokenByHash(t.Context(), hash)
	if err != nil {
		t.Fatalf("OneTimeTokenByHash: %v", err)
	}
	return found && tok.ExpiresAt.After(time.Now())
}

// TestSetupDraft: under the rule, first setup by password creates the
// account only when the second factor is bound, re-admits at the finish,
// marks the owner on that path, and answers the sign-in union.
func TestSetupDraft(t *testing.T) {
	t.Parallel()
	t.Run("pends_and_spends_nothing", func(t *testing.T) {
		t.Parallel()
		r := ruleOn
		r.SetupTokenRequired = nil
		f := newSF(t, r, pwOptions{})
		tok, err := f.svc.IssueSetupToken(t.Context(), account.OutOfBand("cli"), 0)
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		in := setupIn("Owner")
		in.Token = tok
		setupDraft(t, f, localClient, in, access.MethodTOTP, access.MethodPasskey)
		requireNoUsers(t, f.mem)
		if !tokenLive(t, f.mem, access.NewHash(access.HexSHA256(tok.Reveal()))) {
			t.Error("the draft spent the setup token; only the enrolment finish does")
		}
		if n := len(eventsOf(f.events, account.EventUserCreated)); n != 0 {
			t.Errorf("user_created events = %d before the finish, want 0", n)
		}
	})
	t.Run("totp_finish_creates_the_owner", func(t *testing.T) {
		t.Parallel()
		r := ruleOn
		r.SetupTokenRequired = nil
		f := newSF(t, r, pwOptions{})
		tok, err := f.svc.IssueSetupToken(t.Context(), account.OutOfBand("cli"), 0)
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		in := setupIn("owner")
		in.Token = tok
		ticket := setupDraft(t, f, localClient, in, access.MethodTOTP, access.MethodPasskey)
		got, _, err := pendingEnrolTOTP(t, f, localClient, ticket)
		if err != nil {
			t.Fatalf("PendingTOTPFinish = %v", err)
		}
		u := got.User
		if u == nil || u.Username != "owner" || u.Role != access.RoleAdmin || !u.Enabled || !u.Owner || u.PasswordHash.IsZero() {
			t.Fatalf("the created user = %+v, want an enabled admin owner with a password", u)
		}
		if got.Session.AuthMethod != access.MethodPassword || got.Token.IsZero() {
			t.Errorf("session = %+v, want a password session with its token", got.Session)
		}
		if got.RecoveryCode.IsZero() {
			t.Error("the finish issued no recovery code")
		}
		if _, found := totpRecord(t, f.mem, u.ID); !found {
			t.Error("the finish bound no TOTP record")
		}
		if tokenLive(t, f.mem, access.NewHash(access.HexSHA256(tok.Reveal()))) {
			t.Error("the finish left the setup token live (consumed only at the finish)")
		}
		if live(f, ticket) {
			t.Error("the draft's ticket outlived its finish")
		}
		for _, k := range []account.EventKind{account.EventUserCreated, account.EventTOTPAdded, account.EventRecoveryCodeIssued, account.EventSignedIn} {
			if evs := eventsOf(f.events, k); len(evs) != 1 || evs[0].UserID != u.ID {
				t.Errorf("%s events = %+v, want one for the new owner", k, evs)
			}
		}
	})
	t.Run("passkey_finish_creates_the_owner", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, ruleOn, pwOptions{})
		ticket := setupDraft(t, f, localClient, setupIn("owner"), access.MethodTOTP, access.MethodPasskey)
		got, err := pendingEnrolPasskey(t, f, localClient, ticket, accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("PendingPasskeyFinish = %v", err)
		}
		if u := got.User; u == nil || !u.Owner || u.Role != access.RoleAdmin {
			t.Fatalf("the created user = %+v, want the admin owner", got.User)
		}
		if keys, _ := f.mem.PasskeysByUserID(t.Context(), got.User.ID); len(keys) != 1 {
			t.Errorf("passkeys = %d, want the one the finish registered", len(keys))
		}
		if got.RecoveryCode.IsZero() {
			t.Error("a password and a passkey under the rule issued no recovery code")
		}
	})
	t.Run("abandoned_leaves_the_token_usable", func(t *testing.T) {
		t.Parallel()
		r := ruleOn
		r.SetupTokenRequired = nil
		f := newSF(t, r, pwOptions{})
		tok, err := f.svc.IssueSetupToken(t.Context(), account.OutOfBand("cli"), 0)
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		in := setupIn("owner")
		in.Token = tok
		setupDraft(t, f, localClient, in, access.MethodTOTP, access.MethodPasskey)
		f.set(account.Rules{})
		if _, err := completed(f.svc.SetupWithPassword(t.Context(), localClient, in)); err != nil {
			t.Fatalf("setup with the abandoned draft's token = %v, want signed in", err)
		}
	})
	t.Run("setup_completed_since_the_draft", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, ruleOn, pwOptions{})
		first := setupDraft(t, f, localClient, setupIn("first"), access.MethodTOTP, access.MethodPasskey)
		second := setupDraft(t, f, localClient, setupIn("second"), access.MethodTOTP, access.MethodPasskey)
		if _, _, err := pendingEnrolTOTP(t, f, localClient, first); err != nil {
			t.Fatalf("the first finish = %v", err)
		}
		if _, _, err := pendingEnrolTOTP(t, f, localClient, second); !errors.Is(err, account.ErrSetupComplete) {
			t.Fatalf("the second finish = %v, want ErrSetupComplete", err)
		}
		if n, _ := f.mem.UserCount(t.Context()); n != 1 {
			t.Errorf("users = %d, want the first draft's only", n)
		}
		if live(f, second) {
			t.Error("a draft that can no longer finish kept its ticket")
		}
	})
	t.Run("plain_refused_before_anything", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, ruleOn, pwOptions{posture: access.PosturePerRequest})
		c := localClient
		c.Secure = false
		if _, err := f.svc.SetupWithPassword(t.Context(), c, setupIn("owner")); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a plain setup under the rule = %v, want access.ErrHTTPSRequired", err)
		}
		requireNoUsers(t, f.mem)
		if n := account.PendingOf(f.svc).Len(); n != 0 {
			t.Errorf("pending entries = %d, want no ticket", n)
		}
	})
	// The ticket-method function on a setup draft.
	t.Run("passkeys_refused_lists_totp", func(t *testing.T) {
		t.Parallel()
		r := ruleOn
		r.MethodUsable = refusePasskeys
		f := newSF(t, r, pwOptions{})
		setupDraft(t, f, localClient, setupIn("owner"), access.MethodTOTP)
	})
	t.Run("no_usable_method", func(t *testing.T) {
		t.Parallel()
		r := ruleOn
		r.MethodUsable, r.DisableTOTP = refusePasskeys, true
		f := newSF(t, r, pwOptions{})
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, setupIn("owner")); !errors.Is(err, account.ErrNoUsableMethod) {
			t.Fatalf("setup with no enrolment method = %v, want ErrNoUsableMethod", err)
		}
		requireNoUsers(t, f.mem)
		if n := account.PendingOf(f.svc).Len(); n != 0 {
			t.Errorf("pending entries = %d, want no ticket", n)
		}
	})
	t.Run("guard: rule_off_signs_in", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{SetupTokenRequired: tokenless}, pwOptions{})
		got, err := completed(f.svc.SetupWithPassword(t.Context(), localClient, setupIn("owner")))
		if err != nil || got.User == nil || !got.User.Owner {
			t.Fatalf("setup with the rule off = %+v, %v; want the owner signed in", got.User, err)
		}
	})
}

// inviteWorld is an owner root with a recent session, who invites.
func inviteWorld(t *testing.T, r account.Rules) (*sfFixture, access.Principal) {
	t.Helper()
	f := newSF(t, r, pwOptions{})
	root := mustOwner(t, f.mem, "root")
	return f, f.sessionPrincipal(t, root, time.Now())
}

func (f *sfFixture) invite(t *testing.T, p access.Principal, role access.Role) account.IssuedToken {
	t.Helper()
	inv, err := f.svc.CreateInvite(t.Context(), p, role, 0)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return inv
}

// inviteDraft accepts inv as name by password from localClient, required to
// answer a draft's NextEnrol listing totp and passkey.
func inviteDraft(t *testing.T, f *sfFixture, inv account.IssuedToken, name string) access.Secret {
	t.Helper()
	out, err := f.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: inv.Plaintext, Username: name, Password: access.NewSecret(goodPassword)})
	p := pending(t, out, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
	if got, ok := account.TicketOf(f.svc, p.Ticket); !ok || got.Draft != account.ViaInvite || got.UserID != 0 {
		t.Fatalf("the ticket = %+v, %t; want an invite's draft with no user", got, ok)
	}
	return p.Ticket
}

// TestInviteDraft checks the draft for invite acceptance by password,
// with the re-admission at the finish and the sign-in union's answer.
func TestInviteDraft(t *testing.T) {
	t.Parallel()
	t.Run("pends_and_spends_nothing", func(t *testing.T) {
		t.Parallel()
		f, p := inviteWorld(t, ruleOn)
		inv := f.invite(t, p, access.RoleUser)
		inviteDraft(t, f, inv, "newcomer")
		if usernameTakenIn(t, f.mem, "newcomer") {
			t.Error("the draft created the account before its finish")
		}
		if !tokenLive(t, f.mem, hashOf(inv)) {
			t.Error("the draft spent the invite; only the enrolment finish does")
		}
	})
	t.Run("finish_creates_the_invited_role", func(t *testing.T) {
		t.Parallel()
		f, p := inviteWorld(t, ruleOn)
		inv := f.invite(t, p, access.RoleAdmin)
		ticket := inviteDraft(t, f, inv, "newcomer")
		got, _, err := pendingEnrolTOTP(t, f, localClient, ticket)
		if err != nil {
			t.Fatalf("PendingTOTPFinish = %v", err)
		}
		if u := got.User; u == nil || u.Username != "newcomer" || u.Role != access.RoleAdmin || u.Owner || !u.Enabled {
			t.Fatalf("the created user = %+v, want an enabled admin newcomer who is no owner", got.User)
		}
		if got.RecoveryCode.IsZero() {
			t.Error("the finish issued no recovery code")
		}
		if tokenLive(t, f.mem, hashOf(inv)) {
			t.Error("the finish left the invite live (consumed at the finish)")
		}
		if evs := eventsOf(f.events, account.EventUserCreated); len(evs) != 1 || evs[0].UserID != got.User.ID || evs[0].Role != access.RoleAdmin {
			t.Errorf("user_created = %+v, want the newcomer's with its role", evs)
		}
	})
	t.Run("invite_used_since_the_draft", func(t *testing.T) {
		t.Parallel()
		f, p := inviteWorld(t, ruleOn)
		inv := f.invite(t, p, access.RoleUser)
		first := inviteDraft(t, f, inv, "first")
		second := inviteDraft(t, f, inv, "second")
		if _, _, err := pendingEnrolTOTP(t, f, localClient, first); err != nil {
			t.Fatalf("the first finish = %v", err)
		}
		if _, _, err := pendingEnrolTOTP(t, f, localClient, second); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("the second finish = %v, want access.ErrTokenInvalid", err)
		}
		if usernameTakenIn(t, f.mem, "second") {
			t.Error("a spent invite created an account")
		}
		if live(f, second) {
			t.Error("a draft whose invite is spent kept its ticket")
		}
	})
	t.Run("name_taken_since_the_draft", func(t *testing.T) {
		t.Parallel()
		f, p := inviteWorld(t, ruleOn)
		inv := f.invite(t, p, access.RoleUser)
		ticket := inviteDraft(t, f, inv, "newcomer")
		passwordUser(t, f.mem, f.hasher, "newcomer", goodPassword)
		if _, _, err := pendingEnrolTOTP(t, f, localClient, ticket); !errors.Is(err, account.ErrUsernameTaken) {
			t.Fatalf("the finish = %v, want ErrUsernameTaken", err)
		}
		if !tokenLive(t, f.mem, hashOf(inv)) {
			t.Error("a refused finish spent the invite")
		}
	})
	t.Run("guard: rule_off_signs_in", func(t *testing.T) {
		t.Parallel()
		f, p := inviteWorld(t, account.Rules{})
		inv := f.invite(t, p, access.RoleUser)
		got, err := completed(f.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "newcomer", Password: access.NewSecret(goodPassword)}))
		if err != nil || got.User == nil || got.User.Username != "newcomer" {
			t.Fatalf("acceptance with the rule off = %+v, %v; want newcomer signed in", got.User, err)
		}
	})
}

func usernameTakenIn(t *testing.T, s account.Store, name string) bool {
	t.Helper()
	_, found, err := s.UserByUsername(t.Context(), name)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	return found
}

// TestCheckSecondFactorReady checks the enable-time check: a full
// session on a secure request whose user holds a usable TOTP or a usable
// passkey, so a dormant record does not count.
func TestCheckSecondFactorReady(t *testing.T) {
	t.Parallel()
	type held struct{ totp, passkey, oldPasskey bool }
	cases := []struct {
		name   string
		rules  account.Rules
		has    held
		plain  bool
		key    bool
		ssoOff bool // the stored mode SSOOnly keeps the admin dormant
		ok     bool
	}{
		{name: "no_factor"},
		{name: "usable_totp", has: held{totp: true}, ok: true},
		{name: "usable_passkey", has: held{passkey: true}, ok: true},
		{name: "totp_turned_off", rules: account.Rules{DisableTOTP: true}, has: held{totp: true}},
		{name: "passkey_under_an_old_rp", has: held{oldPasskey: true}},
		{name: "passkeys_refused", rules: account.Rules{MethodUsable: refusePasskeys}, has: held{passkey: true}},
		{name: "plain_request", has: held{totp: true}, plain: true},
		{name: "api_key", has: held{totp: true}, key: true},
		{name: "dormant_under_sso_only", has: held{totp: true}, ssoOff: true},
	}
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		p := f.sessionPrincipal(t, mustOwner(t, f.mem, "root"), time.Now())
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		if err := f.svc.CheckSecondFactorReady(t.Context(), localClient, p); !errors.Is(err, account.ErrServiceClosed) {
			t.Fatalf("CheckSecondFactorReady after Shutdown = %v, want ErrServiceClosed", err)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.rules, pwOptions{})
			admin := passwordUser(t, f.mem, f.hasher, "admin", goodPassword)
			admin.Role = access.RoleAdmin
			if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			mustOwner(t, f.mem, "root")
			if tc.has.totp {
				storeTOTP(t, f.mem, admin)
			}
			if tc.has.passkey {
				addPasskey(t, f.mem, admin, rpID)
			}
			if tc.has.oldPasskey {
				addPasskey(t, f.mem, admin, "old.example.com")
			}
			if tc.ssoOff {
				if err := f.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
					t.Fatalf("SetSSOMode: %v", err)
				}
			}
			p := f.sessionPrincipal(t, admin, time.Now())
			if tc.key {
				p = f.keyPrincipal(t, admin, f.svc.AdminScope())
			}
			c := localClient
			c.Secure = !tc.plain
			err := f.svc.CheckSecondFactorReady(t.Context(), c, p)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("CheckSecondFactorReady = %v, want nil", err)
			case !tc.ok && (!errors.Is(err, account.ErrEnableWithoutSecondFactor) || !errors.Is(err, account.ErrSecondFactorRequired)):
				t.Fatalf("CheckSecondFactorReady = %v, want ErrEnableWithoutSecondFactor matching ErrSecondFactorRequired", err)
			}
		})
	}
}

// TestDraftList checks the cache table: drafts have their own list,
// so a flood of them never evicts a pending sign-in and ceremonies never
// evict a draft.
func TestDraftList(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := account.NewPendingCache(2)
	signIn := c.Put(account.PurposeSignIn, access.User{ID: 1}, t0)
	draft := c.Put(account.PurposeDraft, access.User{Username: "draft"}, t0)
	for i := range 5 {
		c.Put(account.PurposeLogin, access.User{}, t0.Add(time.Duration(i)*time.Second))
	}
	if _, ok := c.Take(draft, account.PurposeDraft, t0.Add(time.Minute)); !ok {
		t.Error("a flood of ceremonies evicted a draft")
	}
	if _, ok := c.Take(signIn, account.PurposeSignIn, t0.Add(time.Minute)); !ok {
		t.Error("a draft evicted a pending sign-in")
	}
	late := c.Put(account.PurposeDraft, access.User{Username: "late"}, t0)
	if _, ok := c.Take(late, account.PurposeDraft, t0.Add(10*time.Minute)); ok {
		t.Error("a draft outlived its ten minutes")
	}
}
