package account_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// issueTemp issues u a temporary password as a and returns its shown form.
func issueTemp(t *testing.T, f *sfFixture, a account.Actor, u *access.User) string {
	t.Helper()
	issued, err := f.svc.SetTemporaryPassword(t.Context(), a, u.ID, account.TemporaryPasswordOptions{})
	if err != nil {
		t.Fatalf("SetTemporaryPassword = %v", err)
	}
	return issued.Password.Reveal()
}

func plain(c account.Client) account.Client {
	c.Secure = false
	return c
}

// usedEvents is the temporary_password_used events f recorded.
func usedEvents(f *sfFixture) []account.Event {
	return eventsOf(f.events, account.EventTemporaryPasswordUsed)
}

// requireUsed checks f journalled one temporary_password_used for userID
// over the transport plain names.
func requireUsed(t *testing.T, f *sfFixture, userID int64, plain bool) {
	t.Helper()
	evs := usedEvents(f)
	if len(evs) != 1 || evs[0].UserID != userID || evs[0].Plain != plain {
		t.Fatalf("temporary_password_used = %+v, want one for user %d with Plain %t", evs, userID, plain)
	}
}

// TestTemporaryPasswordSignIn uses one on a secure request: step 1 checks a
// live record first, spends it, and answers
// NextSetCredential.
func TestTemporaryPasswordSignIn(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, r account.Rules, edit func(*account.Config)) (*sfFixture, *access.User, string) {
		t.Helper()
		f := newSF(t, r, pwOptions{edit: edit})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		return f, alice, issueTemp(t, f, account.OutOfBand("cli"), alice)
	}
	// A correct entry that opens the next step is its only one.
	t.Run("spent_once", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{}, nil)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		p := pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		if got, ok := account.TicketOf(f.svc, p.Ticket); !ok || !got.Temporary || got.UserID != alice.ID || !got.Secure {
			t.Errorf("the ticket = %+v, %t; want alice's secure ticket from a temporary password", got, ok)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the record survived the step that spent it")
		}
		requireUsed(t, f, alice.ID, false)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the same temporary password again = %v, want ErrInvalidCredentials", err)
		}
	})
	// Normalisation: dashes and spaces go, any ASCII case, O for 0 and
	// I or L for 1.
	t.Run("normalised", func(t *testing.T) {
		t.Parallel()
		f, _, secret := setup(t, account.Rules{}, nil)
		typed := strings.ToLower(strings.ReplaceAll(secret, "-", " "))
		typed = strings.NewReplacer("0", "o", "1", "l").Replace(typed)
		out, err := f.step1(t.Context(), localClient, "alice", typed)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
	})
	// A temporary password spelled with ı for an I is not accepted at
	// step 1 (ASCII folding only).
	t.Run("dotless_i", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		var secret string
		for range 64 {
			if secret = issueTemp(t, f, account.OutOfBand("cli"), alice); strings.Contains(secret, "1") {
				break
			}
		}
		if !strings.Contains(secret, "1") {
			t.Fatal("64 issues drew no secret holding a 1")
		}
		if _, err := f.step1(t.Context(), localClient, "alice", strings.ReplaceAll(secret, "1", "ı")); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the secret with ı for 1 = %v, want ErrInvalidCredentials", err)
		}
		out, err := f.step1(t.Context(), localClient, "alice", strings.ReplaceAll(secret, "1", "I"))
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
	})
	// An expired temporary password fails exactly as a wrong password.
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{}, nil)
		later := time.Now().Add(25 * time.Hour)
		f.at.Store(&later)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("an expired temporary password = %v, want ErrInvalidCredentials", err)
		}
		if len(usedEvents(f)) != 0 {
			t.Error("an expired temporary password journalled temporary_password_used")
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("an expired temporary password left a password")
		}
	})
	// A store that drops the record fails closed: no temporary sign-in,
	// and never a permanent password.
	t.Run("store_drops_the_record", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{}, nil)
		if err := f.mem.DeleteTemporaryPassword(t.Context(), alice.ID); err != nil {
			t.Fatalf("DeleteTemporaryPassword: %v", err)
		}
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("a dropped record's secret = %v, want ErrInvalidCredentials", err)
		}
		if _, err := f.step1(t.Context(), localClient, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the password the issue cleared = %v, want ErrInvalidCredentials", err)
		}
	})
	// A temporary password is never rehashed, since a rehash
	// would copy it into PasswordHash as a permanent password.
	t.Run("never_rehashed", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		old, err := access.NewHasher(access.HasherConfig{Params: access.Argon2Params{Memory: 12288, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32}})
		if err != nil {
			t.Fatalf("NewHasher: %v", err)
		}
		shown, canonical := account.NewTemporaryPassword()
		hash, err := old.Hash(t.Context(), canonical)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		now := time.Now()
		if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: alice.ID, Hash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		out, err := f.step1(t.Context(), localClient, "alice", shown.Reveal())
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("step 1 wrote the temporary password into PasswordHash")
		}
	})
	// A correct first factor resets the password failure records.
	t.Run("resets_the_failure_count", func(t *testing.T) {
		t.Parallel()
		f, _, secret := setup(t, account.Rules{}, nil)
		f.failN(t, localClient, "alice", 3)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		if rec, found := record(t, f.mem, f.svc, "alice", false); found {
			t.Errorf("the password record = %+v after a correct temporary password, want none", rec)
		}
	})
	// Only a live temporary password is
	// verified, and its NextSetCredential lists passkey only.
	t.Run("password_login_off", func(t *testing.T) {
		t.Parallel()
		f, _, secret := setup(t, account.Rules{DisablePasswordLogin: true}, nil)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPasskey)
	})
	// Under DisablePasswordLogin an old password typed on the form
	// answers invalid credentials, never password_login_disabled.
	t.Run("password_login_off_old_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{DisablePasswordLogin: true}, pwOptions{})
		passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		_, err := f.step1(t.Context(), localClient, "bob", goodPassword)
		if !errors.Is(err, account.ErrInvalidCredentials) || errors.Is(err, account.ErrPasswordLoginDisabled) {
			t.Errorf("a password under DisablePasswordLogin = %v, want ErrInvalidCredentials", err)
		}
		_, err = f.step1(t.Context(), localClient, "nobody", goodPassword)
		if !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("an unknown name under DisablePasswordLogin = %v, want ErrInvalidCredentials", err)
		}
	})
	// With no relying party published, a temporary password under
	// DisablePasswordLogin answers no_usable_method with its record live.
	t.Run("no_relying_party_password_login_off", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{DisablePasswordLogin: true}, func(c *account.Config) {
			c.RP = func() *webauthn.RelyingParty { return nil }
		})
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrNoUsableMethod) {
			t.Errorf("step 1 = %v, want ErrNoUsableMethod", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("a secure no_usable_method deleted the record")
		}
	})
	// Under the rule with DisableTOTP on and passkeys refused, a secure
	// temporary password answers no_usable_method at step 1 with its record
	// live, and the refusal still resets the password failure count.
	t.Run("rule_no_way_to_enrol", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{RequireSecondFactor: true, DisableTOTP: true, MethodUsable: refusePasskeys}, nil)
		f.failN(t, localClient, "alice", 2)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrNoUsableMethod) {
			t.Errorf("step 1 = %v, want ErrNoUsableMethod", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("a secure no_usable_method deleted the record")
		}
		if rec, found := record(t, f.mem, f.svc, "alice", false); found {
			t.Errorf("the password record = %+v, want the refusal to reset it", rec)
		}
	})
	// Ticket-method function: under the rule a set password must still
	// enrol, so password stays while an enrolment method exists.
	t.Run("rule_on", func(t *testing.T) {
		t.Parallel()
		f, _, secret := setup(t, account.Rules{RequireSecondFactor: true}, nil)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
	})
}

// TestTemporaryPasswordPlain checks the burn: a plain step 1 that
// verifies a temporary password and answers no ticket deletes it and
// answers temporary_password_exposed; one whose path finishes over plain
// spends it.
func TestTemporaryPasswordPlain(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, r account.Rules, edit func(*account.Config), limit func(*ratelimit.Config)) (*sfFixture, *access.User, string) {
		t.Helper()
		f := newSF(t, r, pwOptions{posture: access.PosturePerRequest, edit: edit, limiter: limit})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		return f, alice, issueTemp(t, f, account.OutOfBand("cli"), alice)
	}
	burned := func(t *testing.T, f *sfFixture, alice *access.User, secret string) {
		t.Helper()
		_, err := f.step1(t.Context(), plain(localClient), "alice", secret)
		if !errors.Is(err, account.ErrTemporaryPasswordExposed) || !errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("plain step 1 = %v, want ErrTemporaryPasswordExposed matching access.ErrHTTPSRequired", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the burn left the record")
		}
		requireUsed(t, f, alice.ID, true)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the burned secret over HTTPS = %v, want ErrInvalidCredentials", err)
		}
	}
	// Over plain under the rule, a matched temporary password answers
	// 403, and the same secret over HTTPS then fails as a wrong password.
	t.Run("rule_on", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{RequireSecondFactor: true}, nil, nil)
		burned(t, f, alice, secret)
	})
	t.Run("password_login_off", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{DisablePasswordLogin: true}, nil, nil)
		burned(t, f, alice, secret)
	})
	// Ticket-method function: a plain temporary password whose set is
	// empty is burned, not answered no_usable_method.
	t.Run("empty_set", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{DisablePasswordLogin: true}, func(c *account.Config) {
			c.RP = func() *webauthn.RelyingParty { return nil }
		}, nil)
		burned(t, f, alice, secret)
	})
	// With the rule off and password sign-in on, the path finishes over
	// plain, so the secret is spent into a plain ticket listing password.
	t.Run("rule_off_spends", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{}, nil, nil)
		out, err := f.step1(t.Context(), plain(localClient), "alice", secret)
		p := pending(t, out, err, account.NextSetCredential, access.MethodPassword)
		if got, _ := account.TicketOf(f.svc, p.Ticket); got.Secure {
			t.Error("a plain step 1 minted a secure ticket")
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the spent record survived")
		}
		requireUsed(t, f, alice.ID, true)
	})
	// Limiter: the burn's 403 cancels the attempt, so it neither
	// counts nor forgives.
	t.Run("burn_cancels", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, account.Rules{RequireSecondFactor: true}, nil, ipLimit(1))
		if _, err := f.step1(t.Context(), plain(localClient), "alice", secret); !errors.Is(err, account.ErrTemporaryPasswordExposed) {
			t.Fatalf("plain step 1 = %v, want ErrTemporaryPasswordExposed", err)
		}
		if _, err := f.step1(t.Context(), plain(localClient), "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the next attempt from the IP = %v, want ErrInvalidCredentials: the burn spent the IP's one attempt", err)
		}
		_ = alice
	})
}

// TestTemporaryPasswordUnderMode checks the refused local sign-in for
// a temporary password: it looks like a wrong password, writes nothing on a
// secure request, and is burned on a plain one.
func TestTemporaryPasswordUnderMode(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, limit func(*ratelimit.Config)) (*sfFixture, *access.User, *access.User) {
		t.Helper()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest, limiter: limit})
		root := passwordUser(t, f.mem, f.hasher, "root", goodPassword)
		root.Role, root.Owner = access.RoleAdmin, true
		if err := f.mem.UpdateUser(t.Context(), root); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		return f, root, alice
	}
	// A secure sign-in the mode refuses writes nothing to the record,
	// so its one use under SSOOnly, the admin link, survives; it settles as
	// a wrong secret, so the IP's one attempt is spent.
	t.Run("secure_sso_only", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, ipLimit(1))
		setMode(t, f.mem, account.SSOOnly)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("a dormant user's temporary password = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("a secure mode-refused sign-in deleted the record")
		}
		if len(usedEvents(f)) != 0 {
			t.Error("a secure mode-refused sign-in journalled temporary_password_used")
		}
		var refused *ratelimit.RefusedError
		if _, err := f.step1(t.Context(), localClient, "alice", wrongPassword); !errors.As(err, &refused) {
			t.Errorf("the next attempt from the IP = %v, want a RefusedError: the refusal settles as a wrong secret", err)
		}
	})
	// On a plain request the secret has crossed in clear, so the burn
	// wins over the write-nothing rule; the answer is still a wrong
	// password, so no answer tells a non-owner from an owner.
	t.Run("plain_sso_only", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		setMode(t, f.mem, account.SSOOnly)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		_, err := f.step1(t.Context(), plain(localClient), "alice", secret)
		if !errors.Is(err, account.ErrInvalidCredentials) || errors.Is(err, access.ErrHTTPSRequired) {
			t.Fatalf("a plain dormant temporary password = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("a plain mode-refused temporary password survived")
		}
		requireUsed(t, f, alice.ID, true)
	})
	// Over plain under SSOForLinked, a linked non-owner's matched
	// temporary password is deleted and the answer is a wrong password.
	t.Run("plain_sso_for_linked", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		u := storedUser(t, f.mem, alice.ID)
		u.OIDC = access.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "alice"}
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		setMode(t, f.mem, account.SSOForLinked)
		if _, err := f.step1(t.Context(), plain(localClient), "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("a plain linked temporary password = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the matched record survived")
		}
	})
	// Under SSOOnly an owner's temporary password finishes over HTTPS.
	t.Run("owner_under_sso_only", func(t *testing.T) {
		t.Parallel()
		f, root, _ := setup(t, nil)
		setMode(t, f.mem, account.SSOOnly)
		secret := issueTemp(t, f, account.OutOfBand("cli"), root)
		out, err := f.step1(t.Context(), localClient, "root", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
	})
}

// TestTemporaryPasswordIssuerRecheck: use re-checks the issuer:
// a match runs every check the issue ran, again, at use; a failure deletes
// the record and answers as a wrong password.
func TestTemporaryPasswordIssuerRecheck(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, policy account.Policy) (*sfFixture, *access.User, *access.User) {
		t.Helper()
		f := issueFixture(t, account.Rules{}, 0, policy)
		root := mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		return f, root, alice
	}
	refused := func(t *testing.T, f *sfFixture, target *access.User, secret string) {
		t.Helper()
		if _, err := f.step1(t.Context(), localClient, target.Username, secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("step 1 after the issuer lost its authority = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, target.ID); found {
			t.Error("a failed issuer re-check left the record")
		}
	}
	// The issue's own Decision runs again at use, with the issuer's
	// principal and the re-read target.
	t.Run("current_issuer_asked_again", func(t *testing.T) {
		t.Parallel()
		gp := &gatePolicy{}
		f, root, alice := setup(t, gp)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice)
		gp.arm("")
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		asked := slices.ContainsFunc(gp.taken(), func(d account.Decision) bool {
			p, ok := d.Actor.Principal()
			return d.Op == account.OpSetTemporaryPassword && ok && p.User != nil && p.User.ID == admin.ID && d.Target != nil && d.Target.ID == alice.ID
		})
		if !asked {
			t.Errorf("decisions = %+v, want OpSetTemporaryPassword by admin on alice", gp.taken())
		}
		_ = root
	})
	// A test uses a Policy whose answer changes between issue and use.
	t.Run("policy_changes", func(t *testing.T) {
		t.Parallel()
		gp := &gatePolicy{}
		f, _, alice := setup(t, gp)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice)
		gp.arm(account.OpSetTemporaryPassword)
		refused(t, f, alice, secret)
	})
	// After its issuing admin is demoted.
	t.Run("issuer_demoted", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice)
		admin.Role = access.RoleUser
		if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		refused(t, f, alice, secret)
	})
	// The issuer must be enabled.
	t.Run("issuer_disabled", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice)
		admin.Enabled = false
		if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		refused(t, f, alice, secret)
	})
	// An owner who issued one for an owner and has since lost the
	// flag, while still an admin, therefore fails the re-check.
	t.Run("owner_lost_the_flag", func(t *testing.T) {
		t.Parallel()
		f, root, _ := setup(t, nil)
		second := mustOwner(t, f.mem, "second")
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, root, time.Now())), second)
		root.Owner = false
		if err := f.mem.UpdateUser(t.Context(), root); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		refused(t, f, second, secret)
	})
	// After its issuing key is revoked.
	t.Run("key_revoked", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, nil)
		p, key := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeUsers)
		secret := issueTemp(t, f, account.As(p), alice)
		if rec, _ := tempRecord(t, f.mem, alice.ID); rec.IssuedByKey != key.ID {
			t.Fatalf("IssuedByKey = %d, want %d", rec.IssuedByKey, key.ID)
		}
		if err := f.mem.DeleteAPIKey(t.Context(), access.KeyRef{ID: key.ID, UserID: root.ID}); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		refused(t, f, alice, secret)
	})
	// Issued OutOfBand and used: both issuer fields zero pass.
	t.Run("out_of_band", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
	})
	// A secure sign-in the SSO mode refuses writes nothing, the
	// issuer re-check's deletion included.
	t.Run("secure_mode_refused_writes_nothing", func(t *testing.T) {
		t.Parallel()
		gp := &gatePolicy{}
		f, _, alice := setup(t, gp)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		setMode(t, f.mem, account.SSOOnly)
		secret := issueTemp(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice)
		gp.arm(account.OpSetTemporaryPassword)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("step 1 = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("a secure mode-refused sign-in deleted the record on its issuer re-check")
		}
	})
}

// TestTemporaryPasswordLock: one verifier of a name's temporary password
// at a time. The lock sits after the limiter and
// before the hash permit and is held through the success Update.
func TestTemporaryPasswordLock(t *testing.T) {
	t.Parallel()
	type mark struct{}
	// holdSecond blocks the second Update of a request whose ctx carries
	// mark, its success Update, until release closes.
	holdSecond := func(fs *faultStore) (entered, release chan struct{}) {
		entered, release = make(chan struct{}), make(chan struct{})
		var n atomic.Int64
		fs.mu.Lock()
		fs.beforeUpdate = func(ctx context.Context, _ int) {
			if ctx.Value(mark{}) != nil && n.Add(1) == 2 {
				close(entered)
				<-release
			}
		}
		fs.mu.Unlock()
		return entered, release
	}
	// With the hash budget at one share, two posts for one name and
	// one for another, where the queued same-name post holds no permit and
	// the other name runs once the holder finishes its verify.
	t.Run("other_name_runs", func(t *testing.T) {
		t.Parallel()
		budget, err := access.NewHashBudget(access.HashCost(fastParams))
		if err != nil {
			t.Fatalf("NewHashBudget: %v", err)
		}
		fs, waits := newFaultStore(), newNameWaits()
		f := newSF(t, account.Rules{}, pwOptions{store: fs, budget: budget, hooks: waits.hooks()})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		entered, release := holdSecond(fs)
		first := make(chan error, 1)
		go func() {
			_, err := f.step1(context.WithValue(t.Context(), mark{}, true), localClient, "alice", secret)
			first <- err
		}()
		select {
		case <-entered:
		case <-time.After(30 * time.Second):
			t.Fatal("the holder's step 1 never reached its success Update")
		}
		queued := make(chan error, 1)
		go func() {
			_, err := f.step1(t.Context(), localClient, "Alice", wrongPassword)
			queued <- err
		}()
		waits.wait(t, "alice", 2)
		bob := make(chan error, 1)
		go func() {
			_, err := f.login(t.Context(), localClient, "bob", goodPassword)
			bob <- err
		}()
		select {
		case err := <-bob:
			if err != nil {
				t.Errorf("bob's sign-in = %v, want nil", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("bob's sign-in waited on alice's queued post")
		}
		requireQueued(t, queued, "the queued post")
		close(release)
		if err := <-first; err != nil {
			t.Errorf("the holder's step 1 = %v, want its pending sign-in", err)
		}
		if err := <-queued; !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the queued post = %v, want ErrInvalidCredentials", err)
		}
		requireNameFree(t, f.svc, "alice")
	})
	// A cancelled wait calls Cancel and answers as an ended context
	// does.
	t.Run("cancelled_wait", func(t *testing.T) {
		t.Parallel()
		fs, waits := newFaultStore(), newNameWaits()
		f := newSF(t, account.Rules{}, pwOptions{store: fs, limiter: ipLimit(2), hooks: waits.hooks()})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		entered, release := holdSecond(fs)
		first := make(chan error, 1)
		go func() {
			_, err := f.step1(context.WithValue(t.Context(), mark{}, true), localClient, "alice", secret)
			first <- err
		}()
		select {
		case <-entered:
		case <-time.After(30 * time.Second):
			t.Fatal("the holder's step 1 never reached its success Update")
		}
		ctx, cancel := context.WithCancel(t.Context())
		waited := make(chan error, 1)
		go func() {
			_, err := f.step1(ctx, localClient, "alice", wrongPassword)
			waited <- err
		}()
		waits.wait(t, "alice", 2)
		cancel()
		if err := <-waited; !errors.Is(err, context.Canceled) || !errors.Is(err, access.ErrHashBusy) {
			t.Errorf("a cancelled wait = %v, want access.ErrHashBusy with context.Canceled", err)
		}
		close(release)
		if err := <-first; err != nil {
			t.Fatalf("the holder's step 1 = %v", err)
		}
		// Both attempts were cancelled, so the IP's two slots are free.
		for i := range 2 {
			if _, err := f.step1(t.Context(), localClient, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("wrong password %d after the cancelled wait = %v, want ErrInvalidCredentials", i+1, err)
			}
		}
	})
}

// TestSetPasswordDeletesTemporaryPassword: SetPassword from any path also
// deletes a live temporary password.
func TestSetPasswordDeletesTemporaryPassword(t *testing.T) {
	t.Parallel()
	f := newSF(t, account.Rules{}, pwOptions{})
	mustOwner(t, f.mem, "root")
	alice := passwordUser(t, f.mem, nil, "alice", "")
	issueTemp(t, f, account.OutOfBand("cli"), alice)
	p := f.sessionPrincipal(t, alice, time.Now())
	if _, err := f.svc.SetPassword(t.Context(), localClient, p, access.Secret{}, access.NewSecret(goodPassword)); err != nil {
		t.Fatalf("SetPassword = %v", err)
	}
	if _, found := tempRecord(t, f.mem, alice.ID); found {
		t.Error("SetPassword left the live temporary password")
	}
}

// TestTemporaryPasswordFullList checks that step 1 holds its ticket's place
// before it spends a temporary password: while the pending sign-ins are
// full it answers the table's refusal and spends nothing, a failed spend
// gives the place back, and an arm that needs no ticket answers as before.
func TestTemporaryPasswordFullList(t *testing.T) {
	t.Parallel()
	t0 := time.Now().Truncate(time.Second)
	const other = 999 // a user whose live ticket fills the list
	setup := func(t *testing.T, o pwOptions) (*sfFixture, *access.User, string) {
		t.Helper()
		o.posture = access.PosturePerRequest
		f := newSF(t, account.Rules{}, o)
		f.at.Store(&t0)
		root := mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
		cache := account.PendingOf(f.svc)
		cache.SetMax(account.PurposeSignIn, 1)
		mustPut(t, cache, account.PurposeSignIn, access.User{ID: other, Username: root.Username}, t0)
		return f, alice, secret
	}
	requireKept := func(t *testing.T, f *sfFixture, alice *access.User) {
		t.Helper()
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("the refused step spent the temporary password")
		}
		if n := len(usedEvents(f)); n != 0 {
			t.Errorf("temporary_password_used events = %d, want none", n)
		}
	}
	t.Run("spends_nothing", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, pwOptions{})
		_, err := f.step1(t.Context(), localClient, "alice", secret)
		requireFull(t, err, t0, t0, 10*time.Minute)
		requireKept(t, f, alice)
		account.PendingOf(f.svc).DropUser(other)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		requireUsed(t, f, alice.ID, false)
	})
	// The plain burn needs no ticket, so it burns while the list is full.
	t.Run("plain_burn_needs_no_place", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, pwOptions{})
		f.rules.Store(&account.Rules{RequireSecondFactor: true})
		if _, err := f.step1(t.Context(), plain(localClient), "alice", secret); !errors.Is(err, account.ErrTemporaryPasswordExposed) {
			t.Fatalf("a plain step 1 under the rule with the list full = %v, want ErrTemporaryPasswordExposed", err)
		}
		requireUsed(t, f, alice.ID, true)
	})
	// A secure step 1 the SSO mode refuses answers as a wrong secret, full
	// list or not, so no answer tells a correct temporary password apart.
	t.Run("mode_refusal_stays_a_wrong_secret", func(t *testing.T) {
		t.Parallel()
		f, alice, secret := setup(t, pwOptions{})
		setMode(t, f.mem, account.SSOOnly)
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("a mode-refused step 1 with the list full = %v, want ErrInvalidCredentials", err)
		}
		requireKept(t, f, alice)
	})
	t.Run("failed_spend_gives_the_place_back", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f, alice, secret := setup(t, pwOptions{store: fs})
		account.PendingOf(f.svc).DropUser(other)
		fs.failCall("DeleteTemporaryPassword")
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, errFault) {
			t.Fatalf("step 1 whose spend fails = %v, want the store's error", err)
		}
		requireKept(t, f, alice)
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		storeTOTP(t, f.mem, bob)
		out, err := f.step1(t.Context(), localClient, "bob", goodPassword)
		pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
	})
	// A store that re-runs the Update holds one place, filled once.
	t.Run("update_run_twice", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f, alice, secret := setup(t, pwOptions{store: fs})
		cache := account.PendingOf(f.svc)
		cache.DropUser(other)
		fs.reRun(true)
		out, err := f.step1(t.Context(), localClient, "alice", secret)
		fs.reRun(false)
		p := pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		if _, live := account.TicketOf(f.svc, p.Ticket); !live {
			t.Error("the ticket is gone")
		}
		cache.DropUser(alice.ID)
		if _, err := cache.Put(account.PurposeSignIn, access.User{ID: other}, t0); err != nil {
			t.Errorf("a newcomer once the ticket ended = %v, want admitted: the re-run held one place", err)
		}
	})
}
