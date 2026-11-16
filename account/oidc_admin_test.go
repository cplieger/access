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
)

// pendingFor is the pending state an admitted identity of subject left.
func pendingFor(subject string) account.PendingLink {
	return account.PendingLink{Identity: access.OIDCIdentity{Issuer: oidcIssuer, Subject: subject}}
}

// adminLinkFixture is a Service with OIDC, passkeys and the key scopes
// wired, under SSOOnly, holding an owner root and a non-owner alice, both
// with goodPassword.
func adminLinkFixture(t *testing.T, o pwOptions, policy account.Policy) (f *oidcFixture, root, alice *access.User) {
	t.Helper()
	o.options = keyOptions(o.options, policy)
	f = newOIDCFixture(t, rigFor(t, "subject-l"), o)
	root = passwordOwner(t, f.pwFixture, "root")
	alice = passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	storeMode(t, f.mem, account.SSOOnly)
	return f, root, storedUser(t, f.mem, alice.ID)
}

// issueFor issues u a temporary password as a.
func issueFor(t *testing.T, f *oidcFixture, a account.Actor, u *access.User, in account.TemporaryPasswordOptions) account.IssuedTemporaryPassword {
	t.Helper()
	issued, err := f.svc.SetTemporaryPassword(t.Context(), a, u.ID, in)
	if err != nil {
		t.Fatalf("SetTemporaryPassword = %v", err)
	}
	return issued
}

func (f *oidcFixture) adminLink(ctx context.Context, c account.Client, pl account.PendingLink, name, secret string) (account.SignedIn, error) {
	return f.svc.LinkPendingOIDCByAdmin(ctx, c, pl, name, access.NewSecret(secret))
}

// requireUnlinked checks u holds no link.
func requireUnlinked(t *testing.T, f *oidcFixture, u *access.User) {
	t.Helper()
	if got := storedUser(t, f.mem, u.ID); !got.OIDC.IsZero() {
		t.Errorf("%s is linked to %+v, want no link", u.Username, got.OIDC)
	}
}

// holdUpdate blocks the nth Update of a request whose ctx carries key
// until release closes; entered closes when it is reached.
func holdUpdate(fs *faultStore, key any, nth int64) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	var n atomic.Int64
	fs.mu.Lock()
	fs.beforeUpdate = func(ctx context.Context, _ int) {
		if ctx.Value(key) != nil && n.Add(1) == nth {
			close(entered)
			<-release
		}
	}
	fs.mu.Unlock()
	return entered, release
}

// waitRefs waits until name's lock counts n holders and waiters.
func waitRefs(t *testing.T, svc *account.Service, name string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for account.NameLockRefs(svc, name) != n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := account.NameLockRefs(svc, name); got != n {
		t.Fatalf("%s's lock refs = %d, want %d", name, got, n)
	}
}

// TestLinkPendingOIDCByAdmin is design 5.5's "With an admin's consent,
// under SSOOnly only": the pending identity is linked to the account an
// admin's temporary password names, and signed in by OIDC.
func TestLinkPendingOIDCByAdmin(t *testing.T) {
	t.Parallel()
	// 5.5 and 5.10: one session whose AuthMethod is OIDC, no password or
	// passkey session, the record spent, the dormant password kept.
	t.Run("links", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		issued := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{})
		if !issued.Dormant || !issued.PasswordKept {
			t.Fatalf("the issue = %+v, want a dormant record beside the kept password", issued)
		}
		pl := pendingFor("alice-sub")
		mark := len(f.events.all())
		in, err := f.adminLink(t.Context(), localClient, pl, "alice", issued.Password.Reveal())
		if err != nil {
			t.Fatalf("LinkPendingOIDCByAdmin = %v", err)
		}
		u := storedUser(t, f.mem, alice.ID)
		if u.OIDC != pl.Identity {
			t.Errorf("alice's link = %+v, want %+v", u.OIDC, pl.Identity)
		}
		if !u.PasswordHash.Equal(alice.PasswordHash) {
			t.Error("the link changed alice's dormant password")
		}
		if in.User == nil || in.User.ID != alice.ID {
			t.Errorf("signed in %+v, want alice", in.User)
		}
		sessions := sessionsOf(t, f.mem, alice.ID)
		if len(sessions) != 1 || sessions[0].ID != in.Session.ID || sessions[0].AuthMethod != access.MethodOIDC {
			t.Errorf("alice's sessions = %+v, want the one answered, by oidc", sessions)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the link left the record it spent")
		}
		evs := f.events.all()[mark:]
		kinds := make([]account.EventKind, 0, len(evs))
		for _, ev := range evs {
			kinds = append(kinds, ev.Kind)
		}
		if !slices.Equal(kinds, []account.EventKind{account.EventOIDCLinked, account.EventSignedIn}) {
			t.Fatalf("events = %v, want oidc_linked then signed_in", kinds)
		}
		if ev := evs[0]; ev.UserID != alice.ID || ev.IssuerUserID != 0 || ev.KeyID != 0 {
			t.Errorf("oidc_linked = %+v, want alice's, issued out of band", ev)
		}
		if ev := evs[1]; ev.Method != access.MethodOIDC || ev.UserID != alice.ID {
			t.Errorf("signed_in = %+v, want alice by oidc", ev)
		}
		// 4.9 "works once".
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("other-sub"), "alice", issued.Password.Reveal()); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the spent secret again = %v, want ErrInvalidCredentials", err)
		}
	})
	// 4.6's normalisation, which 4.9 gives the secret at every verifier.
	t.Run("normalised", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		typed := strings.NewReplacer("0", "o", "1", "l").Replace(strings.ToLower(strings.ReplaceAll(secret, "-", " ")))
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "Alice", typed); err != nil {
			t.Errorf("the secret typed %q for Alice = %v, want linked", typed, err)
		}
	})
	// 5.5: oidc_linked names the record's issuer.
	t.Run("issuer_named", func(t *testing.T) {
		t.Parallel()
		f, root, alice := adminLinkFixture(t, pwOptions{}, nil)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueFor(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); err != nil {
			t.Fatalf("LinkPendingOIDCByAdmin = %v", err)
		}
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		p, key := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeUsers)
		secret = issueFor(t, f, account.As(p), bob, account.TemporaryPasswordOptions{}).Password.Reveal()
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("bob-sub"), "bob", secret); err != nil {
			t.Fatalf("LinkPendingOIDCByAdmin(bob) = %v", err)
		}
		evs := eventsOf(f.events, account.EventOIDCLinked)
		if len(evs) != 2 || evs[0].IssuerUserID != admin.ID || evs[0].KeyID != 0 || evs[1].KeyID != key.ID || evs[1].IssuerUserID != 0 {
			t.Errorf("oidc_linked = %+v, want admin's issue, then the key's", evs)
		}
	})
	// 5.5: an unknown name, a wrong secret, an expired one, the account's
	// own password and an owner's name are one ErrInvalidCredentials, after
	// the same work: one derivation each, nothing linked.
	t.Run("one_answer", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			prep func(t *testing.T, f *oidcFixture, alice *access.User, secret string) (name, typed string)
			name string
		}{
			{name: "unknown_name", prep: func(_ *testing.T, _ *oidcFixture, _ *access.User, secret string) (string, string) {
				return "nobody", secret
			}},
			{name: "wrong_secret", prep: func(_ *testing.T, _ *oidcFixture, _ *access.User, _ string) (string, string) {
				shown, _ := account.NewTemporaryPassword()
				return "alice", shown.Reveal()
			}},
			{name: "own_password", prep: func(_ *testing.T, _ *oidcFixture, _ *access.User, _ string) (string, string) {
				return "alice", goodPassword
			}},
			{name: "expired", prep: func(t *testing.T, f *oidcFixture, alice *access.User, _ string) (string, string) {
				shown, canonical := account.NewTemporaryPassword()
				hash, err := f.hasher.Hash(t.Context(), canonical)
				if err != nil {
					t.Fatalf("Hash: %v", err)
				}
				past := time.Now().Add(-time.Hour)
				rec := access.TemporaryPassword{UserID: alice.ID, Hash: hash, CreatedAt: past.Add(-time.Hour), ExpiresAt: past, Dormant: true}
				if err := f.mem.SetTemporaryPassword(t.Context(), rec); err != nil {
					t.Fatalf("SetTemporaryPassword: %v", err)
				}
				return "alice", shown.Reveal()
			}},
			{name: "owner_name", prep: func(t *testing.T, f *oidcFixture, alice *access.User, secret string) (string, string) {
				u := storedUser(t, f.mem, alice.ID)
				u.Role, u.Owner = access.RoleAdmin, true
				if err := f.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
				return "alice", secret
			}},
			{name: "disabled", prep: func(t *testing.T, f *oidcFixture, alice *access.User, secret string) (string, string) {
				u := storedUser(t, f.mem, alice.ID)
				u.Enabled = false
				if err := f.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
				return "alice", secret
			}},
			// 5.5: an empty or refused name still does the one dummy hash and
			// takes no lock.
			{name: "empty_name", prep: func(_ *testing.T, _ *oidcFixture, _ *access.User, secret string) (string, string) {
				return "", secret
			}},
			{name: "refused_name", prep: func(_ *testing.T, _ *oidcFixture, _ *access.User, secret string) (string, string) {
				return "al ice\x00", secret
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
				secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
				name, typed := tc.prep(t, f, alice, secret)
				before := len(f.counted.verified())
				_, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), name, typed)
				if !errors.Is(err, account.ErrInvalidCredentials) || err.Error() != account.ErrInvalidCredentials.Error() {
					t.Errorf("LinkPendingOIDCByAdmin = %v, want the bare ErrInvalidCredentials", err)
				}
				if n := len(f.counted.verified()) - before; n != 1 {
					t.Errorf("%d derivations, want 1", n)
				}
				if n := account.NameLocks(f.svc); n != 0 {
					t.Errorf("name locks = %d after the answer, want 0", n)
				}
				requireUnlinked(t, f, alice)
			})
		}
	})
	// 5.25 and ruling Q3: a pending state that did not open is ErrNotFound
	// before any hash and any limiter charge.
	t.Run("no_pending_state", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{limiter: ipLimit(1)}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		for _, pl := range []account.PendingLink{{}, {Identity: access.OIDCIdentity{Issuer: oidcIssuer}}} {
			if _, err := f.adminLink(t.Context(), localClient, pl, "alice", secret); !errors.Is(err, account.ErrNotFound) {
				t.Errorf("LinkPendingOIDCByAdmin(%+v) = %v, want ErrNotFound", pl, err)
			}
		}
		if n := len(f.counted.verified()); n != 0 {
			t.Errorf("%d derivations, want none", n)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); err != nil {
			t.Errorf("the IP's one attempt after two missing states = %v, want linked", err)
		}
	})
	// 5.7: the admin link is refused over plain HTTP, before any work.
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{posture: access.PosturePerRequest}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		if _, err := f.adminLink(t.Context(), plain(localClient), pendingFor("alice-sub"), "alice", secret); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("a plain admin link = %v, want access.ErrHTTPSRequired", err)
		}
		if n := len(f.counted.verified()); n != 0 {
			t.Errorf("%d derivations, want none", n)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("the plain refusal deleted the record")
		}
	})
	// 5.5: under the other modes the route answers ErrInvalidCredentials
	// after the same work, writing nothing.
	t.Run("only_under_sso_only", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []account.SSOMode{account.SSOAlongside, account.SSOForLinked} {
			t.Run(mode.String(), func(t *testing.T) {
				t.Parallel()
				f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
				storeMode(t, f.mem, mode)
				secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
				if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
					t.Errorf("the admin link under %s = %v, want ErrInvalidCredentials", mode, err)
				}
				if n := len(f.counted.verified()); n != 1 {
					t.Errorf("%d derivations, want 1", n)
				}
				if _, found := tempRecord(t, f.mem, alice.ID); !found {
					t.Error("the refusal deleted the record")
				}
				requireUnlinked(t, f, alice)
			})
		}
	})
	// 5.5: failures count on the pending identity, never on the named
	// account, so another identity's failures leave the link usable.
	t.Run("counted_on_the_identity", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{limiter: func(c *ratelimit.Config) {
			c.Account = ratelimit.Rate{Limit: 2, Window: time.Hour}
		}}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		attacker := pendingFor("attacker-sub")
		for i := range 2 {
			if _, err := f.adminLink(t.Context(), localClient, attacker, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Fatalf("attacker's failure %d = %v, want ErrInvalidCredentials", i+1, err)
			}
		}
		var refused *ratelimit.RefusedError
		if _, err := f.adminLink(t.Context(), localClient, attacker, "alice", secret); !errors.As(err, &refused) {
			t.Errorf("the attacker's third try = %v, want a RefusedError", err)
		}
		if _, err := f.step1(t.Context(), localClient, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("a password attempt for alice = %v, want ErrInvalidCredentials: the admin link spent alice's budget", err)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); err != nil {
			t.Errorf("alice's own link after the attacker's failures = %v, want linked", err)
		}
	})
	// 5.5 and 4.9: a match re-checks the record's issuer; a failure deletes
	// the record and answers as a wrong secret.
	t.Run("issuer_recheck", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		secret := issueFor(t, f, account.As(f.sessionPrincipal(t, admin, time.Now())), alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		admin.Role = access.RoleUser
		if err := f.mem.UpdateUser(t.Context(), admin); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the link after its issuer was demoted = %v, want ErrInvalidCredentials", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("a failed issuer re-check left the record")
		}
		requireUnlinked(t, f, alice)
	})
	// 5.5: a conflict is refused, never merged, writing nothing.
	t.Run("identity_taken", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		pl := pendingFor("taken-sub")
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		linkIdentity(t, f.mem, bob, pl.Identity)
		if _, err := f.adminLink(t.Context(), localClient, pl, "alice", secret); !errors.Is(err, account.ErrOIDCIdentityTaken) {
			t.Errorf("an identity linked since the callback = %v, want ErrOIDCIdentityTaken", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("the refusal spent the record")
		}
		requireUnlinked(t, f, alice)
	})
	t.Run("already_linked", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		mine := access.OIDCIdentity{Issuer: oidcIssuer, Subject: "alice-old"}
		linkIdentity(t, f.mem, storedUser(t, f.mem, alice.ID), mine)
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); !errors.Is(err, account.ErrAlreadyLinked) {
			t.Errorf("a user linked since the issue = %v, want ErrAlreadyLinked", err)
		}
		if u := storedUser(t, f.mem, alice.ID); u.OIDC != mine {
			t.Errorf("alice's link = %+v, want %+v kept", u.OIDC, mine)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); !found {
			t.Error("the refusal spent the record")
		}
	})
	// 5.10: a refused local sign-in with a live temporary password leaves
	// the admin link usable (5.3: a secure mode-refused sign-in writes
	// nothing).
	t.Run("refused_sign_in_keeps_the_link", func(t *testing.T) {
		t.Parallel()
		f, _, alice := adminLinkFixture(t, pwOptions{}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		if _, err := f.step1(t.Context(), localClient, "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("alice's sign-in under SSOOnly = %v, want ErrInvalidCredentials", err)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); err != nil {
			t.Errorf("the admin link after the refused sign-in = %v, want linked", err)
		}
	})
	// 5.10: the dormant password the link kept comes back with a
	// loosening.
	t.Run("dormant_password_comes_back", func(t *testing.T) {
		t.Parallel()
		f, root, alice := adminLinkFixture(t, pwOptions{}, nil)
		secret := issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret); err != nil {
			t.Fatalf("LinkPendingOIDCByAdmin = %v", err)
		}
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOAlongside); err != nil {
			t.Fatalf("ApplySSO(alongside) = %v", err)
		}
		if _, err := f.login(t.Context(), localClient, "alice", goodPassword); err != nil {
			t.Errorf("alice's kept password after the loosening = %v, want signed in", err)
		}
	})
	t.Run("oidc_unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		mustOwner(t, f.mem, "root")
		if _, err := f.svc.LinkPendingOIDCByAdmin(t.Context(), localClient, pendingFor("x"), "root", access.NewSecret("x")); !errors.Is(err, account.ErrOIDCUnavailable) {
			t.Errorf("LinkPendingOIDCByAdmin with OIDC unwired = %v, want ErrOIDCUnavailable", err)
		}
	})
}

// TestLinkPendingOIDCByAdminLock is design 4.9's "One verifier of a name's
// temporary password at a time" at the admin link: the lock is the step-1
// lock on the canonical name, so a burn and a link of one secret are
// ordered.
func TestLinkPendingOIDCByAdminLock(t *testing.T) {
	t.Parallel()
	type mark struct{}
	setup := func(t *testing.T) (*oidcFixture, *faultStore, *access.User, string) {
		t.Helper()
		fs := newFaultStore()
		f, _, alice := adminLinkFixture(t, pwOptions{store: fs, posture: access.PosturePerRequest}, nil)
		return f, fs, alice, issueFor(t, f, socket, alice, account.TemporaryPasswordOptions{}).Password.Reveal()
	}
	burnedAndUnlinked := func(t *testing.T, f *oidcFixture, alice *access.User, step, link error) {
		t.Helper()
		if !errors.Is(step, account.ErrInvalidCredentials) {
			t.Errorf("the plain step 1 = %v, want ErrInvalidCredentials", step)
		}
		if !errors.Is(link, account.ErrInvalidCredentials) {
			t.Errorf("the admin link admitted during it = %v, want ErrInvalidCredentials", link)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the burned record survived")
		}
		requireUnlinked(t, f, alice)
		if n := account.NameLocks(f.svc); n != 0 {
			t.Errorf("name locks = %d after both settled, want 0", n)
		}
	}
	// 4.9 and 5.10: a plain step 1 under SSOOnly mid-verification and an
	// admin link of the same secret for "ALICE" admitted during it.
	t.Run("burn_then_link", func(t *testing.T) {
		t.Parallel()
		f, fs, alice, secret := setup(t)
		entered, release := holdUpdate(fs, mark{}, 2)
		step := make(chan error, 1)
		go func() {
			_, err := f.step1(context.WithValue(t.Context(), mark{}, true), plain(localClient), "alice", secret)
			step <- err
		}()
		select {
		case <-entered:
		case <-time.After(30 * time.Second):
			t.Fatal("the plain step 1 never reached its success Update")
		}
		link := make(chan error, 1)
		go func() {
			_, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "ALICE", secret)
			link <- err
		}()
		waitRefs(t, f.svc, "alice", 2)
		close(release)
		burnedAndUnlinked(t, f, alice, <-step, <-link)
	})
	// 5.10: "including when another step 1 for the name holds the lock
	// first".
	t.Run("another_step_holds_first", func(t *testing.T) {
		t.Parallel()
		f, fs, alice, secret := setup(t)
		entered, release := holdUpdate(fs, mark{}, 1)
		first := make(chan error, 1)
		go func() {
			_, err := f.step1(context.WithValue(t.Context(), mark{}, true), localClient, "alice", wrongPassword)
			first <- err
		}()
		select {
		case <-entered:
		case <-time.After(30 * time.Second):
			t.Fatal("the first step 1 never reached its count")
		}
		step := make(chan error, 1)
		go func() {
			_, err := f.step1(t.Context(), plain(localClient), "alice", secret)
			step <- err
		}()
		waitRefs(t, f.svc, "alice", 2)
		link := make(chan error, 1)
		go func() {
			_, err := f.adminLink(t.Context(), localClient, pendingFor("alice-sub"), "alice", secret)
			link <- err
		}()
		waitRefs(t, f.svc, "alice", 3)
		close(release)
		if err := <-first; !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the first step 1 = %v, want ErrInvalidCredentials", err)
		}
		burnedAndUnlinked(t, f, alice, <-step, <-link)
	})
	// 4.9: "two parallel admin-link posts of one secret link once".
	t.Run("two_posts_link_once", func(t *testing.T) {
		t.Parallel()
		f, _, alice, secret := setup(t)
		errs := make(chan error, 2)
		for _, sub := range []string{"one-sub", "two-sub"} {
			go func() {
				_, err := f.adminLink(t.Context(), localClient, pendingFor(sub), "alice", secret)
				errs <- err
			}()
		}
		linked, refused := 0, 0
		for range 2 {
			switch err := <-errs; {
			case err == nil:
				linked++
			case errors.Is(err, account.ErrInvalidCredentials):
				refused++
			default:
				t.Errorf("a post = %v, want linked or ErrInvalidCredentials", err)
			}
		}
		if linked != 1 || refused != 1 {
			t.Errorf("%d linked and %d refused, want one each", linked, refused)
		}
		if u := storedUser(t, f.mem, alice.ID); u.OIDC.IsZero() {
			t.Error("neither post linked alice")
		}
	})
}

// TestAdminRelinkOIDC is design 5.5's "Re-linking is one call":
// AdminUnlinkOIDC then SetTemporaryPassword in one Update, under the
// Policies of both.
func TestAdminRelinkOIDC(t *testing.T) {
	t.Parallel()
	old := access.OIDCIdentity{Issuer: oidcIssuer, Subject: "alice-old"}
	setup := func(t *testing.T, mode account.SSOMode, policy account.Policy) (*oidcFixture, *access.User, *access.User) {
		t.Helper()
		f, root, alice := adminLinkFixture(t, pwOptions{}, policy)
		storeMode(t, f.mem, mode)
		linkIdentity(t, f.mem, alice, old)
		return f, root, storedUser(t, f.mem, alice.ID)
	}
	// 5.5: under SSOOnly the issue keeps the dormant methods, and the
	// secret links the account again; 5.10: a later loosening brings the
	// password back.
	t.Run("sso_only", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, account.SSOOnly, nil)
		live := putSession(t, f.mem, liveSession(t, alice))
		mark := len(f.events.all())
		issued, err := f.svc.AdminRelinkOIDC(t.Context(), socket, alice.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("AdminRelinkOIDC = %v", err)
		}
		if !issued.Dormant || !issued.PasswordKept || !shownForm.MatchString(issued.Password.Reveal()) {
			t.Errorf("issued = %+v, want a dormant shown secret beside the kept password", issued)
		}
		u := storedUser(t, f.mem, alice.ID)
		if !u.OIDC.IsZero() || !u.PasswordHash.Equal(alice.PasswordHash) {
			t.Errorf("alice = link %+v, password kept %t; want unlinked with her password", u.OIDC, u.PasswordHash.Equal(alice.PasswordHash))
		}
		if rec, found := tempRecord(t, f.mem, alice.ID); !found || !rec.Dormant {
			t.Errorf("the record = %+v, %t; want a dormant one", rec, found)
		}
		if n := len(sessionsOf(t, f.mem, alice.ID)); n != 0 {
			t.Errorf("alice holds %d sessions, want none", n)
		}
		var kinds []account.EventKind
		for _, ev := range f.events.all()[mark:] {
			kinds = append(kinds, ev.Kind)
		}
		want := []account.EventKind{account.EventOIDCUnlinked, account.EventUserSessionsRevoked, account.EventTemporaryPasswordSet}
		if !slices.Equal(kinds, want) {
			t.Errorf("events = %v, want %v", kinds, want)
		}
		if ev := eventsOf(f.events, account.EventUserSessionsRevoked); len(ev) != 1 || !slices.Equal(ev[0].SessionIDs, []string{live.ID}) {
			t.Errorf("user_sessions_revoked = %+v, want alice's one session", ev)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-new"), "alice", issued.Password.Reveal()); err != nil {
			t.Fatalf("the admin link with the relink's secret = %v, want linked", err)
		}
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOAlongside); err != nil {
			t.Fatalf("ApplySSO(alongside) = %v", err)
		}
		if _, err := f.login(t.Context(), localClient, "alice", goodPassword); err != nil {
			t.Errorf("alice's kept password after the loosening = %v, want signed in", err)
		}
	})
	// 5.5: under the other modes the unlinked account's methods are usable,
	// so the issue replaces them.
	t.Run("looser_modes_replace", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []account.SSOMode{account.SSOAlongside, account.SSOForLinked} {
			t.Run(mode.String(), func(t *testing.T) {
				t.Parallel()
				f, _, alice := setup(t, mode, nil)
				issued, err := f.svc.AdminRelinkOIDC(t.Context(), socket, alice.ID, account.TemporaryPasswordOptions{})
				if err != nil {
					t.Fatalf("AdminRelinkOIDC = %v", err)
				}
				u := storedUser(t, f.mem, alice.ID)
				if issued.Dormant || !u.PasswordHash.IsZero() || !u.OIDC.IsZero() {
					t.Errorf("issued Dormant %t, password %t, link %+v; want the password replaced and no link", issued.Dormant, !u.PasswordHash.IsZero(), u.OIDC)
				}
			})
		}
	})
	// 5.5: on an account that is not linked it is ErrNotFound with nothing
	// written.
	t.Run("not_linked", func(t *testing.T) {
		t.Parallel()
		f, _, _ := setup(t, account.SSOOnly, nil)
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		live := putSession(t, f.mem, liveSession(t, bob))
		mark := len(f.events.all())
		if _, err := f.svc.AdminRelinkOIDC(t.Context(), socket, bob.ID, account.TemporaryPasswordOptions{}); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("AdminRelinkOIDC(unlinked) = %v, want ErrNotFound", err)
		}
		if _, found := tempRecord(t, f.mem, bob.ID); found {
			t.Error("the refusal stored a record")
		}
		if s := sessionsOf(t, f.mem, bob.ID); len(s) != 1 || s[0].ID != live.ID {
			t.Errorf("bob's sessions = %+v, want the live one kept", s)
		}
		if n := len(f.events.all()) - mark; n != 0 {
			t.Errorf("the refusal journalled %d events", n)
		}
	})
	// 5.5: under the Policies of both OpUnlinkOIDC and
	// OpSetTemporaryPassword; a failure of either half writes nothing.
	t.Run("both_policies", func(t *testing.T) {
		t.Parallel()
		for _, op := range []account.Operation{"", account.OpUnlinkOIDC, account.OpSetTemporaryPassword} {
			t.Run(map[account.Operation]string{"": "asked", account.OpUnlinkOIDC: "unlink_refused", account.OpSetTemporaryPassword: "issue_refused"}[op], func(t *testing.T) {
				t.Parallel()
				gp := &gatePolicy{}
				f, _, alice := setup(t, account.SSOOnly, gp)
				live := putSession(t, f.mem, liveSession(t, alice))
				gp.arm(op)
				mark := len(f.events.all())
				_, err := f.svc.AdminRelinkOIDC(t.Context(), socket, alice.ID, account.TemporaryPasswordOptions{})
				asked := map[account.Operation]bool{}
				for _, d := range gp.taken() {
					if d.Target != nil && d.Target.ID == alice.ID {
						asked[d.Op] = true
					}
				}
				if op == "" {
					if err != nil || !asked[account.OpUnlinkOIDC] || !asked[account.OpSetTemporaryPassword] {
						t.Errorf("AdminRelinkOIDC = %v asking %v, want both operations asked about alice", err, asked)
					}
					return
				}
				if reasonOf(err) != gateReason {
					t.Fatalf("AdminRelinkOIDC with %s refused = %v, want the gate's refusal", op, err)
				}
				if u := storedUser(t, f.mem, alice.ID); u.OIDC != old || !u.PasswordHash.Equal(alice.PasswordHash) {
					t.Error("the refused relink changed alice")
				}
				if _, found := tempRecord(t, f.mem, alice.ID); found {
					t.Error("the refused relink stored a record")
				}
				if s := sessionsOf(t, f.mem, alice.ID); len(s) != 1 || s[0].ID != live.ID {
					t.Errorf("alice's sessions = %+v, want the live one kept", s)
				}
				if n := len(f.events.all()) - mark; n != 0 {
					t.Errorf("the refused relink journalled %d events", n)
				}
			})
		}
	})
	// 5.10: a ManageUsersScope key relinks a regular user and is refused
	// for an admin; a relink by a key whose key is then revoked no longer
	// links.
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, account.SSOOnly, nil)
		p, key := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeUsers)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		linkIdentity(t, f.mem, admin, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "admin"})
		if _, err := f.svc.AdminRelinkOIDC(t.Context(), account.As(p), admin.ID, account.TemporaryPasswordOptions{}); reason(err) != "admin_target" {
			t.Errorf("a key relinking an admin = %v, want admin_target", err)
		}
		issued, err := f.svc.AdminRelinkOIDC(t.Context(), account.As(p), alice.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("AdminRelinkOIDC by a key = %v", err)
		}
		if rec, _ := tempRecord(t, f.mem, alice.ID); rec.IssuedByKey != key.ID {
			t.Errorf("IssuedByKey = %d, want %d", rec.IssuedByKey, key.ID)
		}
		if err := f.mem.DeleteAPIKey(t.Context(), access.KeyRef{ID: key.ID, UserID: root.ID}); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		if _, err := f.adminLink(t.Context(), localClient, pendingFor("alice-new"), "alice", issued.Password.Reveal()); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the secret after its key was revoked = %v, want ErrInvalidCredentials", err)
		}
		requireUnlinked(t, f, alice)
	})
	// 5.10: with keep_keys the target's keys stay, with revoke_passkeys its
	// passkeys go, and with neither the keys go and the passkeys stay.
	t.Run("options", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name           string
			in             account.TemporaryPasswordOptions
			keys, passkeys bool
		}{
			{name: "neither", keys: false, passkeys: true},
			{name: "keep_keys", in: account.TemporaryPasswordOptions{KeepKeys: true}, keys: true, passkeys: true},
			{name: "revoke_passkeys", in: account.TemporaryPasswordOptions{RevokePasskeys: true}, keys: false, passkeys: false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f, _, alice := setup(t, account.SSOOnly, nil)
				f.keyPrincipalFor(t, f.authn, alice, time.Time{}, nil, "read")
				addPasskey(t, f.mem, alice, rpID)
				if _, err := f.svc.AdminRelinkOIDC(t.Context(), socket, alice.ID, tc.in); err != nil {
					t.Fatalf("AdminRelinkOIDC = %v", err)
				}
				keys, err := f.mem.ListAPIKeysByUserID(t.Context(), alice.ID)
				if err != nil {
					t.Fatalf("ListAPIKeysByUserID: %v", err)
				}
				passkeys, err := f.mem.PasskeysByUserID(t.Context(), alice.ID)
				if err != nil {
					t.Fatalf("PasskeysByUserID: %v", err)
				}
				if (len(keys) > 0) != tc.keys || (len(passkeys) > 0) != tc.passkeys {
					t.Errorf("keys %d, passkeys %d; want keys %t, passkeys %t", len(keys), len(passkeys), tc.keys, tc.passkeys)
				}
			})
		}
	})
	// 4.9 via 5.5: the issue's self_recovery refusal, the owner protection
	// and the plain refusal, each before anything is written.
	t.Run("refusals", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, account.SSOOnly, nil)
		linkIdentity(t, f.mem, storedUser(t, f.mem, root.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
		self := f.sessionPrincipal(t, root, time.Now())
		if _, err := f.svc.AdminRelinkOIDC(t.Context(), account.As(self), root.ID, account.TemporaryPasswordOptions{}); reason(err) != account.ReasonSelfRecovery {
			t.Errorf("relinking oneself = %v, want self_recovery", err)
		}
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		if _, err := f.svc.AdminRelinkOIDC(t.Context(), account.As(f.sessionPrincipal(t, admin, time.Now())), root.ID, account.TemporaryPasswordOptions{}); reason(err) != "owner_target" {
			t.Errorf("a non-owner admin relinking the owner = %v, want owner_target", err)
		}
		plainRoot := f.sessionPrincipal(t, root, time.Now())
		plainRoot.Secure = false
		if _, err := f.svc.AdminRelinkOIDC(t.Context(), account.As(plainRoot), alice.ID, account.TemporaryPasswordOptions{}); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("a plain relink = %v, want access.ErrHTTPSRequired", err)
		}
		for _, u := range []*access.User{root, alice} {
			if storedUser(t, f.mem, u.ID).OIDC.IsZero() {
				t.Errorf("a refused relink unlinked %s", u.Username)
			}
			if _, found := tempRecord(t, f.mem, u.ID); found {
				t.Errorf("a refused relink stored a record for %s", u.Username)
			}
		}
	})
}
