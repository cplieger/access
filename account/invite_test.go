package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// refuseInvited refuses only an invite acceptance's OpCreateUser.
type refuseInvited struct{}

func (refuseInvited) Authorize(ctx context.Context, d account.Decision) error {
	if d.Op == account.OpCreateUser && d.Via == account.ViaInvite {
		return &account.PolicyError{Op: d.Op, Reason: "no_invites"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// hashOf is the stored hash of a token's plaintext.
func hashOf(tok account.IssuedToken) access.Hash {
	return access.NewHash(access.HexSHA256(tok.Plaintext.Reveal()))
}

func usernameTaken(t *testing.T, f *fixture, name string) bool {
	t.Helper()
	_, found, err := f.mem.UserByUsername(t.Context(), name)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	return found
}

func TestInviteRefusalsLeaveTokenUsable(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	inv, err := w.f.svc.CreateInvite(t.Context(), w.pr, "", 0)
	if err != nil {
		t.Fatalf("CreateInvite = %v", err)
	}
	refusals := map[string]struct {
		run  func() error
		want func(error) bool
	}{
		"taken_username": {
			run: func() error {
				_, err := w.f.accept(t, inv.Plaintext, "alice")
				return err
			},
			want: func(err error) bool { return errors.Is(err, account.ErrUsernameTaken) },
		},
		"refused_password": {
			run: func() error {
				_, err := w.f.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "newcomer", Password: access.NewSecret("short")})
				return err
			},
			want: func(err error) bool { return errors.As(err, new(*access.PasswordError)) },
		},
		"backend_error": {
			run: func() error {
				w.fs.failCall("CreateSession")
				_, err := w.f.accept(t, inv.Plaintext, "newcomer")
				return err
			},
			want: func(err error) bool { return errors.Is(err, access.ErrAuthBackend) },
		},
	}
	for name, r := range refusals {
		if err := r.run(); !r.want(err) {
			t.Errorf("%s: AcceptInvitePassword = %v", name, err)
		}
		if _, found, _ := w.f.mem.OneTimeTokenByHash(t.Context(), hashOf(inv)); !found {
			t.Fatalf("%s consumed the invite", name)
		}
		if usernameTaken(t, w.f, "newcomer") {
			t.Fatalf("%s created the user", name)
		}
	}
	t.Run("policy", func(t *testing.T) {
		g := newAdminWorld(t, options{}, refuseInvited{})
		ginv, err := g.f.svc.CreateInvite(t.Context(), g.pr, access.RoleUser, 0)
		if err != nil {
			t.Fatalf("CreateInvite = %v", err)
		}
		if _, err := g.f.accept(t, ginv.Plaintext, "newcomer"); reason(err) != "no_invites" {
			t.Errorf("a refused acceptance = %v, want the Policy's no_invites", err)
		}
		if _, found, _ := g.f.mem.OneTimeTokenByHash(t.Context(), hashOf(ginv)); !found {
			t.Error("the Policy's refusal consumed the invite")
		}
	})
	in, err := w.f.accept(t, inv.Plaintext, "Newcomer")
	if err != nil {
		t.Fatalf("the invite after its refusals = %v", err)
	}
	if in.User.Username != "newcomer" || in.User.Role != access.RoleUser || in.Session.UserID != in.User.ID || in.Token.IsZero() {
		t.Errorf("accepted = %+v, want a signed-in RoleUser newcomer", in)
	}
	if recs := attributionsOf(t, w.f, in.User.ID); len(recs) != 0 {
		t.Errorf("a session-issued invite gave records %+v", recs)
	}
	if evs := eventsOf(w.f.events, account.EventUserCreated); len(evs) != 1 || evs[0].KeyID != 0 || evs[0].UserID != in.User.ID {
		t.Errorf("EventUserCreated = %+v, want one with no key", evs)
	}
	if _, err := w.f.accept(t, inv.Plaintext, "again"); !errors.Is(err, access.ErrTokenInvalid) {
		t.Errorf("the spent invite = %v, want access.ErrTokenInvalid", err)
	}
}

func TestAcceptInviteOtherPurposeToken(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	rec, err := w.f.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), w.alice.ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery = %v", err)
	}
	in := account.AcceptInvite{Token: rec.Plaintext, Username: "newcomer", Password: access.NewSecret("short")}
	if _, err := w.f.svc.AcceptInvitePassword(t.Context(), localClient, in); !errors.Is(err, access.ErrTokenInvalid) {
		t.Errorf("a recovery token presented as an invite = %v, want access.ErrTokenInvalid before the password rules", err)
	}
	if usernameTaken(t, w.f, "newcomer") {
		t.Error("a recovery token created a user")
	}
}

// keyIssuer is a world whose admin root holds a session-minted parent P
// (both permissions) and P's child K (manage_users) expiring in expiresIn,
// with a second admin boss for the owner changes.
type keyIssuer struct {
	*adminWorld
	clock *testClock
	boss  *access.User
	bp    access.Principal
	p, k  minted
}

func newKeyIssuer(t *testing.T, expiresIn time.Duration) *keyIssuer {
	t.Helper()
	clock := laterClock()
	w := newAdminWorld(t, options{edit: func(c *account.Config) { c.Now = clock.now }}, nil)
	ki := &keyIssuer{adminWorld: w, clock: clock, boss: mustUser(t, w.f.mem, "boss", access.RoleAdmin)}
	ki.bp = w.f.sessionPrincipal(t, ki.boss, access.SessionFull, time.Now())
	ki.p = w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	ki.k = w.f.mint(t, account.As(ki.p.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}, ExpiresIn: expiresIn})
	return ki
}

func TestKeyIssuedTokens(t *testing.T) {
	t.Parallel()
	t.Run("expiry_cap", func(t *testing.T) {
		t.Parallel()
		ki := newKeyIssuer(t, time.Hour)
		inv, err := ki.f.svc.CreateInvite(t.Context(), ki.k.p, access.RoleUser, 0)
		if err != nil {
			t.Fatalf("CreateInvite = %v", err)
		}
		rec, err := ki.f.svc.IssueRecovery(t.Context(), account.As(ki.k.p), ki.alice.ID, 24*time.Hour)
		if err != nil {
			t.Fatalf("IssueRecovery = %v", err)
		}
		for name, tok := range map[string]account.IssuedToken{"invite": inv, "recovery": rec} {
			stored, found, err := ki.f.mem.OneTimeTokenByHash(t.Context(), hashOf(tok))
			if err != nil || !found {
				t.Fatalf("%s not stored: %v", name, err)
			}
			if stored.IssuedByKey != ki.k.key.ID || !stored.ExpiresAt.Equal(ki.k.key.ExpiresAt) || !tok.ExpiresAt.Equal(stored.ExpiresAt) {
				t.Errorf("%s: issued by %d, stored expiry %v, returned %v; want K %d and K's %v", name, stored.IssuedByKey, stored.ExpiresAt, tok.ExpiresAt, ki.k.key.ID, ki.k.key.ExpiresAt)
			}
		}
		open := newKeyIssuer(t, 0)
		now := open.clock.now()
		inv, err = open.f.svc.CreateInvite(t.Context(), open.k.p, access.RoleUser, 0)
		if err != nil || !inv.ExpiresAt.Equal(now.Add(7*24*time.Hour)) {
			t.Errorf("an unexpiring key's default invite = %v, %v; want 7 days", inv.ExpiresAt, err)
		}
		rec, err = open.f.svc.IssueRecovery(t.Context(), account.As(open.k.p), open.alice.ID, 0)
		if err != nil || !rec.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Errorf("an unexpiring key's default recovery = %v, %v; want 24 h", rec.ExpiresAt, err)
		}
	})
	restart := func(scope string) func(t *testing.T, ki *keyIssuer) *account.Service {
		return func(t *testing.T, ki *keyIssuer) *account.Service {
			cfg := ki.f.cfg
			cfg.ManageUsersScope = scope
			svc, err := account.New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("account.New: %v", err)
			}
			t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
			return svc
		}
	}
	changes := map[string]func(t *testing.T, ki *keyIssuer) *account.Service{
		"revoked": func(t *testing.T, ki *keyIssuer) *account.Service {
			if err := ki.f.svc.RevokeAPIKey(t.Context(), ki.pr, ki.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey = %v", err)
			}
			return ki.f.svc
		},
		"expired": func(_ *testing.T, ki *keyIssuer) *account.Service {
			ki.clock.add(2 * time.Hour)
			return ki.f.svc
		},
		"parent_revoked": func(t *testing.T, ki *keyIssuer) *account.Service {
			if err := ki.f.svc.RevokeAPIKey(t.Context(), ki.pr, ki.p.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(parent) = %v", err)
			}
			return ki.f.svc
		},
		"owner_disabled": func(t *testing.T, ki *keyIssuer) *account.Service {
			if _, err := ki.f.svc.UpdateUser(t.Context(), ki.bp, ki.root.ID, account.UserChange{Enabled: new(false)}); err != nil {
				t.Fatalf("disable the owner = %v", err)
			}
			return ki.f.svc
		},
		"owner_demoted": func(t *testing.T, ki *keyIssuer) *account.Service {
			if _, err := ki.f.svc.UpdateUser(t.Context(), ki.bp, ki.root.ID, account.UserChange{Role: new(access.RoleUser)}); err != nil {
				t.Fatalf("demote the owner = %v", err)
			}
			return ki.f.svc
		},
		"scope_emptied": restart(""),
		"scope_renamed": restart("write"),
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ki := newKeyIssuer(t, time.Hour)
			inv, err := ki.f.svc.CreateInvite(t.Context(), ki.k.p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			svc := change(t, ki)
			sessions := len(sessionsOf(t, ki.f.mem, ki.root.ID))
			_, err = svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "joiner", Password: access.NewSecret(goodPassword)})
			if !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("redeeming after %s = %v, want access.ErrTokenInvalid", name, err)
			}
			if usernameTaken(t, ki.f, "joiner") {
				t.Errorf("redeeming after %s created the user", name)
			}
			if n := len(eventsOf(ki.f.events, account.EventSignedIn)); n != 0 || len(sessionsOf(t, ki.f.mem, ki.root.ID)) != sessions {
				t.Errorf("redeeming after %s signed someone in", name)
			}
			_, found, _ := ki.f.mem.OneTimeTokenByHash(t.Context(), hashOf(inv))
			// An expired invite stays until the sweep: no write runs at
			// expiry, and the peek refuses it without consuming it.
			if found != (name == "expired") {
				t.Errorf("after %s the invite is stored %t", name, found)
			}
		})
	}
	t.Run("scope_emptied_reads_no_key", func(t *testing.T) {
		t.Parallel()
		ki := newKeyIssuer(t, time.Hour)
		inv, err := ki.f.svc.CreateInvite(t.Context(), ki.k.p, access.RoleUser, 0)
		if err != nil {
			t.Fatalf("CreateInvite = %v", err)
		}
		svc := restart("")(t, ki)
		ki.fs.refuseCall("ListAPIKeys", errFault)
		_, err = svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "joiner", Password: access.NewSecret(goodPassword)})
		if !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("redeeming with no ManageUsersScope while key reads fail = %v, want access.ErrTokenInvalid with no key read", err)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		t.Parallel()
		ki := newKeyIssuer(t, time.Hour)
		inv, err := ki.f.svc.CreateInvite(t.Context(), ki.k.p, access.RoleUser, 0)
		if err != nil {
			t.Fatalf("CreateInvite = %v", err)
		}
		in, err := ki.f.accept(t, inv.Plaintext, "joiner")
		if err != nil {
			t.Fatalf("accept = %v", err)
		}
		recs := attributionsOf(t, ki.f, in.User.ID)
		if len(recs) != 1 || recs[0].Action != access.AttributionInviteAccepted || !slices.Equal(recs[0].KeyLineage, ki.k.key.LineageIDs) {
			t.Errorf("records = %+v, want one invite_accepted with K's path %v", recs, ki.k.key.LineageIDs)
		}
		if evs := eventsOf(ki.f.events, account.EventUserCreated); len(evs) != 1 || evs[0].KeyID != ki.k.key.ID {
			t.Errorf("EventUserCreated = %+v, want one naming K", evs)
		}
	})
}

func TestKeyExpiryRefusesEveryUse(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newAdminWorld(t, options{edit: func(c *account.Config) { c.CleanupInterval = 2 * time.Hour }}, nil)
		ctx := t.Context()
		bob := mustUser(t, w.f.mem, "bob", access.RoleUser)
		kc, err := w.f.svc.CreateAPIKey(ctx, account.As(w.pr), w.root.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}, ExpiresIn: time.Hour})
		if err != nil {
			t.Fatalf("mint K = %v", err)
		}
		at := kc.Key.ExpiresAt
		k, err := w.f.bearer(t, kc.Plaintext)
		if err != nil {
			t.Fatalf("Authenticate(K) = %v", err)
		}
		k2c, err := w.f.svc.CreateAPIKey(ctx, account.As(k), w.root.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}, ExpiresIn: time.Until(at)})
		if err != nil || !k2c.Key.ExpiresAt.Equal(at) {
			t.Fatalf("mint K2 = %+v, %v; want it expiring at K's %v", k2c.Key, err, at)
		}
		k2, err := w.f.bearer(t, k2c.Plaintext)
		if err != nil {
			t.Fatalf("Authenticate(K2) = %v", err)
		}
		var tokens []account.IssuedToken
		for subject, p := range map[int64]access.Principal{w.alice.ID: k, bob.ID: k2} {
			inv, err := w.f.svc.CreateInvite(ctx, p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			rec, err := w.f.svc.IssueRecovery(ctx, account.As(p), subject, 0)
			if err != nil {
				t.Fatalf("IssueRecovery = %v", err)
			}
			for _, tok := range []account.IssuedToken{inv, rec} {
				if !tok.ExpiresAt.Equal(at) {
					t.Errorf("a token expires at %v, want the cap %v", tok.ExpiresAt, at)
				}
			}
			tokens = append(tokens, inv, rec)
		}
		seeded, seededRec := access.NewOneTimeToken(access.PurposeInvite, 0, 2*time.Hour, time.Now())
		seededRec.IssuedByKey, seededRec.Role = kc.Key.ID, access.RoleUser
		if err := w.f.mem.CreateOneTimeToken(ctx, seededRec); err != nil {
			t.Fatalf("CreateOneTimeToken: %v", err)
		}
		w.fs.resetRecord()
		time.Sleep(time.Until(at))
		if !time.Now().Equal(at) {
			t.Fatalf("clock at %v, want exactly %v", time.Now(), at)
		}
		if ws := writesOf(w.fs); len(ws) != 0 {
			t.Errorf("writes before the first refusal at T: %v", ws)
		}
		for name, p := range map[string]access.Principal{"K": k, "K2": k2} {
			uses := map[string]func() error{
				"CreateUser": func() error {
					_, err := w.f.svc.CreateUser(ctx, account.As(p), account.NewUser{Username: "late"})
					return err
				},
				"CreateInvite": func() error {
					_, err := w.f.svc.CreateInvite(ctx, p, access.RoleUser, 0)
					return err
				},
				"IssueRecovery": func() error {
					_, err := w.f.svc.IssueRecovery(ctx, account.As(p), w.alice.ID, 0)
					return err
				},
				"CreateAPIKey": func() error {
					_, err := w.f.svc.CreateAPIKey(ctx, account.As(p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}, ExpiresIn: time.Minute})
					return err
				},
			}
			for use, run := range uses {
				w.fs.resetRecord()
				if err := run(); reason(err) != "key_not_current" {
					t.Errorf("%s %s at T = %v, want key_not_current", name, use, err)
				}
				if ws := writesOf(w.fs); len(ws) != 0 {
					t.Errorf("%s %s at T wrote %v", name, use, ws)
				}
			}
		}
		for name, plaintext := range map[string]access.Secret{"K": kc.Plaintext, "K2": k2c.Plaintext} {
			if _, err := w.f.bearer(t, plaintext); !errors.Is(err, access.ErrInvalidCredential) {
				t.Errorf("%s at the API-key verifier at T = %v, want ErrInvalidCredential", name, err)
			}
		}
		for i, tok := range tokens {
			w.fs.resetRecord()
			if _, err := w.f.accept(t, tok.Plaintext, "late"); !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("token %d at T = %v, want access.ErrTokenInvalid", i, err)
			}
			if ws := writesOf(w.fs); len(ws) != 0 {
				t.Errorf("token %d's refusal wrote %v", i, ws)
			}
		}
		w.fs.resetRecord()
		if _, err := w.f.svc.AcceptInvitePassword(ctx, localClient, account.AcceptInvite{Token: seeded, Username: "late", Password: access.NewSecret(goodPassword)}); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the seeded invite of expired K at T = %v, want access.ErrTokenInvalid", err)
		}
		if ws := writesOf(w.fs); !slices.Equal(ws, []string{"ConsumeOneTimeToken"}) {
			t.Errorf("the seeded invite's refusal wrote %v, want its own consumption only", ws)
		}
		if usernameTaken(t, w.f, "late") || tokenStored(t, w.f.mem, seededRec) {
			t.Error("a refusal at T created a user, or left the seeded invite")
		}
		keys, err := w.f.svc.APIKeys(ctx, w.pr)
		if err != nil || !slices.Contains(keyIDs(keys), kc.Key.ID) || !slices.Contains(keyIDs(keys), k2c.Key.ID) {
			t.Errorf("APIKeys at T = %v, %v; want K and K2 still listed", keyIDs(keys), err)
		}
		time.Sleep(time.Hour + time.Minute)
		synctest.Wait()
		for i, tok := range tokens {
			if _, found, _ := w.f.mem.OneTimeTokenByHash(ctx, hashOf(tok)); found {
				t.Errorf("token %d survives the sweep after T", i)
			}
		}
	})
}
