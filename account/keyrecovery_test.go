package account_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// keyRec is a recWorld on a test clock with a second admin boss and its
// session bp, root's key P carrying both permissions, and K, minted last by
// P with ManageUsersScope, expiring after expiresIn (never for 0).
type keyRec struct {
	*recWorld
	clock *testClock
	boss  *access.User
	bp    access.Principal
	p, k  minted
}

func newKeyRec(t *testing.T, expiresIn time.Duration) *keyRec {
	t.Helper()
	clock := laterClock()
	w := newRecWorld(t, pwOptions{edit: func(c *account.Config) { c.Now = clock.now }}, nil)
	kr := &keyRec{recWorld: w, clock: clock, boss: mustUser(t, w.mem, "boss", access.RoleAdmin)}
	kr.bp = w.sessionPrincipal(t, kr.boss, access.SessionFull, time.Now())
	kr.p = w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	kr.k = w.mint(t, account.As(kr.p.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}, ExpiresIn: expiresIn})
	return kr
}

// users is the IDs Users lists for boss under f.
func (kr *keyRec) users(t *testing.T, f account.UserFilter) []int64 {
	t.Helper()
	listed, err := kr.svc.Users(t.Context(), kr.bp, f)
	if err != nil {
		t.Fatalf("Users(%+v) = %v", f, err)
	}
	ids := make([]int64, 0, len(listed))
	for i := range listed {
		ids = append(ids, listed[i].User.ID)
	}
	return ids
}

// actions is userID's records as (action, lineage) strings, oldest first.
func actions(t *testing.T, f *fixture, userID int64) []string {
	t.Helper()
	var out []string
	for _, a := range attributionsOf(t, f, userID) {
		out = append(out, fmt.Sprintf("%s%v", a.Action, a.KeyLineage))
	}
	return out
}

// attr is one record as actions prints it.
func attr(action access.AttributionAction, lineage []int64) string {
	return fmt.Sprintf("%s%v", action, lineage)
}

// issuerChange is one change that ends K's authority over alice's link,
// returning the Service the redemption then runs on.
type issuerChange func(t *testing.T, kr *keyRec) *account.Service

func issuerChanges() map[string]issuerChange {
	restart := func(scope string) issuerChange {
		return func(t *testing.T, kr *keyRec) *account.Service {
			cfg := kr.cfg
			cfg.ManageUsersScope = scope
			svc, err := account.New(context.WithoutCancel(t.Context()), cfg)
			if err != nil {
				t.Fatalf("account.New: %v", err)
			}
			t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
			return svc
		}
	}
	update := func(target func(kr *keyRec) int64, ch account.UserChange) issuerChange {
		return func(t *testing.T, kr *keyRec) *account.Service {
			if _, err := kr.svc.UpdateUser(t.Context(), kr.bp, target(kr), ch); err != nil {
				t.Fatalf("UpdateUser = %v", err)
			}
			return kr.svc
		}
	}
	owner := func(kr *keyRec) int64 { return kr.root.ID }
	return map[string]issuerChange{
		"revoked": func(t *testing.T, kr *keyRec) *account.Service {
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey = %v", err)
			}
			return kr.svc
		},
		"expired_at": func(_ *testing.T, kr *keyRec) *account.Service {
			kr.clock.set(kr.k.key.ExpiresAt)
			return kr.svc
		},
		"expired_after": func(_ *testing.T, kr *keyRec) *account.Service {
			kr.clock.set(kr.k.key.ExpiresAt.Add(time.Second))
			return kr.svc
		},
		"parent_revoked": func(t *testing.T, kr *keyRec) *account.Service {
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.p.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(parent) = %v", err)
			}
			return kr.svc
		},
		"owner_disabled":   update(owner, account.UserChange{Enabled: new(false)}),
		"owner_demoted":    update(owner, account.UserChange{Role: new(access.RoleUser)}),
		"subject_promoted": update(func(kr *keyRec) int64 { return kr.alice.ID }, account.UserChange{Role: new(access.RoleAdmin)}),
		"scope_emptied":    restart(""),
		"scope_renamed":    restart("write"),
	}
}

func TestKeyIssuedRecovery(t *testing.T) {
	t.Parallel()
	for name, change := range issuerChanges() {
		t.Run("start_"+name, func(t *testing.T) {
			t.Parallel()
			kr := newKeyRec(t, time.Hour)
			tok := kr.issue(t, account.As(kr.k.p), kr.alice.ID)
			svc := change(t, kr)
			if _, err := svc.StartRecovery(t.Context(), localClient, tok.Plaintext); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("StartRecovery after %s = %v, want access.ErrTokenInvalid", name, err)
			}
			if n := len(recoverySessions(t, kr.mem, kr.alice.ID)); n != 0 {
				t.Errorf("the refused start opened %d recovery sessions", n)
			}
			_, found, _ := kr.mem.OneTimeTokenByHash(t.Context(), hashOf(tok))
			// An expired link stays until the sweep: the peek refuses it
			// without consuming it, and no write runs at expiry.
			if expired := name == "expired_at" || name == "expired_after"; found != expired {
				t.Errorf("after %s the link is stored %t, want %t", name, found, expired)
			}
			if n := len(eventsOf(kr.events, account.EventRecoveryConsumed)) + len(attributionsOf(t, kr.fixture, kr.alice.ID)); n != 0 {
				t.Errorf("the refused start emitted or attributed %d times", n)
			}
		})
		for _, c := range completions() {
			t.Run("complete_"+c.name+"_"+name, func(t *testing.T) {
				t.Parallel()
				kr := newKeyRec(t, time.Hour)
				_, rp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.k.p), kr.alice.ID))
				svc := change(t, kr)
				// A promotion revokes the target's sessions, the recovery
				// session with them.
				want := access.ErrTokenInvalid
				if name == "subject_promoted" {
					want = account.ErrSessionGone
				}
				if err := c.run(t, kr.recWorld, svc, rp, account.RecoverOptions{}); !errors.Is(err, want) {
					t.Fatalf("completion after %s = %v, want %v", name, err, want)
				}
				if n := len(recoverySessions(t, kr.mem, kr.alice.ID)); n != 0 {
					t.Errorf("the refused completion left %d recovery sessions, want it deleted", n)
				}
				if c.holds(t, kr.recWorld, kr.alice) {
					t.Error("the refused completion set its credential")
				}
				if !signsIn(t, svc, "alice", goodPassword) {
					t.Error("alice's old password no longer signs in")
				}
				if got := actions(t, kr.fixture, kr.alice.ID); len(got) != 1 {
					t.Errorf("records = %v, want the start's alone", got)
				}
			})
		}
	}
	for label, at := range map[string]time.Duration{"at_expiry": 0, "after_expiry": time.Second} {
		t.Run("seeded_past_the_key_"+label, func(t *testing.T) {
			t.Parallel()
			kr := newKeyRec(t, time.Hour)
			plaintext, rec := access.NewOneTimeToken(access.PurposeRecovery, kr.alice.ID, 3*time.Hour, kr.clock.now())
			rec.IssuedByKey = kr.k.key.ID
			if err := kr.mem.CreateOneTimeToken(t.Context(), rec); err != nil {
				t.Fatalf("CreateOneTimeToken: %v", err)
			}
			kr.clock.set(kr.k.key.ExpiresAt.Add(at))
			kr.fs.resetRecord()
			if _, err := kr.svc.StartRecovery(t.Context(), localClient, plaintext); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("StartRecovery of a link outliving its expired key = %v, want access.ErrTokenInvalid", err)
			}
			if ws := writesOf(kr.fs); !slices.Equal(ws, []string{"ConsumeOneTimeToken"}) {
				t.Errorf("the refusal wrote %v, want the link's consumption alone", ws)
			}
			if tokenStored(t, kr.mem, rec) || len(recoverySessions(t, kr.mem, kr.alice.ID)) != 0 {
				t.Error("the refusal left the link or opened a session")
			}
		})
	}
	for _, c := range completions() {
		t.Run("unchanged_"+c.name, func(t *testing.T) {
			t.Parallel()
			kr := newKeyRec(t, time.Hour)
			rec, rp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.k.p), kr.alice.ID))
			if got := storedSession(t, kr.mem, kr.alice.ID, rec.Issued.Session.ID); got.IssuedByKey != kr.k.key.ID {
				t.Errorf("the recovery session's IssuedByKey = %d, want K %d", got.IssuedByKey, kr.k.key.ID)
			}
			if err := c.run(t, kr.recWorld, kr.svc, rp, account.RecoverOptions{}); err != nil {
				t.Fatalf("completion = %v", err)
			}
			if !c.holds(t, kr.recWorld, kr.alice) {
				t.Error("the completion set no credential")
			}
			for _, kind := range []account.EventKind{account.EventRecoveryConsumed, account.EventRecoveryCompleted} {
				if evs := eventsOf(kr.events, kind); len(evs) != 1 || evs[0].KeyID != kr.k.key.ID {
					t.Errorf("%v = %+v, want one naming K %d", kind, evs, kr.k.key.ID)
				}
			}
		})
	}
	t.Run("replacement_key", func(t *testing.T) {
		t.Parallel()
		for _, c := range completions() {
			kr := newKeyRec(t, 0)
			_, rp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.k.p), kr.alice.ID))
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(K) = %v", err)
			}
			k2 := kr.key(t, account.NewKey{Scopes: []string{scopeUsers}})
			if k2.key.ID == kr.k.key.ID {
				t.Fatalf("K2 received K's ID %d", k2.key.ID)
			}
			if err := c.run(t, kr.recWorld, kr.svc, rp, account.RecoverOptions{}); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("%s: completing K's recovery after K2 replaced it = %v, want access.ErrTokenInvalid", c.name, err)
			}
			if len(recoverySessions(t, kr.mem, kr.alice.ID)) != 0 || !signsIn(t, kr.svc, "alice", goodPassword) {
				t.Errorf("%s: the refusal left the recovery session or changed alice's password", c.name)
			}
			if got := kr.users(t, account.UserFilter{AttributedToKey: k2.key.ID}); len(got) != 0 {
				t.Errorf("%s: Users attributed to K2 = %v, want none", c.name, got)
			}
			if got := kr.users(t, account.UserFilter{AttributedToKey: kr.k.key.ID}); !slices.Equal(got, []int64{kr.alice.ID}) {
				t.Errorf("%s: Users attributed to K = %v, want alice", c.name, got)
			}
		}
	})
	for _, c := range completions() {
		t.Run("attribution_"+c.name, func(t *testing.T) {
			t.Parallel()
			kr := newKeyRec(t, 0)
			path := kr.k.key.LineageIDs
			started := attr(access.AttributionRecoveryStarted, path)
			recovered := attr(access.AttributionRecovered, path)
			tok := kr.issue(t, account.As(kr.k.p), kr.alice.ID)
			var rp access.Principal
			for n := 1; ; n++ {
				kr.fs.failWrite(n)
				rec, err := kr.svc.StartRecovery(t.Context(), localClient, tok.Plaintext)
				kr.fs.failWrite(0)
				if err == nil {
					rp = kr.principal(t, rec.Issued.Token)
					break
				}
				if !errors.Is(err, access.ErrAuthBackend) {
					t.Fatalf("start with write %d failing = %v, want ErrAuthBackend", n, err)
				}
				if len(recoverySessions(t, kr.mem, kr.alice.ID)) != 0 || len(actions(t, kr.fixture, kr.alice.ID)) != 0 || !tokenStored(t, kr.mem, access.OneTimeToken{Hash: hashOf(tok)}) {
					t.Fatalf("start with write %d failing left a session or a record, or spent the link", n)
				}
			}
			if got := actions(t, kr.fixture, kr.alice.ID); !slices.Equal(got, []string{started}) {
				t.Fatalf("records after the start = %v, want [%s]", got, started)
			}
			for n := 1; ; n++ {
				kr.fs.failWrite(n)
				err := c.run(t, kr.recWorld, kr.svc, rp, account.RecoverOptions{})
				kr.fs.failWrite(0)
				if err == nil {
					break
				}
				if !errors.Is(err, access.ErrAuthBackend) {
					t.Fatalf("completion with write %d failing = %v, want ErrAuthBackend", n, err)
				}
				if c.holds(t, kr.recWorld, kr.alice) || len(actions(t, kr.fixture, kr.alice.ID)) != 1 || len(recoverySessions(t, kr.mem, kr.alice.ID)) != 1 {
					t.Fatalf("completion with write %d failing set the credential, appended a record or ended the session", n)
				}
			}
			want := []string{started, recovered}
			if got := actions(t, kr.fixture, kr.alice.ID); !slices.Equal(got, want) {
				t.Fatalf("records after the completion = %v, want %v", got, want)
			}
			u1, err := kr.svc.CreateUser(t.Context(), account.As(kr.k.p), account.NewUser{Username: "made"})
			if err != nil {
				t.Fatalf("CreateUser from K = %v", err)
			}
			inv, err := kr.svc.CreateInvite(t.Context(), kr.k.p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite from K = %v", err)
			}
			u2, err := kr.accept(t, inv.Plaintext, "invited")
			if err != nil {
				t.Fatalf("accept = %v", err)
			}
			mustUser(t, kr.mem, "bystander", access.RoleUser)
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(K) = %v", err)
			}
			_, sp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.bp), kr.alice.ID))
			if err := completeWithPassword(t, kr.svc, sp, account.RecoverOptions{}); err != nil {
				t.Fatalf("a session-issued recovery = %v", err)
			}
			if err := kr.svc.RecoverOutOfBand(t.Context(), account.OutOfBand("socket"), kr.alice.ID, access.NewSecret(goodPassword), account.RecoverOptions{}); err != nil {
				t.Fatalf("RecoverOutOfBand = %v", err)
			}
			if got := actions(t, kr.fixture, kr.alice.ID); !slices.Equal(got, want) {
				t.Errorf("records after K's revocation and two unkeyed recoveries = %v, want %v unchanged", got, want)
			}
			wantUsers := []int64{kr.alice.ID, u1.ID, u2.User.ID}
			slices.Sort(wantUsers)
			if got := kr.users(t, account.UserFilter{AttributedToKey: kr.k.key.ID}); !slices.Equal(got, wantUsers) {
				t.Errorf("Users attributed to K = %v, want %v", got, wantUsers)
			}
		})
	}
	t.Run("session_issued_appends_none", func(t *testing.T) {
		t.Parallel()
		for _, c := range completions() {
			kr := newKeyRec(t, 0)
			_, rp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.bp), kr.alice.ID))
			if err := c.run(t, kr.recWorld, kr.svc, rp, account.RecoverOptions{}); err != nil {
				t.Fatalf("%s completion = %v", c.name, err)
			}
			if got := actions(t, kr.fixture, kr.alice.ID); len(got) != 0 {
				t.Errorf("%s: a session-issued recovery appended %v", c.name, got)
			}
		}
	})
}

func TestKeyAttributionLineage(t *testing.T) {
	t.Parallel()
	w := newRecWorld(t, pwOptions{}, nil)
	boss := mustUser(t, w.mem, "boss", access.RoleAdmin)
	bp := w.sessionPrincipal(t, boss, access.SessionFull, time.Now())
	r := passwordUser(t, w.mem, w.hasher, "taken", goodPassword)
	u3 := passwordUser(t, w.mem, w.hasher, "layered", goodPassword)
	k := w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	k2 := w.mint(t, account.As(k.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	k3 := w.mint(t, account.As(k2.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
	path1, path2, path3 := []int64{k.key.ID}, []int64{k.key.ID, k2.key.ID}, []int64{k.key.ID, k2.key.ID, k3.key.ID}
	if !slices.Equal(k3.key.LineageIDs, path3) {
		t.Fatalf("K3's LineageIDs = %v, want %v", k3.key.LineageIDs, path3)
	}
	recoverVia := func(a account.Actor, u *access.User, complete func(rp access.Principal) error) {
		t.Helper()
		_, rp := w.start(t, w.svc, w.issue(t, a, u.ID))
		if err := complete(rp); err != nil {
			t.Fatalf("completion = %v", err)
		}
	}
	byPassword := func(pw string) func(rp access.Principal) error {
		return func(rp access.Principal) error {
			return w.svc.RecoverWithPassword(t.Context(), rp, access.NewSecret(pw), account.RecoverOptions{})
		}
	}
	const takeover = "takeover-horse-battery-2"
	recoverVia(account.As(k3.p), r, byPassword(takeover))
	dev := accesstest.NewPasskeyDevice(t)
	recoverVia(account.As(k.p), u3, func(rp access.Principal) error {
		return w.recoverPasskey(t, w.svc, rp, dev, account.RecoverOptions{})
	})
	recoverVia(account.As(k2.p), u3, byPassword(recoveredPassword))
	recoverVia(account.As(bp), u3, byPassword(newPassword))
	if err := w.svc.RecoverOutOfBand(t.Context(), account.OutOfBand("socket"), u3.ID, access.NewSecret(goodPassword), account.RecoverOptions{}); err != nil {
		t.Fatalf("RecoverOutOfBand = %v", err)
	}
	rWant := []string{attr(access.AttributionRecoveryStarted, path3), attr(access.AttributionRecovered, path3)}
	u3Want := []string{
		attr(access.AttributionRecoveryStarted, path1), attr(access.AttributionRecovered, path1),
		attr(access.AttributionRecoveryStarted, path2), attr(access.AttributionRecovered, path2),
	}
	if got := actions(t, w.fixture, r.ID); !slices.Equal(got, rWant) {
		t.Errorf("R's records = %v, want %v", got, rWant)
	}
	if got := actions(t, w.fixture, u3.ID); !slices.Equal(got, u3Want) {
		t.Errorf("U3's records = %v, want %v in append order", got, u3Want)
	}
	if err := w.svc.RevokeAPIKey(t.Context(), w.pr, k.key.ID); err != nil {
		t.Fatalf("RevokeAPIKey(K) = %v", err)
	}
	if ks := keysOf(t, w.mem, w.root.ID); len(ks) != 0 {
		t.Fatalf("keys after revoking K = %v, want its subtree gone", keyIDs(ks))
	}
	filters := func(step string) {
		t.Helper()
		want := map[int64][]int64{k.key.ID: {r.ID, u3.ID}, k2.key.ID: {r.ID, u3.ID}, k3.key.ID: {r.ID}}
		for key, ids := range want {
			listed, err := w.svc.Users(t.Context(), bp, account.UserFilter{AttributedToKey: key})
			if err != nil {
				t.Fatalf("%s: Users = %v", step, err)
			}
			got := map[int64][]int64{}
			for i := range listed {
				got[listed[i].User.ID] = listed[i].KeyLineage
			}
			if len(got) != len(ids) {
				t.Errorf("%s: Users attributed to %d = %v, want %v", step, key, got, ids)
			}
			if !slices.Equal(got[r.ID], path3) {
				t.Errorf("%s: R's lineage under key %d = %v, want %v", step, key, got[r.ID], path3)
			}
			if key != k3.key.ID && !slices.Equal(got[u3.ID], path2) {
				t.Errorf("%s: U3's lineage under key %d = %v, want %v", step, key, got[u3.ID], path2)
			}
		}
		if got := actions(t, w.fixture, r.ID); !slices.Equal(got, rWant) {
			t.Errorf("%s: R's records = %v, want %v", step, got, rWant)
		}
		if got := actions(t, w.fixture, u3.ID); !slices.Equal(got, u3Want) {
			t.Errorf("%s: U3's records = %v, want %v", step, got, u3Want)
		}
	}
	filters("after revoking K")
	if !signsIn(t, w.svc, "taken", takeover) {
		t.Error("R does not sign in with the password the takeover set")
	}
	pc, err := w.svc.PasskeyLoginBegin(t.Context(), localClient, w.origin, account.LoginModal)
	if err != nil {
		t.Fatalf("PasskeyLoginBegin = %v", err)
	}
	if in, err := w.svc.PasskeyLoginFinish(t.Context(), localClient, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion)))); err != nil || in.User.ID != u3.ID {
		t.Errorf("the passkey K installed on U3 signs in as %v, %v; want U3", in.User, err)
	}
	if err := w.svc.DeleteUser(t.Context(), bp, w.root.ID); err != nil {
		t.Fatalf("DeleteUser(K's owner) = %v", err)
	}
	filters("after deleting K's owner")
	if err := w.svc.DeleteUser(t.Context(), bp, r.ID); err != nil {
		t.Fatalf("DeleteUser(R) = %v", err)
	}
	if got := actions(t, w.fixture, r.ID); len(got) != 0 {
		t.Errorf("R's records after its deletion = %v, want none", got)
	}
	if got := actions(t, w.fixture, u3.ID); !slices.Equal(got, u3Want) {
		t.Errorf("U3's records after R's deletion = %v, want %v", got, u3Want)
	}
}
