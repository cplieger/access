package account_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// recoveryTokensOf is userID's stored recovery tokens, expired ones included.
func recoveryTokensOf(t *testing.T, s account.Store, userID int64) []access.OneTimeToken {
	t.Helper()
	all, err := s.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeRecovery}, time.Time{})
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	return slices.DeleteFunc(all, func(tok access.OneTimeToken) bool { return tok.Subject != userID })
}

// failureRecords reports whether name holds a password record in either
// trust context.
func failureRecords(t *testing.T, w *recWorld, name string) bool {
	t.Helper()
	_, untrusted := record(t, w.mem, w.svc, name, false)
	_, trusted := record(t, w.mem, w.svc, name, true)
	return untrusted || trusted
}

func TestStartRecovery(t *testing.T) {
	t.Parallel()
	t.Run("opens_a_recovery_session", func(t *testing.T) {
		t.Parallel()
		w := newRecWorld(t, pwOptions{}, nil)
		tok := w.issue(t, account.OutOfBand("socket"), w.alice.ID)
		seedLock(t, w.mem, w.svc, "alice", false, false)
		rec, rp := w.start(t, w.svc, tok)
		if rec.Username != "alice" || !rec.Methods.HasPassword || !slices.Equal(rec.Methods.Locks, []account.MethodLock{{Method: access.MethodPassword, Untrusted: true}}) {
			t.Errorf("Recovery = %+v, want alice holding a password locked untrusted", rec)
		}
		sess := rec.Issued.Session
		if sess.Kind != access.SessionRecovery || sess.AuthMethod != access.MethodRecovery || sess.UserID != w.alice.ID || sess.IssuedByKey != 0 {
			t.Errorf("session = %+v, want alice's unkeyed recovery session", sess)
		}
		if !rec.Issued.DeviceCookie.IsZero() {
			t.Error("the recovery start issued a device cookie")
		}
		if !rp.IsRecoverySession() || rp.User.ID != w.alice.ID {
			t.Errorf("principal = %+v, want alice's recovery session", rp)
		}
		if got := storedSession(t, w.mem, w.alice.ID, sess.ID); got.Kind != access.SessionRecovery {
			t.Errorf("stored session kind = %q, want recovery", got.Kind)
		}
		if toks := recoveryTokensOf(t, w.mem, w.alice.ID); len(toks) != 0 {
			t.Errorf("the consumed token is still stored: %+v", toks)
		}
		evs := eventsOf(w.events, account.EventRecoveryConsumed)
		if len(evs) != 1 || evs[0].UserID != w.alice.ID || evs[0].KeyID != 0 || !evs[0].At.Equal(sess.CreatedAt) {
			t.Errorf("EventRecoveryConsumed = %+v, want one for alice naming no key", evs)
		}
		if n := len(eventsOf(w.events, account.EventSignedIn)); n != 0 {
			t.Errorf("EventSignedIn fired %d times, want none: a recovery start signs nobody in", n)
		}
		if _, err := w.svc.StartRecovery(t.Context(), localClient, tok.Plaintext); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a second start with the same token = %v, want access.ErrTokenInvalid", err)
		}
	})
	refusals := map[string]func(t *testing.T, w *recWorld) access.Secret{
		"zero": func(*testing.T, *recWorld) access.Secret { return access.Secret{} },
		"forged": func(*testing.T, *recWorld) access.Secret {
			return access.NewSecret(strings.Repeat("ab", 32))
		},
		"expired": func(t *testing.T, w *recWorld) access.Secret {
			plaintext, rec := access.NewOneTimeToken(access.PurposeRecovery, w.alice.ID, time.Minute, time.Now().Add(-time.Hour))
			if err := w.mem.CreateOneTimeToken(t.Context(), rec); err != nil {
				t.Fatalf("CreateOneTimeToken: %v", err)
			}
			return plaintext
		},
		"invite": func(t *testing.T, w *recWorld) access.Secret {
			inv, err := w.svc.CreateInvite(t.Context(), w.pr, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			return inv.Plaintext
		},
		"disabled_subject": func(t *testing.T, w *recWorld) access.Secret {
			tok := w.issue(t, account.OutOfBand("socket"), w.alice.ID)
			u := storedUser(t, w.mem, w.alice.ID)
			u.Enabled = false
			if err := w.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			return tok.Plaintext
		},
	}
	for name, token := range refusals {
		t.Run("refused_"+name, func(t *testing.T) {
			t.Parallel()
			w := newRecWorld(t, pwOptions{}, nil)
			plaintext := token(t, w)
			tokens := len(recoveryTokensOf(t, w.mem, w.alice.ID))
			w.fs.resetRecord()
			if _, err := w.svc.StartRecovery(t.Context(), localClient, plaintext); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("StartRecovery = %v, want access.ErrTokenInvalid", err)
			}
			if ws := writesOf(w.fs); len(ws) != 0 {
				t.Errorf("the refusal wrote %v", ws)
			}
			if n := len(recoverySessions(t, w.mem, w.alice.ID)); n != 0 {
				t.Errorf("the refusal opened %d recovery sessions", n)
			}
			if n := len(recoveryTokensOf(t, w.mem, w.alice.ID)); n != tokens {
				t.Errorf("recovery tokens after the refusal = %d, want the %d before", n, tokens)
			}
		})
	}
}

// recoveredWorld is alice with two other full sessions, two keys, a second
// recovery token, both password records locked (the trusted one not yet
// reported), and a started recovery.
type recoveredWorld struct {
	*recWorld
	rp       access.Principal
	others   []string
	keys     []int64
	recovery string
}

func newRecoveredWorld(t *testing.T) *recoveredWorld {
	t.Helper()
	w := &recoveredWorld{recWorld: newRecWorld(t, pwOptions{}, nil)}
	for range 2 {
		w.others = append(w.others, w.sessionPrincipal(t, w.alice, access.SessionFull, time.Now()).SessionID)
		w.keys = append(w.keys, w.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}}).key.ID)
	}
	tok := w.issue(t, account.OutOfBand("socket"), w.alice.ID)
	seedToken(t, w.mem, access.PurposeRecovery, w.alice.ID, 0, time.Hour)
	seedLock(t, w.mem, w.svc, "alice", false, false)
	seedLock(t, w.mem, w.svc, "alice", true, true)
	var rec account.Recovery
	rec, w.rp = w.start(t, w.svc, tok)
	w.recovery = rec.Issued.Session.ID
	return w
}

func TestRecoveryCompletion(t *testing.T) {
	t.Parallel()
	for _, c := range completions() {
		t.Run(c.name+"_defaults", func(t *testing.T) {
			t.Parallel()
			w := newRecoveredWorld(t)
			before := len(w.events.all())
			if err := c.run(t, w.recWorld, w.svc, w.rp, account.RecoverOptions{}); err != nil {
				t.Fatalf("completion = %v", err)
			}
			if !c.holds(t, w.recWorld, w.alice) {
				t.Error("the completion did not set its credential")
			}
			if c.name == "password" && w.verifies(t, w.alice, goodPassword) {
				t.Error("the old password still verifies")
			}
			if ss := sessionsOf(t, w.mem, w.alice.ID); len(ss) != 0 {
				t.Errorf("sessions after the completion = %d, want none: it signs nobody in", len(ss))
			}
			if ks := keysOf(t, w.mem, w.alice.ID); len(ks) != 0 {
				t.Errorf("keys after the completion = %v, want none", keyIDs(ks))
			}
			if toks := recoveryTokensOf(t, w.mem, w.alice.ID); len(toks) != 0 {
				t.Errorf("recovery tokens after the completion = %d, want none", len(toks))
			}
			if failureRecords(t, w.recWorld, "alice") {
				t.Error("a failure record survives the completion")
			}
			ended := slices.Sorted(slices.Values(append(slices.Clone(w.others), w.recovery)))
			wantKinds := []account.EventKind{
				account.EventRecoveryCompleted, account.EventKeyRevoked, account.EventKeyRevoked,
				account.EventMethodLocked, account.EventMethodReenabled, account.EventMethodReenabled,
			}
			evs := w.events.all()[before:]
			var kinds []account.EventKind
			for _, ev := range evs {
				kinds = append(kinds, ev.Kind)
			}
			if !slices.Equal(kinds, wantKinds) {
				t.Fatalf("events = %v, want %v", kinds, wantKinds)
			}
			if done := evs[0]; done.UserID != w.alice.ID || !slices.Equal(done.SessionIDs, ended) || done.KeyID != 0 || done.Actor.SessionID != w.rp.SessionID {
				t.Errorf("EventRecoveryCompleted = %+v, want alice's with sessions %v and the recovery session as actor", done, ended)
			}
			if done := evs[0]; done.Method != c.method {
				t.Errorf("EventRecoveryCompleted.Method = %q, want %q, the credential the completion installed", done.Method, c.method)
			}
			if got := []int64{evs[1].KeyID, evs[2].KeyID}; !slices.Equal(got, w.keys) {
				t.Errorf("EventKeyRevoked keys = %v, want %v", got, w.keys)
			}
			if evs[3].Method != access.MethodPassword || !evs[3].Trusted || evs[3].Actor != (account.EventActor{}) {
				t.Errorf("EventMethodLocked = %+v, want the unreported trusted password lock with no actor", evs[3])
			}
			if evs[4].Trusted || !evs[5].Trusted || evs[4].Method != access.MethodPassword || evs[5].Actor.SessionID != w.rp.SessionID {
				t.Errorf("EventMethodReenabled = %+v, %+v; want untrusted then trusted password by the recovery session", evs[4], evs[5])
			}
			if n := len(eventsOf(w.events, account.EventSignedIn)); n != 0 {
				t.Errorf("EventSignedIn fired %d times, want none", n)
			}
		})
		t.Run(c.name+"_keep", func(t *testing.T) {
			t.Parallel()
			w := newRecoveredWorld(t)
			if err := c.run(t, w.recWorld, w.svc, w.rp, account.RecoverOptions{KeepSessions: true, KeepKeys: true}); err != nil {
				t.Fatalf("completion = %v", err)
			}
			if got := sessionIDsOf(t, w.fixture, w.alice.ID); !slices.Equal(got, slices.Sorted(slices.Values(w.others))) {
				t.Errorf("sessions = %v, want the two others kept and the recovery session gone", got)
			}
			if got := keyIDs(keysOf(t, w.mem, w.alice.ID)); !slices.Equal(got, w.keys) {
				t.Errorf("keys = %v, want %v kept", got, w.keys)
			}
			if done := eventsOf(w.events, account.EventRecoveryCompleted); len(done) != 1 || !slices.Equal(done[0].SessionIDs, []string{w.recovery}) {
				t.Errorf("EventRecoveryCompleted = %+v, want the recovery session alone", done)
			}
			if n := len(eventsOf(w.events, account.EventKeyRevoked)); n != 0 {
				t.Errorf("EventKeyRevoked fired %d times with KeepKeys", n)
			}
			if failureRecords(t, w.recWorld, "alice") {
				t.Error("a failure record survives the completion")
			}
		})
		t.Run(c.name+"_session_gone", func(t *testing.T) {
			t.Parallel()
			w := newRecoveredWorld(t)
			if err := w.mem.DeleteSession(t.Context(), access.SessionRef{ID: w.recovery, UserID: w.alice.ID}); err != nil {
				t.Fatalf("DeleteSession: %v", err)
			}
			if err := c.run(t, w.recWorld, w.svc, w.rp, account.RecoverOptions{}); !errors.Is(err, account.ErrSessionGone) {
				t.Fatalf("completion after the session ended = %v, want ErrSessionGone", err)
			}
			if c.holds(t, w.recWorld, w.alice) || len(sessionsOf(t, w.mem, w.alice.ID)) != 2 || !failureRecords(t, w.recWorld, "alice") {
				t.Error("the refused completion changed alice")
			}
		})
	}
	t.Run("refused_password", func(t *testing.T) {
		t.Parallel()
		w := newRecoveredWorld(t)
		w.fs.resetRecord()
		err := w.svc.RecoverWithPassword(t.Context(), w.rp, access.NewSecret("qazwsxedcrfvtgb"), account.RecoverOptions{})
		if pe, ok := errors.AsType[*access.PasswordError](err); !ok || pe.Reason != "common" {
			t.Fatalf("RecoverWithPassword(common) = %v, want *access.PasswordError common", err)
		}
		if ws := writesOf(w.fs); len(ws) != 0 {
			t.Errorf("the refusal wrote %v", ws)
		}
		if len(recoverySessions(t, w.mem, w.alice.ID)) != 1 || !w.verifies(t, w.alice, goodPassword) {
			t.Error("the refusal ended the recovery session or changed the password")
		}
	})
	t.Run("only_a_recovery_session", func(t *testing.T) {
		t.Parallel()
		w := newRecoveredWorld(t)
		full := w.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
		key := w.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}}).p
		for name, p := range map[string]access.Principal{"full_session": full, "key": key, "bypass": w.bypassPrincipal(t)} {
			if err := completeWithPassword(t, w.svc, p, account.RecoverOptions{}); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("RecoverWithPassword from a %s = %v, want ErrSessionRequired", name, err)
			}
			if _, err := w.svc.RecoverPasskeyBegin(t.Context(), p, w.origin); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("RecoverPasskeyBegin from a %s = %v, want ErrSessionRequired", name, err)
			}
			if err := w.svc.RecoverPasskeyFinish(t.Context(), p, "x", bytes.NewReader(nil), account.RecoverOptions{}); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("RecoverPasskeyFinish from a %s = %v, want ErrSessionRequired", name, err)
			}
		}
		if w.verifies(t, w.alice, recoveredPassword) {
			t.Error("a refused completion set the password")
		}
	})
	t.Run("restricted_off_the_recovery_routes", func(t *testing.T) {
		t.Parallel()
		w := newRecWorld(t, pwOptions{}, nil)
		rec, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
		cookie := w.authn.Cookie()
		req.AddCookie(&http.Cookie{Name: cookie.CookieName(req), Value: rec.Issued.Token.Reveal()})
		if _, err := w.authn.Authenticate(req); !errors.Is(err, access.ErrRestrictedSession) {
			t.Errorf("the recovery session off the recovery routes = %v, want access.ErrRestrictedSession", err)
		}
		if _, err := w.svc.Me(t.Context(), rp); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("Me from the recovery session = %v, want ErrSessionRequired", err)
		}
		if _, err := w.setPassword(t.Context(), rp, goodPassword, newPassword); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("SetPassword from the recovery session = %v, want ErrSessionRequired", err)
		}
		if _, err := w.svc.PasskeyRegisterBegin(t.Context(), rp, w.origin); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("PasskeyRegisterBegin from the recovery session = %v, want ErrSessionRequired", err)
		}
	})
	t.Run("passkeys_unavailable", func(t *testing.T) {
		t.Parallel()
		w := newRecWorld(t, pwOptions{edit: func(c *account.Config) { c.RP = nil }}, nil)
		_, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
		if _, err := w.svc.RecoverPasskeyBegin(t.Context(), rp, w.origin); !errors.Is(err, account.ErrPasskeysUnavailable) {
			t.Errorf("RecoverPasskeyBegin with no RP = %v, want ErrPasskeysUnavailable", err)
		}
		if err := w.svc.RecoverPasskeyFinish(t.Context(), rp, "x", bytes.NewReader(nil), account.RecoverOptions{}); !errors.Is(err, account.ErrPasskeysUnavailable) {
			t.Errorf("RecoverPasskeyFinish with no RP = %v, want ErrPasskeysUnavailable", err)
		}
	})
	t.Run("ceremony_of_another_user", func(t *testing.T) {
		t.Parallel()
		w := newRecWorld(t, pwOptions{}, nil)
		bob := passwordUser(t, w.mem, w.hasher, "bob", goodPassword)
		_, alice := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
		_, other := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), bob.ID))
		pc, err := w.svc.RecoverPasskeyBegin(t.Context(), other, w.origin)
		if err != nil {
			t.Fatalf("RecoverPasskeyBegin = %v", err)
		}
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if err := w.svc.RecoverPasskeyFinish(t.Context(), alice, pc.ID, bytes.NewReader(body), account.RecoverOptions{}); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("finishing bob's ceremony from alice's recovery = %v, want ErrCeremonyInvalid", err)
		}
		if len(passkeysOf(t, w.mem, w.alice.ID))+len(passkeysOf(t, w.mem, bob.ID)) != 0 {
			t.Error("a refused ceremony stored a passkey")
		}
	})
}

func TestRecoveryRevokesKeys(t *testing.T) {
	t.Parallel()
	for _, c := range completions() {
		for name, keep := range map[string]bool{"default": false, "keep_keys": true} {
			t.Run(c.name+"_"+name, func(t *testing.T) {
				t.Parallel()
				w := newRecWorld(t, pwOptions{}, nil)
				var plaintexts []access.Secret
				for range 2 {
					created, err := w.svc.CreateAPIKey(t.Context(), account.OutOfBand("socket"), w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}})
					if err != nil {
						t.Fatalf("CreateAPIKey = %v", err)
					}
					plaintexts = append(plaintexts, created.Plaintext)
				}
				_, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
				if err := c.run(t, w, w.svc, rp, account.RecoverOptions{KeepKeys: keep}); err != nil {
					t.Fatalf("completion = %v", err)
				}
				if n := len(keysOf(t, w.mem, w.alice.ID)); (n == 2) != keep {
					t.Errorf("alice holds %d keys after the completion, want them kept %t", n, keep)
				}
				for i, pt := range plaintexts {
					if _, err := w.bearer(t, pt); (err == nil) != keep {
						t.Errorf("key %d at the API-key verifier = %v, want it kept %t", i, err, keep)
					}
				}
			})
		}
	}
}

func TestRecoveryRevokesKeysAndTheirTokens(t *testing.T) {
	t.Parallel()
	for _, c := range completions() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newRecWorld(t, pwOptions{}, nil)
			boss := passwordUser(t, w.mem, w.hasher, "boss", goodPassword)
			boss.Role = access.RoleAdmin
			if err := w.mem.UpdateUser(t.Context(), boss); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			k := w.mint(t, account.OutOfBand("socket"), boss.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeUsers}})
			inv, err := w.svc.CreateInvite(t.Context(), k.p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite from K = %v", err)
			}
			rec := w.issue(t, account.As(k.p), w.alice.ID)
			_, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), boss.ID))
			unchanged := func(t *testing.T, step string) {
				t.Helper()
				if !slices.Equal(keyIDs(keysOf(t, w.mem, boss.ID)), []int64{k.key.ID}) {
					t.Errorf("%s: K is gone", step)
				}
				for name, tok := range map[string]account.IssuedToken{"invite": inv, "recovery": rec} {
					if _, found, _ := w.mem.OneTimeTokenByHash(t.Context(), hashOf(tok)); !found {
						t.Errorf("%s: K's %s is gone", step, name)
					}
				}
				if len(recoverySessions(t, w.mem, boss.ID)) != 1 || c.holds(t, w, boss) {
					t.Errorf("%s: the recovery session ended or the credential was set", step)
				}
			}
			n := 1
			for ; ; n++ {
				w.fs.failWrite(n)
				err := c.run(t, w, w.svc, rp, account.RecoverOptions{})
				w.fs.failWrite(0)
				if err == nil {
					break
				}
				if !errors.Is(err, access.ErrAuthBackend) {
					t.Fatalf("write %d failing: completion = %v, want ErrAuthBackend", n, err)
				}
				unchanged(t, fmt.Sprintf("write %d failing", n))
			}
			if n < 8 {
				t.Errorf("the completion committed with write %d armed, want at least seven writes: the credential, the tokens, the sessions, the keys, their tokens and the failure records", n)
			}
			if ks := keysOf(t, w.mem, boss.ID); len(ks) != 0 {
				t.Errorf("K survives the completion: %v", keyIDs(ks))
			}
			for name, tok := range map[string]account.IssuedToken{"invite": inv, "recovery": rec} {
				if _, found, _ := w.mem.OneTimeTokenByHash(t.Context(), hashOf(tok)); found {
					t.Errorf("K's %s survives the completion", name)
				}
			}
		})
	}
}

func TestShellOnlyRepair(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*recWorld, []string, []int64) {
		w := newRecWorld(t, pwOptions{}, nil)
		var sessions []string
		var keys []int64
		for range 2 {
			sessions = append(sessions, w.sessionPrincipal(t, w.alice, access.SessionFull, time.Now()).SessionID)
			keys = append(keys, w.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}}).key.ID)
		}
		w.issue(t, account.OutOfBand("socket"), w.alice.ID)
		seedLock(t, w.mem, w.svc, "alice", false, false)
		seedLock(t, w.mem, w.svc, "alice", true, false)
		return w, slices.Sorted(slices.Values(sessions)), keys
	}
	oob := account.OutOfBand("admin-socket")
	t.Run("repairs", func(t *testing.T) {
		t.Parallel()
		w, sessions, keys := setup(t)
		before := len(w.events.all())
		if err := w.svc.RecoverOutOfBand(t.Context(), oob, w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{}); err != nil {
			t.Fatalf("RecoverOutOfBand = %v", err)
		}
		if n := len(sessionsOf(t, w.mem, w.alice.ID)); n != 0 {
			t.Errorf("sessions = %d, want none", n)
		}
		if n := len(keysOf(t, w.mem, w.alice.ID)); n != 0 {
			t.Errorf("keys = %d, want none", n)
		}
		if n := len(recoveryTokensOf(t, w.mem, w.alice.ID)); n != 0 {
			t.Errorf("recovery tokens = %d, want none", n)
		}
		if failureRecords(t, w, "alice") {
			t.Error("a failure record survives the repair")
		}
		evs := w.events.all()[before:]
		var kinds []account.EventKind
		for _, ev := range evs {
			kinds = append(kinds, ev.Kind)
		}
		want := []account.EventKind{account.EventRecoveryCompleted, account.EventKeyRevoked, account.EventKeyRevoked, account.EventMethodReenabled, account.EventMethodReenabled}
		if !slices.Equal(kinds, want) {
			t.Fatalf("events = %v, want %v", kinds, want)
		}
		if done := evs[0]; done.Actor.OutOfBand != "admin-socket" || done.UserID != w.alice.ID || !slices.Equal(done.SessionIDs, sessions) || done.KeyID != 0 {
			t.Errorf("EventRecoveryCompleted = %+v, want alice's from admin-socket with sessions %v", done, sessions)
		}
		if done := evs[0]; done.Method != access.MethodPassword {
			t.Errorf("EventRecoveryCompleted.Method = %q, want %q: the repair set a password", done.Method, access.MethodPassword)
		}
		if got := []int64{evs[1].KeyID, evs[2].KeyID}; !slices.Equal(got, keys) {
			t.Errorf("EventKeyRevoked keys = %v, want %v", got, keys)
		}
		for _, ev := range evs[1:] {
			if ev.Actor.OutOfBand != "admin-socket" {
				t.Errorf("%v actor = %+v, want admin-socket", ev.Kind, ev.Actor)
			}
		}
		if !signsIn(t, w.svc, "alice", recoveredPassword) {
			t.Error("the repaired password does not sign in")
		}
		if u := storedUser(t, w.mem, w.alice.ID); !u.Enabled {
			t.Error("the repair changed Enabled")
		}
	})
	t.Run("keep", func(t *testing.T) {
		t.Parallel()
		w, sessions, keys := setup(t)
		if err := w.svc.RecoverOutOfBand(t.Context(), oob, w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{KeepSessions: true, KeepKeys: true}); err != nil {
			t.Fatalf("RecoverOutOfBand = %v", err)
		}
		if got := sessionIDsOf(t, w.fixture, w.alice.ID); !slices.Equal(got, sessions) {
			t.Errorf("sessions = %v, want %v kept", got, sessions)
		}
		if got := keyIDs(keysOf(t, w.mem, w.alice.ID)); !slices.Equal(got, keys) {
			t.Errorf("keys = %v, want %v kept", got, keys)
		}
	})
	t.Run("disabled_user_stays_disabled", func(t *testing.T) {
		t.Parallel()
		w, _, _ := setup(t)
		u := storedUser(t, w.mem, w.alice.ID)
		u.Enabled = false
		if err := w.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if err := w.svc.RecoverOutOfBand(t.Context(), oob, w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{}); err != nil {
			t.Fatalf("RecoverOutOfBand = %v", err)
		}
		if got := storedUser(t, w.mem, w.alice.ID); got.Enabled || !w.verifies(t, got, recoveredPassword) {
			t.Errorf("after the repair alice is enabled %t; want the password set and Enabled unchanged", got.Enabled)
		}
	})
	refusals := map[string]struct {
		run  func(t *testing.T, w *recWorld) error
		want func(error) bool
	}{
		"common_password": {
			run: func(t *testing.T, w *recWorld) error {
				return w.svc.RecoverOutOfBand(t.Context(), oob, w.alice.ID, access.NewSecret("qazwsxedcrfvtgb"), account.RecoverOptions{})
			},
			want: func(err error) bool {
				pe, ok := errors.AsType[*access.PasswordError](err)
				return ok && pe.Reason == "common"
			},
		},
		"principal_actor": {
			run: func(t *testing.T, w *recWorld) error {
				return w.svc.RecoverOutOfBand(t.Context(), account.As(w.pr), w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
			},
			want: func(err error) bool {
				return reason(err) == "out_of_band_only" && errors.Is(err, account.ErrPolicyRefused)
			},
		},
		"zero_actor": {
			run: func(t *testing.T, w *recWorld) error {
				return w.svc.RecoverOutOfBand(t.Context(), account.Actor{}, w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
			},
			want: func(err error) bool { return reason(err) == "out_of_band_only" },
		},
		"missing_user": {
			run: func(t *testing.T, w *recWorld) error {
				return w.svc.RecoverOutOfBand(t.Context(), oob, 9999, access.NewSecret(recoveredPassword), account.RecoverOptions{})
			},
			want: is(account.ErrNotFound),
		},
	}
	for name, r := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, sessions, keys := setup(t)
			w.fs.resetRecord()
			if err := r.run(t, w); !r.want(err) {
				t.Fatalf("RecoverOutOfBand = %v, want the %s refusal", err, name)
			}
			if ws := writesOf(w.fs); len(ws) != 0 {
				t.Errorf("the refusal wrote %v", ws)
			}
			if got := sessionIDsOf(t, w.fixture, w.alice.ID); !slices.Equal(got, sessions) || !slices.Equal(keyIDs(keysOf(t, w.mem, w.alice.ID)), keys) || !w.verifies(t, w.alice, goodPassword) {
				t.Error("the refusal changed alice")
			}
		})
	}
	t.Run("principal_reads_nothing", func(t *testing.T) {
		t.Parallel()
		w, _, _ := setup(t)
		w.fs.resetRecord()
		_ = w.svc.RecoverOutOfBand(t.Context(), account.As(w.pr), w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
		if calls := w.fs.recorded(); len(calls) != 0 {
			t.Errorf("a principal's call made store calls %v, want none", calls)
		}
	})
}

// clearing is one operation that clears alice's password locks, from a
// world where the password is her only method, locked in both contexts.
// prepare arranges it before any hold and returns the clear, and the
// sign-in on a given Service with the method the clear left usable.
type clearing struct {
	prepare func(t *testing.T, w *recWorld) (clear func() error, signIn func(svc *account.Service) error)
	name    string
}

func clearings() []clearing {
	viaPassword := func(t *testing.T, pw string) func(svc *account.Service) error {
		return func(svc *account.Service) error {
			_, err := svc.PasswordLogin(t.Context(), localClient, account.Credentials{Username: "alice", Password: access.NewSecret(pw)})
			return err
		}
	}
	started := func(t *testing.T, w *recWorld) access.Principal {
		_, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
		return rp
	}
	return []clearing{
		{name: "RecoverWithPassword", prepare: func(t *testing.T, w *recWorld) (func() error, func(*account.Service) error) {
			rp := started(t, w)
			return func() error { return completeWithPassword(t, w.svc, rp, account.RecoverOptions{}) }, viaPassword(t, recoveredPassword)
		}},
		{name: "RecoverPasskeyFinish", prepare: func(t *testing.T, w *recWorld) (func() error, func(*account.Service) error) {
			rp := started(t, w)
			dev := accesstest.NewPasskeyDevice(t)
			signIn := func(svc *account.Service) error {
				pc, err := svc.PasskeyLoginBegin(t.Context(), localClient, w.origin, account.LoginModal)
				if err != nil {
					return err
				}
				_, err = svc.PasskeyLoginFinish(t.Context(), localClient, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
				return err
			}
			return func() error { return w.recoverPasskey(t, w.svc, rp, dev, account.RecoverOptions{}) }, signIn
		}},
		{name: "RecoverOutOfBand", prepare: func(t *testing.T, w *recWorld) (func() error, func(*account.Service) error) {
			return func() error {
				return w.svc.RecoverOutOfBand(t.Context(), account.OutOfBand("socket"), w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
			}, viaPassword(t, recoveredPassword)
		}},
		{name: "ReenableMethod", prepare: func(t *testing.T, w *recWorld) (func() error, func(*account.Service) error) {
			pr, _ := w.signedInVia(t, w.alice, access.MethodPasskey)
			return func() error { return w.svc.ReenableMethod(t.Context(), pr, access.MethodPassword) }, viaPassword(t, goodPassword)
		}},
	}
}

func TestDurableLockClears(t *testing.T) {
	t.Parallel()
	locked := func(t *testing.T) *recWorld {
		w := newRecWorld(t, pwOptions{}, nil)
		seedLock(t, w.mem, w.svc, "alice", false, false)
		seedLock(t, w.mem, w.svc, "alice", true, false)
		return w
	}
	for _, c := range clearings() {
		t.Run(c.name+"_new_service", func(t *testing.T) {
			t.Parallel()
			w := locked(t)
			clear, signIn := c.prepare(t, w)
			if err := clear(); err != nil {
				t.Fatalf("%s = %v", c.name, err)
			}
			svc, err := account.New(context.WithoutCancel(t.Context()), w.cfg)
			if err != nil {
				t.Fatalf("account.New over the same store = %v", err)
			}
			t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
			if err := signIn(svc); err != nil {
				t.Errorf("signing in on a new Service after %s = %v, want it signed in", c.name, err)
			}
		})
		t.Run(c.name+"_held_count", func(t *testing.T) {
			t.Parallel()
			w := locked(t)
			clear, _ := c.prepare(t, w)
			entered, release := w.fs.holdUpdate()
			defer release()
			done := make(chan error, 1)
			go func() {
				_, err := w.login(t.Context(), clientAt(1), "alice", wrongPassword)
				done <- err
			}()
			<-entered
			if err := clear(); err != nil {
				t.Fatalf("%s while a count is held = %v", c.name, err)
			}
			release()
			if err := <-done; !errors.Is(err, account.ErrInvalidCredentials) {
				t.Fatalf("the held wrong sign-in = %v, want ErrInvalidCredentials", err)
			}
			if rec, _ := record(t, w.mem, w.svc, "alice", false); rec.Count != 1 || rec.Locked {
				t.Errorf("record after the count landed behind the clear = %+v, want count 1 and no lock", rec)
			}
		})
		t.Run(c.name+"_failed_clear", func(t *testing.T) {
			t.Parallel()
			w := locked(t)
			clear, _ := c.prepare(t, w)
			w.fs.failCall("DeleteAuthFailures")
			if err := clear(); !errors.Is(err, access.ErrAuthBackend) {
				t.Fatalf("%s with its clear failing = %v, want ErrAuthBackend", c.name, err)
			}
			for _, trusted := range []bool{false, true} {
				if rec, found := record(t, w.mem, w.svc, "alice", trusted); !found || !rec.Locked {
					t.Errorf("trusted %t: the lock after a failed clear = %+v, want it kept", trusted, rec)
				}
			}
			if !w.verifies(t, w.alice, goodPassword) {
				t.Error("the failed clear changed the password")
			}
		})
	}
}

func TestStartRecoverySubjectDisabledBeforeUpdate(t *testing.T) {
	t.Parallel()
	w := newRecWorld(t, pwOptions{}, nil)
	tok := w.issue(t, account.OutOfBand("socket"), w.alice.ID)
	var once sync.Once
	w.fs.onUpdate(func(ctx context.Context, _ int) {
		once.Do(func() {
			v := storedUser(t, w.mem, w.alice.ID)
			v.Enabled = false
			if err := w.mem.UpdateUser(ctx, v); err != nil {
				t.Errorf("disable alice: %v", err)
			}
		})
	})
	if _, err := w.svc.StartRecovery(t.Context(), localClient, tok.Plaintext); !errors.Is(err, access.ErrTokenInvalid) {
		t.Errorf("a start whose subject was disabled after the peek = %v, want access.ErrTokenInvalid", err)
	}
	if got := len(recoverySessions(t, w.mem, w.alice.ID)); got != 0 {
		t.Errorf("recovery sessions = %d, want none", got)
	}
}

func TestConcurrentStartRecovery(t *testing.T) {
	t.Parallel()
	w := newRecWorld(t, pwOptions{}, nil)
	tok := w.issue(t, account.OutOfBand("socket"), w.alice.ID)
	const n = 16
	errs := make(chan error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			_, err := w.svc.StartRecovery(t.Context(), localClient, tok.Plaintext)
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	won := 0
	for err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, access.ErrTokenInvalid):
			t.Errorf("a losing start = %v, want access.ErrTokenInvalid", err)
		}
	}
	if won != 1 {
		t.Errorf("%d starts won, want exactly 1", won)
	}
	if got := len(recoverySessions(t, w.mem, w.alice.ID)); got != 1 {
		t.Errorf("recovery sessions = %d, want exactly 1", got)
	}
	if got := len(eventsOf(w.events, account.EventRecoveryConsumed)); got != 1 {
		t.Errorf("EventRecoveryConsumed fired %d times, want 1", got)
	}
}

func TestRecoveryOnSSOGoverned(t *testing.T) {
	t.Parallel()
	w := newRecWorld(t, pwOptions{rules: func() account.Rules {
		r := keyRules()
		r.SSOGoverned = true
		return r
	}}, nil)
	linkIdentity(t, w.mem, w.alice, access.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "alice"})
	full := w.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	if _, err := w.setPassword(t.Context(), full, goodPassword, newPassword); !errors.Is(err, account.ErrSSOGoverned) {
		t.Fatalf("SetPassword of the linked user = %v, want ErrSSOGoverned", err)
	}
	if _, err := w.svc.PasskeyRegisterBegin(t.Context(), full, w.origin); !errors.Is(err, account.ErrSSOGoverned) {
		t.Fatalf("PasskeyRegisterBegin of the linked user = %v, want ErrSSOGoverned", err)
	}
	for _, c := range completions() {
		_, rp := w.start(t, w.svc, w.issue(t, account.OutOfBand("socket"), w.alice.ID))
		if err := c.run(t, w, w.svc, rp, account.RecoverOptions{}); err != nil {
			t.Fatalf("%s recovery of the linked user = %v, want a local method restored", c.name, err)
		}
		if !c.holds(t, w, w.alice) {
			t.Errorf("%s recovery of the linked user set no credential", c.name)
		}
	}
	if !signsIn(t, w.svc, "alice", recoveredPassword) {
		t.Error("the restored password does not sign in")
	}
}
