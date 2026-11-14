package account_test

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// storeState is every record a MemStore holds, each hash replaced by its
// revealed form in hashes, so two reads of one state compare equal.
type storeState struct {
	users        []access.User
	sessions     []access.Session
	passkeys     []access.PasskeyCredential
	keys         []access.Key
	tokens       []access.OneTimeToken
	attributions []access.KeyAttribution
	failures     []account.FailureCount
	log          []account.LogEntry
	hashes       []string
}

func revealed(h access.Hash) string {
	if h.IsZero() {
		return ""
	}
	return h.Reveal()
}

// snapshot reads w's store, with the failure records of names.
func snapshot(t *testing.T, w *opWorld, names []string) storeState {
	t.Helper()
	ctx := t.Context()
	var st storeState
	users, err := w.mem.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	slices.SortFunc(users, func(a, b access.User) int { return cmp.Compare(a.ID, b.ID) })
	for _, u := range users {
		ss, err := w.mem.SessionsByUserID(ctx, u.ID)
		if err != nil {
			t.Fatalf("SessionsByUserID: %v", err)
		}
		slices.SortFunc(ss, func(a, b access.Session) int { return cmp.Compare(a.ID, b.ID) })
		for _, s := range ss {
			st.hashes = append(st.hashes, revealed(s.TokenHash))
			s.TokenHash = access.Hash{}
			st.sessions = append(st.sessions, s)
		}
		st.passkeys = append(st.passkeys, passkeysOf(t, w.mem, u.ID)...)
		st.hashes = append(st.hashes, revealed(u.PasswordHash))
		u.PasswordHash = access.Hash{}
		st.users = append(st.users, u)
	}
	slices.SortFunc(st.passkeys, func(a, b access.PasskeyCredential) int { return cmp.Compare(a.ID, b.ID) })
	keys, err := w.mem.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	slices.SortFunc(keys, func(a, b access.Key) int { return cmp.Compare(a.ID, b.ID) })
	for _, k := range keys {
		st.hashes = append(st.hashes, revealed(k.KeyHash))
		k.KeyHash = access.Hash{}
		st.keys = append(st.keys, k)
	}
	toks, err := w.mem.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeSetup, access.PurposeInvite, access.PurposeRecovery}, time.Time{})
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	slices.SortFunc(toks, func(a, b access.OneTimeToken) int { return cmp.Compare(revealed(a.Hash), revealed(b.Hash)) })
	for _, tok := range toks {
		st.hashes = append(st.hashes, revealed(tok.Hash))
		tok.Hash = access.Hash{}
		st.tokens = append(st.tokens, tok)
	}
	if st.attributions, err = w.mem.ListKeyAttributions(ctx); err != nil {
		t.Fatalf("ListKeyAttributions: %v", err)
	}
	st.log = logOf(t, w.mem)
	for _, name := range names {
		for _, m := range []access.Method{access.MethodPassword, access.MethodPasskey} {
			for _, trusted := range []bool{false, true} {
				rec, found, err := w.mem.AuthFailure(ctx, account.FailureRef{Name: account.FailureName(w.svc, name), Method: m, Trusted: trusted})
				if err != nil {
					t.Fatalf("AuthFailure: %v", err)
				}
				if found {
					st.failures = append(st.failures, rec)
				}
			}
		}
	}
	return st
}

// stateDiff names each kind of record that differs between two states,
// with the first differing element of each.
func stateDiff(a, b storeState) []string {
	var out []string
	add := func(kind string, x, y any) {
		xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
		if xv.Len() != yv.Len() {
			out = append(out, fmt.Sprintf("%s: %d records, then %d", kind, xv.Len(), yv.Len()))
			return
		}
		for i := range xv.Len() {
			if !reflect.DeepEqual(xv.Index(i).Interface(), yv.Index(i).Interface()) {
				out = append(out, fmt.Sprintf("%s[%d]: %+v, then %+v", kind, i, xv.Index(i).Interface(), yv.Index(i).Interface()))
				return
			}
		}
	}
	add("users", a.users, b.users)
	add("sessions", a.sessions, b.sessions)
	add("passkeys", a.passkeys, b.passkeys)
	add("keys", a.keys, b.keys)
	add("tokens", a.tokens, b.tokens)
	add("attributions", a.attributions, b.attributions)
	add("failures", a.failures, b.failures)
	add("log", a.log, b.log)
	add("hashes", a.hashes, b.hashes)
	return out
}

// txScenario is one multi-record operation. prep arranges it in w and
// returns the call, and done checks the state a committed call leaves.
type txScenario struct {
	prep  func(t *testing.T, w *opWorld) (call func(ctx context.Context) error, done func(t *testing.T))
	name  string
	world worldOptions
	// counted names the user whose current password the call checks: its
	// first write, the counted attempt, commits on its own before the
	// compare, so a later failure leaves that one count.
	counted string
}

// lockBoth stores a locked password record of u in both trust contexts.
func lockBoth(t *testing.T, w *opWorld, u *access.User) {
	t.Helper()
	for _, trusted := range []bool{false, true} {
		f := account.FailureCount{
			Name: account.FailureName(w.svc, u.Username), Method: access.MethodPassword, Trusted: trusted,
			Count: account.FailureCap, Locked: true, LockedAt: time.Now().Truncate(time.Millisecond),
		}
		if err := w.mem.PutAuthFailure(t.Context(), f); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
}

// burden gives u two more sessions, a key that issued an invite, a
// recovery token and both password locks, so a repair has every kind of
// record to write.
func burden(t *testing.T, w *opWorld, u *access.User) {
	t.Helper()
	putSession(t, w.mem, liveSession(t, u))
	putSession(t, w.mem, liveSession(t, u))
	k := w.storedKey(t, u, "read")
	seedToken(t, w.mem, access.PurposeInvite, 0, k.ID, time.Hour)
	seedToken(t, w.mem, access.PurposeRecovery, u.ID, 0, time.Hour)
	lockBoth(t, w, u)
}

// usersKey is a key of root's carrying both permission scopes, minted
// out of band, with its principal.
func (w *opWorld) usersKey(t *testing.T) minted {
	t.Helper()
	return w.mint(t, account.OutOfBand("socket"), w.root.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeUsers, scopeKeys}})
}

func (w *opWorld) attributionsOf(t *testing.T, userID int64) []access.AttributionAction {
	t.Helper()
	all, err := w.mem.ListKeyAttributions(t.Context())
	if err != nil {
		t.Fatalf("ListKeyAttributions: %v", err)
	}
	var out []access.AttributionAction
	for _, a := range all {
		if a.UserID == userID {
			out = append(out, a.Action)
		}
	}
	return out
}

// repaired checks the state a completed recovery of u leaves with no
// options: no session, key or recovery token, and no failure record.
func repaired(t *testing.T, w *opWorld, u *access.User) {
	t.Helper()
	if n := len(sessionsOf(t, w.mem, u.ID)); n != 0 {
		t.Errorf("%d sessions remain", n)
	}
	if n := len(keysOf(t, w.mem, u.ID)); n != 0 {
		t.Errorf("%d keys remain", n)
	}
	if _, found := record(t, w.mem, w.svc, u.Username, false); found {
		t.Error("the failure record remains")
	}
	tokensGone(t, w, func(tok access.OneTimeToken) bool { return tok.Subject == u.ID || tok.IssuedByKey != 0 })
}

// tokensGone fails for every live invite or recovery token gone matches.
func tokensGone(t *testing.T, w *opWorld, gone func(access.OneTimeToken) bool) {
	t.Helper()
	toks, err := w.mem.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeRecovery, access.PurposeInvite}, time.Now())
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	for _, tok := range toks {
		if gone(tok) {
			t.Errorf("token %s for %d issued by key %d remains", tok.Purpose, tok.Subject, tok.IssuedByKey)
		}
	}
}

func txScenarios() []txScenario {
	recoverySession := func(t *testing.T, w *opWorld, a account.Actor) access.Principal {
		tok, err := w.svc.IssueRecovery(t.Context(), a, w.alice.ID, 0)
		if err != nil {
			t.Fatalf("IssueRecovery = %v", err)
		}
		rec, err := w.svc.StartRecovery(t.Context(), localClient, tok.Plaintext)
		if err != nil {
			t.Fatalf("StartRecovery = %v", err)
		}
		return w.principal(t, rec.Issued.Token)
	}
	completeWithPassword := func(issuer func(t *testing.T, w *opWorld) account.Actor) func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
		return func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			rp := recoverySession(t, w, issuer(t, w))
			burden(t, w, w.alice)
			return func(ctx context.Context) error {
					return w.svc.RecoverWithPassword(ctx, rp, access.NewSecret(recoveredPassword), account.RecoverOptions{})
				}, func(t *testing.T) {
					repaired(t, w, w.alice)
					if !w.verifies(t, w.alice, recoveredPassword) {
						t.Error("the recovered password does not verify")
					}
				}
		}
	}
	completeWithPasskey := func(issuer func(t *testing.T, w *opWorld) account.Actor) func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
		return func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			rp := recoverySession(t, w, issuer(t, w))
			burden(t, w, w.alice)
			pc, err := w.svc.RecoverPasskeyBegin(t.Context(), rp, w.origin)
			if err != nil {
				t.Fatalf("RecoverPasskeyBegin = %v", err)
			}
			body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
			return func(ctx context.Context) error {
					return w.svc.RecoverPasskeyFinish(ctx, rp, pc.ID, bytes.NewReader(body), account.RecoverOptions{})
				}, func(t *testing.T) {
					repaired(t, w, w.alice)
					if n := len(passkeysOf(t, w.mem, w.alice.ID)); n != 2 {
						t.Errorf("alice holds %d passkeys, want the enrolled one beside her first", n)
					}
				}
		}
	}
	outOfBand := func(*testing.T, *opWorld) account.Actor { return account.OutOfBand("socket") }
	byKey := func(t *testing.T, w *opWorld) account.Actor { return account.As(w.usersKey(t).p) }
	keyAttributed := func(action access.AttributionAction, check func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T))) func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
		return func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			call, done := check(t, w)
			before := len(w.attributionsOf(t, w.alice.ID))
			return call, func(t *testing.T) {
				done(t)
				if got := w.attributionsOf(t, w.alice.ID); len(got) != before+1 || got[len(got)-1] != action {
					t.Errorf("alice's attributions = %v, want one more, %s", got, action)
				}
			}
		}
	}
	scoped := worldOptions{scoped: true}
	revokingKeys := worldOptions{rules: func(r *account.Rules) { r.RevokeKeysOnCredentialChange = true }}
	return []txScenario{
		{name: "setup_password", world: worldOptions{empty: true}, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			return func(ctx context.Context) error {
					_, err := w.svc.SetupWithPassword(ctx, localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)})
					return err
				}, func(t *testing.T) {
					u, found, err := w.mem.UserByUsername(t.Context(), "owner")
					if err != nil || !found || u.Role != access.RoleAdmin || len(sessionsOf(t, w.mem, u.ID)) != 1 {
						t.Errorf("owner = %+v, %t, %v; want an admin with one session", u, found, err)
					}
				}
		}},
		{name: "setup_passkey", world: worldOptions{empty: true}, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			id, body := w.beginSetup(t, access.Secret{}, accesstest.NewPasskeyDevice(t))
			return func(ctx context.Context) error {
					_, err := w.svc.SetupPasskeyFinish(ctx, localClient, id, bytes.NewReader(body))
					return err
				}, func(t *testing.T) {
					u, found, _ := w.mem.UserByUsername(t.Context(), "owner")
					if !found || len(passkeysOf(t, w.mem, u.ID)) != 1 || len(sessionsOf(t, w.mem, u.ID)) != 1 {
						t.Error("owner is missing, or lacks its passkey or session")
					}
				}
		}},
		{name: "invite_acceptance", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			inv, err := w.svc.CreateInvite(t.Context(), w.recent(t, w.root), access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			return acceptCall(w, inv), acceptedCheck(w, inv)
		}},
		{name: "recovery_start", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			tok, err := w.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), w.alice.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery = %v", err)
			}
			return startCall(w, tok), startedCheck(w, tok)
		}},
		{name: "recover_with_password", prep: completeWithPassword(outOfBand)},
		{name: "recover_passkey_finish", prep: completeWithPasskey(outOfBand)},
		{name: "recover_out_of_band", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			burden(t, w, w.alice)
			return func(ctx context.Context) error {
					return w.svc.RecoverOutOfBand(ctx, account.OutOfBand("socket"), w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
				}, func(t *testing.T) {
					repaired(t, w, w.alice)
					if !w.verifies(t, w.alice, recoveredPassword) {
						t.Error("the recovered password does not verify")
					}
				}
		}},
		{name: "set_password_revoking_keys", counted: "alice", world: revokingKeys, prep: setPasswordRevoking(goodPassword)},
		{name: "first_password_revoking_keys", world: revokingKeys, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			u := storedUser(t, w.mem, w.alice.ID)
			u.PasswordHash = access.Hash{}
			if err := w.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			return setPasswordRevoking("")(t, w)
		}},
		{name: "oidc_intent_link_sso_governed", world: worldOptions{rules: func(r *account.Rules) { r.SSOGoverned = true }}, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.alice)
			flow, claims := w.rig.sessionFlow(t, oidc.IntentLink, w.alice, p.SessionID)
			return func(ctx context.Context) error {
					_, err := w.svc.OIDCComplete(ctx, localClient, flow, claims)
					return err
				},
				migratedCheck(w)
		}},
		{name: "link_pending_oidc_sso_governed", world: worldOptions{rules: func(r *account.Rules) { r.SSOGoverned = true }}, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.alice)
			return func(ctx context.Context) error {
				_, _, err := w.svc.LinkPendingOIDC(ctx, p, account.PendingLink{Identity: w.rig.identity()})
				return err
			}, migratedCheck(w)
		}},
		{name: "remove_second_last_passkey", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.alice)
			id := passkeysOf(t, w.mem, w.alice.ID)[0].ID
			return func(ctx context.Context) error { return w.svc.RemovePasskey(ctx, p, id) },
				func(t *testing.T) {
					if n := len(passkeysOf(t, w.mem, w.alice.ID)); n != 0 {
						t.Errorf("alice holds %d passkeys", n)
					}
				}
		}},
		{name: "update_user_role_and_enabled", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.root)
			putSession(t, w.mem, liveSession(t, w.alice))
			w.storedKey(t, w.alice, "read")
			return func(ctx context.Context) error {
					_, err := w.svc.UpdateUser(ctx, p, w.alice.ID, account.UserChange{Role: new(access.RoleAdmin), Enabled: new(false)})
					return err
				}, func(t *testing.T) {
					u := storedUser(t, w.mem, w.alice.ID)
					if u.Role != access.RoleAdmin || u.Enabled || len(sessionsOf(t, w.mem, u.ID)) != 0 || len(keysOf(t, w.mem, u.ID)) != 0 {
						t.Errorf("alice = %s, enabled %t, with sessions or keys left", u.Role, u.Enabled)
					}
				}
		}},
		{name: "delete_user", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.root)
			burden(t, w, w.alice)
			return func(ctx context.Context) error { return w.svc.DeleteUser(ctx, p, w.alice.ID) },
				func(t *testing.T) {
					if stored(t, w.fixture, w.alice.ID) != nil || len(sessionsOf(t, w.mem, w.alice.ID)) != 0 || len(keysOf(t, w.mem, w.alice.ID)) != 0 {
						t.Error("alice, a session or a key of hers remains")
					}
					tokensGone(t, w, func(tok access.OneTimeToken) bool { return tok.Subject == w.alice.ID || tok.IssuedByKey != 0 })
				}
		}},
		{name: "create_api_key_rotating", prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			p := w.recent(t, w.root)
			before := storedSession(t, w.mem, w.root.ID, p.SessionID)
			return func(ctx context.Context) error {
					_, err := w.svc.CreateAPIKey(ctx, account.As(p), w.root.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}})
					return err
				}, func(t *testing.T) {
					after := storedSession(t, w.mem, w.root.ID, p.SessionID)
					if len(keysOf(t, w.mem, w.root.ID)) != 1 || after.TokenHash.Equal(before.TokenHash) {
						t.Error("want one key and the session rotated")
					}
				}
		}},
		{name: "revoke_api_key_subtree", world: scoped, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			parent := w.usersKey(t)
			child := w.mint(t, account.As(parent.p), w.root.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeUsers}})
			if _, err := w.svc.CreateInvite(t.Context(), child.p, access.RoleUser, 0); err != nil {
				t.Fatalf("CreateInvite from the child = %v", err)
			}
			if _, err := w.svc.IssueRecovery(t.Context(), account.As(parent.p), w.alice.ID, 0); err != nil {
				t.Fatalf("IssueRecovery from the parent = %v", err)
			}
			p := w.recent(t, w.root)
			return func(ctx context.Context) error { return w.svc.RevokeAPIKey(ctx, p, parent.key.ID) },
				func(t *testing.T) {
					if n := len(keysOf(t, w.mem, w.root.ID)); n != 0 {
						t.Errorf("%d keys remain", n)
					}
					tokensGone(t, w, func(tok access.OneTimeToken) bool { return tok.IssuedByKey != 0 })
				}
		}},
		{name: "key_issued_invite_acceptance", world: scoped, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			inv, err := w.svc.CreateInvite(t.Context(), w.usersKey(t).p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite from the key = %v", err)
			}
			done := acceptedCheck(w, inv)
			return acceptCall(w, inv), func(t *testing.T) {
				done(t)
				u, _, _ := w.mem.UserByUsername(t.Context(), "invitee")
				if got := w.attributionsOf(t, u.ID); !slices.Equal(got, []access.AttributionAction{access.AttributionInviteAccepted}) {
					t.Errorf("invitee's attributions = %v, want invite_accepted", got)
				}
			}
		}},
		{name: "key_create_user", world: scoped, prep: func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			k := w.usersKey(t)
			return func(ctx context.Context) error {
					_, err := w.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "made", Password: access.NewSecret(goodPassword)})
					return err
				}, func(t *testing.T) {
					u, found, _ := w.mem.UserByUsername(t.Context(), "made")
					if !found || !slices.Equal(w.attributionsOf(t, u.ID), []access.AttributionAction{access.AttributionCreated}) {
						t.Error("want the user made, with one created attribution")
					}
				}
		}},
		{name: "key_disable_user", world: scoped, prep: keyAttributed(access.AttributionDisabled, func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			k := w.usersKey(t)
			putSession(t, w.mem, liveSession(t, w.alice))
			return func(ctx context.Context) error {
					_, err := w.svc.UpdateUser(ctx, k.p, w.alice.ID, account.UserChange{Enabled: new(false)})
					return err
				}, func(t *testing.T) {
					if u := storedUser(t, w.mem, w.alice.ID); u.Enabled || len(sessionsOf(t, w.mem, u.ID)) != 0 {
						t.Error("want alice disabled with no session")
					}
				}
		})},
		{name: "key_issued_recovery_start", world: scoped, prep: keyAttributed(access.AttributionRecoveryStarted, func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
			tok, err := w.svc.IssueRecovery(t.Context(), byKey(t, w), w.alice.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery from the key = %v", err)
			}
			return startCall(w, tok), startedCheck(w, tok)
		})},
		{name: "key_issued_recover_with_password", world: scoped, prep: keyAttributed(access.AttributionRecovered, completeWithPassword(byKey))},
		{name: "key_issued_recover_passkey_finish", world: scoped, prep: keyAttributed(access.AttributionRecovered, completeWithPasskey(byKey))},
	}
}

// setPasswordRevoking is SetPassword from a recent session of alice, who
// holds another session and a key, proving current.
func setPasswordRevoking(current string) func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
	return func(t *testing.T, w *opWorld) (func(context.Context) error, func(*testing.T)) {
		p := w.recent(t, w.alice)
		putSession(t, w.mem, liveSession(t, w.alice))
		w.storedKey(t, w.alice, "read")
		return func(ctx context.Context) error { _, err := w.setPassword(ctx, p, current, newPassword); return err },
			func(t *testing.T) {
				if !w.verifies(t, w.alice, newPassword) || len(keysOf(t, w.mem, w.alice.ID)) != 0 || len(sessionsOf(t, w.mem, w.alice.ID)) != 1 {
					t.Error("want the new password, no key and only the rotated session")
				}
			}
	}
}

func acceptCall(w *opWorld, inv account.IssuedToken) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := w.svc.AcceptInvitePassword(ctx, localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "invitee", Password: access.NewSecret(goodPassword)})
		return err
	}
}

func acceptedCheck(w *opWorld, inv account.IssuedToken) func(*testing.T) {
	return func(t *testing.T) {
		u, found, _ := w.mem.UserByUsername(t.Context(), "invitee")
		if !found || len(sessionsOf(t, w.mem, u.ID)) != 1 {
			t.Error("want invitee created with one session")
		}
		if _, found, _ := w.mem.OneTimeTokenByHash(t.Context(), hashOf(inv)); found {
			t.Error("the invite remains")
		}
	}
}

func startCall(w *opWorld, tok account.IssuedToken) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := w.svc.StartRecovery(ctx, localClient, tok.Plaintext)
		return err
	}
}

func startedCheck(w *opWorld, tok account.IssuedToken) func(*testing.T) {
	return func(t *testing.T) {
		if n := len(recoverySessions(t, w.mem, w.alice.ID)); n != 1 {
			t.Errorf("alice holds %d recovery sessions, want 1", n)
		}
		if _, found, _ := w.mem.OneTimeTokenByHash(t.Context(), hashOf(tok)); found {
			t.Error("the recovery token remains")
		}
	}
}

// migratedCheck is an SSOGoverned link's state: alice linked, with no
// password and no passkey left.
func migratedCheck(w *opWorld) func(*testing.T) {
	return func(t *testing.T) {
		u := storedUser(t, w.mem, w.alice.ID)
		if u.OIDC != w.rig.identity() || !u.PasswordHash.IsZero() || len(passkeysOf(t, w.mem, u.ID)) != 0 {
			t.Errorf("alice = link %+v, password held %t, %d passkeys; want linked with neither left", u.OIDC, !u.PasswordHash.IsZero(), len(passkeysOf(t, w.mem, u.ID)))
		}
	}
}

func TestTransactionsFailNth(t *testing.T) {
	t.Parallel()
	for _, sc := range txScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			for _, panics := range []bool{false, true} {
				n := 1
				for ; ; n++ {
					w := newOpWorld(t, sc.world)
					call, done := sc.prep(t, w)
					names := []string{"owner", "root", "alice", "invitee", "made"}
					before := snapshot(t, w, names)
					mark := len(w.events.all())
					var err error
					if panics {
						w.fs.panicWrite(n)
						if !crash(func() { err = call(t.Context()) }) {
							w.fs.panicWrite(0)
							if err != nil {
								t.Fatalf("write %d armed to panic: %s = %v", n, sc.name, err)
							}
							done(t)
							break
						}
						w.fs.panicWrite(0)
					} else {
						w.fs.failWrite(n)
						err = call(t.Context())
						w.fs.failWrite(0)
						if err == nil {
							done(t)
							break
						}
						if !errors.Is(err, access.ErrAuthBackend) {
							t.Fatalf("write %d failing: %s = %v, want ErrAuthBackend", n, sc.name, err)
						}
					}
					after := snapshot(t, w, names)
					if sc.counted != "" {
						after.failures = uncounted(t, w, sc.counted, n, after.failures)
					}
					if diff := stateDiff(before, after); len(diff) != 0 {
						t.Errorf("write %d %s: the store changed: %v", n, mode(panics), diff)
					}
					if evs := w.events.all()[mark:]; len(evs) != 0 {
						t.Errorf("write %d %s: %d events fired, first %s", n, mode(panics), len(evs), evs[0].Kind)
					}
				}
				if n < 2 {
					t.Errorf("%s %s committed with its first write armed to fail", sc.name, mode(panics))
				}
			}
		})
	}
}

// uncounted is failures with name's untrusted password record taken out
// after checking that the call's counted attempt left it at one, when the
// write armed at n came after that count's own Update.
func uncounted(t *testing.T, w *opWorld, name string, n int, failures []account.FailureCount) []account.FailureCount {
	t.Helper()
	ref := account.FailureRef{Name: account.FailureName(w.svc, name), Method: access.MethodPassword}
	i := slices.IndexFunc(failures, func(f account.FailureCount) bool { return f.FailureRef == ref })
	switch {
	case n == 1 && i >= 0:
		t.Errorf("write 1, the count, failed and left %s's record at %d", name, failures[i].Count)
	case n > 1 && (i < 0 || failures[i].Count != 1):
		t.Errorf("write %d failed after the count committed; want %s's record at one, got %v", n, name, failures)
	}
	if i >= 0 && n > 1 {
		return slices.Delete(slices.Clone(failures), i, i+1)
	}
	return failures
}

func mode(panics bool) string {
	if panics {
		return "panicking"
	}
	return "failing"
}

func TestLogRollsBackWithChange(t *testing.T) {
	t.Parallel()
	rows := map[string]operation{}
	for _, op := range operations() {
		rows[op.name] = op
	}
	// run arranges the named catalogue call by root's recent session, with
	// one more session of root's to revoke, arms fs and makes the call.
	run := func(t *testing.T, name string, arm func(fs *faultStore)) (*opWorld, storeState, int, error) {
		t.Helper()
		w := newOpWorld(t, worldOptions{})
		p := w.actorFor(t, rows[name].class)
		putSession(t, w.mem, liveSession(t, w.root))
		call := rows[name].prep(t, w, p)
		before, mark := snapshot(t, w, nil), len(w.events.all())
		w.fs.resetRecord()
		arm(w.fs)
		err := call.run(t.Context())
		return w, before, mark, err
	}
	unchanged := func(t *testing.T, w *opWorld, before storeState, mark int, err error) {
		t.Helper()
		if !errors.Is(err, access.ErrAuthBackend) {
			t.Errorf("call = %v, want access.ErrAuthBackend", err)
		}
		if diff := stateDiff(before, snapshot(t, w, nil)); len(diff) != 0 {
			t.Errorf("the store changed: %v", diff)
		}
		if evs := w.events.all()[mark:]; len(evs) != 0 {
			t.Errorf("%d events fired, first %s", len(evs), evs[0].Kind)
		}
	}
	appends := func(fs *faultStore) int {
		n := 0
		for _, c := range fs.recorded() {
			if c.name == "AppendLog" {
				n++
			}
		}
		return n
	}
	for _, name := range []string{"RevokeSession", "SetPassword", "CreateAPIKey"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, before, mark, err := run(t, name, func(fs *faultStore) { fs.failCall("AppendLog") })
			unchanged(t, w, before, mark, err)
		})
	}
	t.Run("second_append_of_SetPassword", func(t *testing.T) {
		t.Parallel()
		w, before, mark, err := run(t, "SetPassword", func(fs *faultStore) { fs.failCallNth("AppendLog", 2) })
		unchanged(t, w, before, mark, err)
		if n := appends(w.fs); n != 2 {
			t.Errorf("AppendLog calls = %d, want password_changed's then the failing user_sessions_revoked's", n)
		}
	})
	t.Run("own_write_fails", func(t *testing.T) {
		t.Parallel()
		w, before, mark, err := run(t, "RevokeSession", func(fs *faultStore) { fs.failCall("DeleteSession") })
		unchanged(t, w, before, mark, err)
		if n := appends(w.fs); n != 0 {
			t.Errorf("AppendLog calls after fn's own write failed = %d, want 0", n)
		}
	})
}
