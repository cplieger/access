package account_test

import (
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// raceEnv is one row's world: an admin A whose session-minted root P
// carries the operation's scope S, and K, minted by P with S, expiring at
// T an hour after the row starts. The operation acts through K; a second
// admin B makes the owner and target changes.
type raceEnv struct {
	f      *fixture
	fs     *faultStore
	admin  *access.User
	boss   *access.User
	alice  *access.User     // a RoleUser, the target of the user writes
	pr     access.Principal // A's session
	bp     access.Principal // B's session
	parent minted           // P
	k      minted           // K
	target minted           // alice's key, for RevokeAnyAPIKey
	t      time.Time        // K's ExpiresAt
	// lastChild and childPrincipal are the key the mint row minted.
	lastChild      account.CreatedKey
	childPrincipal access.Principal
	// issued is the invite the invite row minted or the acceptance row
	// redeems; spare is another invite K issued.
	issued account.IssuedToken
	spare  account.IssuedToken
}

// countEvents counts the recorded events of kind that match.
func countEvents(l *eventLog, kind account.EventKind, match func(account.Event) bool) int {
	n := 0
	for _, ev := range eventsOf(l, kind) {
		n += b2i(match(ev))
	}
	return n
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// keyWrite is one key-authorized write of the matrix.
type keyWrite struct {
	setup func(t *testing.T, e *raceEnv) // before the race, when set
	run   func(t *testing.T, e *raceEnv) error
	check func(t *testing.T, e *raceEnv, change int) // the write committed, then change did
	scope string
	name  string
	// produced counts what the write produced, so a change-first row can
	// assert it wrote and emitted nothing.
	produced func(t *testing.T, e *raceEnv) int
}

// keyChange is one change that ends K's authority, as its own Update or,
// for the expiry, as time passing.
type keyChange struct {
	run  func(t *testing.T, e *raceEnv) error
	name string
	n    int
}

var keyChanges = []keyChange{
	{n: 1, name: "revoke_key", run: func(t *testing.T, e *raceEnv) error {
		return e.f.svc.RevokeAPIKey(t.Context(), e.pr, e.k.key.ID)
	}},
	{n: 2, name: "revoke_parent", run: func(t *testing.T, e *raceEnv) error {
		return e.f.svc.RevokeAPIKey(t.Context(), e.pr, e.parent.key.ID)
	}},
	{n: 3, name: "expiry", run: func(_ *testing.T, e *raceEnv) error {
		time.Sleep(time.Until(e.t) + time.Second)
		return nil
	}},
	{n: 4, name: "descope", run: func(t *testing.T, e *raceEnv) error {
		return e.fs.descope(t.Context(), e.k.key.ID, e.k.scope())
	}},
	{n: 5, name: "disable_owner", run: func(t *testing.T, e *raceEnv) error {
		_, err := e.f.svc.UpdateUser(t.Context(), e.bp, e.admin.ID, account.UserChange{Enabled: new(false)})
		return err
	}},
	{n: 6, name: "delete_owner", run: func(t *testing.T, e *raceEnv) error {
		return e.f.svc.DeleteUser(t.Context(), e.bp, e.admin.ID)
	}},
	{n: 7, name: "demote_owner", run: func(t *testing.T, e *raceEnv) error {
		_, err := e.f.svc.UpdateUser(t.Context(), e.bp, e.admin.ID, account.UserChange{Role: new(access.RoleUser)})
		return err
	}},
}

// promoteTarget is change 8, the target's side: B promotes alice to admin
// in its own Update. A write that deleted alice first leaves no one to
// promote, so ErrNotFound there is the change committing after it.
var promoteTarget = keyChange{n: 8, name: "promote_target", run: func(t *testing.T, e *raceEnv) error {
	_, err := e.f.svc.UpdateUser(t.Context(), e.bp, e.alice.ID, account.UserChange{Role: new(access.RoleAdmin)})
	if errors.Is(err, account.ErrNotFound) && stored(t, e.f, e.alice.ID) == nil {
		return nil
	}
	return err
}}

// scope is the operation scope K was minted for: its first scope.
func (m minted) scope() string { return m.key.Scopes[0] }

func newRaceEnv(t *testing.T, scope string, policy account.Policy) *raceEnv {
	t.Helper()
	fs := newFaultStore()
	f := newFixture(t, keyOptions(options{store: fs, edit: func(c *account.Config) {
		c.CleanupInterval = 1000 * time.Hour
	}}, policy))
	e := &raceEnv{f: f, fs: fs, admin: mustUser(t, f.mem, "root", access.RoleAdmin), boss: mustUser(t, f.mem, "boss", access.RoleAdmin)}
	e.pr = f.sessionPrincipal(t, e.admin, time.Now())
	e.bp = f.sessionPrincipal(t, e.boss, time.Now())
	parentScopes := []string{scope, scopeKeys}
	if scope == scopeKeys {
		parentScopes = []string{scopeKeys, "read"}
	}
	e.parent = f.mint(t, account.As(e.pr), e.admin.ID, account.NewKey{Label: uniqueLabel(), Scopes: parentScopes})
	e.pr = f.sessionPrincipal(t, e.admin, time.Now())
	kScopes := []string{scope}
	if scope == scopeKeys {
		kScopes = []string{scopeKeys, "read"}
	}
	e.k = f.mint(t, account.As(e.parent.p), e.admin.ID, account.NewKey{Label: uniqueLabel(), Scopes: kScopes, ExpiresIn: time.Hour})
	e.t = e.k.key.ExpiresAt
	e.alice = mustUser(t, f.mem, "alice", access.RoleUser)
	e.target = f.mint(t, account.OutOfBand("admin-socket"), e.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}})
	return e
}

// childKey is the key the mint row produced, if stored.
func (e *raceEnv) childKey(t *testing.T) (access.Key, bool) {
	t.Helper()
	keys := keysOf(t, e.f.mem, e.admin.ID)
	i := slices.IndexFunc(keys, func(k access.Key) bool { return slices.Contains(k.LineageIDs, e.k.key.ID) && k.ID != e.k.key.ID })
	if i < 0 {
		return access.Key{}, false
	}
	return keys[i], true
}

// kTokens is every stored token K issued, expired ones included.
func (e *raceEnv) kTokens(t *testing.T) []access.OneTimeToken {
	t.Helper()
	all, err := e.f.mem.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeInvite}, time.Time{})
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	return slices.DeleteFunc(all, func(tok access.OneTimeToken) bool { return tok.IssuedByKey != e.k.key.ID })
}

func (e *raceEnv) aboutAlice(ev account.Event) bool { return ev.UserID == e.alice.ID }

// emittedByK is a write-first arm: the write emitted exactly one kind
// about alice, with K as its actor.
func (e *raceEnv) emittedByK(t *testing.T, kind account.EventKind) {
	t.Helper()
	if n := countEvents(e.f.events, kind, func(ev account.Event) bool { return e.aboutAlice(ev) && ev.Actor.KeyID == e.k.key.ID }); n != 1 {
		t.Errorf("%v events about alice by K = %d, want 1", kind, n)
	}
}

// promoted is change 8's write-first arm: B's promotion of alice committed
// after the write.
func (e *raceEnv) promoted(t *testing.T) {
	t.Helper()
	if u := stored(t, e.f, e.alice.ID); u == nil || u.Role != access.RoleAdmin {
		t.Errorf("after change 8 alice is %+v, want her stored as an admin", u)
	}
}

// attributed reports whether userID holds a record of action with K's path.
func (e *raceEnv) attributed(t *testing.T, userID int64, action access.AttributionAction) bool {
	t.Helper()
	return slices.ContainsFunc(attributionsOf(t, e.f, userID), func(a access.KeyAttribution) bool {
		return a.Action == action && slices.Equal(a.KeyLineage, e.k.key.LineageIDs)
	})
}

// mintOf is the CreateAPIKey row, minting a child of K with scopes.
func mintOf(scopes ...string) keyWrite {
	return keyWrite{
		name: "CreateAPIKey", scope: scopeKeys,
		run: func(t *testing.T, e *raceEnv) error {
			created, err := e.f.svc.CreateAPIKey(t.Context(), account.As(e.k.p), e.admin.ID, account.NewKey{Label: uniqueLabel(), Scopes: scopes, ExpiresIn: 30 * time.Minute})
			if err == nil {
				e.lastChild = created
			}
			return err
		},
		produced: func(t *testing.T, e *raceEnv) int {
			_, found := e.childKey(t)
			return countEvents(e.f.events, account.EventKeyMinted, func(ev account.Event) bool { return ev.Actor.KeyID == e.k.key.ID }) + b2i(found)
		},
		check: func(t *testing.T, e *raceEnv, change int) {
			child, found := e.childKey(t)
			switch change {
			case 1, 2, 5, 6:
				if found {
					t.Errorf("the child key %d survived change %d", child.ID, change)
				}
			case 3:
				e.childExpired(t)
			case 4, 7:
				if !found || !slices.Contains(child.LineageIDs, e.k.key.ID) {
					t.Errorf("after change %d the child is stored %t with path %v, want it kept under K", change, found, child.LineageIDs)
				}
			}
		},
	}
}

// inviteWrite is the CreateInvite row: K mints an invite, and its check is
// the token arms of each change.
var inviteWrite = keyWrite{
	name: "CreateInvite", scope: scopeUsers,
	run: func(t *testing.T, e *raceEnv) error {
		tok, err := e.f.svc.CreateInvite(t.Context(), e.k.p, access.RoleUser, 0)
		if err == nil {
			e.issued = tok
		}
		return err
	},
	produced: func(t *testing.T, e *raceEnv) int { return len(e.kTokens(t)) },
	check: func(t *testing.T, e *raceEnv, change int) {
		toks := e.kTokens(t)
		switch change {
		case 1, 2, 5, 6:
			if len(toks) != 0 {
				t.Errorf("after change %d K's invite is still stored", change)
			}
			return
		case 3:
			for _, c := range e.fs.recorded() {
				t.Errorf("store call %s (Update %d) between the commit and the expiry, want none", c.name, c.update)
			}
			if len(toks) != 1 || toks[0].ExpiresAt.After(e.t) {
				t.Errorf("after the expiry K's tokens are %+v, want one expiring with K", toks)
			}
		case 4, 7:
			if len(toks) != 1 {
				t.Errorf("after change %d K's tokens are %d, want the invite it issued, refused at redemption", change, len(toks))
			}
		}
		if _, err := e.f.accept(t, e.issued.Plaintext, "joiner"); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("redeeming K's invite after change %d = %v, want access.ErrTokenInvalid", change, err)
		}
	},
}

var (
	mintWrite      = mintOf(scopeKeys, "read")
	revokeAnyWrite = keyWrite{
		name: "RevokeAnyAPIKey", scope: scopeAdmin,
		run: func(t *testing.T, e *raceEnv) error {
			return e.f.svc.RevokeAnyAPIKey(t.Context(), account.As(e.k.p), e.target.key.ID)
		},
		produced: func(t *testing.T, e *raceEnv) int {
			gone := !slices.Contains(keyIDs(keysOf(t, e.f.mem, e.target.key.UserID)), e.target.key.ID)
			return countEvents(e.f.events, account.EventKeyRevoked, func(ev account.Event) bool { return ev.KeyID == e.target.key.ID }) + b2i(gone)
		},
		check: func(t *testing.T, e *raceEnv, change int) {
			if slices.Contains(keyIDs(keysOf(t, e.f.mem, e.target.key.UserID)), e.target.key.ID) {
				t.Errorf("after change %d the revoked target key is stored again", change)
			}
		},
	}
	createUserWrite = keyWrite{
		name: "CreateUser", scope: scopeUsers,
		run: func(t *testing.T, e *raceEnv) error {
			_, err := e.f.svc.CreateUser(t.Context(), account.As(e.k.p), account.NewUser{Username: "newbie", Password: access.NewSecret(goodPassword)})
			return err
		},
		produced: func(t *testing.T, e *raceEnv) int {
			_, found, err := e.f.mem.UserByUsername(t.Context(), "newbie")
			if err != nil {
				t.Fatalf("UserByUsername: %v", err)
			}
			return b2i(found) + countEvents(e.f.events, account.EventUserCreated, func(ev account.Event) bool { return ev.Actor.KeyID == e.k.key.ID })
		},
		check: func(t *testing.T, e *raceEnv, change int) {
			u, found, err := e.f.mem.UserByUsername(t.Context(), "newbie")
			if err != nil || !found {
				t.Fatalf("after change %d the created user is gone: %v", change, err)
			}
			if !e.attributed(t, u.ID, access.AttributionCreated) {
				t.Errorf("after change %d the created user lacks its created record with K's path %v", change, e.k.key.LineageIDs)
			}
		},
	}
	disableUserWrite = keyWrite{
		name: "UpdateUser", scope: scopeUsers,
		run: func(t *testing.T, e *raceEnv) error {
			_, err := e.f.svc.UpdateUser(t.Context(), e.k.p, e.alice.ID, account.UserChange{Enabled: new(false)})
			return err
		},
		produced: func(t *testing.T, e *raceEnv) int {
			u := stored(t, e.f, e.alice.ID)
			return b2i(u == nil || !u.Enabled) + countEvents(e.f.events, account.EventUserDisabled, e.aboutAlice) + len(attributionsOf(t, e.f, e.alice.ID))
		},
		check: func(t *testing.T, e *raceEnv, change int) {
			if u := stored(t, e.f, e.alice.ID); u == nil || u.Enabled {
				t.Errorf("after change %d alice is %+v, want her stored and disabled", change, u)
			}
			if !e.attributed(t, e.alice.ID, access.AttributionDisabled) {
				t.Errorf("after change %d alice lacks the disabled record with K's path", change)
			}
			e.emittedByK(t, account.EventUserDisabled)
			if change == 8 {
				e.promoted(t)
			}
		},
	}
	deleteUserWrite = keyWrite{
		name: "DeleteUser", scope: scopeUsers,
		run: func(t *testing.T, e *raceEnv) error {
			return e.f.svc.DeleteUser(t.Context(), e.k.p, e.alice.ID)
		},
		produced: func(t *testing.T, e *raceEnv) int {
			return b2i(stored(t, e.f, e.alice.ID) == nil) + countEvents(e.f.events, account.EventUserDeleted, e.aboutAlice)
		},
		check: func(t *testing.T, e *raceEnv, change int) {
			if stored(t, e.f, e.alice.ID) != nil {
				t.Errorf("after change %d the deleted alice is stored", change)
			}
			e.emittedByK(t, account.EventUserDeleted)
		},
	}
)

// childExpired is the expiry arm: the child expires no later than K, so at
// T it fails currentKeyActor and the API-key verifier, and nothing was
// written for the expiry.
func (e *raceEnv) childExpired(t *testing.T) {
	t.Helper()
	child, found := e.childKey(t)
	if !found {
		t.Fatal("the child key is gone, want it stored and expired")
	}
	if child.ExpiresAt.After(e.t) {
		t.Errorf("child expires at %v, after K's %v", child.ExpiresAt, e.t)
	}
	for _, c := range e.fs.recorded() {
		t.Errorf("store call %s (Update %d) between the commit and the expiry, want none", c.name, c.update)
	}
	if _, err := e.f.bearer(t, e.lastChild.Plaintext); !errors.Is(err, access.ErrInvalidCredential) {
		t.Errorf("the expired child at the API-key verifier = %v, want ErrInvalidCredential", err)
	}
	if _, err := e.f.svc.CreateAPIKey(t.Context(), account.As(e.childPrincipal), e.admin.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}, ExpiresIn: time.Minute}); reason(err) != "key_not_current" {
		t.Errorf("a mint from the expired child = %v, want key_not_current", err)
	}
}

// raceRun runs w against ch in one serial order inside a synctest bubble,
// so the expiry is the bubble's clock.
func raceRun(t *testing.T, w keyWrite, ch keyChange, policy account.Policy, changeFirst bool, expect func(t *testing.T, e *raceEnv, err error)) {
	synctest.Test(t, func(t *testing.T) {
		e := newRaceEnv(t, w.scope, policy)
		if w.setup != nil {
			w.setup(t, e)
		}
		if changeFirst {
			before := w.produced(t, e)
			entered, release := e.fs.holdUpdate()
			done := make(chan error, 1)
			go func() { done <- w.run(t, e) }()
			<-entered
			if err := ch.run(t, e); err != nil {
				t.Fatalf("change %s = %v", ch.name, err)
			}
			release()
			err := <-done
			if after := w.produced(t, e); after != before && err != nil {
				t.Errorf("the refused %s wrote or emitted: %d before, %d after", w.name, before, after)
			}
			expect(t, e, err)
			return
		}
		if ch.n == 3 {
			writeThen(t, w, e, func() {
				if err := ch.run(t, e); err != nil {
					t.Fatalf("expiry = %v", err)
				}
			})
		} else {
			entered, release := e.fs.holdUpdate()
			changed := make(chan error, 1)
			go func() { changed <- ch.run(t, e) }()
			<-entered
			writeThen(t, w, e, func() {
				release()
				if err := <-changed; err != nil {
					t.Fatalf("change %s after %s = %v", ch.name, w.name, err)
				}
			})
		}
		expect(t, e, nil)
		w.check(t, e, ch.n)
	})
}

// writeThen runs w to its commit, records the minted child's principal,
// clears the store's record, then runs change.
func writeThen(t *testing.T, w keyWrite, e *raceEnv, change func()) {
	t.Helper()
	if err := w.run(t, e); err != nil {
		t.Fatalf("%s before the change = %v", w.name, err)
	}
	if w.name == mintWrite.name {
		var err error
		if e.childPrincipal, err = e.f.bearer(t, e.lastChild.Plaintext); err != nil {
			t.Fatalf("Authenticate(child) = %v", err)
		}
	}
	e.fs.resetRecord()
	change()
}

// committed is the write-first expectation: the write returned nil.
func committed(t *testing.T, _ *raceEnv, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("the write = %v, want it committed", err)
	}
}

func TestKeyWriteRaces(t *testing.T) {
	t.Parallel()
	refusal := func(n int) func(*testing.T, *raceEnv, error) {
		return func(t *testing.T, _ *raceEnv, err error) {
			t.Helper()
			switch n {
			case 7:
				if !errors.Is(err, account.ErrPolicyRefused) || reason(err) == "key_not_current" {
					t.Errorf("the write after its owner's demotion = %v, want the Policy's ErrPolicyRefused", err)
				}
			case 8:
				if reason(err) != "admin_target" {
					t.Errorf("the write after its target's promotion = %v, want admin_target", err)
				}
			default:
				if reason(err) != "key_not_current" {
					t.Errorf("the write after the change = %v, want key_not_current", err)
				}
			}
		}
	}
	policy := account.RolePolicy{KeysAdminOnly: true}
	for _, w := range []keyWrite{mintWrite, revokeAnyWrite, createUserWrite, disableUserWrite, deleteUserWrite, inviteWrite} {
		changes := keyChanges
		if w.name == "UpdateUser" || w.name == "DeleteUser" {
			changes = append(slices.Clone(keyChanges), promoteTarget)
		}
		for _, ch := range changes {
			t.Run(w.name+"/change_first/"+ch.name, func(t *testing.T) {
				t.Parallel()
				raceRun(t, w, ch, policy, true, refusal(ch.n))
			})
			t.Run(w.name+"/write_first/"+ch.name, func(t *testing.T) {
				t.Parallel()
				raceRun(t, w, ch, policy, false, committed)
			})
		}
	}
	demote := keyChanges[6]
	for order, changeFirst := range map[string]bool{"change_first": true, "write_first": false} {
		t.Run("CreateAPIKey/demotion_without_keys_admin_only/"+order, func(t *testing.T) {
			t.Parallel()
			raceRun(t, mintOf("read"), demote, account.RolePolicy{}, changeFirst, committed)
		})
	}
}

// acceptWrite is the AcceptInvitePassword row: the redemption of an invite
// K issued, beside a spare one K also issued.
var acceptWrite = keyWrite{
	name: "AcceptInvitePassword", scope: scopeUsers,
	setup: func(t *testing.T, e *raceEnv) {
		t.Helper()
		var err error
		if e.issued, err = e.f.svc.CreateInvite(t.Context(), e.k.p, access.RoleUser, 0); err != nil {
			t.Fatalf("CreateInvite from K = %v", err)
		}
		if e.spare, err = e.f.svc.CreateInvite(t.Context(), e.k.p, access.RoleUser, 0); err != nil {
			t.Fatalf("CreateInvite from K = %v", err)
		}
	},
	run: func(t *testing.T, e *raceEnv) error {
		_, err := e.f.accept(t, e.issued.Plaintext, "joiner")
		return err
	},
	produced: func(t *testing.T, e *raceEnv) int {
		_, found, err := e.f.mem.UserByUsername(t.Context(), "joiner")
		if err != nil {
			t.Fatalf("UserByUsername: %v", err)
		}
		return b2i(found) + len(eventsOf(e.f.events, account.EventUserCreated)) + len(eventsOf(e.f.events, account.EventSignedIn))
	},
	check: func(t *testing.T, e *raceEnv, change int) {
		u, found, err := e.f.mem.UserByUsername(t.Context(), "joiner")
		if err != nil || !found {
			t.Fatalf("after change %d the invited user is gone: %v", change, err)
		}
		if !slices.ContainsFunc(attributionsOf(t, e.f, u.ID), func(a access.KeyAttribution) bool {
			return a.Action == access.AttributionInviteAccepted && a.KeyLineage[len(a.KeyLineage)-1] == e.k.key.ID
		}) {
			t.Errorf("after change %d the invited user lacks its invite_accepted record ending with K", change)
		}
		if countEvents(e.f.events, account.EventUserCreated, func(ev account.Event) bool { return ev.UserID == u.ID && ev.KeyID == e.k.key.ID }) != 1 {
			t.Errorf("EventUserCreated for the invited user does not name K")
		}
		left := len(e.kTokens(t))
		switch change {
		case 1, 2, 5, 6:
			if left != 0 {
				t.Errorf("after change %d K's spare invite is still stored", change)
			}
		default:
			if left != 1 {
				t.Errorf("after change %d K holds %d tokens, want the spare", change, left)
			}
		}
	},
}

func TestKeyConsumptionRaces(t *testing.T) {
	t.Parallel()
	refused := func(t *testing.T, e *raceEnv, err error) {
		t.Helper()
		if !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the redemption after the change = %v, want access.ErrTokenInvalid", err)
		}
		if _, found, _ := e.f.mem.UserByUsername(t.Context(), "joiner"); found {
			t.Error("the refused redemption created its user")
		}
		if _, found, _ := e.f.mem.OneTimeTokenByHash(t.Context(), access.NewHash(access.HexSHA256(e.issued.Plaintext.Reveal()))); found {
			t.Error("the refused invite is still stored")
		}
	}
	policy := account.RolePolicy{KeysAdminOnly: true}
	for _, ch := range keyChanges {
		t.Run("AcceptInvitePassword/change_first/"+ch.name, func(t *testing.T) {
			t.Parallel()
			raceRun(t, acceptWrite, ch, policy, true, refused)
		})
		t.Run("AcceptInvitePassword/accept_first/"+ch.name, func(t *testing.T) {
			t.Parallel()
			raceRun(t, acceptWrite, ch, policy, false, committed)
		})
	}
}
