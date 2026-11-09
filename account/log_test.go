package account_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/printcheck"
	"github.com/cplieger/access/oidc"
)

// wholeLog is a LogRange Limit no test log reaches.
const wholeLog = 1 << 20

// logOf is every entry s holds, in ascending Seq.
func logOf(t testing.TB, s account.Store) []account.LogEntry {
	t.Helper()
	entries, err := s.ListLog(t.Context(), account.LogRange{Limit: wholeLog})
	if err != nil {
		t.Fatalf("ListLog: %v", err)
	}
	return entries
}

// logSince is every entry s holds above the last of before.
func logSince(t testing.TB, s account.Store, before []account.LogEntry) []account.LogEntry {
	t.Helper()
	var after uint64
	if len(before) > 0 {
		after = before[len(before)-1].Event.Seq
	}
	entries, err := s.ListLog(t.Context(), account.LogRange{AfterSeq: after, Limit: wholeLog})
	if err != nil {
		t.Fatalf("ListLog: %v", err)
	}
	return entries
}

// sessionClass is the set of kinds in the session class: sign-ins, step-ups
// and session revocations.
var sessionClass = []account.EventKind{account.EventSignedIn, account.EventSteppedUp, account.EventSessionRevoked}

func classOf(k account.EventKind) account.LogClass {
	if slices.Contains(sessionClass, k) {
		return account.LogClassSession
	}
	return account.LogClassChange
}

// stateVariants are catalogued operations run on a stored state their
// catalogue call does not reach, for the kinds only that state produces.
func stateVariants() []operation {
	return []operation{
		{name: "UpdateUser_enable", class: classManageUsers, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			target := w.user(t)
			target.Enabled = false
			if err := w.mem.UpdateUser(t.Context(), target); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.svc.UpdateUser(ctx, p, target.ID, account.UserChange{Enabled: new(true)})
					return err
				},
				want: events(account.Event{Kind: account.EventUserEnabled, UserID: target.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "SetPassword_first", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			u := mustUser(t, w.mem, w.name("nopassword"), access.RoleUser)
			q := w.recent(t, u)
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.svc.SetPassword(ctx, localClient, q, access.Secret{}, access.NewSecret(newPassword))
					return err
				},
				want: events(account.Event{Kind: account.EventPasswordSet, UserID: u.ID, Method: access.MethodPassword, Actor: actorOf(q)}),
			}
		}},
	}
}

func TestLogMatchesEventsEveryOperation(t *testing.T) {
	t.Parallel()
	for _, op := range slices.Concat(operations(), stateVariants()) {
		if op.readOnly {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty, rules: op.rules})
			call := op.prep(t, w, w.actorFor(t, op.class))
			mark, before := len(w.events.all()), logOf(t, w.mem)
			start := time.Now().Truncate(time.Millisecond)
			if err := call.run(t.Context()); err != nil {
				t.Fatalf("%s = %v", op.name, err)
			}
			end := time.Now()
			got := w.events.all()[mark:]
			if g, want := comparableEvents(t, got), comparableEvents(t, withAt(call.want())); !reflect.DeepEqual(g, want) {
				t.Errorf("%s emitted\n%+v\nwant\n%+v", op.name, g, want)
			}
			entries := logSince(t, w.mem, before)
			if len(entries) != len(got) {
				t.Fatalf("%s appended %d entries for %d events:\n%+v", op.name, len(entries), len(got), entries)
			}
			for i := range entries {
				e, ev := &entries[i], got[i]
				if ev.Seq == 0 || !reflect.DeepEqual(e.Event, ev) {
					t.Errorf("entry %d's Event = %+v, want the event OnEvent received, %+v, with its Seq", i, e.Event, ev)
				}
				if want := classOf(ev.Kind); e.Class != want {
					t.Errorf("entry %d (%s) class = %q, want %q", i, ev.Kind, e.Class, want)
				}
				if e.At.Before(start) || e.At.After(end) || !e.At.Equal(e.At.Truncate(time.Millisecond)) {
					t.Errorf("entry %d At = %v, want the call's clock at millisecond precision, in [%v, %v]", i, e.At, start, end)
				}
			}
		})
	}
	for _, op := range slices.Concat(operations(), policyVariants()) {
		for _, refused := range op.asks {
			t.Run(op.name+"_refused_"+string(refused), func(t *testing.T) {
				t.Parallel()
				pol := &gatePolicy{}
				w := newOpWorld(t, worldOptions{empty: op.empty, policy: pol, rules: op.rules})
				call := op.prep(t, w, w.actorFor(t, op.class))
				before := logOf(t, w.mem)
				pol.arm(refused)
				if err := call.run(t.Context()); err == nil {
					t.Fatalf("%s with %s refused = nil, want its refusal", op.name, refused)
				}
				if after := logOf(t, w.mem); !reflect.DeepEqual(after, before) {
					t.Errorf("%s refused changed the log:\n%+v\nwant\n%+v", op.name, after, before)
				}
			})
		}
	}
}

// shown is the actor display data an entry carries.
type shown struct{ label, userAgent, keySuffix string }

func shownOf(e *account.LogEntry) shown {
	return shown{e.ActorLabel, e.ActorUserAgent, e.ActorKeySuffix}
}

// records is the display data of every stored session and key, by ID.
type records struct {
	sessions map[string]shown
	keys     map[int64]shown
}

func recordsOf(t *testing.T, s account.Store) records {
	t.Helper()
	ctx := t.Context()
	r := records{sessions: map[string]shown{}, keys: map[int64]shown{}}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for i := range users {
		ss, err := s.SessionsByUserID(ctx, users[i].ID)
		if err != nil {
			t.Fatalf("SessionsByUserID: %v", err)
		}
		for j := range ss {
			r.sessions[ss[j].ID] = shown{label: ss[j].Label, userAgent: ss[j].UserAgent}
		}
	}
	keys, err := s.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	for i := range keys {
		r.keys[keys[i].ID] = shown{label: keys[i].Label, keySuffix: keys[i].KeySuffix}
	}
	return r
}

// wantShown is e's snapshot: its actor's record as it stood before the call
// (or as the call created it), and for the zero actor the one session the
// call created.
func wantShown(before, after records, e *account.LogEntry) shown {
	a := e.Event.Actor
	switch {
	case a.SessionID != "":
		if s, ok := before.sessions[a.SessionID]; ok {
			return s
		}
		return after.sessions[a.SessionID]
	case a.KeyID != 0:
		return before.keys[a.KeyID]
	case a == account.EventActor{}:
		for id, s := range after.sessions {
			if _, ok := before.sessions[id]; !ok {
				return s
			}
		}
	}
	return shown{}
}

// labeledPrincipal stores a session of u whose Label and UserAgent name it
// and returns the principal the Authenticator grants for it.
func labeledPrincipal(t *testing.T, f *fixture, u *access.User, kind access.SessionKind, method access.Method) access.Principal {
	t.Helper()
	now := time.Now()
	id := newSessionID(t)
	sess := &access.Session{
		ID: id, UserID: u.ID, Kind: kind, AuthMethod: method, CreatedAt: now, LastActivity: now, AuthTime: now,
		Label: "label-" + id[:8], UserAgent: "agent-" + id[:8],
	}
	p, _ := f.principalOf(t, sess)
	return p
}

// labeledKeyPrincipal stores a key of u with a Label and scopes and returns
// the principal the Authenticator grants for it.
func labeledKeyPrincipal(t *testing.T, f *fixture, u *access.User, scopes ...string) (access.Principal, access.Key) {
	t.Helper()
	g, err := access.GenerateAPIKey("")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	key := &access.Key{
		UserID: u.ID, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix,
		Label: "key-label", Scopes: scopes, CreatedAt: time.Now(),
	}
	if err := f.mem.CreateAPIKey(t.Context(), key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+g.Plaintext.Reveal())
	p, err := f.authn.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate(key): %v", err)
	}
	return p, *key
}

// keyScopeOf is the scope a key principal needs for an operation of each
// class that admits one.
var keyScopeOf = map[opClass]string{classAdminScope: scopeAdmin, classManageUsers: scopeUsers, classCreateKeys: scopeKeys}

// labeledActorFor is opWorld.actorFor with a labeled session.
func labeledActorFor(t *testing.T, w *opWorld, class opClass) access.Principal {
	t.Helper()
	switch class {
	case classPublic, classOutOfBand:
		return access.Principal{}
	case classRecovery:
		return labeledPrincipal(t, w.fixture, w.alice, access.SessionRecovery, access.MethodRecovery)
	default:
		return labeledPrincipal(t, w.fixture, w.root, access.SessionFull, access.MethodPassword)
	}
}

// checkShown requires every entry of entries to carry wantShown's data.
func checkShown(t *testing.T, before, after records, entries []account.LogEntry) {
	t.Helper()
	for i := range entries {
		e := &entries[i]
		if got, want := shownOf(e), wantShown(before, after, e); got != want {
			t.Errorf("entry %d (%s, actor %+v) snapshot = %+v, want %+v", i, e.Event.Kind, e.Event.Actor, got, want)
		}
	}
}

// snapshotCall runs call and checks the snapshot of every entry it
// appended; it returns those entries.
func snapshotCall(t *testing.T, s account.Store, call func() error) []account.LogEntry {
	t.Helper()
	before, mark := recordsOf(t, s), logOf(t, s)
	if err := call(); err != nil {
		t.Fatalf("call = %v", err)
	}
	entries := logSince(t, s, mark)
	if len(entries) == 0 {
		t.Fatal("the call appended no entry")
	}
	checkShown(t, before, recordsOf(t, s), entries)
	return entries
}

func TestLogActorSnapshot(t *testing.T) {
	t.Parallel()
	t.Run("catalogue", func(t *testing.T) {
		t.Parallel()
		for _, op := range operations() {
			if op.readOnly {
				continue
			}
			t.Run(op.name, func(t *testing.T) {
				t.Parallel()
				w := newOpWorld(t, worldOptions{empty: op.empty})
				p := access.Principal{}
				if !op.empty {
					p = labeledActorFor(t, w, op.class)
				}
				call := op.prep(t, w, p)
				before, mark := recordsOf(t, w.mem), logOf(t, w.mem)
				if err := call.run(t.Context()); err != nil {
					t.Fatalf("%s = %v", op.name, err)
				}
				entries := logSince(t, w.mem, mark)
				if len(entries) != len(call.want()) {
					t.Fatalf("%s appended %d entries, want one per event, %d", op.name, len(entries), len(call.want()))
				}
				checkShown(t, before, recordsOf(t, w.mem), entries)
			})
		}
	})
	t.Run("key_actor", func(t *testing.T) {
		t.Parallel()
		for _, op := range operations() {
			scope, admitsKey := keyScopeOf[op.class]
			if !admitsKey || op.readOnly {
				continue
			}
			t.Run(op.name, func(t *testing.T) {
				t.Parallel()
				w := newOpWorld(t, worldOptions{scoped: true})
				p, key := labeledKeyPrincipal(t, w.fixture, w.root, scope)
				call := op.prep(t, w, p)
				entries := snapshotCall(t, w.mem, func() error { return call.run(t.Context()) })
				if len(entries) != len(call.want()) {
					t.Fatalf("%s appended %d entries, want one per event, %d", op.name, len(entries), len(call.want()))
				}
				for i := range entries {
					e := &entries[i]
					if e.Event.Actor.KeyID != key.ID || shownOf(e) != (shown{label: key.Label, keySuffix: key.KeySuffix}) {
						t.Errorf("entry %d (%s) actor %+v snapshot %+v, want key %d's Label and Suffix", i, e.Event.Kind, e.Event.Actor, shownOf(e), key.ID)
					}
				}
			})
		}
	})
	t.Run("logout", func(t *testing.T) {
		t.Parallel()
		w := newOpWorld(t, worldOptions{})
		p := labeledPrincipal(t, w.fixture, w.alice, access.SessionFull, access.MethodPassword)
		entries := snapshotCall(t, w.mem, func() error { return w.svc.Logout(t.Context(), p.SessionTokenHash()) })
		if got := shownOf(&entries[0]); got.label == "" || got.userAgent == "" {
			t.Errorf("Logout's entry snapshot = %+v, want the ended session's", got)
		}
	})
	t.Run("oidc_link", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "link-subject"), pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		p := labeledPrincipal(t, f.fixture, u, access.SessionFull, access.MethodPassword)
		flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, p.SessionID)
		entries := snapshotCall(t, f.mem, func() error { _, err := f.complete(t, localClient, flow, claims); return err })
		if got := shownOf(&entries[0]); entries[0].Event.Kind != account.EventOIDCLinked || got.label == "" {
			t.Errorf("link entry %s snapshot = %+v, want oidc_linked with the sealed session's", entries[0].Event.Kind, got)
		}
	})
	t.Run("oidc_step_up", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "step-subject"), pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, u, f.rig.identity())
		p := labeledPrincipal(t, f.fixture, u, access.SessionFull, access.MethodPassword)
		flow, claims := f.rig.sessionFlow(t, oidc.IntentStepUp, u, p.SessionID)
		entries := snapshotCall(t, f.mem, func() error { _, err := f.complete(t, localClient, flow, claims); return err })
		e := &entries[0]
		if e.Event.Kind != account.EventSteppedUp || !slices.Equal(e.Event.SessionIDs, []string{p.SessionID}) || e.ActorLabel == "" || e.ActorUserAgent == "" {
			t.Errorf("step-up entry = %+v, want stepped_up naming %s with the sealed session's Label and UserAgent", e, p.SessionID)
		}
	})
	t.Run("oidc_jit", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "jit-subject"), pwOptions{rules: provisioningOn()})
		mustUser(t, f.mem, "owner", access.RoleAdmin)
		flow, claims := f.rig.signInFlow(t)
		claims.PreferredUsername = "newcomer"
		entries := snapshotCall(t, f.mem, func() error { _, err := f.complete(t, localClient, flow, claims); return err })
		if entries[0].Event.Kind != account.EventUserCreated || entries[0].ActorUserAgent != localClient.UserAgent || entries[0].Event.Actor != (account.EventActor{}) {
			t.Errorf("JIT entry = %+v, want user_created with no actor carrying the created session's UserAgent", entries[0])
		}
	})
	t.Run("sign_in_clears_reported_lock", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{BeforeVerify: hk.hook}})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap-1)
		hk.arm(func(ctx context.Context) {
			hk.disarm()
			if err := account.SweepFailures(ctx, p.svc); err != nil {
				t.Errorf("SweepFailures: %v", err)
			}
		})
		before, mark := recordsOf(t, p.mem), logOf(t, p.mem)
		in, err := p.login(t.Context(), clientAt(1), "alice", goodPassword)
		if err != nil {
			t.Fatalf("PasswordLogin = %v", err)
		}
		// The sweep the hook ran appended its own method_locked, a change
		// of its own with no session; only the sign-in's entries follow it.
		entries := logSince(t, p.mem, mark)
		if len(entries) < 2 || entries[0].Event.Kind != account.EventMethodLocked {
			t.Fatalf("entries = %+v, want the sweep's method_locked then the sign-in's", entries)
		}
		entries = entries[1:]
		checkShown(t, before, recordsOf(t, p.mem), entries)
		i := slices.IndexFunc(entries, func(e account.LogEntry) bool { return e.Event.Kind == account.EventMethodReenabled })
		if i < 0 || entries[i].Event.Actor.SessionID != in.Session.ID || entries[i].ActorUserAgent != in.Session.UserAgent || entries[i].ActorUserAgent == "" {
			t.Fatalf("entries = %+v, want method_reenabled by the created session %s with its UserAgent", entries, in.Session.ID)
		}
		frozen := slices.Clone(entries)
		if err := p.svc.RenameSession(t.Context(), mustPrincipal(t, p.fixture, in.Token), account.SessionLabel{ID: in.Session.ID, Label: "renamed"}); err != nil {
			t.Fatalf("RenameSession = %v", err)
		}
		if after := logSince(t, p.mem, nil); !reflect.DeepEqual(after[len(after)-len(frozen):], frozen) {
			t.Errorf("renaming the created session changed its entries:\n%+v\nwant\n%+v", after, frozen)
		}
	})
	t.Run("eviction", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{rules: rulesWith(func(r *account.Rules) { r.MaxSessionsPerUser = 1 })})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		old := putSession(t, p.mem, liveSession(t, u))
		entries := snapshotCall(t, p.mem, func() error { _, err := p.login(t.Context(), localClient, "alice", goodPassword); return err })
		e := &entries[0]
		if e.Event.Kind != account.EventSessionRevoked || !slices.Equal(e.Event.SessionIDs, []string{old.ID}) || e.ActorUserAgent != localClient.UserAgent {
			t.Errorf("eviction entry = %+v, want one session_revoked naming %s with the created session's UserAgent", e, old.ID)
		}
	})
	t.Run("actor_deleted_before", func(t *testing.T) {
		t.Parallel()
		w := newOpWorld(t, worldOptions{})
		p := labeledPrincipal(t, w.fixture, w.root, access.SessionFull, access.MethodPassword)
		other := putSession(t, w.mem, liveSession(t, w.root))
		if err := w.mem.DeleteSession(t.Context(), access.SessionRef{ID: p.SessionID, UserID: w.root.ID}); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		mark := logOf(t, w.mem)
		if err := w.svc.RevokeSession(t.Context(), p, other.ID); err != nil {
			t.Fatalf("RevokeSession = %v", err)
		}
		entries := logSince(t, w.mem, mark)
		if len(entries) != 1 || shownOf(&entries[0]) != (shown{}) || entries[0].Event.Actor.SessionID != p.SessionID {
			t.Errorf("entries = %+v, want one with the actor's IDs and an empty snapshot", entries)
		}
	})
	t.Run("frozen_actor", func(t *testing.T) {
		t.Parallel()
		w := newOpWorld(t, worldOptions{scoped: true})
		p := labeledPrincipal(t, w.fixture, w.root, access.SessionFull, access.MethodPassword)
		kp, key := labeledKeyPrincipal(t, w.fixture, w.root, scopeUsers)
		other := putSession(t, w.mem, liveSession(t, w.root))
		if err := w.svc.RevokeSession(t.Context(), p, other.ID); err != nil {
			t.Fatalf("RevokeSession = %v", err)
		}
		if _, err := w.svc.CreateUser(t.Context(), account.As(kp), account.NewUser{Username: w.name("keyed"), Role: access.RoleUser}); err != nil {
			t.Fatalf("CreateUser = %v", err)
		}
		frozen := logOf(t, w.mem)
		if err := w.mem.UpdateSessionLabel(t.Context(), access.SessionRef{ID: p.SessionID, UserID: w.root.ID}, "renamed"); err != nil {
			t.Fatalf("UpdateSessionLabel: %v", err)
		}
		if err := w.mem.DeleteSession(t.Context(), access.SessionRef{ID: p.SessionID, UserID: w.root.ID}); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if err := w.mem.DeleteAPIKey(t.Context(), access.KeyRef{UserID: w.root.ID, ID: key.ID}); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		if after := logOf(t, w.mem); !reflect.DeepEqual(after, frozen) {
			t.Errorf("renaming and deleting the actors changed the log:\n%+v\nwant\n%+v", after, frozen)
		}
	})
}

// mustPrincipal is the principal the Authenticator grants for token.
func mustPrincipal(t *testing.T, f *fixture, token access.Secret) access.Principal {
	t.Helper()
	p, err := f.authenticate(t.Context(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return p
}

// clientOperations take a Client, whose IP their entries record.
var clientOperations = []string{
	"SetupWithPassword", "SetupPasskeyFinish", "PasswordLogin", "PasskeyLoginFinish", "OIDCComplete",
	"AcceptInvitePassword", "StartRecovery", "StepUpPassword", "StepUpPasskeyFinish", "SetPassword", "RemovePassword",
}

func TestLogIP(t *testing.T) {
	t.Parallel()
	for _, op := range operations() {
		if op.readOnly {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			p := w.actorFor(t, op.class)
			call := op.prep(t, w, p)
			var want netip.Addr
			switch {
			case slices.Contains(clientOperations, op.name):
				want = localClient.IP
			case op.class == classPublic || op.class == classOutOfBand:
			default:
				if !p.IP.IsValid() || p.IP == localClient.IP {
					t.Fatalf("the actor's Principal.IP = %v, want the request's own address", p.IP)
				}
				want = p.IP
			}
			mark := logOf(t, w.mem)
			if err := call.run(t.Context()); err != nil {
				t.Fatalf("%s = %v", op.name, err)
			}
			entries := logSince(t, w.mem, mark)
			if len(entries) != len(call.want()) {
				t.Fatalf("%s appended %d entries, want one per event, %d", op.name, len(entries), len(call.want()))
			}
			for i := range entries {
				if entries[i].IP != want {
					t.Errorf("%s entry %d (%s) IP = %v, want %v", op.name, i, entries[i].Event.Kind, entries[i].IP, want)
				}
			}
		})
	}
}

func TestLockEntryWrittenBySweep(t *testing.T) {
	t.Parallel()
	t.Run("reported_by_sweep", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap)
		if got := logOf(t, p.mem); len(got) != 0 {
			t.Fatalf("log after %d failures = %+v, want empty", account.FailureCap, got)
		}
		rec, _ := record(t, p.mem, p.svc, "alice", false)
		start := time.Now().Truncate(time.Millisecond)
		sweepFailures(t, p.svc)
		entries := logOf(t, p.mem)
		if len(entries) != 1 {
			t.Fatalf("log after the sweep = %+v, want one method_locked", entries)
		}
		e := entries[0]
		if e.Event.Kind != account.EventMethodLocked || e.Event.UserID != u.ID || !e.Event.At.Equal(rec.LockedAt) || e.At.Before(start) || e.Class != account.LogClassChange {
			t.Errorf("entry = %+v, want method_locked at the lock time %v, appended at the report", e, rec.LockedAt)
		}
		locked := eventsOf(p.events, account.EventMethodLocked)
		if len(locked) != 1 || locked[0].Seq != e.Event.Seq {
			t.Errorf("EventMethodLocked = %+v, want one with Seq %d", locked, e.Event.Seq)
		}
	})
	t.Run("append_fails", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap)
		fs.failCall("AppendLog")
		if err := account.SweepFailures(t.Context(), p.svc); err == nil {
			t.Fatal("SweepFailures with a failing AppendLog = nil, want its error")
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); !rec.Unreported {
			t.Errorf("record after the failed report = %+v, want still Unreported", rec)
		}
		if got := logOf(t, p.mem); len(got) != 0 {
			t.Errorf("log after the failed report = %+v, want empty", got)
		}
		if got := eventsOf(p.events, account.EventMethodLocked); len(got) != 0 {
			t.Errorf("events after the failed report = %+v, want none", got)
		}
		sweepFailures(t, p.svc)
		sweepFailures(t, p.svc)
		if got, ev := logOf(t, p.mem), eventsOf(p.events, account.EventMethodLocked); len(got) != 1 || len(ev) != 1 {
			t.Errorf("after two healthy sweeps: log %+v, events %+v; want the lock once in each", got, ev)
		}
	})
	t.Run("reenable_before_sweep", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		p := newPW(t, pwOptions{store: fs})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap)
		q := labeledPrincipal(t, p.fixture, u, access.SessionFull, access.MethodPasskey)
		fs.resetRecord()
		if err := p.svc.ReenableMethod(t.Context(), q, access.MethodPassword); err != nil {
			t.Fatalf("ReenableMethod = %v", err)
		}
		var kinds []account.EventKind
		updates := map[int]bool{}
		for _, c := range fs.recorded() {
			if c.name == "AppendLog" {
				kinds = append(kinds, account.EventKind(c.arg))
				updates[c.update] = true
			}
		}
		if want := []account.EventKind{account.EventMethodLocked, account.EventMethodReenabled}; !slices.Equal(kinds, want) || len(updates) != 1 {
			t.Errorf("appends = %v in %d Updates, want %v in one", kinds, len(updates), want)
		}
	})
	t.Run("own_lock_cleared_by_success", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		p.failN(t, clientAt(1), "alice", account.FailureCap-1)
		mark := logOf(t, p.mem)
		if _, err := p.login(t.Context(), clientAt(1), "alice", goodPassword); err != nil {
			t.Fatalf("PasswordLogin = %v", err)
		}
		var kinds []account.EventKind
		for _, e := range logSince(t, p.mem, mark) {
			kinds = append(kinds, e.Event.Kind)
		}
		if !slices.Equal(kinds, []account.EventKind{account.EventSignedIn}) {
			t.Errorf("entries of the success clearing its own lock = %v, want signed_in only", kinds)
		}
	})
}

func TestFailedSignInWritesNoEntry(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	p := newPW(t, pwOptions{store: fs})
	passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	disabled := passwordUser(t, p.mem, p.hasher, "dora", goodPassword)
	disabled.Enabled = false
	if err := p.mem.UpdateUser(t.Context(), disabled); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	passwordUser(t, p.mem, p.hasher, "lockie", goodPassword)
	p.failN(t, clientAt(9), "lockie", account.FailureCap)
	shape := func(name, password string) []string {
		t.Helper()
		fs.resetRecord()
		if _, err := p.login(t.Context(), clientAt(1), name, password); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("PasswordLogin(%s) = %v, want ErrInvalidCredentials", name, err)
		}
		var calls []string
		for _, c := range fs.recorded() {
			if c.update != 0 {
				calls = append(calls, c.name)
			}
		}
		return calls
	}
	unknown := shape("ghost", goodPassword)
	if slices.Contains(unknown, "AppendLog") {
		t.Errorf("an unknown user's attempt called AppendLog: %v", unknown)
	}
	for name, got := range map[string][]string{
		"wrong_password": shape("alice", "wrong-password-123"),
		"disabled":       shape("dora", goodPassword),
		"locked":         shape("lockie", goodPassword),
	} {
		if !slices.Equal(got, unknown) {
			t.Errorf("%s attempt's Tx calls = %v, want the unknown user's %v", name, got, unknown)
		}
	}
	if got := logOf(t, p.mem); len(got) != 0 {
		t.Errorf("log after failed attempts = %+v, want empty", got)
	}
}

func TestLogEntryHoldsNoSecret(t *testing.T) {
	t.Parallel()
	t.Run("no_secret_type", func(t *testing.T) {
		t.Parallel()
		if path, found := secretField(reflect.TypeFor[account.LogEntry](), "LogEntry", map[reflect.Type]bool{}); found {
			t.Errorf("%s holds an access.Secret or access.Hash", path)
		}
	})
	t.Run("reviewed_text_fields", func(t *testing.T) {
		t.Parallel()
		allow := printcheck.Allow{Fields: []string{
			"account.LogEntry.ActorLabel", "account.LogEntry.ActorUserAgent", "account.LogEntry.ActorKeySuffix",
			"account.LogEntry.Detail", "account.LogEntry.Class",
			"account.Event.Kind", "account.Event.Method", "account.Event.Role", "account.Event.SessionIDs",
			"account.EventActor.SessionID", "account.EventActor.OutOfBand",
		}, Types: []string{"time.Time", "netip.Addr"}}
		for _, line := range printcheck.Unmasked(allow, reflect.TypeFor[account.LogEntry]()) {
			t.Error(line)
		}
	})
}

var (
	secretType = reflect.TypeFor[access.Secret]()
	hashType   = reflect.TypeFor[access.Hash]()
)

// secretField walks t's type graph through structs, pointers, slices,
// arrays and maps, and returns the path of the first field whose type is
// access.Secret or access.Hash.
func secretField(t reflect.Type, path string, seen map[reflect.Type]bool) (string, bool) {
	if t == secretType || t == hashType {
		return path, true
	}
	if seen[t] {
		return "", false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Struct:
		for f := range t.Fields() {
			if p, found := secretField(f.Type, path+"."+f.Name, seen); found {
				return p, true
			}
		}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return secretField(t.Elem(), path+"[]", seen)
	case reflect.Map:
		if p, found := secretField(t.Key(), path+"{key}", seen); found {
			return p, true
		}
		return secretField(t.Elem(), path+"{}", seen)
	default:
	}
	return "", false
}

func TestSessionsExpiredNotLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, options{edit: withInterval})
		u := mustUser(t, f.mem, "one", access.RoleUser)
		putSessions(t, f, sessionSpec{user: u.ID, inactive: 48 * time.Hour})
		tick()
		got := expiredEvents(f)
		if len(got) != 1 || got[0].Seq != 0 {
			t.Errorf("EventSessionsExpired = %+v, want one with Seq 0", got)
		}
		if entries := logOf(t, f.mem); len(entries) != 0 {
			t.Errorf("log after the session leg = %+v, want empty", entries)
		}
	})
}

func TestLogReRunKeepsLastRun(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	w := newPW(t, pwOptions{store: fs})
	passwordUser(t, w.mem, w.hasher, "alice", goodPassword)
	fs.reRun(true)
	in, err := w.login(t.Context(), localClient, "alice", goodPassword)
	if err != nil {
		t.Fatalf("PasswordLogin = %v", err)
	}
	fs.reRun(false)
	entries := logOf(t, w.mem)
	if len(entries) != 1 || entries[0].Event.Kind != account.EventSignedIn || !slices.Equal(entries[0].Event.SessionIDs, []string{in.Session.ID}) {
		t.Errorf("log after a re-run sign-in = %+v, want one signed_in for %s", entries, in.Session.ID)
	}
	if got := w.events.all(); len(got) != 1 || len(entries) == 1 && got[0].Seq != entries[0].Event.Seq {
		t.Errorf("events = %+v, want the one signed_in once, with its entry's Seq", got)
	}
}

func TestEveryLoggedKindHasAProducer(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		produced = map[account.EventKind]bool{}
	)
	note := func(entries []account.LogEntry) {
		mu.Lock()
		defer mu.Unlock()
		for i := range entries {
			produced[entries[i].Event.Kind] = true
		}
	}
	t.Run("producers", func(t *testing.T) {
		for _, op := range slices.Concat(operations(), policyVariants(), stateVariants()) {
			if op.readOnly {
				continue
			}
			t.Run(op.name, func(t *testing.T) {
				t.Parallel()
				w := newOpWorld(t, worldOptions{empty: op.empty, rules: op.rules})
				call := op.prep(t, w, w.actorFor(t, op.class))
				mark := logOf(t, w.mem)
				if err := call.run(t.Context()); err != nil {
					t.Fatalf("%s = %v", op.name, err)
				}
				note(logSince(t, w.mem, mark))
			})
		}
		t.Run("sweep", func(t *testing.T) {
			t.Parallel()
			p := newPW(t, pwOptions{})
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			p.failN(t, clientAt(1), "alice", account.FailureCap)
			sweepFailures(t, p.svc)
			note(logOf(t, p.mem))
		})
	})
	for _, k := range account.EventKinds() {
		if strings.Contains(string(k), ".") {
			t.Errorf("kind %q contains a dot, which app entries own", k)
		}
		if k != account.EventSessionsExpired && !produced[k] {
			t.Errorf("no catalogue row or sweep appends %q", k)
		}
	}
	if produced[account.EventSessionsExpired] {
		t.Error("an operation appended sessions_expired, which the log never holds")
	}
}
