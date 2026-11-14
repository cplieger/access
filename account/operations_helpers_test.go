package account_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// opClass is the principal an operation admits: the class of the accesshttp
// route that calls it.
type opClass int

const (
	classPublic opClass = iota // takes no principal
	classSession
	classRecentAuth
	classRecovery
	classAdminScope  // key_scope with AdminScope
	classManageUsers // key_permission with ManageUsersScope
	classCreateKeys  // key_permission with CreateKeysScope
	classOutOfBand   // takes an Actor, and admits only an out-of-band one
)

// opWorld is one Service over a faultStore, with an IdP, an admin root and
// a RoleUser alice, each holding goodPassword and one passkey.
type opWorld struct {
	*oidcFixture
	fs    *faultStore
	root  *access.User
	alice *access.User
	devs  map[int64]*accesstest.PasskeyDevice
	seq   atomic.Int64
	// census makes an out-of-band operation's Actor As(p) for every p,
	// the zero principal included.
	census bool
}

// worldOptions shape an opWorld.
type worldOptions struct {
	policy account.Policy       // the Service's Policy; RolePolicy when nil
	rules  func(*account.Rules) // edits the world's rules
	scoped bool                 // the three key scopes configured
	empty  bool                 // no user stored
}

func newOpWorld(t *testing.T, o worldOptions) *opWorld {
	t.Helper()
	w := &opWorld{fs: newFaultStore(), devs: map[int64]*accesstest.PasskeyDevice{}}
	rules := func() account.Rules {
		r := keyRules()
		r.SetupTokenRequired = tokenless
		r.Provisioning = oidc.Provisioning{Enabled: true}
		if o.rules != nil {
			o.rules(&r)
		}
		return r
	}
	opts := options{store: w.fs, rules: rules}
	if o.policy != nil {
		opts.edit = func(c *account.Config) { c.Policy = o.policy }
	}
	if o.scoped {
		opts = keyOptions(opts, nil)
	}
	w.oidcFixture = newOIDCFixture(t, rigFor(t, "op-subject"), pwOptions{options: opts})
	if o.empty {
		return w
	}
	w.root = passwordUser(t, w.mem, w.hasher, "root", goodPassword)
	w.root.Role = access.RoleAdmin
	if err := w.mem.UpdateUser(t.Context(), w.root); err != nil {
		t.Fatalf("UpdateUser(root): %v", err)
	}
	w.alice = passwordUser(t, w.mem, w.hasher, "alice", goodPassword)
	for _, u := range []*access.User{w.root, w.alice} {
		dev := accesstest.NewPasskeyDevice(t)
		w.enrol(t, u, dev)
		w.devs[u.ID] = dev
	}
	return w
}

// actor is the Actor an out-of-band operation is called with: As(p) under
// census or for a principal that names someone, else OutOfBand("socket").
func (w *opWorld) actor(p access.Principal) account.Actor {
	if w.census || p.User != nil || p.Method != "" {
		return account.As(p)
	}
	return account.OutOfBand("socket")
}

// name is a username no earlier call of this world used.
func (w *opWorld) name(prefix string) string { return fmt.Sprintf("%s%d", prefix, w.seq.Add(1)) }

// recent is a full session of u signed in now.
func (w *opWorld) recent(t *testing.T, u *access.User) access.Principal {
	t.Helper()
	return w.sessionPrincipal(t, u, access.SessionFull, time.Now())
}

// actorFor is the principal an operation of class is called with when the
// test does not vary it: a recent session of root, or a recovery session of
// alice; the zero principal for a public or out-of-band operation.
func (w *opWorld) actorFor(t *testing.T, class opClass) access.Principal {
	t.Helper()
	switch class {
	case classPublic, classOutOfBand:
		return access.Principal{}
	case classRecovery:
		return w.sessionPrincipal(t, w.alice, access.SessionRecovery, time.Now())
	default:
		return w.recent(t, w.root)
	}
}

// owner is p's user as stored, or root when p names none the store holds.
func (w *opWorld) owner(t *testing.T, p access.Principal) *access.User {
	t.Helper()
	if p.User != nil {
		if u, found, err := w.mem.UserByID(t.Context(), p.User.ID); err == nil && found {
			return u
		}
	}
	return storedUser(t, w.mem, w.root.ID)
}

// user stores a fresh RoleUser holding goodPassword and returns it.
func (w *opWorld) user(t *testing.T) *access.User {
	t.Helper()
	return passwordUser(t, w.mem, w.hasher, w.name("user"), goodPassword)
}

// storedKey stores a key of u carrying scopes, issuing nothing, and
// returns it.
func (w *opWorld) storedKey(t *testing.T, u *access.User, scopes ...string) access.Key {
	t.Helper()
	_, k := w.keyPrincipalFor(t, nil, u, time.Time{}, nil, scopes...)
	return k
}

// storedPasskey stores a spare passkey of u under the fixture's RP and
// returns its ID.
func (w *opWorld) storedPasskey(t *testing.T, u *access.User) int64 {
	t.Helper()
	cred := &access.PasskeyCredential{
		UserID: u.ID, CredentialID: []byte(w.name("credential-")), PublicKey: []byte("public-key"),
		RPID: rpID, Name: "spare", CreatedAt: time.Now(),
	}
	if err := w.mem.CreatePasskey(t.Context(), cred); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	return cred.ID
}

// lockPasskey stores a reported lock of u's passkey method in the
// untrusted context.
func (w *opWorld) lockPasskey(t *testing.T, u *access.User) {
	t.Helper()
	f := account.FailureCount{
		Name: account.FailureName(w.svc, u.Username), Method: access.MethodPasskey,
		Count: account.FailureCap, Locked: true, LockedAt: time.Now().Truncate(time.Millisecond),
	}
	if err := w.mem.PutAuthFailure(t.Context(), f); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
}

// otherSessions are u's stored session IDs other than except, sorted.
func (w *opWorld) otherSessions(t *testing.T, u *access.User, except string) []string {
	t.Helper()
	return slices.DeleteFunc(sessionIDsOf(t, w.fixture, u.ID), func(id string) bool { return id == except })
}

// keysOfUser are u's stored key IDs, ascending.
func (w *opWorld) keysOfUser(t *testing.T, u *access.User) []int64 {
	t.Helper()
	ids := keyIDs(keysOf(t, w.mem, u.ID))
	slices.Sort(ids)
	return ids
}

// opCall is one arranged call: run makes it, and want, read after it
// returned, is every event it must emit, in order, compared on everything
// but At. A call that asks the Policy names the actor and the target user
// (0 for none) its decisions carry.
type opCall struct {
	run    func(ctx context.Context) error
	want   func() []account.Event
	actor  account.EventActor
	target int64
}

// operation is one exported operation of Service that reads or writes the
// store, or could. prep arranges a call made by p, from localClient, and
// arranges any record the call needs; a call made by a principal the
// operation refuses still compiles to that refusal.
type operation struct {
	prep  func(t *testing.T, w *opWorld, p access.Principal) opCall
	rules func(*account.Rules) // edits the world's rules for this call
	// refused is the answer when the Policy refuses one of asks;
	// ErrPolicyRefused when nil.
	refused  error
	name     string
	asks     []account.Operation // the Policy operations the call asks, in order (design 6.4)
	class    opClass
	empty    bool // the call needs a store with no user
	readOnly bool // the call writes nothing
	direct   bool // the call writes through one store call outside Update
}

// actorOf is the EventActor of an event p's call emits.
func actorOf(p access.Principal) account.EventActor {
	a := account.EventActor{SessionID: p.SessionID, KeyID: p.KeyID}
	if p.User != nil {
		a.UserID = p.User.ID
	}
	return a
}

// none is an opCall's want for a call that emits nothing.
func none() []account.Event { return nil }

// events is a fixed want.
func events(evs ...account.Event) func() []account.Event {
	return func() []account.Event { return evs }
}

// finishWith begins a ceremony with p and, when p is refused at the begin,
// with the default principal of class, so a finish made by p reaches the
// finish's own checks.
func finishWith(t *testing.T, w *opWorld, class opClass, p access.Principal, begin func(access.Principal) (account.PendingCeremony, error)) (access.Principal, account.PendingCeremony) {
	t.Helper()
	if pc, err := begin(p); err == nil {
		return p, pc
	}
	q := w.actorFor(t, class)
	pc, err := begin(q)
	if err != nil {
		t.Fatalf("begin with the default principal = %v", err)
	}
	return q, pc
}

// operations is every exported Service operation that reaches the store,
// with its class.
func operations() []operation {
	return slices.Concat(publicOperations(), sessionOperations(), recentOperations(), recoveryOperations(), adminOperations())
}

func publicOperations() []operation {
	return []operation{
		{name: "State", class: classPublic, readOnly: true, prep: func(_ *testing.T, w *opWorld, _ access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.State(ctx); return err }, want: none}
		}},
		{name: "IssueSetupToken", class: classOutOfBand, empty: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			a := w.actor(p)
			return opCall{
				run:  func(ctx context.Context) error { _, err := w.svc.IssueSetupToken(ctx, a, 0); return err },
				want: events(account.Event{Kind: account.EventSetupTokenIssued, Actor: account.EventActor{OutOfBand: "socket"}}),
			}
		}},
		{name: "SetupWithPassword", class: classPublic, empty: true, asks: []account.Operation{account.OpCreateUser}, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			var in account.SignedIn
			return opCall{
				run: func(ctx context.Context) (err error) {
					in, err = w.svc.SetupWithPassword(ctx, localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)})
					return err
				},
				want: func() []account.Event { return setupEvents(in, access.MethodPassword) },
			}
		}},
		{name: "SetupPasskeyBegin", class: classPublic, empty: true, readOnly: true, prep: func(_ *testing.T, w *opWorld, _ access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error {
				_, err := w.svc.SetupPasskeyBegin(ctx, localClient, account.SetupPasskey{Username: "owner", Origin: w.origin})
				return err
			}, want: none}
		}},
		{name: "SetupPasskeyFinish", class: classPublic, empty: true, asks: []account.Operation{account.OpCreateUser}, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			id, body := w.beginSetup(t, access.Secret{}, accesstest.NewPasskeyDevice(t))
			var in account.SignedIn
			return opCall{
				run: func(ctx context.Context) (err error) {
					in, err = w.svc.SetupPasskeyFinish(ctx, localClient, id, bytes.NewReader(body))
					return err
				},
				want: func() []account.Event { return setupEvents(in, access.MethodPasskey) },
			}
		}},
		{name: "PasswordLogin", class: classPublic, prep: func(_ *testing.T, w *opWorld, _ access.Principal) opCall {
			var in account.SignedIn
			return opCall{
				run: func(ctx context.Context) (err error) {
					in, err = w.login(ctx, localClient, "alice", goodPassword)
					return err
				},
				want: func() []account.Event { return []account.Event{signedIn(in, access.MethodPassword)} },
			}
		}},
		{name: "PasskeyLoginBegin", class: classPublic, readOnly: true, prep: func(_ *testing.T, w *opWorld, _ access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error {
				_, err := w.svc.PasskeyLoginBegin(ctx, localClient, w.origin, account.LoginModal)
				return err
			}, want: none}
		}},
		{name: "PasskeyLoginFinish", class: classPublic, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			pc, err := w.svc.PasskeyLoginBegin(t.Context(), localClient, w.origin, account.LoginModal)
			if err != nil {
				t.Fatalf("PasskeyLoginBegin = %v", err)
			}
			body := w.devs[w.alice.ID].Assert(browserJSON(t, pc.Assertion))
			var in account.SignedIn
			return opCall{
				run: func(ctx context.Context) (err error) {
					in, err = w.svc.PasskeyLoginFinish(ctx, localClient, pc.ID, bytes.NewReader(body))
					return err
				},
				want: func() []account.Event { return []account.Event{signedIn(in, access.MethodPasskey)} },
			}
		}},
		{name: "OIDCComplete", class: classPublic, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			linkIdentity(t, w.mem, storedUser(t, w.mem, w.alice.ID), w.rig.identity())
			flow, claims := w.rig.signInFlow(t)
			var out account.OIDCOutcome
			return opCall{
				run: func(ctx context.Context) (err error) {
					out, err = w.svc.OIDCComplete(ctx, localClient, flow, claims)
					return err
				},
				want: func() []account.Event { return []account.Event{signedIn(out.SignedIn, access.MethodOIDC)} },
			}
		}},
		{name: "AcceptInvitePassword", class: classPublic, asks: []account.Operation{account.OpCreateUser}, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			inv, err := w.svc.CreateInvite(t.Context(), w.recent(t, w.root), access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			var in account.SignedIn
			return opCall{
				run: func(ctx context.Context) (err error) {
					in, err = w.svc.AcceptInvitePassword(ctx, localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "invitee", Password: access.NewSecret(goodPassword)})
					return err
				},
				want: func() []account.Event {
					return []account.Event{{Kind: account.EventUserCreated, UserID: in.User.ID, Role: access.RoleUser}, signedIn(in, access.MethodPassword)}
				},
			}
		}},
		{name: "StartRecovery", class: classPublic, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			tok, err := w.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), w.alice.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery = %v", err)
			}
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.svc.StartRecovery(ctx, localClient, tok.Plaintext)
					return err
				},
				want: events(account.Event{Kind: account.EventRecoveryConsumed, UserID: w.alice.ID}),
			}
		}},
		{name: "Logout", class: classPublic, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			sess := putSession(t, w.mem, liveSession(t, w.alice))
			return opCall{
				run: func(ctx context.Context) error { return w.svc.Logout(ctx, sess.TokenHash) },
				want: events(account.Event{
					Kind: account.EventSessionRevoked, UserID: w.alice.ID, SessionIDs: []string{sess.ID},
					Actor: account.EventActor{UserID: w.alice.ID, SessionID: sess.ID},
				}),
			}
		}},
	}
}

// setupEvents are a setup's EventUserCreated of the admin it created, then
// its EventSignedIn.
func setupEvents(in account.SignedIn, m access.Method) []account.Event {
	created := account.Event{Kind: account.EventUserCreated, Role: access.RoleAdmin}
	if in.User != nil {
		created.UserID = in.User.ID
	}
	return []account.Event{created, signedIn(in, m)}
}

// signedIn is the EventSignedIn of a sign-in that returned in.
func signedIn(in account.SignedIn, m access.Method) account.Event {
	ev := account.Event{Kind: account.EventSignedIn, Method: m, SessionIDs: []string{in.Session.ID}}
	if in.User != nil {
		ev.UserID = in.User.ID
	}
	return ev
}

func sessionOperations() []operation {
	return []operation{
		{name: "Me", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.Me(ctx, p); return err }, want: none}
		}},
		{name: "UpdateProfile", class: classSession, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.UpdateProfile(ctx, p, "Display Name"); return err }, want: none}
		}},
		{name: "StepUpPassword", class: classSession, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{
				run: func(ctx context.Context) error { _, err := w.stepUp(ctx, localClient, p, goodPassword); return err },
				want: events(account.Event{
					Kind: account.EventSteppedUp, UserID: actorOf(p).UserID, Method: access.MethodPassword,
					SessionIDs: []string{p.SessionID}, Actor: actorOf(p),
				}),
			}
		}},
		{name: "StepUpPasskeyBegin", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.StepUpPasskeyBegin(ctx, p, w.origin); return err }, want: none}
		}},
		{name: "StepUpPasskeyFinish", class: classSession, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			b, pc := finishWith(t, w, classSession, p, func(q access.Principal) (account.PendingCeremony, error) {
				return w.svc.StepUpPasskeyBegin(t.Context(), q, w.origin)
			})
			body := w.devs[w.owner(t, b).ID].Assert(browserJSON(t, pc.Assertion))
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.svc.StepUpPasskeyFinish(ctx, localClient, p, pc.ID, bytes.NewReader(body))
					return err
				},
				want: events(account.Event{
					Kind: account.EventSteppedUp, UserID: actorOf(p).UserID, Method: access.MethodPasskey,
					SessionIDs: []string{p.SessionID}, Actor: actorOf(p),
				}),
			}
		}},
		{name: "Passkeys", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.Passkeys(ctx, p); return err }, want: none}
		}},
		{name: "RenamePasskey", class: classSession, direct: true, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			id := w.storedPasskey(t, w.owner(t, p))
			return opCall{run: func(ctx context.Context) error { return w.svc.RenamePasskey(ctx, p, id, "renamed") }, want: none}
		}},
		{name: "WebAuthnSignals", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.WebAuthnSignals(ctx, p); return err }, want: none}
		}},
		{name: "Sessions", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.Sessions(ctx, p); return err }, want: none}
		}},
		{name: "RenameSession", class: classSession, direct: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error {
				return w.svc.RenameSession(ctx, p, account.SessionLabel{ID: p.SessionID, Label: "laptop"})
			}, want: none}
		}},
		{name: "RevokeSession", class: classSession, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			target := putSession(t, w.mem, liveSession(t, u))
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.RevokeSession(ctx, p, target.ID) },
				want: events(account.Event{Kind: account.EventSessionRevoked, UserID: u.ID, SessionIDs: []string{target.ID}, Actor: actorOf(p)}),
			}
		}},
		{name: "APIKeys", class: classSession, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.APIKeys(ctx, p); return err }, want: none}
		}},
		{name: "RevokeAPIKey", class: classSession, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			k := w.storedKey(t, u, "read")
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.RevokeAPIKey(ctx, p, k.ID) },
				want: events(account.Event{Kind: account.EventKeyRevoked, UserID: u.ID, KeyID: k.ID, Actor: actorOf(p)}),
			}
		}},
	}
}

func recentOperations() []operation {
	return []operation{
		{name: "ReenableMethod", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			w.lockPasskey(t, u)
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.ReenableMethod(ctx, p, access.MethodPasskey) },
				want: events(account.Event{Kind: account.EventMethodReenabled, UserID: u.ID, Method: access.MethodPasskey, Actor: actorOf(p)}),
			}
		}},
		{name: "SetPassword", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			others := w.otherSessions(t, u, p.SessionID)
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.setPassword(ctx, p, goodPassword, newPassword)
					return err
				},
				want: func() []account.Event {
					evs := []account.Event{{Kind: account.EventPasswordChanged, UserID: u.ID, Method: access.MethodPassword, Actor: actorOf(p)}}
					if len(others) > 0 {
						evs = append(evs, account.Event{Kind: account.EventUserSessionsRevoked, UserID: u.ID, SessionIDs: others, Actor: actorOf(p)})
					}
					return evs
				},
			}
		}},
		{name: "RemovePassword", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			return opCall{
				run: func(ctx context.Context) error {
					_, err := w.svc.RemovePassword(ctx, localClient, p, access.NewSecret(goodPassword))
					return err
				},
				want: events(account.Event{Kind: account.EventPasswordRemoved, UserID: u.ID, Method: access.MethodPassword, Actor: actorOf(p)}),
			}
		}},
		{name: "PasskeyRegisterBegin", class: classRecentAuth, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.PasskeyRegisterBegin(ctx, p, w.origin); return err }, want: none}
		}},
		{name: "PasskeyRegisterFinish", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			_, pc := finishWith(t, w, classRecentAuth, p, func(q access.Principal) (account.PendingCeremony, error) {
				return w.svc.PasskeyRegisterBegin(t.Context(), q, w.origin)
			})
			body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
			var reg account.Registered
			return opCall{
				run: func(ctx context.Context) (err error) {
					reg, err = w.svc.PasskeyRegisterFinish(ctx, p, pc.ID, bytes.NewReader(body))
					return err
				},
				want: func() []account.Event {
					return []account.Event{{Kind: account.EventPasskeyAdded, UserID: actorOf(p).UserID, PasskeyID: reg.Passkey.ID, Actor: actorOf(p)}}
				},
			}
		}},
		{name: "RemovePasskey", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			id := w.storedPasskey(t, u)
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.RemovePasskey(ctx, p, id) },
				want: events(account.Event{Kind: account.EventPasskeyRemoved, UserID: u.ID, PasskeyID: id, Actor: actorOf(p)}),
			}
		}},
		{name: "RevokeOtherSessions", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			putSession(t, w.mem, liveSession(t, u))
			others := w.otherSessions(t, u, p.SessionID)
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.RevokeOtherSessions(ctx, p) },
				want: events(account.Event{Kind: account.EventUserSessionsRevoked, UserID: u.ID, SessionIDs: others, Actor: actorOf(p)}),
			}
		}},
		{name: "LinkPendingOIDC", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			pending := account.PendingLink{Identity: access.OIDCIdentity{Issuer: oidcIssuer, Subject: w.name("pending-")}}
			return opCall{
				run:  func(ctx context.Context) error { _, _, err := w.svc.LinkPendingOIDC(ctx, p, pending); return err },
				want: events(account.Event{Kind: account.EventOIDCLinked, UserID: u.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "UnlinkOIDC", class: classRecentAuth, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			linkIdentity(t, w.mem, u, access.OIDCIdentity{Issuer: oidcIssuer, Subject: w.name("linked-")})
			return opCall{
				run:  func(ctx context.Context) error { return w.svc.UnlinkOIDC(ctx, p) },
				want: events(account.Event{Kind: account.EventOIDCUnlinked, UserID: u.ID, Actor: actorOf(p)}),
			}
		}},
	}
}

// completed is a recovery completion's events for u, ended by p, that
// installed a credential of method: the sessions it ended, then one
// EventKeyRevoked per key.
func completed(u *access.User, p access.Principal, method access.Method, sessions []string, keys []int64) []account.Event {
	evs := []account.Event{{Kind: account.EventRecoveryCompleted, UserID: u.ID, Method: method, SessionIDs: sessions, Actor: actorOf(p)}}
	for _, id := range keys {
		evs = append(evs, account.Event{Kind: account.EventKeyRevoked, UserID: u.ID, KeyID: id, Actor: actorOf(p)})
	}
	return evs
}

func recoveryOperations() []operation {
	return []operation{
		{name: "RecoverWithPassword", class: classRecovery, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			sessions, keys := sessionIDsOf(t, w.fixture, u.ID), w.keysOfUser(t, u)
			return opCall{
				run: func(ctx context.Context) error {
					return w.svc.RecoverWithPassword(ctx, p, access.NewSecret(recoveredPassword), account.RecoverOptions{})
				},
				want: func() []account.Event { return completed(u, p, access.MethodPassword, sessions, keys) },
			}
		}},
		{name: "RecoverPasskeyBegin", class: classRecovery, readOnly: true, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.RecoverPasskeyBegin(ctx, p, w.origin); return err }, want: none}
		}},
		{name: "RecoverPasskeyFinish", class: classRecovery, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			_, pc := finishWith(t, w, classRecovery, p, func(q access.Principal) (account.PendingCeremony, error) {
				return w.svc.RecoverPasskeyBegin(t.Context(), q, w.origin)
			})
			body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
			u := w.owner(t, p)
			sessions, keys := sessionIDsOf(t, w.fixture, u.ID), w.keysOfUser(t, u)
			return opCall{
				run: func(ctx context.Context) error {
					return w.svc.RecoverPasskeyFinish(ctx, p, pc.ID, bytes.NewReader(body), account.RecoverOptions{})
				},
				want: func() []account.Event { return completed(u, p, access.MethodPasskey, sessions, keys) },
			}
		}},
		{name: "RecoverOutOfBand", class: classOutOfBand, asks: []account.Operation{account.OpIssueRecovery}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			a := w.actor(p)
			sessions, keys := sessionIDsOf(t, w.fixture, w.alice.ID), w.keysOfUser(t, w.alice)
			return opCall{
				actor: account.EventActorOf(a), target: w.alice.ID,
				run: func(ctx context.Context) error {
					return w.svc.RecoverOutOfBand(ctx, a, w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{})
				},
				want: func() []account.Event {
					evs := completed(w.alice, access.Principal{}, access.MethodPassword, sessions, keys)
					for i := range evs {
						evs[i].Actor = account.EventActor{OutOfBand: "socket"}
					}
					return evs
				},
			}
		}},
	}
}

func adminOperations() []operation {
	return []operation{
		{name: "Users", class: classAdminScope, readOnly: true, asks: []account.Operation{account.OpListUsers}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.Users(ctx, p, account.UserFilter{}); return err }, want: none, actor: actorOf(p)}
		}},
		{name: "AllAPIKeys", class: classAdminScope, readOnly: true, asks: []account.Operation{account.OpManageAllKeys}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.AllAPIKeys(ctx, account.As(p)); return err }, want: none, actor: actorOf(p)}
		}},
		{name: "Tokens", class: classAdminScope, readOnly: true, asks: []account.Operation{account.OpListUsers}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.Tokens(ctx, p); return err }, want: none, actor: actorOf(p)}
		}},
		{name: "SecurityLog", class: classAdminScope, readOnly: true, asks: []account.Operation{account.OpListUsers}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{run: func(ctx context.Context) error { _, err := w.svc.SecurityLog(ctx, p, account.LogFilter{}); return err }, want: none, actor: actorOf(p)}
		}},
		{name: "RevokeAnyAPIKey", class: classAdminScope, asks: []account.Operation{account.OpManageAllKeys}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			k := w.storedKey(t, w.alice, "read")
			return opCall{
				actor: actorOf(p),
				run:   func(ctx context.Context) error { return w.svc.RevokeAnyAPIKey(ctx, account.As(p), k.ID) },
				want:  events(account.Event{Kind: account.EventKeyRevoked, UserID: w.alice.ID, KeyID: k.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "CreateUser", class: classManageUsers, asks: []account.Operation{account.OpCreateUser}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			var u *access.User
			name := w.name("created")
			return opCall{
				actor: actorOf(p),
				run: func(ctx context.Context) (err error) {
					u, err = w.svc.CreateUser(ctx, account.As(p), account.NewUser{Username: name, Role: access.RoleUser})
					return err
				},
				want: func() []account.Event {
					return []account.Event{{Kind: account.EventUserCreated, UserID: u.ID, Role: access.RoleUser, Actor: actorOf(p)}}
				},
			}
		}},
		{name: "UpdateUser", class: classManageUsers, asks: []account.Operation{account.OpSetEnabled}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			target := w.user(t)
			return opCall{
				actor: actorOf(p), target: target.ID,
				run: func(ctx context.Context) error {
					_, err := w.svc.UpdateUser(ctx, p, target.ID, account.UserChange{Enabled: new(false)})
					return err
				},
				want: events(account.Event{Kind: account.EventUserDisabled, UserID: target.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "DeleteUser", class: classManageUsers, asks: []account.Operation{account.OpDeleteUser}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			target := w.user(t)
			return opCall{
				actor: actorOf(p), target: target.ID,
				run:  func(ctx context.Context) error { return w.svc.DeleteUser(ctx, p, target.ID) },
				want: events(account.Event{Kind: account.EventUserDeleted, UserID: target.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "IssueRecovery", class: classManageUsers, asks: []account.Operation{account.OpIssueRecovery}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			target := w.user(t)
			return opCall{
				actor: actorOf(p), target: target.ID,
				run: func(ctx context.Context) error {
					_, err := w.svc.IssueRecovery(ctx, account.As(p), target.ID, 0)
					return err
				},
				want: events(account.Event{Kind: account.EventRecoveryIssued, UserID: target.ID, Actor: actorOf(p)}),
			}
		}},
		{name: "CreateInvite", class: classManageUsers, asks: []account.Operation{account.OpInvite}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			return opCall{
				run:   func(ctx context.Context) error { _, err := w.svc.CreateInvite(ctx, p, access.RoleUser, 0); return err },
				want:  events(account.Event{Kind: account.EventInviteIssued, Role: access.RoleUser, Actor: actorOf(p)}),
				actor: actorOf(p),
			}
		}},
		{name: "CreateAPIKey", class: classCreateKeys, asks: []account.Operation{account.OpCreateOwnKey}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			u := w.owner(t, p)
			scopes := []string{"read"}
			if p.IsAPIKey() {
				scopes = slices.Clone(p.Scopes)
			}
			var created account.CreatedKey
			return opCall{
				actor: actorOf(p), target: u.ID,
				run: func(ctx context.Context) (err error) {
					created, err = w.svc.CreateAPIKey(ctx, account.As(p), u.ID, account.NewKey{Label: uniqueLabel(), Scopes: scopes})
					return err
				},
				want: func() []account.Event {
					return []account.Event{{Kind: account.EventKeyMinted, UserID: u.ID, KeyID: created.Key.ID, Actor: actorOf(p)}}
				},
			}
		}},
	}
}
