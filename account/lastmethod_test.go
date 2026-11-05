package account_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

const (
	rpID      = "example.com"
	foreignRP = "other.example"
)

// newRP is a relying party for rpID.
func newRP(t testing.TB) *webauthn.RelyingParty {
	t.Helper()
	rp, err := webauthn.New(webauthn.RPConfig{ID: rpID, DisplayName: "Example", Origins: []string{"https://" + rpID}})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return rp
}

// newProvider is an OIDC provider discovered from idp.
func newProvider(t testing.TB, idp *accesstest.IdP) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: "https://" + rpID + "/auth/oidc/callback", HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	return p
}

// addPasskey stores a passkey of u registered under rp and returns it.
func addPasskey(t testing.TB, s account.Store, u *access.User, rp string) access.PasskeyCredential {
	t.Helper()
	cred := access.PasskeyCredential{UserID: u.ID, CredentialID: []byte(newSessionID(t)), PublicKey: []byte("pk"), RPID: rp, Name: "key", CreatedAt: time.Now()}
	if err := s.CreatePasskey(t.Context(), &cred); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	return cred
}

// lockPassword locks u's password record in one trust context.
func lockPassword(t testing.TB, s account.Store, svc *account.Service, u *access.User, trusted bool) {
	t.Helper()
	rec := account.FailureCount{
		Name: account.FailureName(svc, u.Username), Method: access.MethodPassword, Trusted: trusted,
		Count: account.FailureCap, Locked: true, LockedAt: time.Now().Truncate(time.Millisecond),
	}
	if err := s.PutAuthFailure(t.Context(), rec); err != nil {
		t.Fatalf("PutAuthFailure: %v", err)
	}
}

// linkUser links u to issuer.
func linkUser(t testing.TB, s account.Store, u *access.User, issuer string) {
	t.Helper()
	u.OIDC = access.OIDCIdentity{Issuer: issuer, Subject: "sub-" + u.Username}
	if err := s.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// lastMethodEnv is what one guard case configures: the relying party and
// provider the Service resolves, and the Rules it reads.
type lastMethodEnv struct {
	rp       *webauthn.RelyingParty
	provider *oidc.Provider
	rules    account.Rules
}

func (e lastMethodEnv) fixture(t *testing.T) *pwFixture {
	t.Helper()
	return newPW(t, pwOptions{
		rules: func() account.Rules { return e.rules },
		edit: func(c *account.Config) {
			c.RP = func() *webauthn.RelyingParty { return e.rp }
			c.OIDC = func() *oidc.Provider { return e.provider }
		},
	})
}

func usableExcept(m access.Method) func(context.Context, account.Tx, *access.User, access.Method) bool {
	return func(_ context.Context, _ account.Tx, _ *access.User, got access.Method) bool { return got != m }
}

// txRecorder is a Store that records the tx each Update hands its callback.
type txRecorder struct {
	account.Store
	mu  sync.Mutex
	txs []account.Tx
}

func (r *txRecorder) Update(ctx context.Context, fn func(account.Tx) error) error {
	return r.Store.Update(ctx, func(tx account.Tx) error {
		r.mu.Lock()
		r.txs = append(r.txs, tx)
		r.mu.Unlock()
		return fn(tx)
	})
}

func (r *txRecorder) updates() []account.Tx {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.txs)
}

// usableTxs records the tx of every MethodUsable call.
type usableTxs struct {
	mu  sync.Mutex
	txs []account.Tx
}

func (u *usableTxs) usable(_ context.Context, tx account.Tx, _ *access.User, _ access.Method) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.txs = append(u.txs, tx)
	return true
}

func (u *usableTxs) seen() []account.Tx {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.txs)
}

// removalTxs runs remove on a fixture whose Store is a txRecorder and whose
// MethodUsable records its tx, and returns the store, the Updates' txs and
// MethodUsable's txs.
func removalTxs(t *testing.T, rp *webauthn.RelyingParty, remove func(*pwFixture, *access.User, access.Principal, access.PasskeyCredential) error) (store account.Tx, updates, usable []account.Tx) {
	t.Helper()
	var (
		rec  *txRecorder
		seen usableTxs
	)
	p := newPW(t, pwOptions{
		rules: func() account.Rules { return account.Rules{MethodUsable: seen.usable} },
		edit: func(c *account.Config) {
			rec = &txRecorder{Store: c.Store}
			c.Store = rec
			c.RP = func() *webauthn.RelyingParty { return rp }
		},
	})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pk := addPasskey(t, p.mem, u, rpID)
	addPasskey(t, p.mem, u, rpID)
	pr, _ := p.signedInVia(t, u, access.MethodPassword)
	updatesBefore, usableBefore := len(rec.updates()), len(seen.seen())
	if err := remove(p, u, pr, pk); err != nil {
		t.Fatalf("removal = %v, want nil", err)
	}
	return rec, rec.updates()[updatesBefore:], seen.seen()[usableBefore:]
}

func TestLastMethodUsable(t *testing.T) {
	t.Parallel()
	rp := newRP(t)
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	other := accesstest.NewIdP(t, accesstest.IdPOptions{})
	provider, otherProvider := newProvider(t, idp), newProvider(t, other)
	removePasskey := func(t *testing.T, e lastMethodEnv, seed func(*testing.T, *pwFixture, *access.User)) error {
		t.Helper()
		p := e.fixture(t)
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pk := addPasskey(t, p.mem, u, rpID)
		if seed != nil {
			seed(t, p, u)
		}
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		err := p.svc.RemovePasskey(t.Context(), pr, pk.ID)
		kept := slices.ContainsFunc(passkeysOf(t, p.mem, u.ID), func(k access.PasskeyCredential) bool { return k.ID == pk.ID })
		switch {
		case err == nil && kept:
			t.Error("RemovePasskey succeeded with the passkey still stored")
		case err != nil && !kept:
			t.Errorf("RemovePasskey = %v with the passkey removed", err)
		case err != nil && len(p.events.all()) != 0:
			t.Errorf("a refused removal emitted %d events, want none", len(p.events.all()))
		}
		return err
	}
	removePassword := func(t *testing.T, e lastMethodEnv, seed func(*testing.T, *pwFixture, *access.User)) error {
		t.Helper()
		p := e.fixture(t)
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		seed(t, p, u)
		pr, _ := p.signedInVia(t, u, access.MethodPassword)
		_, err := p.svc.RemovePassword(t.Context(), localClient, pr, access.NewSecret(goodPassword))
		stored := storedUser(t, p.mem, u.ID)
		switch {
		case err == nil && !stored.PasswordHash.IsZero():
			t.Error("RemovePassword succeeded with the password still stored")
		case err != nil && stored.PasswordHash.IsZero():
			t.Errorf("RemovePassword = %v with the password removed", err)
		case err != nil && len(p.events.all()) != 0:
			t.Errorf("a refused removal emitted %d events, want none", len(p.events.all()))
		}
		return err
	}
	passkeys := func(rps ...string) func(*testing.T, *pwFixture, *access.User) {
		return func(t *testing.T, p *pwFixture, u *access.User) {
			for _, r := range rps {
				addPasskey(t, p.mem, u, r)
			}
		}
	}
	linked := func(t *testing.T, p *pwFixture, u *access.User) { linkUser(t, p.mem, u, idp.Issuer()) }
	full := lastMethodEnv{rp: rp, provider: provider}
	with := func(edit func(*lastMethodEnv)) lastMethodEnv {
		e := full
		edit(&e)
		return e
	}
	cases := []struct {
		run  func(*testing.T) error
		name string
		want error
	}{
		{name: "passkey_removal_all_usable", run: func(t *testing.T) error { return removePasskey(t, full, nil) }},
		{name: "password_login_disabled", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePasskey(t, with(func(e *lastMethodEnv) { e.rules.DisablePasswordLogin = true }), nil)
		}},
		{name: "password_locked_in_both_contexts", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePasskey(t, full, func(t *testing.T, p *pwFixture, u *access.User) {
				lockPassword(t, p.mem, p.svc, u, false)
				lockPassword(t, p.mem, p.svc, u, true)
			})
		}},
		{name: "password_locked_untrusted_only", run: func(t *testing.T) error {
			return removePasskey(t, full, func(t *testing.T, p *pwFixture, u *access.User) { lockPassword(t, p.mem, p.svc, u, false) })
		}},
		{name: "password_locked_trusted_only", run: func(t *testing.T) error {
			return removePasskey(t, full, func(t *testing.T, p *pwFixture, u *access.User) { lockPassword(t, p.mem, p.svc, u, true) })
		}},
		{name: "password_not_usable", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePasskey(t, with(func(e *lastMethodEnv) { e.rules.MethodUsable = usableExcept(access.MethodPassword) }), nil)
		}},
		{name: "password_removal_matching_passkey", run: func(t *testing.T) error {
			return removePassword(t, full, passkeys(foreignRP, rpID))
		}},
		{name: "every_passkey_foreign", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, full, passkeys(foreignRP, foreignRP))
		}},
		{name: "no_relying_party", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, with(func(e *lastMethodEnv) { e.rp = nil }), passkeys(rpID))
		}},
		{name: "passkeys_not_usable", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, with(func(e *lastMethodEnv) { e.rules.MethodUsable = usableExcept(access.MethodPasskey) }), passkeys(rpID))
		}},
		{name: "password_removal_linked_usable", run: func(t *testing.T) error { return removePassword(t, full, linked) }},
		{name: "no_provider", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, with(func(e *lastMethodEnv) { e.provider = nil }), linked)
		}},
		{name: "provider_of_another_issuer", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, with(func(e *lastMethodEnv) { e.provider = otherProvider }), linked)
		}},
		{name: "oidc_not_usable", want: account.ErrLastMethod, run: func(t *testing.T) error {
			return removePassword(t, with(func(e *lastMethodEnv) { e.rules.MethodUsable = usableExcept(access.MethodOIDC) }), linked)
		}},
		{name: "passkey_removal_passes_its_update_tx", run: func(t *testing.T) error {
			_, updates, usable := removalTxs(t, rp, func(p *pwFixture, _ *access.User, pr access.Principal, pk access.PasskeyCredential) error {
				return p.svc.RemovePasskey(t.Context(), pr, pk.ID)
			})
			if len(usable) == 0 {
				t.Fatal("MethodUsable was never called")
			}
			for i, tx := range usable {
				if !slices.Contains(updates, tx) {
					t.Errorf("MethodUsable call %d got tx %T, want the removal's Update tx", i, tx)
				}
			}
			return nil
		}},
		{name: "password_removal_passes_the_store_then_its_update_tx", run: func(t *testing.T) error {
			store, updates, usable := removalTxs(t, rp, func(p *pwFixture, _ *access.User, pr access.Principal, _ access.PasskeyCredential) error {
				_, err := p.svc.RemovePassword(t.Context(), localClient, pr, access.NewSecret(goodPassword))
				return err
			})
			if len(usable) < 2 {
				t.Fatalf("MethodUsable was called %d times, want the pre-check's and the Update's", len(usable))
			}
			if usable[0] != store {
				t.Errorf("the pre-check's MethodUsable got tx %T, want the Store", usable[0])
			}
			if last := usable[len(usable)-1]; !slices.Contains(updates, last) {
				t.Errorf("the deciding MethodUsable got tx %T, want the removal's Update tx", last)
			}
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(t); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("removal = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRequireHeld(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	alice := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	linkUser(t, p.mem, alice, "https://idp.example")
	own := addPasskey(t, p.mem, alice, rpID)
	bob := passwordUser(t, p.mem, nil, "bob", "")
	bobs := addPasskey(t, p.mem, bob, rpID)
	cases := []struct {
		want      error
		name      string
		method    access.Method
		user      int64
		passkeyID int64
	}{
		{name: "password_held", user: alice.ID, method: access.MethodPassword},
		{name: "password_not_held", user: bob.ID, method: access.MethodPassword, want: account.ErrNotFound},
		{name: "oidc_held", user: alice.ID, method: access.MethodOIDC},
		{name: "oidc_not_held", user: bob.ID, method: access.MethodOIDC, want: account.ErrNotFound},
		{name: "passkey_held", user: alice.ID, method: access.MethodPasskey, passkeyID: own.ID},
		{name: "passkey_of_another_user", user: alice.ID, method: access.MethodPasskey, passkeyID: bobs.ID, want: account.ErrNotFound},
		{name: "passkey_unknown", user: bob.ID, method: access.MethodPasskey, passkeyID: own.ID + bobs.ID + 1, want: account.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := account.RequireHeld(t.Context(), p.svc, tc.user, tc.method, tc.passkeyID)
			if !errors.Is(err, tc.want) {
				t.Errorf("RequireHeld = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLastMethodUsableSeesTheUpdate(t *testing.T) {
	t.Parallel()
	type seen struct {
		ctx  context.Context
		user access.User
	}
	var (
		mu    sync.Mutex
		calls []seen
	)
	var hk armed
	rp := newRP(t)
	p := newPW(t, pwOptions{
		hooks: account.Hooks{AfterVerify: hk.hook},
		rules: func() account.Rules {
			return account.Rules{MethodUsable: func(ctx context.Context, _ account.Tx, u *access.User, _ access.Method) bool {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, seen{ctx: ctx, user: *u})
				return true
			}}
		},
		edit: func(c *account.Config) { c.RP = func() *webauthn.RelyingParty { return rp } },
	})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	addPasskey(t, p.mem, u, rpID)
	pr, _ := p.signedInVia(t, u, access.MethodPassword)
	hk.arm(func(ctx context.Context) {
		hk.disarm()
		cur := storedUser(t, p.mem, u.ID)
		cur.DisplayName = "renamed inside the race window"
		if err := p.mem.UpdateUser(ctx, cur); err != nil {
			t.Errorf("UpdateUser: %v", err)
		}
	})
	ctx := context.WithValue(t.Context(), ctxMarker{}, "removal")
	if _, err := p.svc.RemovePassword(ctx, localClient, pr, access.NewSecret(goodPassword)); err != nil {
		t.Fatalf("RemovePassword = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("MethodUsable was never called")
	}
	for i, c := range calls {
		if c.ctx.Value(ctxMarker{}) != "removal" {
			t.Errorf("call %d: MethodUsable's context lacks the removing call's value", i)
		}
	}
	if last := calls[len(calls)-1].user; last.DisplayName != "renamed inside the race window" {
		t.Errorf("the deciding call saw display name %q, want the user as the removal's Update read it", last.DisplayName)
	}
}

func TestLastMethodConcurrent(t *testing.T) {
	t.Parallel()
	rp := newRP(t)
	type fixture struct {
		p      *pwFixture
		fs     *faultStore
		hk     *armed
		u      *access.User
		pr     access.Principal
		usable access.PasskeyCredential
	}
	removePassword := func(t *testing.T, f fixture) error {
		_, err := f.p.svc.RemovePassword(t.Context(), localClient, f.pr, access.NewSecret(goodPassword))
		return err
	}
	removePasskey := func(t *testing.T, f fixture) error {
		return f.p.svc.RemovePasskey(t.Context(), f.pr, f.usable.ID)
	}
	keptOne := func(t *testing.T, f fixture) {
		t.Helper()
		keys := passkeysOf(t, f.p.mem, f.u.ID)
		password := !storedUser(t, f.p.mem, f.u.ID).PasswordHash.IsZero()
		passkey := slices.ContainsFunc(keys, func(k access.PasskeyCredential) bool { return k.ID == f.usable.ID })
		if password == passkey {
			t.Errorf("password kept %t, usable passkey kept %t; want exactly one kept", password, passkey)
		}
	}
	orders := []struct {
		run  func(t *testing.T, f fixture)
		name string
	}{
		{name: "passkey_commits_inside_password_removal", run: func(t *testing.T, f fixture) {
			passkeyErr := make(chan error, 1)
			f.hk.arm(func(context.Context) {
				f.hk.disarm()
				passkeyErr <- removePasskey(t, f)
			})
			if err := removePassword(t, f); !errors.Is(err, account.ErrLastMethod) {
				t.Errorf("the password removal whose Update follows the passkey's = %v, want ErrLastMethod", err)
			}
			if err := <-passkeyErr; err != nil {
				t.Errorf("the passkey removal committed inside the window = %v, want nil", err)
			}
		}},
		{name: "password_commits_inside_passkey_removal", run: func(t *testing.T, f fixture) {
			entered, release := f.fs.holdUpdate()
			passkeyErr := make(chan error, 1)
			go func() { passkeyErr <- removePasskey(t, f) }()
			<-entered
			if err := removePassword(t, f); err != nil {
				t.Errorf("the password removal committed while the passkey's Update is held = %v, want nil", err)
			}
			release()
			if err := <-passkeyErr; !errors.Is(err, account.ErrLastMethod) {
				t.Errorf("the held passkey removal = %v, want ErrLastMethod", err)
			}
		}},
	}
	// Both stores are the fault store over MemStore, so either order can be
	// held; the second also sleeps in every read outside an Update.
	stores := []struct {
		name      string
		readDelay time.Duration
	}{
		{name: "memstore"},
		{name: "sleeping_single_calls", readDelay: 20 * time.Millisecond},
	}
	for _, st := range stores {
		for _, order := range orders {
			t.Run(st.name+"/"+order.name, func(t *testing.T) {
				t.Parallel()
				f := fixture{fs: newFaultStore(), hk: &armed{}}
				f.fs.delayReads(st.readDelay)
				f.p = newPW(t, pwOptions{
					store: f.fs,
					hooks: account.Hooks{AfterVerify: f.hk.hook},
					edit:  func(c *account.Config) { c.RP = func() *webauthn.RelyingParty { return rp } },
				})
				f.u = passwordUser(t, f.p.mem, f.p.hasher, "alice", goodPassword)
				f.usable = addPasskey(t, f.p.mem, f.u, rpID)
				addPasskey(t, f.p.mem, f.u, foreignRP)
				f.pr, _ = f.p.signedInVia(t, f.u, access.MethodPassword)
				order.run(t, f)
				keptOne(t, f)
			})
		}
	}
}

// passkeysOf reads userID's passkeys as stored.
func passkeysOf(t testing.TB, s account.Store, userID int64) []access.PasskeyCredential {
	t.Helper()
	keys, err := s.PasskeysByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("PasskeysByUserID: %v", err)
	}
	return keys
}
