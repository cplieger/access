package account_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

const (
	usableIssuer  = "https://idp.example"
	foreignIssuer = "https://other-idp.example"
	thirdRP       = "third.example"
)

// usableFixture is a Service whose published state counts nothing: no
// relying party, no provider, and Rules that disable password sign-in and
// refuse every method. Every method UsableMethods counts therefore comes
// from the MethodState it is given.
func usableFixture(t *testing.T) *pwFixture {
	t.Helper()
	return newPW(t, pwOptions{
		rules: func() account.Rules {
			return account.Rules{
				DisablePasswordLogin: true,
				MethodUsable:         func(context.Context, account.Tx, *access.User, access.Method) bool { return false },
			}
		},
		edit: func(c *account.Config) {
			c.RP = func() *webauthn.RelyingParty { return nil }
			c.OIDC = func() *oidc.Provider { return nil }
		},
	})
}

// heldMethods is what a test user holds.
type heldMethods struct {
	issuer   string   // the linked identity's issuer; empty for none
	passkeys []string // one passkey per relying party ID
	password bool
}

func (h heldMethods) user(t *testing.T, p *pwFixture) *access.User {
	t.Helper()
	var hasher *access.Hasher
	if h.password {
		hasher = p.hasher
	}
	u := passwordUser(t, p.mem, hasher, "alice", goodPassword)
	for _, rp := range h.passkeys {
		addPasskey(t, p.mem, u, rp)
	}
	if h.issuer != "" {
		linkUser(t, p.mem, u, h.issuer)
	}
	return u
}

func TestUsableMethods(t *testing.T) {
	t.Parallel()
	full := heldMethods{password: true, passkeys: []string{rpID, rpID, foreignRP}, issuer: usableIssuer}
	state := account.MethodState{RPID: rpID, OIDCIssuer: usableIssuer}
	all := access.MethodAvailability{PasskeyCount: 2, HasPassword: true, OIDCEnabled: true, OIDCLinked: true}
	locked := func(contexts ...bool) func(*testing.T, *pwFixture, *access.User) {
		return func(t *testing.T, p *pwFixture, u *access.User) {
			for _, trusted := range contexts {
				lockPassword(t, p.mem, p.svc, u, trusted)
			}
		}
	}
	cases := []struct {
		seed  func(*testing.T, *pwFixture, *access.User)
		edit  func(*account.MethodState)
		held  func(*heldMethods)
		name  string
		avail access.MethodAvailability
	}{
		{name: "all_usable", avail: all},
		{
			name: "password_not_held", held: func(h *heldMethods) { h.password = false },
			avail: access.MethodAvailability{PasskeyCount: 2, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "password_login_disabled", edit: func(s *account.MethodState) { s.Rules.DisablePasswordLogin = true },
			avail: access.MethodAvailability{PasskeyCount: 2, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "password_locked_in_both_contexts", seed: locked(false, true),
			avail: access.MethodAvailability{PasskeyCount: 2, OIDCEnabled: true, OIDCLinked: true},
		},
		{name: "password_locked_untrusted_only", seed: locked(false), avail: all},
		{name: "password_locked_trusted_only", seed: locked(true), avail: all},
		{
			name: "password_not_usable", edit: func(s *account.MethodState) { s.Rules.MethodUsable = usableExcept(access.MethodPassword) },
			avail: access.MethodAvailability{PasskeyCount: 2, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "no_passkeys_held", held: func(h *heldMethods) { h.passkeys = nil },
			avail: access.MethodAvailability{HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "passkeys_not_usable", edit: func(s *account.MethodState) { s.Rules.MethodUsable = usableExcept(access.MethodPasskey) },
			avail: access.MethodAvailability{HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "no_relying_party", edit: func(s *account.MethodState) { s.RPID = "" },
			avail: access.MethodAvailability{HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "no_relying_party_passkey_without_rp_id", held: func(h *heldMethods) { h.passkeys = []string{""} },
			edit:  func(s *account.MethodState) { s.RPID = "" },
			avail: access.MethodAvailability{HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "relying_party_of_the_other_passkey", edit: func(s *account.MethodState) { s.RPID = foreignRP },
			avail: access.MethodAvailability{PasskeyCount: 1, HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "relying_party_of_no_passkey", edit: func(s *account.MethodState) { s.RPID = thirdRP },
			avail: access.MethodAvailability{HasPassword: true, OIDCEnabled: true, OIDCLinked: true},
		},
		{
			name: "oidc_not_linked", held: func(h *heldMethods) { h.issuer = "" },
			avail: access.MethodAvailability{PasskeyCount: 2, HasPassword: true},
		},
		{
			name: "oidc_not_usable", edit: func(s *account.MethodState) { s.Rules.MethodUsable = usableExcept(access.MethodOIDC) },
			avail: access.MethodAvailability{PasskeyCount: 2, HasPassword: true},
		},
		{
			name: "no_oidc_issuer", edit: func(s *account.MethodState) { s.OIDCIssuer = "" },
			avail: access.MethodAvailability{PasskeyCount: 2, HasPassword: true, OIDCLinked: true},
		},
		{
			name: "oidc_issuer_of_another_provider", edit: func(s *account.MethodState) { s.OIDCIssuer = foreignIssuer },
			avail: access.MethodAvailability{PasskeyCount: 2, HasPassword: true, OIDCLinked: true},
		},
		{
			name: "no_oidc_issuer_identity_without_issuer", edit: func(s *account.MethodState) { s.OIDCIssuer = "" },
			seed: func(t *testing.T, p *pwFixture, u *access.User) {
				u.OIDC = access.OIDCIdentity{Subject: "sub-without-issuer"}
				if err := p.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
			},
			avail: access.MethodAvailability{PasskeyCount: 2, HasPassword: true, OIDCLinked: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := usableFixture(t)
			h := full
			if tc.held != nil {
				tc.held(&h)
			}
			u := h.user(t, p)
			if tc.seed != nil {
				tc.seed(t, p, u)
			}
			st := state
			if tc.edit != nil {
				tc.edit(&st)
			}
			got, err := p.svc.UsableMethods(t.Context(), p.mem, u.ID, st)
			if err != nil {
				t.Fatalf("UsableMethods = %v", err)
			}
			if got != tc.avail {
				t.Errorf("UsableMethods = %+v, want %+v", got, tc.avail)
			}
		})
	}
}

func TestUsableMethodsReadsThroughTx(t *testing.T) {
	t.Parallel()
	type call struct {
		ctx  context.Context
		tx   account.Tx
		user access.User
	}
	var (
		mu    sync.Mutex
		calls []call
	)
	st := account.MethodState{
		RPID: rpID, OIDCIssuer: usableIssuer,
		Rules: account.Rules{MethodUsable: func(ctx context.Context, tx account.Tx, u *access.User, _ access.Method) bool {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, call{ctx: ctx, tx: tx, user: *u})
			return true
		}},
	}
	p := usableFixture(t)
	u := heldMethods{password: true, passkeys: []string{rpID}, issuer: usableIssuer}.user(t, p)
	rollback := errors.New("roll back")
	var (
		inTx account.Tx
		got  access.MethodAvailability
	)
	ctx := context.WithValue(t.Context(), ctxMarker{}, "settings")
	err := p.mem.Update(ctx, func(tx account.Tx) error {
		inTx = tx
		cur, _, readErr := tx.UserByID(ctx, u.ID)
		if readErr != nil {
			return readErr
		}
		cur.OIDC, cur.DisplayName = access.OIDCIdentity{}, "renamed inside the transaction"
		if updErr := tx.UpdateUser(ctx, cur); updErr != nil {
			return updErr
		}
		pk := access.PasskeyCredential{UserID: u.ID, CredentialID: []byte("in-tx"), PublicKey: []byte("pk"), RPID: rpID, Name: "key", CreatedAt: time.Now()}
		if pkErr := tx.CreatePasskey(ctx, &pk); pkErr != nil {
			return pkErr
		}
		for _, trusted := range []bool{false, true} {
			rec := account.FailureCount{
				Name: account.FailureName(p.svc, u.Username), Method: access.MethodPassword, Trusted: trusted,
				Count: account.FailureCap, Locked: true, LockedAt: time.Now().Truncate(time.Millisecond),
			}
			if putErr := tx.PutAuthFailure(ctx, rec); putErr != nil {
				return putErr
			}
		}
		var usableErr error
		got, usableErr = p.svc.UsableMethods(ctx, tx, u.ID, st)
		if usableErr != nil {
			return usableErr
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("Update = %v, want the rollback", err)
	}
	if want := (access.MethodAvailability{PasskeyCount: 2}); got != want {
		t.Errorf("UsableMethods inside the transaction = %+v, want %+v", got, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("MethodUsable was never called")
	}
	for i, c := range calls {
		if c.tx != inTx {
			t.Errorf("call %d: MethodUsable got tx %T, want the caller's", i, c.tx)
		}
		if c.ctx.Value(ctxMarker{}) != "settings" {
			t.Errorf("call %d: MethodUsable's context lacks the caller's value", i)
		}
		if c.user.DisplayName != "renamed inside the transaction" {
			t.Errorf("call %d: MethodUsable saw display name %q, want the user as tx read it", i, c.user.DisplayName)
		}
	}
}

// failingTx is a Tx whose one read named by fail returns errRead.
type failingTx struct {
	account.Tx
	fail string
}

var errRead = errors.New("store read failed")

func (f failingTx) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	if f.fail == "user" {
		return nil, false, errRead
	}
	return f.Tx.UserByID(ctx, id)
}

func (f failingTx) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if f.fail == "passkeys" {
		return nil, errRead
	}
	return f.Tx.PasskeysByUserID(ctx, userID)
}

func (f failingTx) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	if f.fail == "failure_record" {
		return account.FailureCount{}, false, errRead
	}
	return f.Tx.AuthFailure(ctx, ref)
}

func TestUsableMethodsRefusals(t *testing.T) {
	t.Parallel()
	state := account.MethodState{RPID: rpID, OIDCIssuer: usableIssuer}
	cases := []struct {
		call func(*testing.T, *pwFixture, *access.User) error
		want error
		name string
	}{
		{name: "unknown_user", want: account.ErrNotFound, call: func(t *testing.T, p *pwFixture, u *access.User) error {
			_, err := p.svc.UsableMethods(t.Context(), p.mem, u.ID+1, state)
			return err
		}},
		{name: "rules_out_of_bounds", want: account.ErrRulesInvalid, call: func(t *testing.T, p *pwFixture, u *access.User) error {
			st := state
			st.Rules.RecentAuth = time.Second
			_, err := p.svc.UsableMethods(t.Context(), p.mem, u.ID, st)
			return err
		}},
		{name: "breach_mode_without_a_checker", want: account.ErrRulesInvalid, call: func(t *testing.T, p *pwFixture, u *access.User) error {
			st := state
			st.Rules.Breach = account.BreachFailClosed
			_, err := p.svc.UsableMethods(t.Context(), p.mem, u.ID, st)
			return err
		}},
		{name: "service_closed", want: account.ErrServiceClosed, call: func(t *testing.T, p *pwFixture, u *access.User) error {
			if err := p.svc.Shutdown(t.Context()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
			_, err := p.svc.UsableMethods(t.Context(), p.mem, u.ID, state)
			return err
		}},
	}
	for _, read := range []string{"user", "passkeys", "failure_record"} {
		cases = append(cases, struct {
			call func(*testing.T, *pwFixture, *access.User) error
			want error
			name string
		}{name: "store_error_" + read, want: errRead, call: func(t *testing.T, p *pwFixture, u *access.User) error {
			_, err := p.svc.UsableMethods(t.Context(), failingTx{Tx: p.mem, fail: read}, u.ID, state)
			if errors.Is(err, access.ErrAuthBackend) {
				t.Errorf("UsableMethods = %v, want the store's error as it is, not wrapped as ErrAuthBackend", err)
			}
			return err
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := usableFixture(t)
			u := heldMethods{password: true, passkeys: []string{rpID}, issuer: usableIssuer}.user(t, p)
			if err := tc.call(t, p, u); !errors.Is(err, tc.want) {
				t.Errorf("UsableMethods = %v, want %v", err, tc.want)
			}
		})
	}
}
