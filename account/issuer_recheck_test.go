package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// issuerWorld is a fixture over a faultStore with the key scopes, an admin
// root with its recent session pr, and K, a manage_users key of root's
// minted by root's key P.
type issuerWorld struct {
	*pwFixture
	fs   *faultStore
	root *access.User
	pr   access.Principal
	k    minted
}

func newIssuerWorld(t *testing.T) *issuerWorld {
	t.Helper()
	fs := newFaultStore()
	w := &issuerWorld{pwFixture: newPW(t, pwOptions{options: keyOptions(options{store: fs}, nil)}), fs: fs}
	w.root = mustUser(t, w.mem, "root", access.RoleAdmin)
	w.pr = w.sessionPrincipal(t, w.root, time.Now())
	p := w.mint(t, account.As(w.pr), w.root.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeUsers, scopeKeys}})
	w.pr = w.sessionPrincipal(t, w.root, time.Now())
	w.k = w.mint(t, account.As(p.p), w.root.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeUsers}})
	return w
}

// keyIssuedPath is one catalogued operation that redeems what K issued.
type keyIssuedPath struct {
	arrange func(t *testing.T, kr *issuerWorld) issuedLink
	name    string
}

// issuedLink is one arranged redemption. A refusal answers
// access.ErrTokenInvalid, writes exactly writes, and check finds nothing
// else done.
type issuedLink struct {
	run     func(ctx context.Context) error
	promote func(t *testing.T) // raises the role the path's target rule reads, by a store write
	check   func(t *testing.T)
	token   *access.OneTimeToken // the stored link a token path consumes
	writes  []string
}

// storedLink is tok's record as the store holds it.
func storedLink(t *testing.T, kr *issuerWorld, tok account.IssuedToken) *access.OneTimeToken {
	t.Helper()
	rec, found, err := kr.mem.OneTimeTokenByHash(t.Context(), hashOf(tok))
	if err != nil || !found {
		t.Fatalf("OneTimeTokenByHash = %v, %t", err, found)
	}
	return &rec
}

func keyIssuedPaths() []keyIssuedPath {
	return []keyIssuedPath{
		{name: "AcceptInvitePassword", arrange: func(t *testing.T, kr *issuerWorld) issuedLink {
			inv, err := kr.svc.CreateInvite(t.Context(), kr.k.p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite from K = %v", err)
			}
			rec := storedLink(t, kr, inv)
			return issuedLink{
				token:  rec,
				writes: []string{"ConsumeOneTimeToken"},
				run: func(ctx context.Context) error {
					_, err := kr.svc.AcceptInvitePassword(ctx, localClient, account.AcceptInvite{Token: inv.Plaintext, Username: "joiner", Password: access.NewSecret(goodPassword)})
					return err
				},
				// An invite's target rule reads the role it carries.
				promote: func(t *testing.T) {
					if _, _, err := kr.mem.ConsumeOneTimeToken(t.Context(), rec.Hash, time.Now()); err != nil {
						t.Fatalf("ConsumeOneTimeToken: %v", err)
					}
					rec.Role = access.RoleAdmin
					if err := kr.mem.CreateOneTimeToken(t.Context(), *rec); err != nil {
						t.Fatalf("CreateOneTimeToken: %v", err)
					}
				},
				check: func(t *testing.T) {
					if usernameTaken(t, kr.fixture, "joiner") {
						t.Error("the refused acceptance created the user")
					}
					if n := len(eventsOf(kr.events, account.EventUserCreated)) + len(eventsOf(kr.events, account.EventSignedIn)); n != 0 {
						t.Errorf("the refused acceptance emitted %d creation or sign-in events", n)
					}
					if tokenStored(t, kr.mem, *rec) {
						t.Error("the refused acceptance left the invite")
					}
				},
			}
		}},
	}
}

// issuerCase is one change after K issued that its re-check must refuse.
type issuerCase struct {
	change func(t *testing.T, kr *issuerWorld, link *issuedLink)
	name   string
}

func issuerCases() []issuerCase {
	return []issuerCase{
		{name: "issuer_revoked", change: func(t *testing.T, kr *issuerWorld, link *issuedLink) {
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(K) = %v", err)
			}
			// The revocation deletes K's links with it, so a
			// token path meets a revoked issuer only in a link that outlived
			// its key: it is stored again.
			if link.token != nil {
				if err := kr.mem.CreateOneTimeToken(t.Context(), *link.token); err != nil {
					t.Fatalf("CreateOneTimeToken: %v", err)
				}
			}
		}},
		{name: "issuer_descoped", change: func(t *testing.T, kr *issuerWorld, _ *issuedLink) {
			if err := kr.fs.descope(t.Context(), kr.k.key.ID, scopeUsers); err != nil {
				t.Fatalf("descope(K) = %v", err)
			}
		}},
		{name: "target_promoted_in_store", change: func(t *testing.T, _ *issuerWorld, link *issuedLink) { link.promote(t) }},
	}
}

func TestIssuerRecheckEveryKeyIssuedPath(t *testing.T) {
	t.Parallel()
	catalogued := map[string]bool{}
	for _, op := range operations() {
		catalogued[op.name] = true
	}
	for _, path := range keyIssuedPaths() {
		if !catalogued[path.name] {
			t.Errorf("key-issued path %s is not a catalogued operation", path.name)
		}
		for _, ic := range issuerCases() {
			t.Run(path.name+"_"+ic.name, func(t *testing.T) {
				t.Parallel()
				kr := newIssuerWorld(t)
				link := path.arrange(t, kr)
				ic.change(t, kr, &link)
				kr.fs.resetRecord()
				if err := link.run(t.Context()); !errors.Is(err, access.ErrTokenInvalid) {
					t.Fatalf("%s after %s = %v, want access.ErrTokenInvalid", path.name, ic.name, err)
				}
				if ws := writesOf(kr.fs); !slices.Equal(ws, link.writes) {
					t.Errorf("the refusal wrote %v, want %v", ws, link.writes)
				}
				link.check(t)
			})
		}
	}
}
