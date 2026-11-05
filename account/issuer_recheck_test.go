package account_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// keyIssuedPath is one catalogued operation that redeems what K, a
// manage_users key, issued for alice, or completes the recovery K's link
// started. arrange issues K's link and, for a completion, opens its
// recovery session.
type keyIssuedPath struct {
	arrange func(t *testing.T, kr *keyRec) issuedLink
	name    string
}

// issuedLink is one arranged redemption. A refusal answers
// access.ErrTokenInvalid, writes exactly writes, and check finds nothing
// else done.
type issuedLink struct {
	run     func(ctx context.Context) error
	promote func(t *testing.T) // raises the role the path's target rule reads, by a store write
	check   func(t *testing.T)
	token   *access.OneTimeToken // the stored link a token path consumes; nil for a completion
	writes  []string
}

// storedLink is tok's record as the store holds it.
func storedLink(t *testing.T, kr *keyRec, tok account.IssuedToken) *access.OneTimeToken {
	t.Helper()
	rec, found, err := kr.mem.OneTimeTokenByHash(t.Context(), hashOf(tok))
	if err != nil || !found {
		t.Fatalf("OneTimeTokenByHash = %v, %t", err, found)
	}
	return &rec
}

// promoteAlice makes alice an admin through the store, which revokes
// nothing.
func promoteAlice(t *testing.T, kr *keyRec) {
	t.Helper()
	u := storedUser(t, kr.mem, kr.alice.ID)
	u.Role = access.RoleAdmin
	if err := kr.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser(alice): %v", err)
	}
}

func keyIssuedPaths() []keyIssuedPath {
	paths := []keyIssuedPath{
		{name: "AcceptInvitePassword", arrange: func(t *testing.T, kr *keyRec) issuedLink {
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
		{name: "StartRecovery", arrange: func(t *testing.T, kr *keyRec) issuedLink {
			tok := kr.issue(t, account.As(kr.k.p), kr.alice.ID)
			rec := storedLink(t, kr, tok)
			return issuedLink{
				token:  rec,
				writes: []string{"ConsumeOneTimeToken"},
				run: func(ctx context.Context) error {
					_, err := kr.svc.StartRecovery(ctx, localClient, tok.Plaintext)
					return err
				},
				promote: func(t *testing.T) { promoteAlice(t, kr) },
				check: func(t *testing.T) {
					if n := len(recoverySessions(t, kr.mem, kr.alice.ID)); n != 0 {
						t.Errorf("the refused start opened %d recovery sessions", n)
					}
					if got := actions(t, kr.fixture, kr.alice.ID); len(got) != 0 {
						t.Errorf("the refused start appended %v", got)
					}
					if n := len(eventsOf(kr.events, account.EventRecoveryConsumed)); n != 0 {
						t.Errorf("the refused start emitted %d EventRecoveryConsumed", n)
					}
					if tokenStored(t, kr.mem, *rec) {
						t.Error("the refused start left the link")
					}
				},
			}
		}},
	}
	for _, c := range completions() {
		name := map[string]string{"password": "RecoverWithPassword", "passkey": "RecoverPasskeyFinish"}[c.name]
		paths = append(paths, keyIssuedPath{name: name, arrange: func(t *testing.T, kr *keyRec) issuedLink {
			_, rp := kr.start(t, kr.svc, kr.issue(t, account.As(kr.k.p), kr.alice.ID))
			return issuedLink{
				writes:  []string{"DeleteSession"},
				run:     func(context.Context) error { return c.run(t, kr.recWorld, kr.svc, rp, account.RecoverOptions{}) },
				promote: func(t *testing.T) { promoteAlice(t, kr) },
				check: func(t *testing.T) {
					if n := len(recoverySessions(t, kr.mem, kr.alice.ID)); n != 0 {
						t.Errorf("the refused completion left %d recovery sessions", n)
					}
					if c.holds(t, kr.recWorld, kr.alice) {
						t.Error("the refused completion set its credential")
					}
					if want := []string{attr(access.AttributionRecoveryStarted, kr.k.key.LineageIDs)}; !slices.Equal(actions(t, kr.fixture, kr.alice.ID), want) {
						t.Errorf("records = %v, want %v", actions(t, kr.fixture, kr.alice.ID), want)
					}
					if n := len(eventsOf(kr.events, account.EventRecoveryCompleted)); n != 0 {
						t.Errorf("the refused completion emitted %d EventRecoveryCompleted", n)
					}
					if !signsIn(t, kr.svc, "alice", goodPassword) {
						t.Error("alice's old password no longer signs in")
					}
				},
			}
		}})
	}
	return paths
}

// issuerCase is one change after K issued that its re-check must refuse.
type issuerCase struct {
	change func(t *testing.T, kr *keyRec, link *issuedLink)
	name   string
}

func issuerCases() []issuerCase {
	return []issuerCase{
		{name: "issuer_revoked", change: func(t *testing.T, kr *keyRec, link *issuedLink) {
			if err := kr.svc.RevokeAPIKey(t.Context(), kr.pr, kr.k.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey(K) = %v", err)
			}
			// The revocation deletes K's links with it (design 6.1), so a
			// token path meets a revoked issuer only in a link that outlived
			// its key: it is stored again.
			if link.token != nil {
				if err := kr.mem.CreateOneTimeToken(t.Context(), *link.token); err != nil {
					t.Fatalf("CreateOneTimeToken: %v", err)
				}
			}
		}},
		{name: "issuer_descoped", change: func(t *testing.T, kr *keyRec, _ *issuedLink) {
			if err := kr.fs.descope(t.Context(), kr.k.key.ID, scopeUsers); err != nil {
				t.Fatalf("descope(K) = %v", err)
			}
		}},
		{name: "target_promoted_in_store", change: func(t *testing.T, _ *keyRec, link *issuedLink) { link.promote(t) }},
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
				kr := newKeyRec(t, 0)
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
	t.Run("RecoverOutOfBand_target_promoted_in_store_no_key_issuer", recoverOutOfBandPromoted)
}

// recoverOutOfBandPromoted is RecoverOutOfBand's row. Its actor is
// out-of-band, so it has no key issuer to re-check, and it repairs any
// user (design 6.4); alice promoted through the store after its first read
// is decided and written as the Update reads her.
func recoverOutOfBandPromoted(t *testing.T) {
	t.Parallel()
	pol := &recordingPolicy{inner: account.RolePolicy{}}
	w := newRecWorld(t, pwOptions{}, pol)
	var once sync.Once
	w.fs.onUpdate(func(ctx context.Context, _ int) {
		once.Do(func() {
			u := storedUser(t, w.mem, w.alice.ID)
			u.Role = access.RoleAdmin
			if err := w.mem.UpdateUser(ctx, u); err != nil {
				t.Errorf("UpdateUser(alice): %v", err)
			}
		})
	})
	if err := w.svc.RecoverOutOfBand(t.Context(), account.OutOfBand("socket"), w.alice.ID, access.NewSecret(recoveredPassword), account.RecoverOptions{}); err != nil {
		t.Fatalf("RecoverOutOfBand on a user promoted mid-call = %v", err)
	}
	ds := pol.taken()
	if len(ds) != 1 || ds[0].Op != account.OpIssueRecovery || ds[0].Target == nil || ds[0].Target.Role != access.RoleAdmin {
		t.Errorf("decisions = %+v, want one OpIssueRecovery on alice as an admin", ds)
	}
	if got := storedUser(t, w.mem, w.alice.ID); got.Role != access.RoleAdmin {
		t.Errorf("alice's stored role = %s, want the promotion kept", got.Role)
	}
	if !signsIn(t, w.svc, "alice", recoveredPassword) {
		t.Error("alice does not sign in with the repaired password")
	}
}
