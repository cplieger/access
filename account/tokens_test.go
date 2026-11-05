package account_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

func TestTokensListsLiveTokens(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	ctx := t.Context()
	root := w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	child := w.f.mint(t, account.As(root.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	grand := w.f.mint(t, account.As(child.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
	invite, err := w.f.svc.CreateInvite(ctx, w.pr, access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite = %v", err)
	}
	recovery, err := w.f.svc.IssueRecovery(ctx, account.As(w.pr), w.alice.ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery = %v", err)
	}
	byGrand, err := w.f.svc.CreateInvite(ctx, grand.p, access.RoleUser, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite from the grandchild = %v", err)
	}
	seedToken(t, w.f.mem, access.PurposeSetup, 0, 0, time.Hour)
	seedToken(t, w.f.mem, access.PurposeInvite, 0, 0, -time.Minute)
	w.fs.resetRecord()
	rows, err := w.f.svc.Tokens(ctx, w.pr)
	if err != nil {
		t.Fatalf("Tokens = %v", err)
	}
	for _, c := range w.fs.recorded() {
		if c.name == "Update" {
			t.Error("Tokens ran an Update")
		}
	}
	if len(rows) != 3 {
		t.Fatalf("Tokens = %d rows, want the three live invite and recovery tokens", len(rows))
	}
	wantOrder := []time.Time{byGrand.ExpiresAt, recovery.ExpiresAt, invite.ExpiresAt}
	for i, r := range rows {
		if !r.Token.ExpiresAt.Equal(wantOrder[i]) {
			t.Errorf("row %d expires at %v, want %v (by expiry)", i, r.Token.ExpiresAt, wantOrder[i])
		}
		if r.Token.Purpose == access.PurposeSetup || !r.Token.ExpiresAt.After(time.Now()) {
			t.Errorf("row %d is a %s token expiring %v", i, r.Token.Purpose, r.Token.ExpiresAt)
		}
	}
	if rows[0].Token.IssuedByKey != grand.key.ID || !slices.Equal(rows[0].IssuerLineage, grand.key.LineageIDs) || len(rows[0].IssuerLineage) != 3 {
		t.Errorf("the grandchild's invite lists issuer %d with lineage %v, want %v", rows[0].Token.IssuedByKey, rows[0].IssuerLineage, grand.key.LineageIDs)
	}
	if rows[1].IssuerLineage != nil || rows[2].IssuerLineage != nil {
		t.Errorf("session-issued rows carry lineages %v and %v, want nil", rows[1].IssuerLineage, rows[2].IssuerLineage)
	}
	if err := w.f.svc.RevokeAPIKey(ctx, w.pr, grand.key.ID); err != nil {
		t.Fatalf("RevokeAPIKey(grandchild) = %v", err)
	}
	if rows, err := w.f.svc.Tokens(ctx, w.pr); err != nil || len(rows) != 2 || rows[0].Token.IssuedByKey != 0 {
		t.Errorf("Tokens after the grandchild's revocation = %d rows, %v; want its invite gone", len(rows), err)
	}
	up := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	if _, err := w.f.svc.Tokens(ctx, up); !errors.Is(err, account.ErrPolicyRefused) {
		t.Errorf("Tokens from a RoleUser session = %v, want ErrPolicyRefused", err)
	}
	if _, err := w.f.svc.Tokens(ctx, root.p); !errors.Is(err, account.ErrScopeRequired) {
		t.Errorf("Tokens from a key without the admin scope = %v, want ErrScopeRequired", err)
	}
	if _, err := w.f.svc.Tokens(ctx, w.f.sessionPrincipal(t, w.root, access.SessionRecovery, time.Now())); !errors.Is(err, account.ErrSessionRequired) {
		t.Errorf("Tokens from a recovery session = %v, want ErrSessionRequired", err)
	}
}
