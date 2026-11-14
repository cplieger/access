package account_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

const (
	scopeUsers = "manage_users"
	scopeKeys  = "create_keys"
	scopeAdmin = "admin"
)

// labels numbers uniqueLabel's answers.
var labels atomic.Int64

// uniqueLabel is a key label no other key of the run carries, for a test
// whose subject is not the label rule (keylabel_test.go pins that).
func uniqueLabel() string { return "key " + strconv.FormatInt(labels.Add(1), 10) }

// keyRules names every scope the key tests mint.
func keyRules() account.Rules {
	return account.Rules{Scopes: []string{"read", "write", scopeUsers, scopeKeys, scopeAdmin}}
}

// keyOptions configures the three permission scopes and keyRules, then
// applies edit.
func keyOptions(o options, policy account.Policy) options {
	edit := o.edit
	o.edit = func(c *account.Config) {
		c.ManageUsersScope, c.CreateKeysScope, c.AdminScope = scopeUsers, scopeKeys, scopeAdmin
		if policy != nil {
			c.Policy = policy
		}
		if edit != nil {
			edit(c)
		}
	}
	if o.rules == nil {
		o.rules = keyRules
	}
	return o
}

// bearer is the principal the Authenticator grants for key plaintext.
func (f *fixture) bearer(t testing.TB, plaintext access.Secret) (access.Principal, error) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+plaintext.Reveal())
	return f.authn.Authenticate(req)
}

// minted is a key CreateAPIKey returned, with its principal.
type minted struct {
	p   access.Principal
	key access.Key
}

// mint has a mint key in for userID and returns it with its principal.
func (f *fixture) mint(t testing.TB, a account.Actor, userID int64, in account.NewKey) minted {
	t.Helper()
	created, err := f.svc.CreateAPIKey(t.Context(), a, userID, in)
	if err != nil {
		t.Fatalf("CreateAPIKey(%v) = %v", in.Scopes, err)
	}
	p, err := f.bearer(t, created.Plaintext)
	if err != nil {
		t.Fatalf("Authenticate(minted key) = %v", err)
	}
	return minted{p: p, key: created.Key}
}

// reason is the Reason of err's *PolicyError, or "" when it has none.
func reason(err error) string {
	if pe, ok := errors.AsType[*account.PolicyError](err); ok {
		return pe.Reason
	}
	return ""
}

// seedToken stores a token of purpose for subject issued by keyID (0 for a
// session), expiring in ttl, and returns its record.
func seedToken(t testing.TB, s account.Store, purpose access.TokenPurpose, subject, keyID int64, ttl time.Duration) access.OneTimeToken {
	t.Helper()
	_, rec := access.NewOneTimeToken(purpose, subject, ttl, time.Now())
	rec.IssuedByKey = keyID
	if purpose == access.PurposeInvite {
		rec.Role = access.RoleUser
	}
	if err := s.CreateOneTimeToken(t.Context(), rec); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}
	return rec
}

// tokenStored reports whether tok's record is still stored.
func tokenStored(t testing.TB, s account.Store, tok access.OneTimeToken) bool {
	t.Helper()
	_, found, err := s.OneTimeTokenByHash(t.Context(), tok.Hash)
	if err != nil {
		t.Fatalf("OneTimeTokenByHash: %v", err)
	}
	return found
}

// keyIDs is the IDs of keys, in their order.
func listedKeyIDs(keys []account.ListedKey) []int64 {
	ids := make([]int64, len(keys))
	for i := range keys {
		ids[i] = keys[i].Key.ID
	}
	return ids
}

func keyIDs(keys []access.Key) []int64 {
	ids := make([]int64, len(keys))
	for i := range keys {
		ids[i] = keys[i].ID
	}
	return ids
}

// crash runs fn and reports whether it panicked.
func crash(fn func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	fn()
	return false
}
