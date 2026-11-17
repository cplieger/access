package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// adminScoped configures Config.AdminScope.
var adminScoped = pwOptions{edit: func(c *account.Config) { c.AdminScope = scopeAdmin }}

// storedAdmin stores a non-owner admin holding goodPassword.
func storedAdmin(t *testing.T, f *oidcFixture, name string) *access.User {
	t.Helper()
	u := passwordUser(t, f.mem, f.hasher, name, goodPassword)
	u.Role = access.RoleAdmin
	if err := f.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	return u
}

// Readiness is an admin read, a session or an AdminScope key
// re-read inside the read, then Policy OpListUsers; no owner check and no
// recent auth, and refused over plain HTTP.
func TestSSOReadinessReaders(t *testing.T) {
	t.Parallel()
	read := func(t *testing.T, f *oidcFixture, p access.Principal) error {
		t.Helper()
		_, err := f.svc.SSOReadiness(t.Context(), account.As(p), account.SSOForLinked)
		return err
	}
	t.Run("admin_scope_key", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, adminScoped)
		p, _ := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeAdmin)
		if err := read(t, f, p); err != nil {
			t.Errorf("SSOReadiness by an AdminScope key = %v", err)
		}
	})
	t.Run("key_without_admin_scope", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, adminScoped)
		p, _ := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeKeys)
		if err := read(t, f, p); !errors.Is(err, account.ErrScopeRequired) {
			t.Errorf("SSOReadiness by a key without AdminScope = %v, want ErrScopeRequired", err)
		}
	})
	t.Run("admin_scope_unset", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		p, _ := f.keyPrincipalFor(t, f.authn, root, time.Time{}, nil, scopeAdmin)
		if err := read(t, f, p); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("SSOReadiness by a key with AdminScope unset = %v, want ErrSessionRequired", err)
		}
	})
	t.Run("key_of_a_non_admin", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, adminScoped)
		ann := passwordUser(t, f.mem, f.hasher, "ann", goodPassword)
		p, _ := f.keyPrincipalFor(t, f.authn, ann, time.Time{}, nil, scopeAdmin)
		if err := read(t, f, p); !errors.Is(err, account.ErrPolicyRefused) || reasonOf(err) != account.ReasonNotAdmin {
			t.Errorf("SSOReadiness by a RoleUser's AdminScope key = %v, want not_admin", err)
		}
	})
	t.Run("key_reread_inside_the_read", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, adminScoped)
		kim := storedAdmin(t, f, "kim")
		p, _ := f.keyPrincipalFor(t, f.authn, kim, time.Time{}, nil, scopeAdmin)
		kim.Enabled = false
		if err := f.mem.UpdateUser(t.Context(), kim); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if err := read(t, f, p); !errors.Is(err, account.ErrPolicyRefused) || reasonOf(err) != account.ReasonKeyNotCurrent {
			t.Errorf("SSOReadiness by a key whose owner was disabled = %v, want key_not_current", err)
		}
	})
	t.Run("non_owner_admin_without_step_up", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		ann := storedAdmin(t, f, "ann")
		p := f.sessionPrincipal(t, ann, time.Now().Add(-time.Hour))
		if err := read(t, f, p); err != nil {
			t.Errorf("SSOReadiness by a non-owner admin's full session = %v", err)
		}
		if err := f.svc.CheckSSOReady(t.Context(), account.As(p), account.SSOForLinked); !errors.Is(err, access.ErrRecentAuthRequired) {
			t.Errorf("CheckSSOReady by the same session = %v, want ApplySSO's ErrRecentAuthRequired", err)
		}
	})
	t.Run("non_admin_session", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, pwOptions{})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if err := read(t, f, f.sessionPrincipal(t, alice, time.Now())); !errors.Is(err, account.ErrPolicyRefused) || reasonOf(err) != account.ReasonNotAdmin {
			t.Errorf("SSOReadiness by a RoleUser's session = %v, want not_admin", err)
		}
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		p := f.sessionPrincipal(t, root, time.Now())
		p.Secure = false
		if err := read(t, f, p); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("SSOReadiness over plain HTTP = %v, want ErrHTTPSRequired", err)
		}
	})
}

// The preview never disagrees with the change for the person who can make
// it: an owner session's readiness refusal is its own
// ApplySSO's answer, and any other reader's is the out-of-band one.
func TestSSOReadinessRefusalIsTheReaders(t *testing.T) {
	t.Parallel()
	t.Run("acting_owner_without_local_method", func(t *testing.T) {
		t.Parallel()
		f, _ := modeFixture(t, adminScoped)
		bare := mustOwner(t, f.mem, "bare")
		pr, _ := f.signedInVia(t, bare, access.MethodOIDC)
		rd, err := f.svc.SSOReadiness(t.Context(), account.As(pr), account.SSOOnly)
		if err != nil || !errors.Is(rd.Refusal, account.ErrPolicyRefused) || reasonOf(rd.Refusal) != account.ReasonOwnerNeedsLocalMethod {
			t.Fatalf("the owner's preview = %+v, %v; want owner_needs_local_method", rd, err)
		}
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOOnly); err == nil || err.Error() != rd.Refusal.Error() {
			t.Errorf("the owner's ApplySSO = %v, want exactly its preview %v", err, rd.Refusal)
		}
		others := map[string]account.Actor{"out_of_band": socket}
		key, _ := f.keyPrincipalFor(t, f.authn, bare, time.Time{}, nil, scopeAdmin)
		others["owner_key"] = account.As(key)
		others["non_owner_admin"] = account.As(f.sessionPrincipal(t, storedAdmin(t, f, "ann"), time.Now()))
		for name, a := range others {
			if rd, err := f.svc.SSOReadiness(t.Context(), a, account.SSOOnly); err != nil || rd.Refusal != nil {
				t.Errorf("%s's preview = %+v, %v; want the out-of-band rule, met by root's password", name, rd, err)
			}
		}
	})
	t.Run("no_owner_with_local_method", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "subject-y"), adminScoped)
		bare := mustOwner(t, f.mem, "bare")
		key, _ := f.keyPrincipalFor(t, f.authn, bare, time.Time{}, nil, scopeAdmin)
		rd, err := f.svc.SSOReadiness(t.Context(), account.As(key), account.SSOOnly)
		if err != nil || reasonOf(rd.Refusal) != account.ReasonOwnerNeedsLocalMethod {
			t.Errorf("a key's preview with no owner holding a local method = %+v, %v; want owner_needs_local_method", rd, err)
		}
	})
	t.Run("owner_passing", func(t *testing.T) {
		t.Parallel()
		f, root := modeFixture(t, pwOptions{})
		pr, _ := f.signedInVia(t, root, access.MethodPassword)
		rd, err := f.svc.SSOReadiness(t.Context(), account.As(pr), account.SSOOnly)
		if err != nil || rd.Refusal != nil {
			t.Fatalf("the owner's preview = %+v, %v; want no refusal", rd, err)
		}
		if err := f.svc.ApplySSO(t.Context(), account.As(pr), account.SSOOnly); err != nil {
			t.Errorf("the owner's ApplySSO after a passing preview = %v", err)
		}
		if mode, _ := modeOf(t, f.mem); mode != account.SSOOnly {
			t.Errorf("stored mode = %v, want only", mode)
		}
	})
}
