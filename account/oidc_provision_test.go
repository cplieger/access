package account_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// opsAdmin maps the groups claim's "ops" to an admin, syncing at each
// sign-in when sync is set.
func opsAdmin(sync bool) func() account.Rules {
	return rulesWith(func(r *account.Rules) {
		r.Provisioning = account.Provisioning{RoleClaim: "groups", AdminValues: []string{"ops"}, SyncRole: sync}
	})
}

// TestRoleSync: design 5.4, SyncRole re-applies the RoleClaim mapping at
// each SSO sign-in only while the claim is present and readable, and never
// changes an owner.
func TestRoleSync(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		raw      string // the groups claim; empty is absent
		start    access.Role
		want     access.Role
		event    account.EventKind // empty: none
		owner    bool
		disabled bool // SyncRole off
	}{
		{name: "promoted", raw: `["staff","ops"]`, start: access.RoleUser, want: access.RoleAdmin, event: account.EventRoleSynced},
		{name: "demoted", raw: `"staff"`, start: access.RoleAdmin, want: access.RoleUser, event: account.EventRoleSynced},
		{name: "unchanged", raw: `"ops"`, start: access.RoleAdmin, want: access.RoleAdmin},
		{name: "absent", start: access.RoleAdmin, want: access.RoleAdmin, event: account.EventRoleSyncSkipped},
		{name: "number", raw: `7`, start: access.RoleUser, want: access.RoleUser, event: account.EventRoleSyncSkipped},
		{name: "owner", raw: `"staff"`, start: access.RoleAdmin, want: access.RoleAdmin, owner: true},
		{name: "sync_off", raw: `"ops"`, start: access.RoleUser, want: access.RoleUser, disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: opsAdmin(!tc.disabled)})
			mustOwner(t, f.mem, "root")
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			u.Role, u.Owner = tc.start, tc.owner
			linkIdentity(t, f.mem, u, f.rig.identity())
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, withClaim(claims, "groups", tc.raw))
			if err != nil || out.Kind != account.OutcomeSignedIn {
				t.Fatalf("OIDCComplete = %+v, %v; want SignedIn", out, err)
			}
			if got := storedUser(t, f.mem, u.ID).Role; got != tc.want || out.SignedIn.User.Role != tc.want {
				t.Errorf("role = %s (answered %s), want %s", got, out.SignedIn.User.Role, tc.want)
			}
			var kinds []account.EventKind
			for _, ev := range f.events.all() {
				if ev.Kind == account.EventRoleSynced || ev.Kind == account.EventRoleSyncSkipped {
					kinds = append(kinds, ev.Kind)
					if ev.UserID != u.ID || ev.Role != tc.want {
						t.Errorf("%s = %+v, want alice with role %s", ev.Kind, ev, tc.want)
					}
				}
			}
			if want := slices.DeleteFunc([]account.EventKind{tc.event}, func(k account.EventKind) bool { return k == "" }); !slices.Equal(kinds, want) {
				t.Errorf("sync events = %v, want %v", kinds, want)
			}
		})
	}
}

// TestRoleSyncReachesLiveSessions is FileRise GHSA-92g3-h8h2-p4wq's
// regression: a provider demotion applies to the user's existing session at
// its next request.
func TestRoleSyncReachesLiveSessions(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: opsAdmin(true)})
	mustOwner(t, f.mem, "root")
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	u.Role = access.RoleAdmin
	linkIdentity(t, f.mem, u, f.rig.identity())
	sess := liveSession(t, u)
	before, token := f.principalOf(t, &sess)
	if before.User.Role != access.RoleAdmin {
		t.Fatalf("alice's session before the sync has role %s, want admin", before.User.Role)
	}
	flow, claims := f.rig.signInFlow(t)
	if out, err := f.complete(t, localClient, flow, withClaim(claims, "groups", `"staff"`)); err != nil || out.Kind != account.OutcomeSignedIn {
		t.Fatalf("OIDCComplete = %+v, %v; want SignedIn", out, err)
	}
	after, err := f.authenticate(t.Context(), token)
	if err != nil {
		t.Fatalf("alice's earlier session after the demotion = %v, want it to authenticate", err)
	}
	if after.User.Role != access.RoleUser {
		t.Errorf("alice's earlier session answers role %s after the demotion, want user", after.User.Role)
	}
}

// TestUsersRoleFromProvider: design 5.25, the admin list marks a role the
// provider syncs: a linked non-owner under SyncRole.
func TestUsersRoleFromProvider(t *testing.T) {
	t.Parallel()
	for _, sync := range []bool{false, true} {
		t.Run(map[bool]string{false: "sync_off", true: "sync_on"}[sync], func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: opsAdmin(sync)})
			owner := mustOwner(t, f.mem, "root")
			linkIdentity(t, f.mem, owner, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
			linked := passwordUser(t, f.mem, f.hasher, "linked", goodPassword)
			linkIdentity(t, f.mem, linked, f.rig.identity())
			passwordUser(t, f.mem, f.hasher, "local", goodPassword)
			listed, err := f.svc.Users(t.Context(), f.sessionPrincipal(t, owner, time.Now()), account.UserFilter{})
			if err != nil {
				t.Fatalf("Users = %v", err)
			}
			want := map[string]bool{"root": false, "linked": sync, "local": false}
			for _, l := range listed {
				if l.RoleFromProvider != want[l.User.Username] {
					t.Errorf("%s RoleFromProvider = %t, want %t", l.User.Username, l.RoleFromProvider, want[l.User.Username])
				}
			}
		})
	}
}

// takenPending is a fixture under provisioning whose IdP's name is held,
// and the PendingLink its callback offered.
func takenPending(t *testing.T, rules func() account.Rules) (*oidcFixture, account.PendingLink) {
	t.Helper()
	return takenPendingUnder(t, rules, nil)
}

// takenPendingUnder is takenPending under policy, RolePolicy when nil.
func takenPendingUnder(t *testing.T, rules func() account.Rules, policy account.Policy) (*oidcFixture, account.PendingLink) {
	t.Helper()
	o := pwOptions{rules: rules}
	if policy != nil {
		o.edit = func(c *account.Config) { c.Policy = policy }
	}
	f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{Groups: []string{"ops"}}), o)
	mustOwner(t, f.mem, "root")
	passwordUser(t, f.mem, f.hasher, accesstest.DefaultIdPUsername, goodPassword)
	flow, claims := f.rig.signInFlow(t)
	out, err := f.complete(t, localClient, flow, claims)
	if err != nil || out.Kind != account.OutcomeNotLinked || out.Pending.Provision == nil {
		t.Fatalf("OIDCComplete = %+v, %v; want NotLinked offering a creation", out, err)
	}
	return f, out.Pending
}

// TestCreatePendingOIDC: design 5.4, an admitted identity whose name is
// taken picks a free one; the create re-runs the gates that need no claims.
func TestCreatePendingOIDC(t *testing.T) {
	t.Parallel()
	on := rulesWith(func(r *account.Rules) { r.Provisioning.Enabled = true })
	// Gitea CVE-2026-120263: a taken name links nothing, and the pending
	// state stays valid for another pick.
	t.Run("taken_then_free", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, on)
		if pending.SuggestedUsername != accesstest.DefaultIdPUsername+"_2" || pending.Provision.Role != access.RoleUser {
			t.Errorf("pending = %+v, want the hint with _2 and RoleUser", pending)
		}
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, accesstest.DefaultIdPUsername); !errors.Is(err, account.ErrUsernameTaken) {
			t.Fatalf("CreatePendingOIDC(a taken name) = %v, want ErrUsernameTaken", err)
		}
		if _, found, err := f.mem.UserByOIDC(t.Context(), f.rig.identity()); err != nil || found {
			t.Fatalf("UserByOIDC after the refusal = %t, %v; want nothing linked", found, err)
		}
		in, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "Picked")
		if err != nil {
			t.Fatalf("CreatePendingOIDC(a free name) = %v", err)
		}
		u := storedUser(t, f.mem, in.User.ID)
		if u.Username != "picked" || u.OIDC != f.rig.identity() || u.Role != access.RoleUser || !u.Enabled || u.Owner {
			t.Errorf("created = %+v, want enabled picked, a RoleUser linked to the identity", u)
		}
		if sess := storedSession(t, f.mem, u.ID, in.Session.ID); sess.AuthMethod != access.MethodOIDC {
			t.Errorf("session AuthMethod = %q, want oidc", sess.AuthMethod)
		}
		evs := f.events.all()
		if n := len(evs); n < 2 || evs[n-2].Kind != account.EventUserCreated || evs[n-1].Kind != account.EventSignedIn || evs[n-2].UserID != u.ID {
			t.Errorf("events = %+v, want EventUserCreated then EventSignedIn for picked", evs)
		}
	})
	// design 5.4: admission and the role are the callback's.
	t.Run("role_from_callback", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, rulesWith(func(r *account.Rules) {
			r.Provisioning = account.Provisioning{Enabled: true, RoleClaim: "groups", AdminValues: []string{"ops"}}
		}))
		in, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "picked")
		if err != nil || in.User.Role != access.RoleAdmin {
			t.Errorf("CreatePendingOIDC = %+v, %v; want an admin, the role the callback mapped", in.User, err)
		}
	})
	t.Run("provisioning_turned_off", func(t *testing.T) {
		t.Parallel()
		var off atomic.Bool
		f, pending := takenPending(t, func() account.Rules {
			return account.Rules{Provisioning: account.Provisioning{Enabled: !off.Load()}}
		})
		off.Store(true)
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "picked"); !errors.Is(err, account.ErrProvisioningDisabled) {
			t.Errorf("CreatePendingOIDC with provisioning off = %v, want ErrProvisioningDisabled", err)
		}
	})
	t.Run("no_offer", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, on)
		pending.Provision = nil
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "picked"); !errors.Is(err, account.ErrProvisioningDisabled) {
			t.Errorf("CreatePendingOIDC of a pending link with no offer = %v, want ErrProvisioningDisabled", err)
		}
	})
	// design 5.25: a pending state that does not open is not found, as
	// the pending read answers it.
	t.Run("no_pending", func(t *testing.T) {
		t.Parallel()
		f, _ := takenPending(t, on)
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, account.PendingLink{}, "picked"); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("CreatePendingOIDC with no pending link = %v, want ErrNotFound", err)
		}
	})
	t.Run("identity_linked_since", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, on)
		linkIdentity(t, f.mem, passwordUser(t, f.mem, f.hasher, "bob", goodPassword), f.rig.identity())
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "picked"); !errors.Is(err, account.ErrOIDCIdentityTaken) {
			t.Errorf("CreatePendingOIDC of an identity linked since = %v, want ErrOIDCIdentityTaken", err)
		}
	})
	t.Run("policy_refuses", func(t *testing.T) {
		t.Parallel()
		var refusing atomic.Bool
		f, pending := takenPendingUnder(t, on, togglePolicy{refusing: &refusing})
		refusing.Store(true)
		_, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "picked")
		var pe *account.PolicyError
		if !errors.As(err, &pe) || pe.Reason != "custom_refused" {
			t.Errorf("CreatePendingOIDC under a Policy refusing provisioning = %v, want its PolicyError", err)
		}
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, on)
		plain := localClient
		plain.Secure = false
		if _, err := f.svc.CreatePendingOIDC(t.Context(), plain, pending, "picked"); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("CreatePendingOIDC over plain HTTP = %v, want ErrHTTPSRequired", err)
		}
	})
	t.Run("name_invalid", func(t *testing.T) {
		t.Parallel()
		f, pending := takenPending(t, on)
		var ue *account.UsernameError
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, ""); !errors.As(err, &ue) {
			t.Errorf("CreatePendingOIDC with no name = %v, want a UsernameError", err)
		}
	})
}

// togglePolicy is RolePolicy that, while refusing holds, refuses every
// user-adding operation but setup.
type togglePolicy struct{ refusing *atomic.Bool }

func (togglePolicy) SingleUser() bool { return false }

func (p togglePolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p.refusing.Load() && d.Op == account.OpCreateUser && d.Via != account.ViaSetup {
		return &account.PolicyError{Op: d.Op, Reason: "custom_refused"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// TestAdminUnlinkOIDC: design 5.5, an admin or OutOfBand removes a link
// with no last-method guard, ending every session of the user.
func TestAdminUnlinkOIDC(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, policy account.Policy) (*oidcFixture, *access.User, *access.User) {
		t.Helper()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{options: keyOptions(options{}, policy)})
		root := mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		linkIdentity(t, f.mem, alice, f.rig.identity())
		return f, root, alice
	}
	t.Run("ends_every_session", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, nil)
		sso := liveSession(t, alice)
		sso.AuthMethod = access.MethodOIDC
		a, b := putSession(t, f.mem, sso), putSession(t, f.mem, liveSession(t, alice))
		p := f.sessionPrincipal(t, root, time.Now())
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(p), alice.ID); err != nil {
			t.Fatalf("AdminUnlinkOIDC of an OIDC-only user = %v, want nil: no last-method guard", err)
		}
		if got := storedUser(t, f.mem, alice.ID).OIDC; !got.IsZero() {
			t.Errorf("link = %+v, want none", got)
		}
		if n := len(sessionsOf(t, f.mem, alice.ID)); n != 0 {
			t.Errorf("alice holds %d sessions, want none", n)
		}
		actor := account.EventActor{SessionID: p.SessionID, UserID: root.ID}
		evs := f.events.all()
		want := []string{a.ID, b.ID}
		slices.Sort(want)
		if len(evs) != 2 || evs[0].Kind != account.EventOIDCUnlinked || evs[0].Actor != actor ||
			evs[1].Kind != account.EventUserSessionsRevoked || !slices.Equal(evs[1].SessionIDs, want) || evs[1].Actor != actor {
			t.Errorf("events = %+v, want oidc_unlinked then user_sessions_revoked %v by root", evs, want)
		}
	})
	t.Run("not_linked", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, nil)
		linkIdentity(t, f.mem, alice, access.OIDCIdentity{})
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(f.sessionPrincipal(t, root, time.Now())), alice.ID); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("AdminUnlinkOIDC of an unlinked user = %v, want ErrNotFound", err)
		}
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.OutOfBand("cli"), 999999); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("AdminUnlinkOIDC of a missing user = %v, want ErrNotFound", err)
		}
	})
	t.Run("not_admin", func(t *testing.T) {
		t.Parallel()
		f, _, alice := setup(t, nil)
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(f.sessionPrincipal(t, bob, time.Now())), alice.ID); reason(err) != account.ReasonNotAdmin {
			t.Errorf("a RoleUser's AdminUnlinkOIDC = %v, want not_admin", err)
		}
		if got := storedUser(t, f.mem, alice.ID).OIDC; got.IsZero() {
			t.Error("the refused unlink removed the link")
		}
	})
	// design 5.5: a ManageUsersScope key unlinks a regular user, never an
	// admin (admin_target).
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		f, root, alice := setup(t, nil)
		key := f.keyPrincipal(t, root, scopeUsers)
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		linkIdentity(t, f.mem, admin, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "admin"})
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(key), admin.ID); reason(err) != account.ReasonAdminTarget {
			t.Errorf("a key's unlink of an admin = %v, want admin_target", err)
		}
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(key), alice.ID); err != nil {
			t.Errorf("a key's unlink of a regular user = %v, want nil", err)
		}
	})
	// design 5.2: a principal that is no owner never acts on an owner.
	t.Run("owner_target", func(t *testing.T) {
		t.Parallel()
		f, root, _ := setup(t, nil)
		linkIdentity(t, f.mem, root, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(f.sessionPrincipal(t, admin, time.Now())), root.ID); reason(err) != account.ReasonOwnerTarget {
			t.Errorf("an admin's unlink of an owner = %v, want owner_target", err)
		}
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.OutOfBand("cli"), root.ID); err != nil {
			t.Errorf("an out-of-band unlink of an owner = %v, want nil", err)
		}
	})
	// "Across the parts": SingleOwnerPolicy's OpUnlinkOIDC arm is
	// OutOfBand only, for the owner.
	t.Run("single_owner", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		owner := mustOwner(t, f.mem, "owner")
		linkIdentity(t, f.mem, owner, f.rig.identity())
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.As(f.sessionPrincipal(t, owner, time.Now())), owner.ID); reason(err) != account.ReasonOutOfBandOnly {
			t.Errorf("the owner's own AdminUnlinkOIDC = %v, want out_of_band_only", err)
		}
		if err := f.svc.AdminUnlinkOIDC(t.Context(), account.OutOfBand("cli"), owner.ID); err != nil {
			t.Errorf("an out-of-band unlink of the owner = %v, want nil", err)
		}
	})
	// design 5.5: an API-key principal cannot link or unlink its own user.
	t.Run("key_own_link", func(t *testing.T) {
		t.Parallel()
		f, root, _ := setup(t, nil)
		linkIdentity(t, f.mem, root, access.OIDCIdentity{Issuer: oidcIssuer, Subject: "root"})
		key := f.keyPrincipal(t, root, scopeUsers)
		if err := f.svc.UnlinkOIDC(t.Context(), key); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("UnlinkOIDC by a key = %v, want ErrSessionRequired", err)
		}
		pending := account.PendingLink{Identity: access.OIDCIdentity{Issuer: oidcIssuer, Subject: "other"}}
		if _, _, err := f.svc.LinkPendingOIDC(t.Context(), key, pending); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("LinkPendingOIDC by a key = %v, want ErrSessionRequired", err)
		}
	})
}

// TestSessionCapsByMethod: design 5.6, Rules.SessionCaps gets the method
// the session is created with, once, and a step-up never calls it.
func TestSessionCapsByMethod(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		calls []access.Method
	)
	rules := rulesWith(func(r *account.Rules) {
		r.SessionCaps = func(_ context.Context, _ account.Client, m access.Method) (time.Duration, time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, m)
			if m == access.MethodOIDC {
				return time.Hour, 0
			}
			return 0, 0
		}
	})
	taken := func() []access.Method {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(calls)
		calls = nil
		return out
	}
	f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: rules})
	alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	linkIdentity(t, f.mem, alice, f.rig.identity())
	in, err := completed(f.svc.PasswordLogin(t.Context(), localClient, account.Credentials{Username: "alice", Password: access.NewSecret(goodPassword)}))
	if err != nil {
		t.Fatalf("PasswordLogin = %v", err)
	}
	if got := taken(); !slices.Equal(got, []access.Method{access.MethodPassword}) {
		t.Errorf("SessionCaps calls at a password sign-in = %v, want [password]", got)
	}
	flow, claims := f.rig.signInFlow(t)
	out, err := f.complete(t, localClient, flow, claims)
	if err != nil {
		t.Fatalf("OIDCComplete = %v", err)
	}
	if got := taken(); !slices.Equal(got, []access.Method{access.MethodOIDC}) {
		t.Errorf("SessionCaps calls at an OIDC sign-in = %v, want [oidc]", got)
	}
	if sess := storedSession(t, f.mem, alice.ID, out.SignedIn.Session.ID); sess.IdleCap != time.Hour {
		t.Errorf("the OIDC session's IdleCap = %v, want the 1h its method was given", sess.IdleCap)
	}
	pr, err := f.authenticate(t.Context(), in.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := f.svc.StepUpPassword(t.Context(), localClient, pr, access.NewSecret(goodPassword)); err != nil {
		t.Fatalf("StepUpPassword = %v", err)
	}
	stepFlow, stepClaims := f.rig.sessionFlow(t, oidc.IntentStepUp, alice, in.Session.ID)
	if _, err := f.complete(t, localClient, stepFlow, stepClaims); err != nil {
		t.Fatalf("OIDC step-up = %v", err)
	}
	if got := taken(); len(got) != 0 {
		t.Errorf("SessionCaps calls at two step-ups = %v, want none", got)
	}
	if sess := storedSession(t, f.mem, alice.ID, in.Session.ID); sess.IdleCap != 0 {
		t.Errorf("the password session's IdleCap after an OIDC step-up = %v, want the 0 it was created with", sess.IdleCap)
	}
}
