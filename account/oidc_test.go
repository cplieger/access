package account_test

import (
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// oidcFixture is a pkFixture whose OIDC() is rig's Provider.
type oidcFixture struct {
	*pkFixture
	rig *oidcRig
}

func newOIDCFixture(t testing.TB, rig *oidcRig, o pwOptions) *oidcFixture {
	t.Helper()
	edit := o.edit
	o.edit = func(c *account.Config) {
		rig.withOIDC(c)
		if edit != nil {
			edit(c)
		}
	}
	return &oidcFixture{pkFixture: newPK(t, o), rig: rig}
}

func (f *oidcFixture) complete(t testing.TB, c account.Client, flow oidc.Flow, claims oidc.Claims) (account.OIDCOutcome, error) {
	t.Helper()
	return f.svc.OIDCComplete(t.Context(), c, flow, claims)
}

// liveSession is a full password session of u, signed in and active now.
func liveSession(t testing.TB, u *access.User) access.Session {
	t.Helper()
	now := time.Now()
	return access.Session{
		ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPassword,
		CreatedAt: now, LastActivity: now, AuthTime: now,
	}
}

// provisioningOn is Rules with every OIDC identity admitted.
func provisioningOn() func() account.Rules {
	return rulesWith(func(r *account.Rules) { r.Provisioning = oidc.Provisioning{Enabled: true} })
}

func TestOIDCSignIn(t *testing.T) {
	t.Parallel()
	t.Run("linked", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		u := passwordUser(t, f.mem, nil, "alice", "")
		linkIdentity(t, f.mem, u, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		start := time.Now()
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil {
			t.Fatalf("OIDCComplete = %v", err)
		}
		if out.Kind != account.OutcomeSignedIn || out.SignedIn.User == nil || out.SignedIn.User.ID != u.ID {
			t.Fatalf("outcome = %+v, want alice signed in", out)
		}
		if out.Redirect != "/home" {
			t.Errorf("Redirect = %q, want the sealed /home", out.Redirect)
		}
		sess := storedSession(t, f.mem, u.ID, out.SignedIn.Session.ID)
		if sess.Kind != access.SessionFull || sess.AuthMethod != access.MethodOIDC || sess.AuthTime.Before(start) {
			t.Errorf("stored session = %+v, want a full OIDC session signed in now", sess)
		}
		if pr, err := f.authenticate(t.Context(), out.SignedIn.Token); err != nil || pr.User.ID != u.ID {
			t.Errorf("Authenticate(the issued token) = %v, %v; want alice", pr.User, err)
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventSignedIn || evs[0].Method != access.MethodOIDC || evs[0].UserID != u.ID {
			t.Errorf("events = %+v, want one OIDC EventSignedIn for alice", evs)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: provisioningOn()})
		u := passwordUser(t, f.mem, nil, "alice", "")
		u.Enabled = false
		linkIdentity(t, f.mem, u, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("OIDCComplete for a disabled user = %v, want ErrInvalidCredentials", err)
		}
		if n := len(sessionsOf(t, f.mem, u.ID)); n != 0 {
			t.Errorf("sessions of the disabled user = %d, want 0", n)
		}
		if n := userCount(t, f.fixture); n != 1 {
			t.Errorf("users = %d, want only alice: provisioning must not run for a linked identity", n)
		}
		if evs := f.events.all(); len(evs) != 0 {
			t.Errorf("events = %+v, want none", evs)
		}
	})
	for name, pw := range map[string]string{"name_held_with_password": goodPassword, "name_held_passwordless": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: provisioningOn()})
			h := f.hasher
			if pw == "" {
				h = nil
			}
			held := passwordUser(t, f.mem, h, accesstest.DefaultIdPUsername, pw)
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil {
				t.Fatalf("OIDCComplete = %v", err)
			}
			if out.Kind != account.OutcomeNotLinked || out.Pending.Identity != f.rig.identity() {
				t.Errorf("outcome = %+v, want NotLinked for the IdP identity", out)
			}
			if got := storedUser(t, f.mem, held.ID); !got.OIDC.IsZero() {
				t.Errorf("the account holding the name was linked to %+v", got.OIDC)
			}
			if n := userCount(t, f.fixture); n != 1 {
				t.Errorf("users = %d, want 1", n)
			}
		})
	}
}

func TestOIDCProvisioning(t *testing.T) {
	t.Parallel()
	staff := oidc.Provisioning{Enabled: true, Claim: "groups", AllowedValues: []string{"staff"}}
	staffAdmin := staff
	staffAdmin.Role = access.RoleAdmin
	for _, tc := range []struct {
		groups   any
		policy   account.Policy
		name     string
		wantRole access.Role // empty: NotLinked
		prov     oidc.Provisioning
	}{
		{name: "off", groups: "staff"},
		{name: "claim_absent", prov: staff},
		{name: "claim_values_miss", prov: staff, groups: []string{"guests", "ops"}},
		{name: "admitted_with_role", prov: staffAdmin, groups: []string{"ops", "staff"}, wantRole: access.RoleAdmin},
		{name: "admitted_default_role", prov: staff, groups: "staff", wantRole: access.RoleUser},
		{name: "any_identity", prov: oidc.Provisioning{Enabled: true}, wantRole: access.RoleUser},
		{name: "single_owner", prov: staff, groups: "staff", policy: account.SingleOwnerPolicy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{Groups: tc.groups}), pwOptions{
				rules: rulesWith(func(r *account.Rules) { r.Provisioning = tc.prov }),
				edit: func(c *account.Config) {
					if tc.policy != nil {
						c.Policy = tc.policy
					}
				},
			})
			mustUser(t, f.mem, "owner", access.RoleAdmin)
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil {
				t.Fatalf("OIDCComplete = %v", err)
			}
			u, found, err := f.mem.UserByOIDC(t.Context(), f.rig.identity())
			if err != nil {
				t.Fatalf("UserByOIDC: %v", err)
			}
			if tc.wantRole == "" {
				if out.Kind != account.OutcomeNotLinked || found {
					t.Errorf("outcome %+v, user linked %v; want NotLinked and no user", out, found)
				}
				if n := userCount(t, f.fixture); n != 1 {
					t.Errorf("users = %d, want only the owner", n)
				}
				if evs := f.events.all(); len(evs) != 0 {
					t.Errorf("events = %+v, want none", evs)
				}
				return
			}
			if !found || out.Kind != account.OutcomeSignedIn || out.SignedIn.User == nil || out.SignedIn.User.ID != u.ID {
				t.Fatalf("outcome %+v, user linked %v; want the provisioned user signed in", out, found)
			}
			if u.Username != accesstest.DefaultIdPUsername || u.Role != tc.wantRole || !u.Enabled || len(u.WebAuthnHandle) == 0 {
				t.Errorf("provisioned user = %+v, want enabled %s %s with a WebAuthn handle", u, accesstest.DefaultIdPUsername, tc.wantRole)
			}
			if sess := storedSession(t, f.mem, u.ID, out.SignedIn.Session.ID); sess.AuthMethod != access.MethodOIDC {
				t.Errorf("session AuthMethod = %q, want oidc", sess.AuthMethod)
			}
			evs := f.events.all()
			if len(evs) != 2 || evs[0].Kind != account.EventUserCreated || evs[0].UserID != u.ID || evs[0].Actor != (account.EventActor{}) || evs[1].Kind != account.EventSignedIn {
				t.Errorf("events = %+v, want EventUserCreated with no actor, then EventSignedIn", evs)
			}
		})
	}
	t.Run("empty_store", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: provisioningOn()})
		flow, claims := f.rig.signInFlow(t)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil || out.Kind != account.OutcomeNotLinked {
			t.Fatalf("OIDCComplete on an empty store = %+v, %v; want NotLinked", out, err)
		}
		if n := userCount(t, f.fixture); n != 0 {
			t.Fatalf("users = %d, want 0", n)
		}
		in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, account.ErrSetupTokenRequired) {
			t.Fatalf("setup with no token = %v, want ErrSetupTokenRequired: the token rule still holds", err)
		}
		tok, err := f.svc.IssueSetupToken(t.Context(), account.OutOfBand("cli"), 0)
		if err != nil {
			t.Fatalf("IssueSetupToken: %v", err)
		}
		in.Token = tok
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); err != nil {
			t.Errorf("setup after the refused provisioning = %v", err)
		}
	})
	t.Run("hot_reload", func(t *testing.T) {
		t.Parallel()
		var on atomic.Bool
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: func() account.Rules {
			return account.Rules{Provisioning: oidc.Provisioning{Enabled: on.Load()}}
		}})
		mustUser(t, f.mem, "owner", access.RoleAdmin)
		flow, claims := f.rig.signInFlow(t)
		if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeNotLinked {
			t.Fatalf("callback with provisioning off = %+v, %v; want NotLinked", out, err)
		}
		on.Store(true)
		flow, claims = f.rig.signInFlow(t)
		if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeSignedIn {
			t.Errorf("next callback with provisioning on = %+v, %v; want SignedIn", out, err)
		}
	})
	t.Run("policy_sees_provisioning", func(t *testing.T) {
		t.Parallel()
		pol := &recordingPolicy{inner: account.RolePolicy{}}
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{
			rules: provisioningOn(),
			edit:  func(c *account.Config) { c.Policy = pol },
		})
		owner := mustUser(t, f.mem, "owner", access.RoleAdmin)
		flow, claims := f.rig.signInFlow(t)
		if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeSignedIn {
			t.Fatalf("OIDCComplete = %+v, %v; want SignedIn", out, err)
		}
		ds := pol.taken()
		if len(ds) != 1 {
			t.Fatalf("decisions = %+v, want one", ds)
		}
		d := ds[0]
		_, isPrincipal := d.Actor.Principal()
		_, isOutOfBand := d.Actor.OutOfBandChannel()
		if d.Op != account.OpCreateUser || d.Via != account.ViaProvisioning || d.Role != access.RoleUser || isPrincipal || isOutOfBand {
			t.Errorf("decision = %+v, want OpCreateUser ViaProvisioning RoleUser from the zero Actor", d)
		}
		if len(d.Users) != 1 || d.Users[0].ID != owner.ID {
			t.Errorf("Decision.Users = %+v, want the owner read inside the Update", d.Users)
		}
	})
	t.Run("rules_refuse_claim_without_values", func(t *testing.T) {
		t.Parallel()
		r := account.Rules{Provisioning: oidc.Provisioning{Enabled: true, Claim: "groups"}}
		if err := r.Validate(); !errors.Is(err, account.ErrRulesInvalid) {
			t.Errorf("Validate = %v, want ErrRulesInvalid", err)
		}
	})
}

func TestOIDCNotLinkedOneShape(t *testing.T) {
	t.Parallel()
	outcome := func(t *testing.T, o accesstest.IdPOptions, rules func() account.Rules, holder string) account.OIDCOutcome {
		t.Helper()
		f := newOIDCFixture(t, newOIDCRig(t, o), pwOptions{rules: rules})
		mustUser(t, f.mem, "owner", access.RoleAdmin)
		switch holder {
		case "password":
			passwordUser(t, f.mem, f.hasher, accesstest.DefaultIdPUsername, goodPassword)
		case "passwordless":
			passwordUser(t, f.mem, nil, accesstest.DefaultIdPUsername, "")
		}
		flow, claims := f.rig.signInFlow(t)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil {
			t.Fatalf("OIDCComplete = %v", err)
		}
		return out
	}
	off := rulesWith(func(*account.Rules) {})
	want := outcome(t, accesstest.IdPOptions{}, off, "")
	wantPending := account.PendingLink{
		Identity:     access.OIDCIdentity{Issuer: oidcIssuer, Subject: accesstest.DefaultIdPSubject},
		UsernameHint: accesstest.DefaultIdPUsername, Email: accesstest.DefaultIdPEmail,
	}
	if want.Kind != account.OutcomeNotLinked || want.Pending != wantPending || want.Redirect != "/home" {
		t.Fatalf("NotLinked outcome = %+v, want Pending %+v and Redirect /home", want, wantPending)
	}
	for name, tc := range map[string]struct {
		rules  func() account.Rules
		holder string
	}{
		"off_name_held":               {rules: off, holder: "password"},
		"provisioning_name_held":      {rules: provisioningOn(), holder: "password"},
		"provisioning_name_held_bare": {rules: provisioningOn(), holder: "passwordless"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := outcome(t, accesstest.IdPOptions{}, tc.rules, tc.holder); !reflect.DeepEqual(got, want) {
				t.Errorf("outcome = %+v, want the same as with the name free, %+v", got, want)
			}
		})
	}
	t.Run("email_unverified", func(t *testing.T) {
		t.Parallel()
		got := outcome(t, accesstest.IdPOptions{EmailVerified: false}, off, "")
		if got.Pending.Email != "" || got.Pending.UsernameHint != accesstest.DefaultIdPUsername {
			t.Errorf("Pending = %+v, want the hint and no unverified email", got.Pending)
		}
	})
}

// pendingFixture is an oidcFixture over an IdP for subject-y, with alice
// holding a password and the PendingLink a callback for subject-y returned.
type pendingFixture struct {
	*oidcFixture
	u       *access.User
	pending account.PendingLink
}

func newPendingFixture(t *testing.T, o pwOptions) *pendingFixture {
	t.Helper()
	f := newOIDCFixture(t, rigFor(t, "subject-y"), o)
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	flow, claims := f.rig.signInFlow(t)
	out, err := f.complete(t, localClient, flow, claims)
	if err != nil || out.Kind != account.OutcomeNotLinked {
		t.Fatalf("OIDCComplete = %+v, %v; want NotLinked", out, err)
	}
	return &pendingFixture{oidcFixture: f, u: u, pending: out.Pending}
}

func TestOIDCPendingLink(t *testing.T) {
	t.Parallel()
	identityX := access.OIDCIdentity{Issuer: oidcIssuer, Subject: "subject-x"}
	t.Run("links", func(t *testing.T) {
		t.Parallel()
		f := newPendingFixture(t, pwOptions{})
		pr, old := f.signedInVia(t, f.u, access.MethodPassword)
		is, view, err := f.svc.LinkPendingOIDC(t.Context(), pr, f.pending)
		if err != nil {
			t.Fatalf("LinkPendingOIDC = %v", err)
		}
		if got := storedUser(t, f.mem, f.u.ID).OIDC; got != f.rig.identity() {
			t.Errorf("stored link = %+v, want %+v", got, f.rig.identity())
		}
		if is.Session.ID != pr.SessionID || !storedSession(t, f.mem, f.u.ID, pr.SessionID).TokenHash.Equal(access.SessionHash(is.Token.Reveal())) {
			t.Error("the session was not rotated into Issued")
		}
		if _, err := f.authenticate(t.Context(), old); err == nil {
			t.Error("the pre-link token still authenticates")
		}
		if got := kindsOf(f.events); !slices.Equal(got, []account.EventKind{account.EventOIDCLinked}) {
			t.Errorf("events = %v, want only EventOIDCLinked", got)
		}
		me, err := f.svc.Me(t.Context(), f.principal(t, is.Token))
		if err != nil || me.CanLinkOIDC || !me.Methods.OIDCLinked {
			t.Errorf("Me after the link = %+v, %v; want OIDCLinked and CanLinkOIDC false", me, err)
		}
		after, err := f.svc.Me(t.Context(), pr)
		if err != nil || !reflect.DeepEqual(*view.User, *after.User) || !reflect.DeepEqual(view.Methods, after.Methods) || view.CanLinkOIDC != after.CanLinkOIDC || view.Current != after.Current {
			t.Errorf("LinkPendingOIDC's view = %+v, want Me after the link %+v (%v)", view, after, err)
		}
	})
	for _, tc := range []struct {
		arrange func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink)
		want    error
		name    string
		kept    access.OIDCIdentity // the link alice still holds
	}{
		{name: "stale_session", want: access.ErrRecentAuthRequired, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			return f.sessionPrincipal(t, f.u, access.SessionFull, time.Now().Add(-time.Hour)), f.pending
		}},
		{name: "identity_taken", want: account.ErrOIDCIdentityTaken, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			linkIdentity(t, f.mem, passwordUser(t, f.mem, nil, "bob", ""), f.pending.Identity)
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			return pr, f.pending
		}},
		{name: "already_linked", want: account.ErrAlreadyLinked, kept: identityX, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			linkIdentity(t, f.mem, f.u, identityX)
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			return pr, f.pending
		}},
		{name: "no_identity", want: account.ErrNotFound, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			return pr, account.PendingLink{}
		}},
		{name: "no_subject", want: account.ErrNotFound, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			return pr, account.PendingLink{Identity: access.OIDCIdentity{Issuer: oidcIssuer}}
		}},
		{name: "disabled_user", want: account.ErrSessionGone, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			u := storedUser(t, f.mem, f.u.ID)
			u.Enabled = false
			if err := f.mem.UpdateUser(t.Context(), u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			return pr, f.pending
		}},
		{name: "session_ended", want: account.ErrSessionGone, arrange: func(t *testing.T, f *pendingFixture) (access.Principal, account.PendingLink) {
			pr, _ := f.signedInVia(t, f.u, access.MethodPassword)
			if err := f.mem.DeleteSession(t.Context(), access.SessionRef{ID: pr.SessionID, UserID: f.u.ID}); err != nil {
				t.Fatalf("DeleteSession: %v", err)
			}
			return pr, f.pending
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPendingFixture(t, pwOptions{})
			pr, pending := tc.arrange(t, f)
			if _, _, err := f.svc.LinkPendingOIDC(t.Context(), pr, pending); !errors.Is(err, tc.want) {
				t.Fatalf("LinkPendingOIDC = %v, want %v", err, tc.want)
			}
			if got := storedUser(t, f.mem, f.u.ID).OIDC; got != tc.kept {
				t.Errorf("alice's link = %+v, want %+v", got, tc.kept)
			}
			if got := kindsOf(f.events); len(got) != 0 {
				t.Errorf("events = %v, want none", got)
			}
			if tc.name != "already_linked" {
				return
			}
			me, err := f.svc.Me(t.Context(), pr)
			if err != nil || me.CanLinkOIDC {
				t.Errorf("Me of a linked user = %+v, %v; want CanLinkOIDC false", me, err)
			}
		})
	}
}

// linkFixture is an oidcFixture over an IdP for subject-y, with alice
// holding a password.
func linkFixture(t *testing.T, o pwOptions) (*oidcFixture, *access.User) {
	t.Helper()
	f := newOIDCFixture(t, rigFor(t, "subject-y"), o)
	return f, passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
}

func TestOIDCLinkIntent(t *testing.T) {
	t.Parallel()
	t.Run("links", func(t *testing.T) {
		t.Parallel()
		f, u := linkFixture(t, pwOptions{})
		sess := putSession(t, f.mem, liveSession(t, u))
		flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil {
			t.Fatalf("OIDCComplete = %v", err)
		}
		if out.Kind != account.OutcomeLinked || out.Redirect != "/settings" || out.Issued.Session.ID != sess.ID {
			t.Fatalf("outcome = %+v, want Linked with sess rotated and Redirect /settings", out)
		}
		if got := storedSession(t, f.mem, u.ID, sess.ID); !got.TokenHash.Equal(access.SessionHash(out.Issued.Token.Reveal())) || got.TokenHash.Equal(sess.TokenHash) {
			t.Error("the stored session does not hold the issued token")
		}
		if got := storedUser(t, f.mem, u.ID).OIDC; got != f.rig.identity() {
			t.Errorf("stored link = %+v, want %+v", got, f.rig.identity())
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventOIDCLinked || evs[0].Actor != (account.EventActor{SessionID: sess.ID, UserID: u.ID}) {
			t.Errorf("events = %+v, want EventOIDCLinked by alice's session", evs)
		}
	})
	t.Run("recent_auth_rule", func(t *testing.T) {
		t.Parallel()
		f, u := linkFixture(t, pwOptions{rules: rulesWith(func(r *account.Rules) { r.RecentAuth = 30 * time.Minute })})
		sess := putSession(t, f.mem, liveSession(t, u))
		flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
		flow.BeganAt = flow.BeganAt.Add(-20 * time.Minute)
		if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeLinked {
			t.Errorf("a flow begun 20m ago under RecentAuth 30m = %+v, %v; want Linked", out, err)
		}
	})
	identityX := access.OIDCIdentity{Issuer: oidcIssuer, Subject: "subject-x"}
	for _, tc := range []struct {
		session func(s *access.Session)                                                 // edits the stored session
		after   func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session) // runs between Finish and OIDCComplete
		flow    func(t *testing.T, f *oidcFixture, fl *oidc.Flow)
		pol     account.Policy
		want    error
		name    string
		kept    access.OIDCIdentity
		admin   bool
		sso     bool
	}{
		{name: "revoked_mid_flight", want: account.ErrSessionGone, after: func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session) {
			if err := f.mem.DeleteSession(t.Context(), access.SessionRef{ID: sess.ID, UserID: u.ID}); err != nil {
				t.Fatalf("DeleteSession: %v", err)
			}
		}},
		{name: "idle_expired_unswept", want: account.ErrSessionGone, session: func(s *access.Session) {
			s.LastActivity = time.Now().Add(-access.DefaultIdleTimeout - time.Minute)
		}},
		{name: "past_own_idle_cap", want: account.ErrSessionGone, session: func(s *access.Session) {
			s.IdleCap, s.LastActivity = 5*time.Minute, time.Now().Add(-10*time.Minute)
		}},
		{name: "recovery_session", want: account.ErrSessionGone, session: func(s *access.Session) {
			s.Kind, s.AuthMethod = access.SessionRecovery, access.MethodRecovery
		}},
		{name: "disabled_user", want: account.ErrSessionGone, after: func(t *testing.T, f *oidcFixture, u *access.User, _ access.Session) {
			stored := storedUser(t, f.mem, u.ID)
			stored.Enabled = false
			if err := f.mem.UpdateUser(t.Context(), stored); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
		{name: "another_users_session", want: account.ErrSessionGone, flow: func(t *testing.T, f *oidcFixture, fl *oidc.Flow) {
			fl.UserID = passwordUser(t, f.mem, nil, "bob", "").ID
		}},
		{name: "stale_flow", want: access.ErrRecentAuthRequired, flow: func(_ *testing.T, _ *oidcFixture, fl *oidc.Flow) {
			fl.BeganAt = fl.BeganAt.Add(-11 * time.Minute)
		}},
		{name: "future_flow", want: access.ErrRecentAuthRequired, flow: func(_ *testing.T, _ *oidcFixture, fl *oidc.Flow) {
			fl.BeganAt = time.Now().Add(time.Minute)
		}},
		{name: "already_linked", want: account.ErrAlreadyLinked, kept: identityX, after: func(t *testing.T, f *oidcFixture, u *access.User, _ access.Session) {
			linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), identityX)
		}},
		{name: "identity_taken", want: account.ErrOIDCIdentityTaken, after: func(t *testing.T, f *oidcFixture, _ *access.User, _ access.Session) {
			linkIdentity(t, f.mem, passwordUser(t, f.mem, nil, "bob", ""), f.rig.identity())
		}},
		{name: "last_local_admin", want: account.ErrPolicyRefused, admin: true, sso: true, pol: account.RolePolicy{KeepLocalAdmin: true}},
		{name: "identity_taken_before_migration", want: account.ErrOIDCIdentityTaken, admin: true, sso: true, pol: account.RolePolicy{KeepLocalAdmin: true}, after: func(t *testing.T, f *oidcFixture, _ *access.User, _ access.Session) {
			linkIdentity(t, f.mem, passwordUser(t, f.mem, nil, "bob", ""), f.rig.identity())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, u := linkFixture(t, pwOptions{
				rules: rulesWith(func(r *account.Rules) { r.SSOGoverned = tc.sso }),
				edit: func(c *account.Config) {
					if tc.pol != nil {
						c.Policy = tc.pol
					}
				},
			})
			if tc.admin {
				u.Role = access.RoleAdmin
				if err := f.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
			}
			s := liveSession(t, u)
			if tc.session != nil {
				tc.session(&s)
			}
			sess := putSession(t, f.mem, s)
			flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
			if tc.flow != nil {
				tc.flow(t, f, &flow)
			}
			if tc.after != nil {
				tc.after(t, f, u, sess)
			}
			_, err := f.complete(t, localClient, flow, claims)
			if !errors.Is(err, tc.want) {
				t.Fatalf("OIDCComplete = %v, want %v", err, tc.want)
			}
			stored := storedUser(t, f.mem, u.ID)
			if stored.OIDC != tc.kept {
				t.Errorf("alice's link = %+v, want %+v", stored.OIDC, tc.kept)
			}
			if stored.PasswordHash.IsZero() {
				t.Error("a refused link removed the password")
			}
			if got := kindsOf(f.events); len(got) != 0 {
				t.Errorf("events = %v, want none", got)
			}
		})
	}
}

func TestOIDCSSOMigration(t *testing.T) {
	t.Parallel()
	paths := map[string]func(t *testing.T, f *oidcFixture, u *access.User) (string, error){
		"intent_link": func(t *testing.T, f *oidcFixture, u *access.User) (string, error) {
			sess := putSession(t, f.mem, liveSession(t, u))
			flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
			_, err := f.complete(t, localClient, flow, claims)
			return sess.ID, err
		},
		"pending_link": func(t *testing.T, f *oidcFixture, u *access.User) (string, error) {
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil || out.Kind != account.OutcomeNotLinked {
				t.Fatalf("OIDCComplete = %+v, %v; want NotLinked", out, err)
			}
			pr, _ := f.signedInVia(t, u, access.MethodPassword)
			_, _, err = f.svc.LinkPendingOIDC(t.Context(), pr, out.Pending)
			return pr.SessionID, err
		},
	}
	for path, link := range paths {
		for _, tc := range []struct {
			name       string
			governed   bool
			revokeKeys bool
		}{
			{name: "governed_revoking_keys", governed: true, revokeKeys: true},
			{name: "governed_keeping_keys", governed: true},
			{name: "not_governed", revokeKeys: true},
		} {
			t.Run(path+"_"+tc.name, func(t *testing.T) {
				t.Parallel()
				f, u := linkFixture(t, pwOptions{rules: rulesWith(func(r *account.Rules) {
					r.SSOGoverned, r.RevokeKeysOnCredentialChange = tc.governed, tc.revokeKeys
				})})
				pk1, pk2 := addPasskey(t, f.mem, u, rpID), addPasskey(t, f.mem, u, rpID)
				_, key := f.keyPrincipalFor(t, nil, u, time.Time{}, nil)
				_, issued := access.NewOneTimeToken(access.PurposeInvite, 0, time.Hour, time.Now())
				issued.IssuedByKey = key.ID
				if err := f.mem.CreateOneTimeToken(t.Context(), issued); err != nil {
					t.Fatalf("CreateOneTimeToken: %v", err)
				}
				other := putSession(t, f.mem, liveSession(t, u))
				current, err := link(t, f, u)
				if err != nil {
					t.Fatalf("link = %v", err)
				}
				stored := storedUser(t, f.mem, u.ID)
				if stored.OIDC != f.rig.identity() {
					t.Fatalf("stored link = %+v, want %+v", stored.OIDC, f.rig.identity())
				}
				passkeys := len(passkeysOf(t, f.mem, u.ID))
				keys, err := f.mem.ListAPIKeysByUserID(t.Context(), u.ID)
				if err != nil {
					t.Fatalf("ListAPIKeysByUserID: %v", err)
				}
				_, tokenKept, err := f.mem.OneTimeTokenByHash(t.Context(), issued.Hash)
				if err != nil {
					t.Fatalf("OneTimeTokenByHash: %v", err)
				}
				ids := make([]string, 0, 2)
				for _, s := range sessionsOf(t, f.mem, u.ID) {
					ids = append(ids, s.ID)
				}
				slices.Sort(ids)
				keysGone := tc.governed && tc.revokeKeys
				if got := !stored.PasswordHash.IsZero(); got == tc.governed {
					t.Errorf("password held = %v, want %v", got, !tc.governed)
				}
				if want := map[bool]int{true: 0, false: 2}[tc.governed]; passkeys != want {
					t.Errorf("passkeys = %d, want %d", passkeys, want)
				}
				if (len(keys) == 0) != keysGone || tokenKept == keysGone {
					t.Errorf("keys = %d, issued token kept %v; want keys deleted with their tokens = %v", len(keys), tokenKept, keysGone)
				}
				wantIDs := []string{current}
				if !tc.governed {
					wantIDs = append(wantIDs, other.ID)
					slices.Sort(wantIDs)
				}
				if !slices.Equal(ids, wantIDs) {
					t.Errorf("sessions = %v, want %v", ids, wantIDs)
				}
				want := []account.EventKind{account.EventOIDCLinked}
				if tc.governed {
					want = append(want, account.EventPasswordRemoved, account.EventPasskeyRemoved, account.EventPasskeyRemoved)
					if keysGone {
						want = append(want, account.EventKeyRevoked)
					}
					want = append(want, account.EventUserSessionsRevoked)
				}
				if got := kindsOf(f.events); !slices.Equal(got, want) {
					t.Fatalf("events = %v, want %v", got, want)
				}
				if !tc.governed {
					return
				}
				removed := eventsOf(f.events, account.EventPasskeyRemoved)
				if removed[0].PasskeyID != pk1.ID || removed[1].PasskeyID != pk2.ID {
					t.Errorf("EventPasskeyRemoved IDs = %d, %d; want %d, %d", removed[0].PasskeyID, removed[1].PasskeyID, pk1.ID, pk2.ID)
				}
				if ev := eventsOf(f.events, account.EventUserSessionsRevoked)[0]; !slices.Equal(ev.SessionIDs, []string{other.ID}) {
					t.Errorf("EventUserSessionsRevoked = %v, want the other session", ev.SessionIDs)
				}
			})
		}
	}
}

func TestOIDCStepUp(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, edit func(*access.Session)) (*oidcFixture, *access.User, access.Session) {
		t.Helper()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, u, f.rig.identity())
		s := liveSession(t, u)
		s.AuthTime = time.Now().Add(-time.Hour)
		if edit != nil {
			edit(&s)
		}
		return f, u, putSession(t, f.mem, s)
	}
	t.Run("rotates", func(t *testing.T) {
		t.Parallel()
		f, u, sess := setup(t, nil)
		flow, claims := f.rig.sessionFlow(t, oidc.IntentStepUp, u, sess.ID)
		start := time.Now()
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil {
			t.Fatalf("OIDCComplete = %v", err)
		}
		if out.Kind != account.OutcomeSteppedUp || out.Redirect != "/settings" || out.Issued.Session.ID != sess.ID {
			t.Fatalf("outcome = %+v, want SteppedUp on sess with Redirect /settings", out)
		}
		got := storedSession(t, f.mem, u.ID, sess.ID)
		if !got.TokenHash.Equal(access.SessionHash(out.Issued.Token.Reveal())) || got.AuthMethod != access.MethodOIDC || got.AuthTime.Before(start) {
			t.Errorf("stored session = %+v, want the issued token, AuthMethod oidc and AuthTime now", got)
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventSteppedUp || evs[0].Method != access.MethodOIDC || !slices.Equal(evs[0].SessionIDs, []string{sess.ID}) {
			t.Errorf("events = %+v, want one OIDC EventSteppedUp for sess", evs)
		}
	})
	for _, tc := range []struct {
		session func(*access.Session)
		after   func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session)
		want    error
		name    string
		zero    bool // claims carry the zero identity
	}{
		{name: "idle_expired_not_revived", want: account.ErrSessionGone, session: func(s *access.Session) {
			s.LastActivity = time.Now().Add(-access.DefaultIdleTimeout - time.Minute)
		}},
		{name: "past_own_idle_cap", want: account.ErrSessionGone, session: func(s *access.Session) {
			s.IdleCap, s.LastActivity = 5*time.Minute, time.Now().Add(-10*time.Minute)
		}},
		{name: "revoked_mid_flight", want: account.ErrSessionGone, after: func(t *testing.T, f *oidcFixture, u *access.User, sess access.Session) {
			if err := f.mem.DeleteSession(t.Context(), access.SessionRef{ID: sess.ID, UserID: u.ID}); err != nil {
				t.Fatalf("DeleteSession: %v", err)
			}
		}},
		{name: "other_identity", want: account.ErrInvalidCredentials, after: func(t *testing.T, f *oidcFixture, u *access.User, _ access.Session) {
			linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "subject-x"})
		}},
		{name: "unlinked_user", want: account.ErrInvalidCredentials, after: func(t *testing.T, f *oidcFixture, u *access.User, _ access.Session) {
			linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{})
		}},
		{name: "zero_claims_unlinked_user", want: account.ErrInvalidCredentials, zero: true, after: func(t *testing.T, f *oidcFixture, u *access.User, _ access.Session) {
			linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, u, sess := setup(t, tc.session)
			flow, claims := f.rig.sessionFlow(t, oidc.IntentStepUp, u, sess.ID)
			if tc.after != nil {
				tc.after(t, f, u, sess)
			}
			if tc.zero {
				claims.Identity = access.OIDCIdentity{}
			}
			if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, tc.want) {
				t.Fatalf("OIDCComplete = %v, want %v", err, tc.want)
			}
			for _, got := range sessionsOf(t, f.mem, u.ID) {
				if !got.TokenHash.Equal(sess.TokenHash) || got.AuthMethod != access.MethodPassword || !got.LastActivity.Equal(sess.LastActivity) {
					t.Errorf("session after a refused step-up = %+v, want it unchanged", got)
				}
			}
			if evs := f.events.all(); len(evs) != 0 {
				t.Errorf("events = %+v, want none", evs)
			}
		})
	}
}

func TestOIDCDeviceCookie(t *testing.T) {
	t.Parallel()
	// One failure fills a device's bucket, so a cookie whose device ID is
	// kept is refused at once and a fresh device is admitted.
	oneFailure := func(c *ratelimit.Config) { c.Device = ratelimit.Rate{Limit: 1, Window: time.Hour} }
	setup := func(t *testing.T) (*oidcFixture, *access.User, access.Secret) {
		t.Helper()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{limiter: oneFailure})
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, u, f.rig.identity())
		spent := f.deviceCookie(t, localClient, "alice", goodPassword)
		c := localClient
		c.Device = spent
		if _, err := f.login(t.Context(), c, "alice", wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("wrong password on the device = %v", err)
		}
		return f, u, spent
	}
	// keeps reports whether cookie names the spent device: a password
	// attempt carrying it is refused by that device's bucket.
	keeps := func(t *testing.T, f *oidcFixture, cookie access.Secret) bool {
		t.Helper()
		if cookie.IsZero() {
			t.Fatal("no device cookie was returned")
		}
		c := localClient
		c.Device = cookie
		_, err := f.login(t.Context(), c, "alice", goodPassword)
		return errors.Is(err, ratelimit.ErrRefused)
	}
	for name, outcomeCookie := range map[string]func(t *testing.T, f *oidcFixture, u *access.User, c account.Client) access.Secret{
		"sign_in": func(t *testing.T, f *oidcFixture, _ *access.User, c account.Client) access.Secret {
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, c, flow, claims)
			if err != nil || out.Kind != account.OutcomeSignedIn {
				t.Fatalf("OIDC sign-in = %+v, %v", out, err)
			}
			return out.SignedIn.DeviceCookie
		},
		"step_up": func(t *testing.T, f *oidcFixture, u *access.User, c account.Client) access.Secret {
			sess := putSession(t, f.mem, liveSession(t, u))
			flow, claims := f.rig.sessionFlow(t, oidc.IntentStepUp, u, sess.ID)
			out, err := f.complete(t, c, flow, claims)
			if err != nil || out.Kind != account.OutcomeSteppedUp {
				t.Fatalf("OIDC step-up = %+v, %v", out, err)
			}
			return out.Issued.DeviceCookie
		},
	} {
		t.Run(name+"_keeps_device", func(t *testing.T) {
			t.Parallel()
			f, u, spent := setup(t)
			c := localClient
			c.Device = spent
			if !keeps(t, f, outcomeCookie(t, f, u, c)) {
				t.Error("the device cookie names a new device, want the presented one kept")
			}
		})
		t.Run(name+"_new_device", func(t *testing.T) {
			t.Parallel()
			f, u, _ := setup(t)
			if keeps(t, f, outcomeCookie(t, f, u, localClient)) {
				t.Error("with no device presented, the cookie names the spent device")
			}
		})
	}
}

func TestUnlinkLastUsable(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, o pwOptions, password bool) (*oidcFixture, *access.User) {
		t.Helper()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), o)
		h := f.hasher
		if !password {
			h = nil
		}
		u := passwordUser(t, f.mem, h, "alice", goodPassword)
		linkIdentity(t, f.mem, u, f.rig.identity())
		return f, u
	}
	unlink := func(t *testing.T, f *oidcFixture, u *access.User) error {
		t.Helper()
		pr, _ := f.signedInVia(t, u, access.MethodPassword)
		return f.svc.UnlinkOIDC(t.Context(), pr)
	}
	t.Run("foreign_passkey_then_matching", func(t *testing.T) {
		t.Parallel()
		f, u := setup(t, pwOptions{}, false)
		addPasskey(t, f.mem, u, foreignRP)
		if err := unlink(t, f, u); !errors.Is(err, account.ErrLastMethod) {
			t.Fatalf("unlink with only a foreign passkey left = %v, want ErrLastMethod", err)
		}
		if got := storedUser(t, f.mem, u.ID).OIDC; got != f.rig.identity() || len(f.events.all()) != 0 {
			t.Fatalf("after the refusal: link %+v, events %+v; want the link kept and no event", got, f.events.all())
		}
		addPasskey(t, f.mem, u, rpID)
		pr, _ := f.signedInVia(t, u, access.MethodPassword)
		if err := f.svc.UnlinkOIDC(t.Context(), pr); err != nil {
			t.Fatalf("unlink with a matching passkey = %v", err)
		}
		if got := storedUser(t, f.mem, u.ID).OIDC; !got.IsZero() {
			t.Errorf("link after the unlink = %+v, want none", got)
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventOIDCUnlinked || evs[0].UserID != u.ID || evs[0].Actor.SessionID != pr.SessionID {
			t.Errorf("events = %+v, want one EventOIDCUnlinked by the session", evs)
		}
	})
	for _, tc := range []struct {
		arrange  func(t *testing.T, f *oidcFixture, u *access.User)
		rules    func(*account.Rules)
		want     error
		name     string
		password bool
		noOIDC   bool
	}{
		{name: "password_held", password: true},
		{name: "password_login_disabled", password: true, want: account.ErrLastMethod, rules: func(r *account.Rules) { r.DisablePasswordLogin = true }},
		{name: "password_locked_in_both", password: true, want: account.ErrLastMethod, arrange: func(t *testing.T, f *oidcFixture, u *access.User) {
			lockPassword(t, f.mem, f.svc, u, false)
			lockPassword(t, f.mem, f.svc, u, true)
		}},
		{name: "password_locked_untrusted", password: true, arrange: func(t *testing.T, f *oidcFixture, u *access.User) {
			lockPassword(t, f.mem, f.svc, u, false)
		}},
		{name: "no_provider", password: true, noOIDC: true},
		{name: "not_linked", password: true, want: account.ErrNotFound, arrange: func(t *testing.T, f *oidcFixture, u *access.User) {
			linkIdentity(t, f.mem, storedUser(t, f.mem, u.ID), access.OIDCIdentity{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := pwOptions{}
			if tc.rules != nil {
				o.rules = rulesWith(tc.rules)
			}
			if tc.noOIDC {
				o.edit = func(c *account.Config) { c.OIDC = nil }
			}
			f, u := setup(t, o, tc.password)
			if tc.arrange != nil {
				tc.arrange(t, f, u)
			}
			before := storedUser(t, f.mem, u.ID).OIDC
			err := unlink(t, f, u)
			if !errors.Is(err, tc.want) {
				t.Fatalf("UnlinkOIDC = %v, want %v", err, tc.want)
			}
			after := storedUser(t, f.mem, u.ID).OIDC
			if tc.want != nil && (after != before || len(f.events.all()) != 0) {
				t.Errorf("a refused unlink: link %+v (was %+v), events %+v; want nothing written", after, before, f.events.all())
			}
			if tc.want == nil && !after.IsZero() {
				t.Errorf("link after the unlink = %+v, want none", after)
			}
		})
	}
	t.Run("stale_session", func(t *testing.T) {
		t.Parallel()
		f, u := setup(t, pwOptions{}, true)
		pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour))
		if err := f.svc.UnlinkOIDC(t.Context(), pr); !errors.Is(err, access.ErrRecentAuthRequired) {
			t.Errorf("UnlinkOIDC from a stale session = %v, want ErrRecentAuthRequired", err)
		}
	})
}

func TestOIDCUnavailable(t *testing.T) {
	t.Parallel()
	rig := newOIDCRig(t, accesstest.IdPOptions{})
	f := newPW(t, pwOptions{})
	u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	flow, claims := rig.signInFlow(t)
	if _, err := f.svc.OIDCComplete(t.Context(), localClient, flow, claims); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("OIDCComplete with no provider = %v, want ErrOIDCUnavailable", err)
	}
	pr, _ := f.signedInVia(t, u, access.MethodPassword)
	if _, _, err := f.svc.LinkPendingOIDC(t.Context(), pr, account.PendingLink{Identity: rig.identity()}); !errors.Is(err, account.ErrOIDCUnavailable) {
		t.Errorf("LinkPendingOIDC with no provider = %v, want ErrOIDCUnavailable", err)
	}
	if got := storedUser(t, f.mem, u.ID).OIDC; !got.IsZero() {
		t.Errorf("link = %+v, want none", got)
	}
	withProvider := newOIDCFixture(t, rig, pwOptions{})
	flow.Intent = "elsewhere"
	if _, err := withProvider.complete(t, localClient, flow, claims); !errors.Is(err, oidc.ErrFlowInvalid) {
		t.Errorf("OIDCComplete of an unknown intent = %v, want oidc.ErrFlowInvalid", err)
	}
}
