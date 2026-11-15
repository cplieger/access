package account_test

import (
	"encoding/json"
	"errors"
	"maps"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// withClaim is claims with name set to the raw JSON value, or removed when
// raw is empty.
func withClaim(claims oidc.Claims, name, raw string) oidc.Claims {
	claims.Raw = maps.Clone(claims.Raw)
	if claims.Raw == nil {
		claims.Raw = map[string]json.RawMessage{}
	}
	if raw == "" {
		delete(claims.Raw, name)
	} else {
		claims.Raw[name] = json.RawMessage(raw)
	}
	return claims
}

// staffAdmission admits a token whose groups claim holds "staff".
func staffAdmission(r *account.Rules) {
	r.OIDCAdmission = account.OIDCAdmission{Claim: "groups", AllowedValues: []string{"staff"}}
}

// TestOIDCIdentityIsIssuerAndSubject: OpenID Connect Core 1.0 §5.7, only
// (iss, sub) identifies an end user; neither email nor preferred_username
// ever links, selects or creates an account.
func TestOIDCIdentityIsIssuerAndSubject(t *testing.T) {
	t.Parallel()
	for _, prov := range []bool{false, true} {
		rules := rulesWith(func(r *account.Rules) { r.Provisioning.Enabled = prov })
		suffix := map[bool]string{false: "_provisioning_off", true: "_provisioning_on"}[prov]
		// Vaultwarden GHSA-6x5c-84vm-5j56: an email match bound an existing
		// account, verified or not.
		for _, verified := range []bool{false, true} {
			t.Run("email_match_verified_"+map[bool]string{false: "false", true: "true"}[verified]+suffix, func(t *testing.T) {
				t.Parallel()
				f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{EmailVerified: verified}), pwOptions{rules: rules})
				mustOwner(t, f.mem, "owner")
				bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
				bob.Email = accesstest.DefaultIdPEmail
				if err := f.mem.UpdateUser(t.Context(), bob); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
				flow, claims := f.rig.signInFlow(t)
				out, err := f.complete(t, localClient, flow, claims)
				if err != nil {
					t.Fatalf("OIDCComplete = %v", err)
				}
				if out.SignedIn.User != nil && out.SignedIn.User.ID == bob.ID {
					t.Errorf("signed in bob by his email")
				}
				if got := storedUser(t, f.mem, bob.ID).OIDC; !got.IsZero() {
					t.Errorf("bob linked to %+v by his email", got)
				}
			})
		}
		// authentik GHSA-35v6-hv2g-6992, django-allauth GHSA-8m3c-c723-h4p4,
		// ash_authentication GHSA-777c-2fxx-qr28: a username match took over
		// the account; the hint never authorises.
		t.Run("username_match"+suffix, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: rules})
			mustOwner(t, f.mem, "owner")
			held := passwordUser(t, f.mem, f.hasher, accesstest.DefaultIdPUsername, goodPassword)
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil || out.Kind != account.OutcomeNotLinked {
				t.Fatalf("OIDCComplete = %+v, %v; want NotLinked", out, err)
			}
			if got := storedUser(t, f.mem, held.ID).OIDC; !got.IsZero() {
				t.Errorf("the account named by the hint was linked to %+v", got)
			}
		})
	}
	t.Run("renamed_preferred_username", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, alice, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil || out.SignedIn.User == nil || out.SignedIn.User.ID != alice.ID {
			t.Fatalf("OIDCComplete = %+v, %v; want alice signed in", out, err)
		}
		if got := storedUser(t, f.mem, alice.ID); got.Username != "alice" || got.OIDC != f.rig.identity() {
			t.Errorf("alice = %+v, want her name and link unchanged by the token's preferred_username", got)
		}
	})
	// Grafana CVE-2023-3128: the comparison is exact on both parts.
	for name, id := range map[string]access.OIDCIdentity{
		"subject_prefix": {Issuer: oidcIssuer, Subject: accesstest.DefaultIdPSubject[:len(accesstest.DefaultIdPSubject)-1]},
		"subject_suffix": {Issuer: oidcIssuer, Subject: accesstest.DefaultIdPSubject + "x"},
		"subject_case":   {Issuer: oidcIssuer, Subject: "Accesstest-subject"},
		"issuer_prefix":  {Issuer: oidcIssuer[:len(oidcIssuer)-1], Subject: accesstest.DefaultIdPSubject},
		"issuer_slash":   {Issuer: oidcIssuer + "/", Subject: accesstest.DefaultIdPSubject},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
			alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			linkIdentity(t, f.mem, alice, id)
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil || out.Kind != account.OutcomeNotLinked {
				t.Errorf("OIDCComplete for an identity near alice's = %+v, %v; want NotLinked", out, err)
			}
		})
	}
}

// TestOIDCAdmission: design 5.4, Rules.OIDCAdmission is checked at every
// intent before any write, owners included, and a refusal is journalled.
func TestOIDCAdmission(t *testing.T) {
	t.Parallel()
	admitted := rulesWith(staffAdmission)
	t.Run("sign_in", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: admitted})
		owner := mustOwner(t, f.mem, "owner")
		linkIdentity(t, f.mem, owner, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Fatalf("an owner's sign-in outside the group = %v, want ErrNotAdmitted", err)
		}
		if n := len(sessionsOf(t, f.mem, owner.ID)); n != 0 {
			t.Errorf("owner holds %d sessions, want 0", n)
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventOIDCNotAdmitted || evs[0].UserID != owner.ID || evs[0].Method != access.MethodOIDC {
			t.Errorf("events = %+v, want one oidc_not_admitted for the owner", evs)
		}
	})
	t.Run("sign_in_unlinked", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: rulesWith(func(r *account.Rules) {
			staffAdmission(r)
			r.Provisioning.Enabled = true
		})})
		mustOwner(t, f.mem, "owner")
		flow, claims := f.rig.signInFlow(t)
		out, err := f.complete(t, localClient, flow, claims)
		if !errors.Is(err, account.ErrNotAdmitted) || out.Kind == account.OutcomeNotLinked {
			t.Fatalf("an unknown identity outside the group = %+v, %v; want ErrNotAdmitted and no pending link", out, err)
		}
		if n := userCount(t, f.fixture); n != 1 {
			t.Errorf("users = %d, want only the owner: provisioning reads admission", n)
		}
		if evs := f.events.all(); len(evs) != 1 || evs[0].Kind != account.EventOIDCNotAdmitted || evs[0].UserID != 0 {
			t.Errorf("events = %+v, want one oidc_not_admitted naming no user", evs)
		}
	})
	t.Run("link", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, rigFor(t, "subject-y"), pwOptions{rules: admitted})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sess := putSession(t, f.mem, liveSession(t, alice))
		flow, claims := f.rig.sessionFlow(t, oidc.IntentLink, alice, sess.ID)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Fatalf("a link outside the group = %v, want ErrNotAdmitted", err)
		}
		if got := storedUser(t, f.mem, alice.ID).OIDC; !got.IsZero() {
			t.Errorf("alice linked to %+v", got)
		}
		if got := storedSession(t, f.mem, alice.ID, sess.ID); !got.TokenHash.Equal(sess.TokenHash) {
			t.Error("the refused link rotated alice's session")
		}
		if evs := f.events.all(); len(evs) != 1 || evs[0].Kind != account.EventOIDCNotAdmitted || evs[0].UserID != alice.ID {
			t.Errorf("events = %+v, want one oidc_not_admitted for alice", evs)
		}
	})
	t.Run("step_up", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: admitted})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, alice, f.rig.identity())
		s := liveSession(t, alice)
		s.AuthTime = time.Now().Add(-time.Hour)
		sess := putSession(t, f.mem, s)
		flow, claims := f.rig.sessionFlow(t, oidc.IntentStepUp, alice, sess.ID)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Fatalf("a step-up outside the group = %v, want ErrNotAdmitted", err)
		}
		if got := storedSession(t, f.mem, alice.ID, sess.ID); !got.TokenHash.Equal(sess.TokenHash) || !got.AuthTime.Equal(sess.AuthTime) {
			t.Error("the refused step-up rotated alice's session")
		}
	})
	// design 5.4 "Readable shapes": a string or an array of strings; Entra
	// sends one group as a string and several as an array.
	for name, tc := range map[string]struct {
		raw  string
		want error
	}{
		"string":           {raw: `"staff"`},
		"array":            {raw: `["guests","staff"]`},
		"absent":           {want: account.ErrNotAdmitted},
		"other_string":     {raw: `"guests"`, want: account.ErrNotAdmitted},
		"case_differs":     {raw: `"Staff"`, want: account.ErrNotAdmitted},
		"number":           {raw: `7`, want: account.ErrNotAdmitted},
		"array_with_other": {raw: `["guests",7,"staff"]`, want: account.ErrNotAdmitted},
		"null":             {raw: `null`, want: account.ErrNotAdmitted},
		"empty_array":      {raw: `[]`, want: account.ErrNotAdmitted},
	} {
		t.Run("shape_"+name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: admitted})
			alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			linkIdentity(t, f.mem, alice, f.rig.identity())
			flow, claims := f.rig.signInFlow(t)
			_, err := f.complete(t, localClient, flow, withClaim(claims, "groups", tc.raw))
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("groups %s: OIDCComplete = %v, want %v", tc.raw, err, tc.want)
			}
		})
	}
	// design 5.1: Entra's group overage replaces the claim with
	// _claim_names, which admission cannot read and so refuses.
	t.Run("entra_overage", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: admitted})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, alice, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		claims = withClaim(claims, "groups", "")
		claims = withClaim(claims, "_claim_names", `{"groups":"src1"}`)
		claims = withClaim(claims, "_claim_sources", `{"src1":{"endpoint":"https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}`)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Errorf("an overage token = %v, want ErrNotAdmitted", err)
		}
	})
	t.Run("unset_admits", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, alice, f.rig.identity())
		flow, claims := f.rig.signInFlow(t)
		if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeSignedIn {
			t.Errorf("OIDCComplete with no admission rule = %+v, %v; want SignedIn", out, err)
		}
	})
}

// TestSingleUserOIDCIdentity: design 5.4, a single-user app accepts no
// identity but the owner's, refused as invalid credentials at sign-in and
// step-up whatever its claims, and the owner's own identity still meets
// OIDCAdmission.
func TestSingleUserOIDCIdentity(t *testing.T) {
	t.Parallel()
	for name, pol := range singleUserPolicies() {
		setup := func(t *testing.T, rules func() account.Rules) (*oidcFixture, *access.User, *oidcRig) {
			t.Helper()
			other := rigFor(t, "other-subject")
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{Groups: "staff"}), pwOptions{rules: rules, edit: func(c *account.Config) { c.Policy = pol }})
			owner := mustOwner(t, f.mem, "owner")
			linkIdentity(t, f.mem, owner, f.rig.identity())
			return f, owner, other
		}
		t.Run(name+"/other_identity_sign_in", func(t *testing.T) {
			t.Parallel()
			f, _, other := setup(t, nil)
			flow, claims := other.signInFlow(t)
			out, err := f.complete(t, localClient, flow, withClaim(claims, "groups", `"staff"`))
			if !errors.Is(err, account.ErrInvalidCredentials) || out.Kind == account.OutcomeNotLinked {
				t.Fatalf("another identity's sign-in = %+v, %v; want ErrInvalidCredentials and no pending link", out, err)
			}
			if n := userCount(t, f.fixture); n != 1 {
				t.Errorf("users = %d, want the owner alone", n)
			}
			if evs := f.events.all(); len(evs) != 0 {
				t.Errorf("events = %+v, want none", evs)
			}
		})
		t.Run(name+"/other_identity_step_up", func(t *testing.T) {
			t.Parallel()
			f, owner, other := setup(t, nil)
			sess := putSession(t, f.mem, liveSession(t, owner))
			flow, claims := other.sessionFlow(t, oidc.IntentStepUp, owner, sess.ID)
			if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("a step-up by another identity = %v, want ErrInvalidCredentials", err)
			}
		})
		t.Run(name+"/admission_unknown_identity", func(t *testing.T) {
			t.Parallel()
			f, _, other := setup(t, rulesWith(staffAdmission))
			flow, claims := other.signInFlow(t)
			if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("an unknown identity outside the group = %v, want ErrInvalidCredentials, which reveals no owner", err)
			}
		})
		t.Run(name+"/admission_owner_identity", func(t *testing.T) {
			t.Parallel()
			f, _, _ := setup(t, rulesWith(staffAdmission))
			flow, claims := f.rig.signInFlow(t)
			if _, err := f.complete(t, localClient, flow, withClaim(claims, "groups", `"guests"`)); !errors.Is(err, account.ErrNotAdmitted) {
				t.Errorf("the owner's identity outside the group = %v, want ErrNotAdmitted", err)
			}
		})
		for _, allowed := range []bool{false, true} {
			t.Run(name+"/owner_link_admitted_"+map[bool]string{false: "false", true: "true"}[allowed], func(t *testing.T) {
				t.Parallel()
				f, owner, other := setup(t, rulesWith(staffAdmission))
				linkIdentity(t, f.mem, owner, access.OIDCIdentity{})
				sess := putSession(t, f.mem, liveSession(t, owner))
				flow, claims := other.sessionFlow(t, oidc.IntentLink, owner, sess.ID)
				group := `"guests"`
				if allowed {
					group = `"staff"`
				}
				_, err := f.complete(t, localClient, flow, withClaim(claims, "groups", group))
				got := storedUser(t, f.mem, owner.ID).OIDC
				switch {
				case allowed && (err != nil || got != other.identity()):
					t.Errorf("the owner's admitted link = %v, link %+v; want linked", err, got)
				case !allowed && (!errors.Is(err, account.ErrNotAdmitted) || !got.IsZero()):
					t.Errorf("the owner's link outside the group = %v, link %+v; want ErrNotAdmitted and no link", err, got)
				}
			})
		}
	}
}

// TestProvisioningUnderSingleUser: design 5.4, checkRules refuses
// Provisioning.Enabled under a single-user Policy at every operation, so a
// reloaded Rules value cannot turn it on.
func TestProvisioningUnderSingleUser(t *testing.T) {
	t.Parallel()
	for name, pol := range singleUserPolicies() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var on atomic.Bool
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{
				rules: func() account.Rules { return account.Rules{Provisioning: account.Provisioning{Enabled: on.Load()}} },
				edit:  func(c *account.Config) { c.Policy = pol },
			})
			mustOwner(t, f.mem, "owner")
			on.Store(true)
			flow, claims := f.rig.signInFlow(t)
			_, err := f.complete(t, localClient, flow, claims)
			var re *account.RulesError
			if !errors.As(err, &re) || re.Field != "Provisioning" {
				t.Errorf("OIDCComplete after provisioning was turned on = %v, want a RulesError on Provisioning", err)
			}
			if n := userCount(t, f.fixture); n != 1 {
				t.Errorf("users = %d, want the owner alone", n)
			}
		})
	}
}
