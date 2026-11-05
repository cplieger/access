package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

const (
	adminScope = "admin"
	usersScope = "manage_users"
	keysScope  = "create_keys"
)

// principals are one of each kind a guard meets, for one admin user.
type principals struct {
	fresh, stale, recovery, bypass, zero access.Principal
	custom                               access.Principal // every scope, through a custom verifier
	customLabelledKey                    access.Principal
	keys                                 map[string]access.Principal
	unscoped                             access.Principal
}

func newPrincipals(t *testing.T, f *fixture) principals {
	t.Helper()
	u := mustUser(t, f.mem, "owner", access.RoleAdmin)
	ps := principals{
		fresh:             f.sessionPrincipal(t, u, access.SessionFull, time.Now()),
		stale:             f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour)),
		recovery:          f.sessionPrincipal(t, u, access.SessionRecovery, time.Now()),
		bypass:            f.bypassPrincipal(t),
		custom:            f.customPrincipal(t, "agent", 0, adminScope, usersScope, keysScope),
		customLabelledKey: f.customPrincipal(t, access.MethodAPIKey, 77, adminScope, usersScope, keysScope),
		keys:              map[string]access.Principal{},
	}
	for _, s := range []string{adminScope, usersScope, keysScope} {
		ps.keys[s] = f.keyPrincipal(t, u, s)
	}
	ps.unscoped = f.keyPrincipal(t, u)
	return ps
}

func TestRequireAdminScopeMatrix(t *testing.T) {
	t.Parallel()
	for name, scope := range map[string]string{"scope_set": adminScope, "scope_empty": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{edit: func(c *account.Config) { c.AdminScope = scope }})
			ps := newPrincipals(t, f)
			keyAnswer, otherAnswer := error(nil), account.ErrScopeRequired
			if scope == "" {
				keyAnswer, otherAnswer = account.ErrSessionRequired, account.ErrSessionRequired
			}
			for _, tc := range []struct {
				want error
				name string
				p    access.Principal
			}{
				{name: "fresh_session", p: ps.fresh},
				{name: "stale_session", p: ps.stale},
				{name: "recovery_session", p: ps.recovery, want: account.ErrSessionRequired},
				{name: "admin_scope_key", p: ps.keys[adminScope], want: keyAnswer},
				{name: "users_scope_key", p: ps.keys[usersScope], want: otherAnswer},
				{name: "keys_scope_key", p: ps.keys[keysScope], want: otherAnswer},
				{name: "unscoped_key", p: ps.unscoped, want: otherAnswer},
				{name: "custom_every_scope", p: ps.custom, want: otherAnswer},
				{name: "custom_labelled_key", p: ps.customLabelledKey, want: otherAnswer},
				{name: "bypass", p: ps.bypass, want: otherAnswer},
				{name: "zero", p: ps.zero, want: otherAnswer},
			} {
				if err := f.svc.RequireAdminScope(tc.p); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
					t.Errorf("%s: RequireAdminScope = %v, want %v", tc.name, err, tc.want)
				}
			}
		})
	}
}

func TestRequireKeyPermissionMatrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		scope string // the permission under test
		set   bool
	}{
		{name: "manage_users_set", scope: usersScope, set: true},
		{name: "manage_users_empty", scope: usersScope},
		{name: "create_keys_set", scope: keysScope, set: true},
		{name: "create_keys_empty", scope: keysScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{edit: func(c *account.Config) {
				c.AdminScope = adminScope
				if tc.set {
					c.ManageUsersScope, c.CreateKeysScope = usersScope, keysScope
				}
			}})
			ps := newPrincipals(t, f)
			scope := f.svc.ManageUsersScope()
			if tc.scope == keysScope {
				scope = f.svc.CreateKeysScope()
			}
			check := func(name string, p access.Principal, want error) {
				t.Helper()
				err := f.svc.RequireKeyPermission(p, scope)
				if (want == nil && err != nil) || !errors.Is(err, want) {
					t.Errorf("%s: RequireKeyPermission(%q) = %v, want %v", name, scope, err, want)
				}
			}
			check("fresh_session", ps.fresh, nil)
			check("stale_session", ps.stale, access.ErrRecentAuthRequired)
			check("recovery_session", ps.recovery, account.ErrSessionRequired)
			if !tc.set {
				for s, p := range ps.keys {
					check("key_"+s, p, account.ErrSessionRequired)
				}
				check("unscoped_key", ps.unscoped, account.ErrSessionRequired)
				check("custom_every_scope", ps.custom, account.ErrSessionRequired)
				check("custom_labelled_key", ps.customLabelledKey, account.ErrSessionRequired)
				check("bypass", ps.bypass, account.ErrSessionRequired)
				return
			}
			for s, p := range ps.keys {
				if s == tc.scope {
					check("key_"+s, p, nil)
				} else {
					check("key_"+s, p, account.ErrScopeRequired)
				}
			}
			check("unscoped_key", ps.unscoped, account.ErrScopeRequired)
			check("custom_every_scope", ps.custom, account.ErrScopeRequired)
			check("custom_labelled_key", ps.customLabelledKey, account.ErrScopeRequired)
			check("bypass", ps.bypass, account.ErrScopeRequired)
			check("zero", ps.zero, account.ErrScopeRequired)
		})
	}
}

func TestActorPrecondition(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	ps := newPrincipals(t, f)
	for _, tc := range []struct {
		want error
		name string
		p    access.Principal
	}{
		{name: "full_session", p: ps.fresh},
		{name: "stale_full_session", p: ps.stale},
		{name: "bypass", p: ps.bypass, want: account.ErrSessionRequired},
		{name: "key", p: ps.keys[adminScope], want: account.ErrSessionRequired},
		{name: "custom", p: ps.custom, want: account.ErrSessionRequired},
		{name: "recovery_session", p: ps.recovery, want: account.ErrSessionRequired},
		{name: "zero", p: ps.zero, want: account.ErrSessionRequired},
	} {
		if err := account.RequireSession(tc.p); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: RequireSession = %v, want %v", tc.name, err, tc.want)
		}
	}
	t.Run("actor_accessors", func(t *testing.T) {
		t.Parallel()
		if p, ok := account.As(ps.fresh).Principal(); !ok || p.SessionID != ps.fresh.SessionID {
			t.Errorf("As(p).Principal() = %v, %t, want p and true", p.SessionID, ok)
		}
		if _, ok := account.As(ps.fresh).OutOfBandChannel(); ok {
			t.Error("As(p).OutOfBandChannel() ok = true")
		}
		if ch, ok := account.OutOfBand("socket").OutOfBandChannel(); !ok || ch != "socket" {
			t.Errorf("OutOfBand(socket).OutOfBandChannel() = %q, %t", ch, ok)
		}
		if _, ok := account.OutOfBand("socket").Principal(); ok {
			t.Error("OutOfBand(socket).Principal() ok = true")
		}
		var zero account.Actor
		if _, ok := zero.Principal(); ok {
			t.Error("the zero Actor has a principal")
		}
		if _, ok := zero.OutOfBandChannel(); ok {
			t.Error("the zero Actor has a channel")
		}
	})
	t.Run("event_actor", func(t *testing.T) {
		t.Parallel()
		key := ps.keys[adminScope]
		for name, tc := range map[string]struct {
			a    account.Actor
			want account.EventActor
		}{
			"session":     {a: account.As(ps.fresh), want: account.EventActor{UserID: ps.fresh.User.ID, SessionID: ps.fresh.SessionID}},
			"key":         {a: account.As(key), want: account.EventActor{UserID: key.User.ID, KeyID: key.KeyID}},
			"out_of_band": {a: account.OutOfBand("socket"), want: account.EventActor{OutOfBand: "socket"}},
			"zero":        {},
		} {
			if got := account.EventActorOf(tc.a); got != tc.want {
				t.Errorf("%s: event actor = %+v, want %+v", name, got, tc.want)
			}
		}
	})
}
