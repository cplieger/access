package account_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// restart is a second New over f's store and Policy, as an app restart is.
func restart(t *testing.T, f *fixture) (*account.Service, error) {
	t.Helper()
	svc, err := account.New(t.Context(), ownAuthenticator(t, f.cfg))
	if err == nil {
		t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	}
	return svc, err
}

// storeUser stores u as given, with a WebAuthn handle.
func storeUser(t *testing.T, s account.Store, u access.User) *access.User {
	t.Helper()
	u.WebAuthnHandle = access.GenerateWebAuthnHandle()
	if err := s.CreateUser(t.Context(), &u); err != nil {
		t.Fatalf("CreateUser(%s): %v", u.Username, err)
	}
	return &u
}

// ownerNames is the usernames whose stored row carries the owner flag.
func ownerNames(t *testing.T, s account.Store) []string {
	t.Helper()
	users, err := s.ListUsers(t.Context())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var names []string
	for i := range users {
		if users[i].Owner {
			names = append(names, users[i].Username)
		}
	}
	slices.Sort(names)
	return names
}

// ownerEntries is every owner_set and owner_removed entry s holds.
func ownerEntries(t *testing.T, s account.Store) []account.LogEntry {
	t.Helper()
	var out []account.LogEntry
	for _, e := range logOf(t, s) {
		if e.Event.Kind == account.EventOwnerSet || e.Event.Kind == account.EventOwnerRemoved {
			out = append(out, e)
		}
	}
	return out
}

var (
	someHash = access.NewHash("$argon2id$owner-test")
	t0       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

// TestNewMarksOwner: on an existing store, New marks the enabled
// admin with the earliest CreatedAt, preferring one holding a local method,
// journals owner_set by "migration", and never reads IDs.
func TestNewMarksOwner(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		users      []access.User
		name       string
		wantOwners []string
		wantDetail string
		wantWarn   int
	}{
		{
			name: "earliest_admin_with_a_local_method",
			users: []access.User{
				{Username: "ex", Role: access.RoleAdmin, PasswordHash: someHash, CreatedAt: t0},
				{Username: "bare", Role: access.RoleAdmin, Enabled: true, CreatedAt: t0.Add(time.Hour)},
				{Username: "late", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0.Add(3 * time.Hour)},
				{Username: "local", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0.Add(2 * time.Hour)},
				{Username: "user", Role: access.RoleUser, Enabled: true, PasswordHash: someHash, CreatedAt: t0},
			},
			wantOwners: []string{"local"},
		},
		{
			name: "no_admin_holds_a_local_method",
			users: []access.User{
				{Username: "sso", Role: access.RoleAdmin, Enabled: true, CreatedAt: t0, OIDC: access.OIDCIdentity{Issuer: "https://idp.example", Subject: "s"}},
				{Username: "later", Role: access.RoleAdmin, Enabled: true, CreatedAt: t0.Add(time.Hour)},
			},
			wantOwners: []string{"sso"},
			wantDetail: account.LogDetailOwnerNeedsLocalMethod,
			wantWarn:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{})
			for i := range tc.users {
				storeUser(t, f.mem, tc.users[i])
			}
			warn := warnings(f.logs)
			if _, err := restart(t, f); err != nil {
				t.Fatalf("New = %v", err)
			}
			if got := ownerNames(t, f.mem); !slices.Equal(got, tc.wantOwners) {
				t.Errorf("owners = %v, want %v", got, tc.wantOwners)
			}
			entries := ownerEntries(t, f.mem)
			if len(entries) != 1 || entries[0].Event.Kind != account.EventOwnerSet || entries[0].Event.Actor.OutOfBand != "migration" || entries[0].Detail != tc.wantDetail {
				t.Errorf("owner entries = %+v, want one owner_set by migration with detail %q", entries, tc.wantDetail)
			}
			if got := warnings(f.logs) - warn; got != tc.wantWarn {
				t.Errorf("WARN records = %d, want %d", got, tc.wantWarn)
			}
			if _, err := restart(t, f); err != nil {
				t.Fatalf("second New = %v", err)
			}
			if again := ownerEntries(t, f.mem); len(again) != 1 {
				t.Errorf("a second start journalled %d owner entries, want none", len(again)-1)
			}
		})
	}
	t.Run("an_owner_exists", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		mustOwner(t, f.mem, "late")
		storeUser(t, f.mem, access.User{Username: "early", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0})
		if _, err := restart(t, f); err != nil {
			t.Fatalf("New = %v", err)
		}
		if got := ownerNames(t, f.mem); !slices.Equal(got, []string{"late"}) || len(ownerEntries(t, f.mem)) != 0 {
			t.Errorf("owners = %v, entries %v; want late alone and nothing journalled", got, ownerEntries(t, f.mem))
		}
	})
	t.Run("no_enabled_admin", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		storeUser(t, f.mem, access.User{Username: "ex", Role: access.RoleAdmin, PasswordHash: someHash, CreatedAt: t0})
		storeUser(t, f.mem, access.User{Username: "user", Role: access.RoleUser, Enabled: true, PasswordHash: someHash, CreatedAt: t0})
		_, err := restart(t, f)
		if !errors.Is(err, account.ErrNoOwner) || !strings.Contains(err.Error(), "enable an admin") {
			t.Errorf("New = %v, want ErrNoOwner naming the store repair", err)
		}
		if got := ownerNames(t, f.mem); len(got) != 0 {
			t.Errorf("a refused New marked %v", got)
		}
	})
	t.Run("empty_store_is_setup", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		st, err := f.svc.State(t.Context(), localClient)
		if err != nil || !st.SetupRequired {
			t.Errorf("State on an empty store = %+v, %v; want setup required", st, err)
		}
	})
}

// TestSetupMarksOwner: setup creates its account as an owner in
// the Update that creates it, on the password and the passkey path.
func TestSetupMarksOwner(t *testing.T) {
	t.Parallel()
	t.Run("password", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: noSetupToken})
		in, err := completed(f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}))
		if err != nil {
			t.Fatalf("SetupWithPassword = %v", err)
		}
		if !in.User.Owner || !stored(t, f, in.User.ID).Owner {
			t.Error("the password setup account is not an owner")
		}
	})
	t.Run("passkey", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{rules: noSetupToken})
		id, body := p.beginSetup(t, access.Secret{}, accesstest.NewPasskeyDevice(t))
		in, err := p.svc.SetupPasskeyFinish(t.Context(), localClient, id, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("SetupPasskeyFinish = %v", err)
		}
		if !in.User.Owner || !stored(t, p.fixture, in.User.ID).Owner {
			t.Error("the passkey setup account is not an owner")
		}
	})
}

// TestSetOwner: SetOwner under OpSetOwner for an owner
// principal or OutOfBand; an owner needs an enabled admin holding a usable
// password or passkey; the last enabled owner stays one.
func TestSetOwner(t *testing.T) {
	t.Parallel()
	t.Run("needs_a_local_method", func(t *testing.T) {
		t.Parallel()
		p := newPK(t, pwOptions{})
		owner := mustOwner(t, p.mem, "owner")
		pr := p.sessionPrincipal(t, owner, time.Now())
		passkeyOnly := storeUser(t, p.mem, access.User{Username: "pk", Role: access.RoleAdmin, Enabled: true, CreatedAt: t0})
		if err := p.mem.CreatePasskey(t.Context(), &access.PasskeyCredential{UserID: passkeyOnly.ID, CredentialID: []byte("pk-cred"), RPID: p.rp.ID(), CreatedAt: t0}); err != nil {
			t.Fatalf("CreatePasskey: %v", err)
		}
		for _, tc := range []struct {
			user   access.User
			name   string
			reason string
		}{
			{name: "password_admin", user: access.User{Username: "pw", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash}},
			{name: "no_method", reason: account.ReasonOwnerNeedsLocalMethod, user: access.User{Username: "bare", Role: access.RoleAdmin, Enabled: true}},
			{name: "oidc_only", reason: account.ReasonOwnerNeedsLocalMethod, user: access.User{Username: "sso", Role: access.RoleAdmin, Enabled: true, OIDC: access.OIDCIdentity{Issuer: "https://idp.example", Subject: "s"}}},
			{name: "role_user", reason: account.ReasonOwnerNeedsLocalMethod, user: access.User{Username: "plain", Role: access.RoleUser, Enabled: true, PasswordHash: someHash}},
			{name: "disabled_admin", reason: account.ReasonOwnerNeedsLocalMethod, user: access.User{Username: "off", Role: access.RoleAdmin, PasswordHash: someHash}},
		} {
			u := storeUser(t, p.mem, tc.user)
			got, err := p.svc.SetOwner(t.Context(), account.As(pr), u.ID, true)
			if reason(err) != tc.reason || (tc.reason == "") != (got != nil && got.Owner) {
				t.Errorf("%s: SetOwner = %v, %v; want reason %q", tc.name, got, err, tc.reason)
			}
			if tc.reason != "" && stored(t, p.fixture, u.ID).Owner {
				t.Errorf("%s: a refused SetOwner wrote the flag", tc.name)
			}
		}
		if _, err := p.svc.SetOwner(t.Context(), account.As(pr), passkeyOnly.ID, true); err != nil {
			t.Errorf("a passkey-only admin: SetOwner = %v, want an owner", err)
		}
	})
	t.Run("who_may_call", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newFixture(t, keyOptions(options{store: fs}, nil))
		owner := mustOwner(t, f.mem, "owner")
		admin := storeUser(t, f.mem, access.User{Username: "admin", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash})
		target := storeUser(t, f.mem, access.User{Username: "target", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash})
		for _, tc := range []struct {
			want  error
			actor account.Actor
			name  string
			id    int64
		}{
			{name: "admin_session", want: account.ErrPolicyRefused, actor: account.As(f.sessionPrincipal(t, admin, time.Now())), id: target.ID},
			{name: "admin_session_missing_user", want: account.ErrPolicyRefused, actor: account.As(f.sessionPrincipal(t, admin, time.Now())), id: 9999},
			{name: "owner_key", want: account.ErrSessionRequired, actor: account.As(f.keyPrincipal(t, owner, scopeUsers)), id: target.ID},
			{name: "stale_owner_session", want: access.ErrRecentAuthRequired, actor: account.As(f.sessionPrincipal(t, owner, time.Now().Add(-time.Hour))), id: target.ID},
			{name: "owner_missing_user", want: account.ErrNotFound, actor: account.As(f.sessionPrincipal(t, owner, time.Now())), id: 9999},
		} {
			fs.resetRecord()
			if _, err := f.svc.SetOwner(t.Context(), tc.actor, tc.id, true); !errors.Is(err, tc.want) {
				t.Errorf("%s: SetOwner = %v, want %v", tc.name, err, tc.want)
			}
			if ws := writesOf(fs); len(ws) != 0 {
				t.Errorf("%s: a refused SetOwner wrote %v", tc.name, ws)
			}
		}
		got, err := f.svc.SetOwner(t.Context(), account.OutOfBand("socket"), target.ID, true)
		if err != nil || !got.Owner {
			t.Fatalf("an out-of-band SetOwner = %v, %v; want an owner", got, err)
		}
		set := eventsOf(f.events, account.EventOwnerSet)
		if len(set) != 1 || set[0].UserID != target.ID || set[0].Actor.OutOfBand != "socket" {
			t.Errorf("owner_set events = %+v, want one for target by the socket", set)
		}
		fs.resetRecord()
		if _, err := f.svc.SetOwner(t.Context(), account.OutOfBand("socket"), target.ID, true); err != nil {
			t.Errorf("setting a flag that holds = %v", err)
		}
		if ws := writesOf(fs); len(ws) != 0 {
			t.Errorf("setting a flag that holds wrote %v", ws)
		}
		if _, err := f.svc.SetOwner(t.Context(), account.As(f.sessionPrincipal(t, owner, time.Now())), target.ID, false); err != nil {
			t.Errorf("an owner removing another owner = %v", err)
		}
		if removed := eventsOf(f.events, account.EventOwnerRemoved); len(removed) != 1 || removed[0].UserID != target.ID {
			t.Errorf("owner_removed events = %+v, want one for target", removed)
		}
	})
	t.Run("last_owner", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		owner := mustOwner(t, f.mem, "owner")
		storeUser(t, f.mem, access.User{Username: "admin", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash})
		pr := f.sessionPrincipal(t, owner, time.Now())
		if _, err := f.svc.SetOwner(t.Context(), account.As(pr), owner.ID, false); reason(err) != account.ReasonLastOwner {
			t.Errorf("the last owner removing its own flag = %v, want last_owner", err)
		}
		if _, err := f.svc.SetOwner(t.Context(), account.OutOfBand("socket"), owner.ID, false); reason(err) != account.ReasonLastOwner {
			t.Errorf("an out-of-band removal of the last owner = %v, want last_owner", err)
		}
		if _, err := f.svc.UpdateUser(t.Context(), pr, owner.ID, account.UserChange{Enabled: new(false)}); reason(err) != account.ReasonLastOwner {
			t.Errorf("the last owner disabling itself = %v, want last_owner", err)
		}
		if !stored(t, f, owner.ID).Owner || !stored(t, f, owner.ID).Enabled {
			t.Error("a refused change moved the last owner")
		}
	})
}

// TestOwnerProtections: owners are protected by operation. A
// principal that is no owner is refused owner_target on an owner target,
// also when the owner is not the last admin, and an owner's role never
// changes (owner_role); each refusal writes nothing.
func TestOwnerProtections(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	f := newFixture(t, options{store: fs})
	owner := mustOwner(t, f.mem, "owner")
	other := mustOwner(t, f.mem, "other")
	admin := storeUser(t, f.mem, access.User{Username: "admin", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash})
	byAdmin := f.sessionPrincipal(t, admin, time.Now())
	byOther := f.sessionPrincipal(t, other, time.Now())
	for _, tc := range []struct {
		run    func() error
		name   string
		reason string
	}{
		{name: "demote", reason: account.ReasonOwnerTarget, run: func() error {
			_, err := f.svc.UpdateUser(t.Context(), byAdmin, owner.ID, account.UserChange{Role: new(access.RoleUser)})
			return err
		}},
		{name: "disable", reason: account.ReasonOwnerTarget, run: func() error {
			_, err := f.svc.UpdateUser(t.Context(), byAdmin, owner.ID, account.UserChange{Enabled: new(false)})
			return err
		}},
		{name: "delete", reason: account.ReasonOwnerTarget, run: func() error { return f.svc.DeleteUser(t.Context(), byAdmin, owner.ID) }},
		{name: "unowner", reason: account.ReasonNotOwner, run: func() error {
			_, err := f.svc.SetOwner(t.Context(), account.As(byAdmin), owner.ID, false)
			return err
		}},
		{name: "owner_demotes_owner", reason: account.ReasonOwnerRole, run: func() error {
			_, err := f.svc.UpdateUser(t.Context(), byOther, owner.ID, account.UserChange{Role: new(access.RoleUser)})
			return err
		}},
	} {
		fs.resetRecord()
		if err := tc.run(); reason(err) != tc.reason {
			t.Errorf("%s = %v, want %s", tc.name, err, tc.reason)
		}
		if ws := writesOf(fs); len(ws) != 0 {
			t.Errorf("%s wrote %v", tc.name, ws)
		}
	}
	if _, err := f.svc.UpdateUser(t.Context(), byOther, owner.ID, account.UserChange{Enabled: new(false)}); err != nil {
		t.Errorf("an owner disabling another owner = %v, want allowed", err)
	}
}

// TestRecreatedAccountIsNoOwner: an account re-created after
// deletion is never an owner.
func TestRecreatedAccountIsNoOwner(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	owner := mustOwner(t, f.mem, "owner")
	gone := mustOwner(t, f.mem, "gone")
	pr := f.sessionPrincipal(t, owner, time.Now())
	if err := f.svc.DeleteUser(t.Context(), pr, gone.ID); err != nil {
		t.Fatalf("DeleteUser = %v", err)
	}
	again, err := f.svc.CreateUser(t.Context(), account.As(pr), account.NewUser{Username: "gone", Role: access.RoleAdmin})
	if err != nil {
		t.Fatalf("CreateUser = %v", err)
	}
	if again.Owner || stored(t, f, again.ID).Owner {
		t.Error("the re-created account is an owner")
	}
}
