package account_test

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// shownForm is design 4.9's display form: four groups of four Crockford
// symbols (crockford.com/base32.html: no I, L, O or U), joined by dashes.
var shownForm = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

// issueFixture is a second-factor fixture whose Rules carry the key
// scopes, under posture.
func issueFixture(t *testing.T, r account.Rules, posture access.CookiePosture, policy account.Policy) *sfFixture {
	t.Helper()
	r.Scopes = keyRules().Scopes
	return newSF(t, r, pwOptions{options: keyOptions(options{posture: posture}, policy)})
}

// tempRecord is userID's stored temporary password.
func tempRecord(t testing.TB, s account.Store, userID int64) (access.TemporaryPassword, bool) {
	t.Helper()
	rec, found, err := s.TemporaryPasswordByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("TemporaryPasswordByUserID: %v", err)
	}
	return rec, found
}

func setMode(t testing.TB, s account.Store, mode account.SSOMode) {
	t.Helper()
	if err := s.SetSSOMode(t.Context(), mode); err != nil {
		t.Fatalf("SetSSOMode: %v", err)
	}
}

func kinds(evs []account.Event) []account.EventKind {
	out := make([]account.EventKind, len(evs))
	for i := range evs {
		out[i] = evs[i].Kind
	}
	return out
}

// loaded is a user holding a password, a TOTP record, a recovery code, a
// passkey, a key, a session and a password lock, so an issue's effect on
// each shows.
type loaded struct {
	user    *access.User
	passkey access.PasskeyCredential
	key     access.Key
	session access.Session
}

func loadUser(t *testing.T, f *sfFixture, name string) loaded {
	t.Helper()
	u := passwordUser(t, f.mem, f.hasher, name, goodPassword)
	storeTOTP(t, f.mem, u)
	storeRecoveryCode(t, f.mem, u)
	lockPassword(t, f.mem, f.svc, u, false)
	_, key := f.keyPrincipalFor(t, nil, u, time.Time{}, nil)
	return loaded{user: u, passkey: addPasskey(t, f.mem, u, f.rp.ID()), key: key, session: putSession(t, f.mem, liveSession(t, u))}
}

// TestSetTemporaryPassword is design 4.9's "What issuing does" and the
// secret's form.
func TestSetTemporaryPassword(t *testing.T) {
	t.Parallel()
	// 4.9: a usable user's password, TOTP and recovery code go, with the
	// keys, sessions and locks; the passkeys stay without RevokePasskeys.
	t.Run("usable", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		l := loadUser(t, f, "alice")
		before := time.Now()
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), l.user.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword = %v, want nil", err)
		}
		if !shownForm.MatchString(issued.Password.Reveal()) {
			t.Errorf("Password = %q, want XXXX-XXXX-XXXX-XXXX in Crockford's alphabet", issued.Password.Reveal())
		}
		// 4.9: 24 hours by default.
		if d := issued.ExpiresAt.Sub(before); d < 24*time.Hour-time.Minute || d > 24*time.Hour+time.Minute {
			t.Errorf("ExpiresAt is %v after the call, want 24h", d)
		}
		if issued.Dormant || issued.PasswordKept {
			t.Errorf("Dormant, PasswordKept = %t, %t, want false, false", issued.Dormant, issued.PasswordKept)
		}
		rec, found := tempRecord(t, f.mem, l.user.ID)
		if !found {
			t.Fatal("no temporary password stored")
		}
		if rec.Dormant || rec.IssuedByUser != 0 || rec.IssuedByKey != 0 || !rec.ExpiresAt.Equal(issued.ExpiresAt) {
			t.Errorf("record = %+v, want an out-of-band, usable record expiring at %v", rec, issued.ExpiresAt)
		}
		// 4.9: hashed with the password hasher in 4.6's normalised form.
		canonical := strings.ReplaceAll(issued.Password.Reveal(), "-", "")
		if ok, _, verr := f.hasher.Verify(t.Context(), canonical, rec.Hash); verr != nil || !ok {
			t.Errorf("the record's hash does not verify the secret without dashes: %t, %v", ok, verr)
		}
		if ok, _, _ := f.hasher.Verify(t.Context(), issued.Password.Reveal(), rec.Hash); ok {
			t.Error("the record's hash verifies the dashed display form, want only the normalised one")
		}
		if u := storedUser(t, f.mem, l.user.ID); !u.PasswordHash.IsZero() {
			t.Error("the user's password survived the issue")
		}
		if _, held := totpRecord(t, f.mem, l.user.ID); held {
			t.Error("the user's TOTP survived the issue")
		}
		if _, held, _ := f.mem.RecoveryCodeByUserID(t.Context(), l.user.ID); held {
			t.Error("the user's recovery code survived the issue")
		}
		if pks, _ := f.mem.PasskeysByUserID(t.Context(), l.user.ID); len(pks) != 1 {
			t.Errorf("passkeys = %d, want the one kept without RevokePasskeys", len(pks))
		}
		if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), l.user.ID); len(keys) != 0 {
			t.Errorf("keys = %d, want none without KeepKeys", len(keys))
		}
		if n := len(sessionsOf(t, f.mem, l.user.ID)); n != 0 {
			t.Errorf("sessions = %d, want none", n)
		}
		if _, locked := record(t, f.mem, f.svc, "alice", false); locked {
			t.Error("the password lock survived the issue")
		}
		evs := f.events.all()
		want := []account.EventKind{account.EventTemporaryPasswordSet, account.EventKeyRevoked, account.EventUserSessionsRevoked}
		if !slices.Equal(kinds(evs), want) {
			t.Fatalf("events = %v, want %v", kinds(evs), want)
		}
		if evs[1].KeyID != l.key.ID || !slices.Equal(evs[2].SessionIDs, []string{l.session.ID}) {
			t.Errorf("key_revoked names %d, sessions %v; want %d, [%s]", evs[1].KeyID, evs[2].SessionIDs, l.key.ID, l.session.ID)
		}
		for i := range evs {
			if evs[i].UserID != l.user.ID || evs[i].Actor != (account.EventActor{OutOfBand: "cli"}) {
				t.Errorf("event %s = user %d by %+v, want alice by cli", evs[i].Kind, evs[i].UserID, evs[i].Actor)
			}
		}
	})
	// 4.9: RevokePasskeys deletes them, journalling passkey_removed for
	// each; KeepKeys keeps the keys.
	t.Run("options", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		l := loadUser(t, f, "alice")
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), l.user.ID, account.TemporaryPasswordOptions{RevokePasskeys: true, KeepKeys: true}); err != nil {
			t.Fatalf("SetTemporaryPassword = %v", err)
		}
		if pks, _ := f.mem.PasskeysByUserID(t.Context(), l.user.ID); len(pks) != 0 {
			t.Errorf("passkeys = %d, want none under RevokePasskeys", len(pks))
		}
		if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), l.user.ID); len(keys) != 1 {
			t.Errorf("keys = %d, want the one KeepKeys keeps", len(keys))
		}
		removed := eventsOf(f.events, account.EventPasskeyRemoved)
		if len(removed) != 1 || removed[0].PasskeyID != l.passkey.ID || len(eventsOf(f.events, account.EventKeyRevoked)) != 0 {
			t.Errorf("events = %v, want one passkey_removed for %d and no key_revoked", kinds(f.events.all()), l.passkey.ID)
		}
	})
	// 4.9: at most 7 days; a negative lifetime is refused, and a refusal
	// writes nothing.
	t.Run("ttl", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		for _, tc := range []struct {
			name string
			ttl  time.Duration
			want error
		}{
			{"above_7_days", 7*24*time.Hour + time.Second, account.ErrTTLTooLong},
			{"negative", -time.Second, account.ErrTTLNegative},
		} {
			if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{TTL: tc.ttl}); !errors.Is(err, tc.want) {
				t.Errorf("%s: SetTemporaryPassword = %v, want %v", tc.name, err, tc.want)
			}
		}
		if _, found := tempRecord(t, f.mem, u.ID); found || storedUser(t, f.mem, u.ID).PasswordHash.IsZero() {
			t.Error("a refused lifetime wrote the issue")
		}
		before := time.Now()
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{TTL: 7 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("a 7-day SetTemporaryPassword = %v, want nil", err)
		}
		if d := issued.ExpiresAt.Sub(before); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour+time.Minute {
			t.Errorf("ExpiresAt is %v after the call, want 7 days", d)
		}
	})
	// 4.9: issuing replaces any earlier record.
	t.Run("replaces", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		first, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword = %v", err)
		}
		second, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("a second SetTemporaryPassword = %v", err)
		}
		rec, _ := tempRecord(t, f.mem, u.ID)
		strip := func(s access.Secret) string { return strings.ReplaceAll(s.Reveal(), "-", "") }
		if first.Password.Reveal() == second.Password.Reveal() {
			t.Fatal("two issues drew the same secret")
		}
		if ok, _, _ := f.hasher.Verify(t.Context(), strip(first.Password), rec.Hash); ok {
			t.Error("the first secret still matches the stored record")
		}
		if ok, _, _ := f.hasher.Verify(t.Context(), strip(second.Password), rec.Hash); !ok {
			t.Error("the stored record is not the second secret's")
		}
	})
	t.Run("missing_user", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), 999999, account.TemporaryPasswordOptions{}); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("SetTemporaryPassword of a missing user = %v, want ErrNotFound", err)
		}
	})
}

// TestSetTemporaryPasswordDormant is design 5.3's "A temporary password
// beside dormant methods" and 5.5's refusal of a linked non-owner.
func TestSetTemporaryPasswordDormant(t *testing.T) {
	t.Parallel()
	identity := access.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "alice"}
	// 5.3: under SSOOnly an unlinked non-owner's password, TOTP and
	// recovery code stay, and the record carries Dormant.
	t.Run("unlinked_under_sso_only", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		setMode(t, f.mem, account.SSOOnly)
		l := loadUser(t, f, "alice")
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), l.user.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword = %v, want nil", err)
		}
		if !issued.Dormant || !issued.PasswordKept {
			t.Errorf("Dormant, PasswordKept = %t, %t, want true, true", issued.Dormant, issued.PasswordKept)
		}
		if rec, _ := tempRecord(t, f.mem, l.user.ID); !rec.Dormant {
			t.Error("the record is not Dormant")
		}
		if storedUser(t, f.mem, l.user.ID).PasswordHash.IsZero() {
			t.Error("the dormant password went")
		}
		if _, held := totpRecord(t, f.mem, l.user.ID); !held {
			t.Error("the dormant TOTP went")
		}
		if _, held, _ := f.mem.RecoveryCodeByUserID(t.Context(), l.user.ID); !held {
			t.Error("the dormant recovery code went")
		}
		// 5.3: the explicit options still apply.
		if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), l.user.ID); len(keys) != 0 {
			t.Errorf("keys = %d, want none without KeepKeys", len(keys))
		}
		if n := len(sessionsOf(t, f.mem, l.user.ID)); n != 0 {
			t.Errorf("sessions = %d, want none", n)
		}
	})
	// 4.31: password_kept is the Update's fact, false for a dormant user
	// holding no password.
	t.Run("no_password_kept", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		setMode(t, f.mem, account.SSOOnly)
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword = %v", err)
		}
		if !issued.Dormant || issued.PasswordKept {
			t.Errorf("Dormant, PasswordKept = %t, %t, want true, false", issued.Dormant, issued.PasswordKept)
		}
	})
	// 5.5: a linked non-owner under SSOForLinked and SSOOnly is refused
	// (ErrSSOOnly, linked), and nothing is written.
	for _, mode := range []account.SSOMode{account.SSOForLinked, account.SSOOnly} {
		t.Run("linked_under_"+mode.String(), func(t *testing.T) {
			t.Parallel()
			f := issueFixture(t, account.Rules{}, 0, nil)
			mustOwner(t, f.mem, "root")
			setMode(t, f.mem, mode)
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			linkIdentity(t, f.mem, u, identity)
			sess := putSession(t, f.mem, liveSession(t, u))
			_, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
			if !errors.Is(err, account.ErrSSOLinked) || !errors.Is(err, account.ErrSSOOnly) {
				t.Errorf("SetTemporaryPassword = %v, want ErrSSOLinked matching ErrSSOOnly", err)
			}
			if _, found := tempRecord(t, f.mem, u.ID); found {
				t.Error("the refusal stored a record")
			}
			if storedUser(t, f.mem, u.ID).PasswordHash.IsZero() || len(sessionsOf(t, f.mem, u.ID)) != 1 || sess.ID == "" {
				t.Error("the refusal changed the user")
			}
		})
	}
	// 5.3: a linked user under SSOAlongside, and an owner under SSOOnly, are
	// usable: the issue takes the usable arm.
	t.Run("usable_linked", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		mustOwner(t, f.mem, "second")
		u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		linkIdentity(t, f.mem, u, identity)
		if issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{}); err != nil || issued.Dormant {
			t.Errorf("a linked user under alongside = %+v, %v, want a usable issue", issued, err)
		}
		setMode(t, f.mem, account.SSOOnly)
		linkIdentity(t, f.mem, root, access.OIDCIdentity{Issuer: identity.Issuer, Subject: "root"})
		if issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), root.ID, account.TemporaryPasswordOptions{}); err != nil || issued.Dormant {
			t.Errorf("a linked owner under only = %+v, %v, want a usable issue", issued, err)
		}
	})
}

// TestSetTemporaryPasswordWho is design 4.9's "Who may" and "Never for
// yourself", and 5.2's owner protection.
func TestSetTemporaryPasswordWho(t *testing.T) {
	t.Parallel()
	opts := account.TemporaryPasswordOptions{}
	// 4.9: a principal whose user is the target is refused (self_recovery),
	// a session's and a key's alike, before any Policy call or hash.
	t.Run("self", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		for name, p := range map[string]access.Principal{
			"session": f.sessionPrincipal(t, root, time.Now()),
			"key":     f.keyPrincipal(t, root, scopeUsers),
		} {
			if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(p), root.ID, opts); reason(err) != account.ReasonSelfRecovery {
				t.Errorf("%s: SetTemporaryPassword of oneself = %v, want self_recovery", name, err)
			}
		}
		if _, found := tempRecord(t, f.mem, root.ID); found || f.counted.hashed.Load() != 0 {
			t.Error("a refused self issue wrote a record or spent a hash")
		}
	})
	// 4.9: RolePolicy allows an admin principal; a regular user is refused
	// and nothing is written.
	t.Run("admin", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		mustOwner(t, f.mem, "root")
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		bob := mustUser(t, f.mem, "bob", access.RoleUser)
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(f.sessionPrincipal(t, bob, time.Now())), alice.ID, opts); reason(err) != account.ReasonNotAdmin {
			t.Errorf("a regular user's issue = %v, want not_admin", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found || storedUser(t, f.mem, alice.ID).PasswordHash.IsZero() {
			t.Error("the refused issue wrote")
		}
		p := f.sessionPrincipal(t, admin, time.Now())
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(p), alice.ID, opts); err != nil {
			t.Fatalf("an admin's issue = %v, want nil", err)
		}
		if rec, _ := tempRecord(t, f.mem, alice.ID); rec.IssuedByUser != admin.ID || rec.IssuedByKey != 0 {
			t.Errorf("issuer = user %d, key %d, want user %d", rec.IssuedByUser, rec.IssuedByKey, admin.ID)
		}
		if evs := eventsOf(f.events, account.EventTemporaryPasswordSet); len(evs) != 1 || evs[0].Actor.SessionID != p.SessionID {
			t.Errorf("temporary_password_set = %+v, want one by the admin's session", evs)
		}
	})
	// 4.9 and 5.2: only another owner or OutOfBand issues one for an owner.
	t.Run("owner_target", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		second := mustOwner(t, f.mem, "second")
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(f.sessionPrincipal(t, admin, time.Now())), root.ID, opts); reason(err) != account.ReasonOwnerTarget {
			t.Errorf("an admin's issue for an owner = %v, want owner_target", err)
		}
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(f.sessionPrincipal(t, second, time.Now())), root.ID, opts); err != nil {
			t.Errorf("another owner's issue for an owner = %v, want nil", err)
		}
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), second.ID, opts); err != nil {
			t.Errorf("an out-of-band issue for an owner = %v, want nil", err)
		}
	})
	// 4.9: a manage_users key sets one for a regular user only
	// (admin_target), attributes it and caps its expiry at its own.
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, nil)
		root := mustOwner(t, f.mem, "root")
		admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		keyExpiry := time.Now().Add(2 * time.Hour).Truncate(time.Millisecond)
		p, key := f.keyPrincipalFor(t, f.authn, root, keyExpiry, nil, scopeUsers)
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(p), admin.ID, opts); reason(err) != account.ReasonAdminTarget {
			t.Errorf("a key's issue for an admin = %v, want admin_target", err)
		}
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.As(p), alice.ID, opts)
		if err != nil {
			t.Fatalf("a key's issue for a regular user = %v, want nil", err)
		}
		rec, _ := tempRecord(t, f.mem, alice.ID)
		if rec.IssuedByKey != key.ID || rec.IssuedByUser != 0 {
			t.Errorf("issuer = user %d, key %d, want key %d", rec.IssuedByUser, rec.IssuedByKey, key.ID)
		}
		if !rec.ExpiresAt.Equal(keyExpiry) || !issued.ExpiresAt.Equal(keyExpiry) {
			t.Errorf("ExpiresAt = %v (answered %v), want the key's %v", rec.ExpiresAt, issued.ExpiresAt, keyExpiry)
		}
		attrs, err := f.mem.ListKeyAttributions(t.Context())
		if err != nil {
			t.Fatalf("ListKeyAttributions: %v", err)
		}
		if len(attrs) != 1 || attrs[0].UserID != alice.ID || attrs[0].Action != access.AttributionTemporaryPasswordSet {
			t.Errorf("attributions = %+v, want one temporary_password_set on alice", attrs)
		}
	})
	// 4.9: SingleOwnerPolicy allows OutOfBand only.
	t.Run("single_owner", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, 0, account.SingleOwnerPolicy{})
		owner := mustOwner(t, f.mem, "owner")
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(f.sessionPrincipal(t, owner, time.Now())), owner.ID, opts); reason(err) != account.ReasonSelfRecovery {
			t.Errorf("the owner's own issue = %v, want self_recovery", err)
		}
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), owner.ID, opts); err != nil {
			t.Errorf("an out-of-band issue for the owner = %v, want nil", err)
		}
	})
	// 4.9: issuing answers a new secret, so a plain request is refused.
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, access.PosturePerRequest, nil)
		root := mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
		sess := liveSession(t, root)
		sess.Secure = false
		p := f.plainPrincipalOf(t, &sess)
		if _, err := f.svc.SetTemporaryPassword(t.Context(), account.As(p), alice.ID, opts); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("a plain issue = %v, want ErrHTTPSRequired", err)
		}
		if _, found := tempRecord(t, f.mem, alice.ID); found {
			t.Error("the plain issue stored a record")
		}
	})
}

// TestTemporaryPasswordHTTPSOnly is design 4.9's six cases, 4.43's SSOOnly
// clause inside the posture guard and 4.44's named postures.
func TestTemporaryPasswordHTTPSOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		posture access.CookiePosture
		mode    account.SSOMode
		rules   account.Rules
		after   *account.Rules // published after the issue
		want    bool
	}{
		{name: "secure_rule_on_sso_only", posture: access.PostureSecure, mode: account.SSOOnly, rules: account.Rules{RequireSecondFactor: true}, want: false},
		{name: "per_request_alongside_off", posture: access.PosturePerRequest, want: false},
		{name: "per_request_rule_on", posture: access.PosturePerRequest, rules: account.Rules{RequireSecondFactor: true}, want: true},
		{name: "per_request_password_login_off", posture: access.PosturePerRequest, rules: account.Rules{DisablePasswordLogin: true}, want: true},
		{name: "per_request_sso_only", posture: access.PosturePerRequest, mode: account.SSOOnly, want: true},
		{name: "per_request_password_login_restored", posture: access.PosturePerRequest, rules: account.Rules{DisablePasswordLogin: true}, after: &account.Rules{}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := issueFixture(t, tc.rules, tc.posture, nil)
			mustOwner(t, f.mem, "root")
			u := mustUser(t, f.mem, "alice", access.RoleUser)
			setMode(t, f.mem, tc.mode)
			issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
			if err != nil {
				t.Fatalf("SetTemporaryPassword = %v", err)
			}
			if tc.after != nil {
				r := *tc.after
				r.Scopes = keyRules().Scopes
				f.rules.Store(&r)
			}
			if got := f.svc.TemporaryPasswordHTTPSOnly(issued); got != tc.want {
				t.Errorf("TemporaryPasswordHTTPSOnly = %t, want %t", got, tc.want)
			}
		})
	}
	// 4.9: the mode is the one the issue decided under; a later ApplySSO is
	// a change the copy does not follow.
	t.Run("mode_as_issued", func(t *testing.T) {
		t.Parallel()
		f := issueFixture(t, account.Rules{}, access.PosturePerRequest, nil)
		mustOwner(t, f.mem, "root")
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), u.ID, account.TemporaryPasswordOptions{})
		if err != nil {
			t.Fatalf("SetTemporaryPassword = %v", err)
		}
		setMode(t, f.mem, account.SSOOnly)
		if f.svc.TemporaryPasswordHTTPSOnly(issued) {
			t.Error("TemporaryPasswordHTTPSOnly followed a mode stored after the issue")
		}
	})
}

// TestStateTemporaryPasswordHTTPSOnly is design 4.12: a plain State under
// each of the three settings answers true and under none false; a secure
// State never sets it.
func TestStateTemporaryPasswordHTTPSOnly(t *testing.T) {
	t.Parallel()
	plain := account.Client{Secure: false}
	for _, tc := range []struct {
		name   string
		rules  account.Rules
		mode   account.SSOMode
		client account.Client
		want   bool
	}{
		{name: "plain_rule_on", rules: account.Rules{RequireSecondFactor: true}, client: plain, want: true},
		{name: "plain_password_login_off", rules: account.Rules{DisablePasswordLogin: true}, client: plain, want: true},
		{name: "plain_sso_only", mode: account.SSOOnly, client: plain, want: true},
		{name: "plain_none", client: plain, want: false},
		{name: "secure_rule_on", rules: account.Rules{RequireSecondFactor: true, DisablePasswordLogin: true}, mode: account.SSOOnly, client: clientAt(1), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := issueFixture(t, tc.rules, access.PosturePerRequest, nil)
			setMode(t, f.mem, tc.mode)
			st, err := f.svc.State(t.Context(), tc.client)
			if err != nil {
				t.Fatalf("State = %v", err)
			}
			if st.TemporaryPasswordHTTPSOnly != tc.want {
				t.Errorf("TemporaryPasswordHTTPSOnly = %t, want %t", st.TemporaryPasswordHTTPSOnly, tc.want)
			}
		})
	}
}

// TestTemporaryPasswordIsAWayIn is design 4.9's last-method guard: a live
// temporary password counts as a way in whatever DisablePasswordLogin says,
// and an expired one does not.
func TestTemporaryPasswordIsAWayIn(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		rules   account.Rules
		expires time.Duration
		want    bool
	}{
		{name: "live", expires: time.Hour, want: true},
		{name: "live_password_login_off", rules: account.Rules{DisablePasswordLogin: true}, expires: time.Hour, want: true},
		{name: "expired", expires: -time.Second, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := issueFixture(t, tc.rules, 0, nil)
			mustOwner(t, f.mem, "root")
			u := mustUser(t, f.mem, "alice", access.RoleUser)
			now := time.Now()
			if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: u.ID, Hash: access.NewHash("temp"), CreatedAt: now, ExpiresAt: now.Add(tc.expires)}); err != nil {
				t.Fatalf("SetTemporaryPassword: %v", err)
			}
			r := tc.rules
			r.Scopes = keyRules().Scopes
			avail, err := f.svc.UsableMethods(t.Context(), f.mem, u.ID, account.MethodState{Rules: r, RPID: f.rp.ID()})
			if err != nil {
				t.Fatalf("UsableMethods = %v", err)
			}
			if avail.HasPassword != tc.want {
				t.Errorf("HasPassword = %t, want %t", avail.HasPassword, tc.want)
			}
		})
	}
}

// TestUsersSecondFactorRows is design 4.12's UserMethodsView row facts:
// TOTP enrolment and a live temporary password's expiry.
func TestUsersSecondFactorRows(t *testing.T) {
	t.Parallel()
	f := issueFixture(t, account.Rules{}, 0, nil)
	root := mustOwner(t, f.mem, "root")
	alice := mustUser(t, f.mem, "alice", access.RoleUser)
	bob := mustUser(t, f.mem, "bob", access.RoleUser)
	storeTOTP(t, f.mem, alice)
	issued, err := f.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), alice.ID, account.TemporaryPasswordOptions{KeepKeys: true})
	if err != nil {
		t.Fatalf("SetTemporaryPassword = %v", err)
	}
	storeTOTP(t, f.mem, alice)
	now := time.Now()
	if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: bob.ID, Hash: access.NewHash("old"), CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("SetTemporaryPassword: %v", err)
	}
	users, err := f.svc.Users(t.Context(), f.sessionPrincipal(t, root, time.Now()), account.UserFilter{})
	if err != nil {
		t.Fatalf("Users = %v", err)
	}
	byName := map[string]account.ListedUser{}
	for _, l := range users {
		byName[l.User.Username] = l
	}
	if a := byName["alice"]; !a.TOTP || !a.TemporaryPasswordExpiresAt.Equal(issued.ExpiresAt) {
		t.Errorf("alice's row = totp %t, temporary password %v; want true, %v", a.TOTP, a.TemporaryPasswordExpiresAt, issued.ExpiresAt)
	}
	if b := byName["bob"]; b.TOTP || !b.TemporaryPasswordExpiresAt.IsZero() {
		t.Errorf("bob's row = totp %t, temporary password %v; want false and none for an expired record", b.TOTP, b.TemporaryPasswordExpiresAt)
	}
}
