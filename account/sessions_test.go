package account_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// storeSession writes a session of u whose activity times are created and
// last, under a fresh token, and returns it.
func storeSession(t *testing.T, s account.Store, u *access.User, created, last time.Time) access.Session {
	t.Helper()
	_, hash := access.GenerateSessionToken()
	sess := access.Session{
		ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, TokenHash: hash,
		AuthMethod: access.MethodPassword, CreatedAt: created, LastActivity: last, AuthTime: created,
	}
	if err := s.CreateSession(t.Context(), &sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}

func TestSessionsListsLiveOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{timeouts: func() access.SessionTimeouts {
		return access.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}
	}})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	now := time.Now()
	live := storeSession(t, f.mem, u, now.Add(-2*time.Hour), now.Add(-time.Minute))
	storeSession(t, f.mem, u, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	storeSession(t, f.mem, u, now.Add(-25*time.Hour), now.Add(-time.Minute))
	other := mustUser(t, f.mem, "bob", access.RoleUser)
	storeSession(t, f.mem, other, now, now)
	got, err := f.svc.Sessions(t.Context(), pr)
	if err != nil {
		t.Fatalf("Sessions = %v", err)
	}
	ids := make([]string, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	if want := []string{live.ID, pr.SessionID}; strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("Sessions = %v, want the live session then the current one, oldest first: %v", ids, want)
	}
	if _, err := f.svc.Sessions(t.Context(), f.keyPrincipal(t, u, "read")); !errors.Is(err, account.ErrSessionRequired) {
		t.Errorf("Sessions from a key = %v, want ErrSessionRequired", err)
	}
}

func TestLogoutIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	keep := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	for i := range 2 {
		if err := f.svc.Logout(t.Context(), pr.SessionTokenHash()); err != nil {
			t.Fatalf("Logout %d = %v", i+1, err)
		}
	}
	if err := f.svc.Logout(t.Context(), access.Hash{}); err != nil {
		t.Errorf("Logout of the zero hash = %v, want nil", err)
	}
	ss := sessionsOf(t, f.mem, u.ID)
	if len(ss) != 1 || ss[0].ID != keep.SessionID {
		t.Errorf("sessions after Logout = %d, want only the other one", len(ss))
	}
	revoked := eventsOf(f.events, account.EventSessionRevoked)
	if len(revoked) != 1 || !sameIDs(revoked[0].SessionIDs, pr.SessionID) || revoked[0].UserID != u.ID {
		t.Errorf("EventSessionRevoked = %+v, want one, for the ended session only", revoked)
	}
}

func TestRenameSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	other := mustUser(t, f.mem, "bob", access.RoleUser)
	foreign := f.sessionPrincipal(t, other, access.SessionFull, time.Now())
	cases := []struct {
		want  error
		in    account.SessionLabel
		name  string
		label string
	}{
		{name: "at_cap", in: account.SessionLabel{ID: pr.SessionID, Label: strings.Repeat("é", 64)}, label: strings.Repeat("é", 64)},
		{name: "cleared", in: account.SessionLabel{ID: pr.SessionID}},
		{name: "over_cap", in: account.SessionLabel{ID: pr.SessionID, Label: strings.Repeat("a", 65)}, want: &account.TextError{Field: "label", Reason: "too_long"}},
		{name: "newline", in: account.SessionLabel{ID: pr.SessionID, Label: "laptop\nphone"}, want: &account.TextError{Field: "label", Reason: "disallowed_character"}},
		{name: "bidi_control", in: account.SessionLabel{ID: pr.SessionID, Label: "lap\u202etop"}, want: &account.TextError{Field: "label", Reason: "disallowed_character"}},
		{name: "invalid_utf8", in: account.SessionLabel{ID: pr.SessionID, Label: "lap\xfftop"}, want: &account.TextError{Field: "label", Reason: "disallowed_character"}},
		{name: "other_users_session", in: account.SessionLabel{ID: foreign.SessionID, Label: "mine"}, want: account.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.svc.RenameSession(t.Context(), pr, tc.in)
			var textErr *account.TextError
			switch want := tc.want.(type) {
			case nil:
				if err != nil {
					t.Fatalf("RenameSession = %v, want nil", err)
				}
				if got := storedSession(t, f.mem, u.ID, pr.SessionID).Label; got != tc.label {
					t.Errorf("stored label = %q, want %q", got, tc.label)
				}
			case *account.TextError:
				if !errors.As(err, &textErr) || *textErr != *want {
					t.Errorf("RenameSession = %v, want %+v", err, *want)
				}
			default:
				if !errors.Is(err, want) {
					t.Errorf("RenameSession = %v, want %v", err, want)
				}
			}
		})
	}
	if got := storedSession(t, f.mem, other.ID, foreign.SessionID).Label; got != "" {
		t.Errorf("another user's session label = %q, want it untouched", got)
	}
}

func TestRevokeSession(t *testing.T) {
	t.Parallel()
	t.Run("own_and_foreign", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		target := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		other := mustUser(t, f.mem, "bob", access.RoleUser)
		foreign := f.sessionPrincipal(t, other, access.SessionFull, time.Now())
		if err := f.svc.RevokeSession(t.Context(), pr, target.SessionID); err != nil {
			t.Fatalf("RevokeSession = %v", err)
		}
		if err := f.svc.RevokeSession(t.Context(), pr, foreign.SessionID); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("RevokeSession of another user's session = %v, want ErrNotFound", err)
		}
		if ss := sessionsOf(t, f.mem, other.ID); len(ss) != 1 {
			t.Errorf("the other user's sessions = %d, want 1", len(ss))
		}
		if ss := sessionsOf(t, f.mem, u.ID); len(ss) != 1 || ss[0].ID != pr.SessionID {
			t.Errorf("sessions = %d, want only the caller's", len(ss))
		}
		revoked := eventsOf(f.events, account.EventSessionRevoked)
		if len(revoked) != 1 || !sameIDs(revoked[0].SessionIDs, target.SessionID) || revoked[0].Actor.SessionID != pr.SessionID {
			t.Errorf("EventSessionRevoked = %+v, want one naming the target with the caller as actor", revoked)
		}
	})
}

func TestRevokeOtherSessions(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	a := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	b := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	stale := f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour))
	if err := f.svc.RevokeOtherSessions(t.Context(), stale); !errors.Is(err, access.ErrRecentAuthRequired) {
		t.Errorf("RevokeOtherSessions from a stale session = %v, want ErrRecentAuthRequired", err)
	}
	if err := f.svc.RevokeOtherSessions(t.Context(), pr); err != nil {
		t.Fatalf("RevokeOtherSessions = %v", err)
	}
	if ss := sessionsOf(t, f.mem, u.ID); len(ss) != 1 || ss[0].ID != pr.SessionID {
		t.Errorf("sessions = %d, want only the caller's", len(ss))
	}
	revoked := eventsOf(f.events, account.EventUserSessionsRevoked)
	if len(revoked) != 1 || !sameIDs(revoked[0].SessionIDs, a.SessionID, b.SessionID, stale.SessionID) {
		t.Errorf("EventUserSessionsRevoked = %+v, want one naming the three others", revoked)
	}
	if err := f.svc.RevokeOtherSessions(t.Context(), pr); err != nil {
		t.Fatalf("RevokeOtherSessions with none left = %v", err)
	}
	if n := len(eventsOf(f.events, account.EventUserSessionsRevoked)); n != 1 {
		t.Errorf("EventUserSessionsRevoked after a call that ended nothing = %d, want still 1", n)
	}
}

func TestUpdateProfile(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	name := strings.Repeat("ü", 128)
	got, err := f.svc.UpdateProfile(t.Context(), pr, name)
	if err != nil {
		t.Fatalf("UpdateProfile = %v", err)
	}
	if got.User.DisplayName != name || storedUser(t, f.mem, u.ID).DisplayName != name {
		t.Errorf("display name returned %q, stored %q; want %q", got.User.DisplayName, storedUser(t, f.mem, u.ID).DisplayName, name)
	}
	if got.Current.ID != pr.SessionID || !got.Methods.PasswordLogin {
		t.Errorf("UpdateProfile's Me = %+v, want the caller's session and methods", got)
	}
	for _, tc := range []struct {
		name, in, reason string
	}{
		{name: "over_cap", in: strings.Repeat("a", 129), reason: "too_long"},
		{name: "tab", in: "a\tb", reason: "disallowed_character"},
		{name: "line_separator", in: "a\u2028b", reason: "disallowed_character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var textErr *account.TextError
			if _, err := f.svc.UpdateProfile(t.Context(), pr, tc.in); !errors.As(err, &textErr) || *textErr != (account.TextError{Field: "display_name", Reason: tc.reason}) {
				t.Errorf("UpdateProfile(%q) = %v, want display_name %s", tc.in, err, tc.reason)
			}
		})
	}
	if storedUser(t, f.mem, u.ID).DisplayName != name {
		t.Error("a refused name was stored")
	}
	if _, err := f.svc.UpdateProfile(t.Context(), f.keyPrincipal(t, u, "read"), "x"); !errors.Is(err, account.ErrSessionRequired) {
		t.Errorf("UpdateProfile from a key = %v, want ErrSessionRequired", err)
	}
}
