package account_test

import (
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// sessionOf stores a full password session of u on the transport secure
// names, last active ago before now.
func sessionOf(t *testing.T, s account.Store, u *access.User, secure bool, ago time.Duration) access.Session {
	t.Helper()
	now := time.Now()
	return putSession(t, s, access.Session{
		ID: newSessionID(t), UserID: u.ID, AuthMethod: access.MethodPassword,
		CreatedAt: now.Add(-time.Hour), LastActivity: now.Add(-ago), AuthTime: now.Add(-time.Hour), Secure: secure,
	})
}

// signedInAgain is every session_revoked entry carrying the signed_in_again
// detail, by the sessions it names.
func signedInAgain(t *testing.T, s account.Store) [][]string {
	t.Helper()
	var out [][]string
	for _, e := range revokedEntries(t, s) {
		if e.Detail == account.LogDetailSignedInAgain {
			out = append(out, e.Event.SessionIDs)
		}
	}
	return out
}

// TestFreshSignInReplacesPresented pins the fresh sign-in: the session the
// request presented, when it is the signing-in user's on the request's
// transport, is deleted before the MaxSessionsPerUser count and journalled
// as signed_in_again; any other presented session is left alone.
func TestFreshSignInReplacesPresented(t *testing.T) {
	t.Parallel()
	if account.LogDetailSignedInAgain != "signed_in_again" {
		t.Fatalf("LogDetailSignedInAgain = %q, want signed_in_again", account.LogDetailSignedInAgain)
	}
	// world is a PosturePerRequest fixture under MaxSessionsPerUser max
	// holding password users alice and bob.
	world := func(t *testing.T, maxSessions int) (*pwFixture, *access.User, *access.User) {
		t.Helper()
		p := newPW(t, pwOptions{
			posture: access.PosturePerRequest,
			rules:   rulesWith(func(r *account.Rules) { r.MaxSessionsPerUser = maxSessions }),
		})
		return p, passwordUser(t, p.mem, p.hasher, "alice", goodPassword), passwordUser(t, p.mem, p.hasher, "bob", goodPassword)
	}
	signIn := func(t *testing.T, p *pwFixture, secure bool, presented access.Hash) account.SignedIn {
		t.Helper()
		c := clientAt(1)
		c.Secure, c.Presented = secure, presented
		in, err := p.login(t.Context(), c, "alice", goodPassword)
		if err != nil {
			t.Fatalf("PasswordLogin(Secure %t) = %v", secure, err)
		}
		return in
	}
	for _, secure := range []bool{false, true} {
		name := "plain"
		if secure {
			name = "secure"
		}
		t.Run(name+"_replaces_before_the_count", func(t *testing.T) {
			t.Parallel()
			p, alice, _ := world(t, 2)
			other := sessionOf(t, p.mem, alice, secure, 2*time.Minute)
			presented := sessionOf(t, p.mem, alice, secure, time.Minute)
			in := signIn(t, p, secure, presented.TokenHash)
			got := sessionIDsOf(t, p.fixture, alice.ID)
			want := []string{other.ID, in.Session.ID}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("alice's sessions = %v, want the other device's %s and the new %s", got, other.ID, in.Session.ID)
			}
			if again := signedInAgain(t, p.mem); !slices.EqualFunc(again, [][]string{{presented.ID}}, slices.Equal[[]string]) {
				t.Errorf("signed_in_again entries = %v, want one naming %s", again, presented.ID)
			}
			if n := len(revokedEntries(t, p.mem)); n != 1 {
				t.Errorf("session_revoked entries = %d, want only the replacement's", n)
			}
		})
	}
	t.Run("replacement_before_eviction", func(t *testing.T) {
		t.Parallel()
		p, alice, _ := world(t, 1)
		older := sessionOf(t, p.mem, alice, false, 2*time.Minute)
		presented := sessionOf(t, p.mem, alice, false, time.Minute)
		in := signIn(t, p, false, presented.TokenHash)
		if got := sessionIDsOf(t, p.fixture, alice.ID); !slices.Equal(got, []string{in.Session.ID}) {
			t.Errorf("alice's sessions = %v, want only the new %s", got, in.Session.ID)
		}
		var named [][]string
		var details []string
		for _, e := range revokedEntries(t, p.mem) {
			named, details = append(named, e.Event.SessionIDs), append(details, e.Detail)
		}
		if !slices.EqualFunc(named, [][]string{{presented.ID}, {older.ID}}, slices.Equal[[]string]) || !slices.Equal(details, []string{account.LogDetailSignedInAgain, ""}) {
			t.Errorf("session_revoked entries = %v with details %q, want [%s] signed_in_again then the eviction of [%s]", named, details, presented.ID, older.ID)
		}
	})
	for name, arrange := range map[string]func(t *testing.T, p *pwFixture, alice, bob *access.User) access.Hash{
		"another_users": func(t *testing.T, p *pwFixture, _, bob *access.User) access.Hash {
			return sessionOf(t, p.mem, bob, false, time.Minute).TokenHash
		},
		"other_transport": func(t *testing.T, p *pwFixture, alice, _ *access.User) access.Hash {
			return sessionOf(t, p.mem, alice, true, time.Minute).TokenHash
		},
		"missing": func(*testing.T, *pwFixture, *access.User, *access.User) access.Hash {
			_, hash := access.GenerateSessionToken()
			return hash
		},
	} {
		t.Run(name+"_left_alone", func(t *testing.T) {
			t.Parallel()
			p, alice, bob := world(t, 0)
			presented := arrange(t, p, alice, bob)
			signIn(t, p, false, presented)
			if _, found, err := p.mem.SessionByHash(t.Context(), presented); err != nil || found != (name != "missing") {
				t.Errorf("presented session after the sign-in: found %t, %v; want it untouched", found, err)
			}
			if n := len(revokedEntries(t, p.mem)); n != 0 {
				t.Errorf("session_revoked entries = %d, want none", n)
			}
		})
	}
}
