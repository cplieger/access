package account_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// appendApp runs AppendLog in its own Update on store, as an app's write
// does.
func appendApp(ctx context.Context, svc *account.Service, store account.Store, e account.AppEntry) (account.LogEntry, error) {
	var got account.LogEntry
	err := store.Update(ctx, func(tx account.Tx) error {
		var err error
		got, err = svc.AppendLog(ctx, tx, e)
		return err
	})
	return got, err
}

// appReason is err's AppEntryError Reason, or "" when it is none.
func appReason(err error) string {
	if ae, ok := errors.AsType[*account.AppEntryError](err); ok {
		return ae.Reason
	}
	return ""
}

func callsUnder(ctx context.Context, fs *faultStore) []string {
	var names []string
	for _, c := range fs.recorded() {
		if c.ctx == ctx {
			names = append(names, c.name)
		}
	}
	return names
}

func TestAppendLog(t *testing.T) {
	t.Parallel()
	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		for _, tc := range []struct {
			name   string
			e      account.AppEntry
			reason string // "" accepted
		}{
			{"kind_one_dot", account.AppEntry{Kind: "app.x"}, ""},
			{"kind_two_dots_digit_underscore", account.AppEntry{Kind: "a.b.c_d9"}, ""},
			{"kind_64_bytes", account.AppEntry{Kind: "a." + strings.Repeat("b", 62)}, ""},
			{"kind_no_dot", account.AppEntry{Kind: "appx"}, account.ReasonAppKind},
			{"kind_uppercase", account.AppEntry{Kind: "app.X"}, account.ReasonAppKind},
			{"kind_leading_digit", account.AppEntry{Kind: "1app.x"}, account.ReasonAppKind},
			{"kind_segment_leading_digit", account.AppEntry{Kind: "app.1x"}, account.ReasonAppKind},
			{"kind_empty_segment", account.AppEntry{Kind: "app..x"}, account.ReasonAppKind},
			{"kind_trailing_dot", account.AppEntry{Kind: "app."}, account.ReasonAppKind},
			{"kind_empty", account.AppEntry{}, account.ReasonAppKind},
			{"kind_65_bytes", account.AppEntry{Kind: "a." + strings.Repeat("b", 63)}, account.ReasonAppKind},
			{"kind_library", account.AppEntry{Kind: string(account.EventSignedIn)}, account.ReasonAppKind},
			{"detail_256_bytes", account.AppEntry{Kind: "app.x", Detail: strings.Repeat("d", 256)}, ""},
			{"detail_256_bytes_multibyte", account.AppEntry{Kind: "app.x", Detail: strings.Repeat("é", 128)}, ""},
			{"detail_257_bytes", account.AppEntry{Kind: "app.x", Detail: strings.Repeat("d", 257)}, account.ReasonAppDetail},
			{"detail_257_bytes_129_runes", account.AppEntry{Kind: "app.x", Detail: strings.Repeat("é", 128) + "d"}, account.ReasonAppDetail},
			{"detail_newline", account.AppEntry{Kind: "app.x", Detail: "one\ntwo"}, account.ReasonAppDetail},
			{"detail_c1_control", account.AppEntry{Kind: "app.x", Detail: "a\u0085b"}, account.ReasonAppDetail},
			{"detail_bidi_override", account.AppEntry{Kind: "app.x", Detail: "a\u202eb"}, account.ReasonAppDetail},
			{"detail_line_separator", account.AppEntry{Kind: "app.x", Detail: "a\u2028b"}, account.ReasonAppDetail},
			{"detail_invalid_utf8", account.AppEntry{Kind: "app.x", Detail: "a\xffb"}, account.ReasonAppDetail},
			{"method_empty", account.AppEntry{Kind: "app.x", Method: ""}, ""},
			{"method_library", account.AppEntry{Kind: "app.x", Method: access.MethodPasskey}, ""},
			{"method_app_defined", account.AppEntry{Kind: "app.x", Method: "agent"}, ""},
			{"method_digit_underscore", account.AppEntry{Kind: "app.x", Method: "agent_key2"}, ""},
			{"method_64_bytes", account.AppEntry{Kind: "app.x", Method: access.Method("a" + strings.Repeat("b", 63))}, ""},
			{"method_uppercase", account.AppEntry{Kind: "app.x", Method: "Agent"}, account.ReasonAppMethod},
			{"method_leading_digit", account.AppEntry{Kind: "app.x", Method: "2fa"}, account.ReasonAppMethod},
			{"method_leading_underscore", account.AppEntry{Kind: "app.x", Method: "_agent"}, account.ReasonAppMethod},
			{"method_hyphen", account.AppEntry{Kind: "app.x", Method: "api-key"}, account.ReasonAppMethod},
			{"method_dot", account.AppEntry{Kind: "app.x", Method: "app.agent"}, account.ReasonAppMethod},
			{"method_65_bytes", account.AppEntry{Kind: "app.x", Method: access.Method("a" + strings.Repeat("b", 64))}, account.ReasonAppMethod},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := logOf(t, f.mem)
				got, err := appendApp(t.Context(), f.svc, f.mem, tc.e)
				after := logOf(t, f.mem)
				if tc.reason != "" {
					if appReason(err) != tc.reason {
						t.Errorf("AppendLog(%+v) = %v, want an *AppEntryError with Reason %q", tc.e, err, tc.reason)
					}
					if len(after) != len(before) {
						t.Errorf("a refused entry changed the log from %d to %d entries", len(before), len(after))
					}
					return
				}
				if err != nil {
					t.Fatalf("AppendLog(%+v) = %v, want nil", tc.e, err)
				}
				if len(after) != len(before)+1 {
					t.Fatalf("log holds %d entries, want %d", len(after), len(before)+1)
				}
				if stored := after[len(after)-1].Event.Seq; got.Event.Seq == 0 || stored != got.Event.Seq {
					t.Errorf("returned Seq %d, stored %d; want the stored entry's non-zero Seq", got.Event.Seq, stored)
				}
				stored := after[len(after)-1]
				if stored.Event.Kind != account.EventKind(tc.e.Kind) || stored.Detail != tc.e.Detail || stored.Event.Method != tc.e.Method {
					t.Errorf("stored Kind %q Detail %q Method %q, want %q %q %q", stored.Event.Kind, stored.Detail, stored.Event.Method, tc.e.Kind, tc.e.Detail, tc.e.Method)
				}
			})
		}
	})
	t.Run("clock_and_class", func(t *testing.T) {
		t.Parallel()
		at := time.Date(2031, 5, 6, 7, 8, 9, 123456789, time.UTC)
		f := newFixture(t, options{edit: func(c *account.Config) { c.Now = func() time.Time { return at } }})
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.settings_changed"})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if want := at.Truncate(time.Millisecond); !got.At.Equal(want) || !got.Event.At.Equal(at) {
			t.Errorf("At %v, Event.At %v, want %v and %v from Config.Now", got.At, got.Event.At, want, at)
		}
		if got.Class != account.LogClassChange {
			t.Errorf("Class = %q, want %q", got.Class, account.LogClassChange)
		}
		if stored := logOf(t, f.mem); len(stored) != 1 || stored[0].Class != account.LogClassChange || !stored[0].At.Equal(got.At) {
			t.Errorf("stored %+v, want the one change entry returned", stored)
		}
	})
	t.Run("one_clock_read", func(t *testing.T) {
		t.Parallel()
		// A clock that moves a millisecond per read: an entry stamped from a
		// second read would carry an At a millisecond after its Event.At.
		var reads atomic.Int64
		base := time.Date(2031, 5, 6, 7, 8, 9, 400000, time.UTC)
		f := newFixture(t, options{edit: func(c *account.Config) {
			c.Now = func() time.Time { return base.Add(time.Duration(reads.Add(1)) * time.Millisecond) }
		}})
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x"})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if want := got.Event.At.Truncate(time.Millisecond); !got.At.Equal(want) {
			t.Errorf("At %v, Event.At %v; want At %v, the same clock read to the millisecond", got.At, got.Event.At, want)
		}
	})
	t.Run("session_actor", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		now := time.Now()
		sess := &access.Session{
			ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull, AuthMethod: access.MethodPassword,
			CreatedAt: now, LastActivity: now, AuthTime: now, Label: "laptop", UserAgent: "Firefox on Linux",
		}
		p, _ := f.principalOf(t, sess)
		if !p.IP.IsValid() {
			t.Fatalf("the principal carries no IP; the case needs one")
		}
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x", Actor: account.As(p)})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if got.Event.Actor != actorOf(p) || got.IP != p.IP || got.ActorLabel != "laptop" || got.ActorUserAgent != "Firefox on Linux" || got.ActorKeySuffix != "" {
			t.Errorf("entry actor %+v IP %v snapshot %q %q %q, want %+v %v \"laptop\" \"Firefox on Linux\" \"\"",
				got.Event.Actor, got.IP, got.ActorLabel, got.ActorUserAgent, got.ActorKeySuffix, actorOf(p), p.IP)
		}
	})
	t.Run("key_actor", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		p, key := labelledKey(t, f, u, "deploy bot")
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x", Actor: account.As(p)})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if got.Event.Actor != actorOf(p) || got.ActorLabel != "deploy bot" || got.ActorKeySuffix != key.KeySuffix || key.KeySuffix == "" || got.ActorUserAgent != "" || got.IP != p.IP {
			t.Errorf("entry actor %+v snapshot %q %q %q IP %v, want %+v \"deploy bot\" %q \"\" %v",
				got.Event.Actor, got.ActorLabel, got.ActorKeySuffix, got.ActorUserAgent, got.IP, actorOf(p), key.KeySuffix, p.IP)
		}
	})
	t.Run("actor_reads", func(t *testing.T) {
		t.Parallel()
		snapshotReads := []string{"SessionsByUserID", "ListAPIKeysByUserID"}
		for _, tc := range []struct {
			actor func(t *testing.T, f *fixture) account.Actor
			name  string
			calls []string // the AppendLog Update's store calls, in order
		}{
			{name: "session", actor: func(t *testing.T, f *fixture) account.Actor {
				return account.As(f.sessionPrincipal(t, mustUser(t, f.mem, "alice", access.RoleUser), access.SessionFull, time.Now()))
			}, calls: []string{"Update", "SessionsByUserID", "AppendLog", "PruneLog"}},
			{name: "key", actor: func(t *testing.T, f *fixture) account.Actor {
				p, _ := labelledKey(t, f, mustUser(t, f.mem, "alice", access.RoleUser), "deploy bot")
				return account.As(p)
			}, calls: []string{"Update", "ListAPIKeysByUserID", "AppendLog", "PruneLog"}},
			{name: "out_of_band", actor: func(*testing.T, *fixture) account.Actor { return account.OutOfBand("cli") }, calls: []string{"Update", "AppendLog", "PruneLog"}},
			{name: "none", actor: func(*testing.T, *fixture) account.Actor { return account.Actor{} }, calls: []string{"Update", "AppendLog", "PruneLog"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				t.Run("calls", func(t *testing.T) {
					t.Parallel()
					fs := newFaultStore()
					f := newFixture(t, options{store: fs})
					a := tc.actor(t, f)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if _, err := appendApp(ctx, f.svc, fs, account.AppEntry{Kind: "app.x", Actor: a}); err != nil {
						t.Fatalf("AppendLog = %v", err)
					}
					if got := callsUnder(ctx, fs); !slices.Equal(got, tc.calls) {
						t.Errorf("AppendLog's store calls = %v, want %v", got, tc.calls)
					}
				})
				for _, read := range snapshotReads {
					t.Run(read+"_fails", func(t *testing.T) {
						t.Parallel()
						fs := newFaultStore()
						f := newFixture(t, options{store: fs})
						a := tc.actor(t, f)
						fs.refuseCall(read, errFault)
						err := fs.Update(t.Context(), func(tx account.Tx) error {
							bob := &access.User{Username: "bob", Role: access.RoleUser, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: time.Now()}
							if err := tx.CreateUser(t.Context(), bob); err != nil {
								return err
							}
							_, err := f.svc.AppendLog(t.Context(), tx, account.AppEntry{Kind: "app.x", Actor: a})
							return err
						})
						fails := slices.Contains(tc.calls, read)
						if (err != nil) != fails || errors.Is(err, access.ErrAuthBackend) != fails || errors.Is(err, errFault) != fails {
							t.Errorf("the app's Update with %s refused = %v; want it to fail with access.ErrAuthBackend wrapping the refusal: %v", read, err, fails)
						}
						_, stored, uerr := f.mem.UserByUsername(t.Context(), "bob")
						if uerr != nil {
							t.Fatalf("UserByUsername: %v", uerr)
						}
						wantEntries := 1
						if fails {
							wantEntries = 0
						}
						if n := len(logOf(t, f.mem)); stored == fails || n != wantEntries {
							t.Errorf("after the Update the app's user is stored: %v and the log holds %d entries; want %v and %d", stored, n, !fails, wantEntries)
						}
					})
				}
			})
		}
	})
	t.Run("out_of_band_actor", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.store_reset", Actor: account.OutOfBand("cli")})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if got.Event.Actor != (account.EventActor{OutOfBand: "cli"}) || got.IP.IsValid() || got.ActorLabel != "" {
			t.Errorf("entry actor %+v IP %v label %q, want the cli channel, no IP and no snapshot", got.Event.Actor, got.IP, got.ActorLabel)
		}
	})
	t.Run("zero_actor", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.store_fenced"})
		if err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if got.Event.Actor != (account.EventActor{}) || got.IP.IsValid() || got.ActorLabel != "" || got.ActorUserAgent != "" {
			t.Errorf("entry %+v, want no actor, no IP and no snapshot", got)
		}
	})
	t.Run("no_on_event", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		if _, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x", Actor: account.OutOfBand("cli")}); err != nil {
			t.Fatalf("AppendLog = %v", err)
		}
		if evs := f.events.all(); len(evs) != 0 {
			t.Errorf("OnEvent received %v, want nothing", evs)
		}
	})
	t.Run("change_class_trim", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: withLogCaps(3, 2)})
		var seqs []uint64
		for range 4 {
			got, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x"})
			if err != nil {
				t.Fatalf("AppendLog = %v", err)
			}
			seqs = append(seqs, got.Event.Seq)
		}
		if got := classSeqs(t, f.mem, account.LogClassChange); !slices.Equal(got, seqs[1:]) {
			t.Errorf("change class holds %v, want the three newest %v", got, seqs[1:])
		}
		if st := statsOf(t, f.mem)[account.LogClassChange]; st.Count != 3 || st.Evicted != 1 {
			t.Errorf("change class stats %+v, want Count 3 and Evicted 1", st)
		}
	})
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
		if _, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x"}); !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("AppendLog after Shutdown = %v, want ErrServiceClosed", err)
		}
		if n := len(logOf(t, f.mem)); n != 0 {
			t.Errorf("log holds %d entries after a closed AppendLog, want 0", n)
		}
	})
	t.Run("rules_ignored", func(t *testing.T) {
		t.Parallel()
		var invalid atomic.Bool
		f := newFixture(t, options{rules: func() account.Rules {
			if invalid.Load() {
				return account.Rules{Breach: account.BreachFailOpen}
			}
			return account.Rules{}
		}})
		invalid.Store(true)
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		p := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		if err := f.svc.RequireKeyPermission(p, ""); !errors.Is(err, account.ErrRulesInvalid) {
			t.Fatalf("an operation under the flipped Rules = %v, want ErrRulesInvalid; the case needs invalid Rules", err)
		}
		if _, err := appendApp(t.Context(), f.svc, f.mem, account.AppEntry{Kind: "app.x", Actor: account.As(p)}); err != nil {
			t.Errorf("AppendLog under invalid Rules = %v, want nil", err)
		}
		if n := len(logOf(t, f.mem)); n != 1 {
			t.Errorf("log holds %d entries, want the app's one", n)
		}
	})
	t.Run("store_error", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newFixture(t, options{store: fs})
		fs.failCall("AppendLog")
		_, err := appendApp(t.Context(), f.svc, fs, account.AppEntry{Kind: "app.x"})
		if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errFault) {
			t.Errorf("AppendLog on a failing store = %v, want access.ErrAuthBackend wrapping the store error", err)
		}
		if n := len(logOf(t, f.mem)); n != 0 {
			t.Errorf("log holds %d entries, want 0", n)
		}
	})
	t.Run("callback_error_rolls_back", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		errApp := errors.New("the app's own write failed")
		err := f.mem.Update(t.Context(), func(tx account.Tx) error {
			if _, err := f.svc.AppendLog(t.Context(), tx, account.AppEntry{Kind: "app.x"}); err != nil {
				return err
			}
			return errApp
		})
		if !errors.Is(err, errApp) {
			t.Fatalf("Update = %v, want the callback's error", err)
		}
		if n := len(logOf(t, f.mem)); n != 0 {
			t.Errorf("log holds %d entries after the app's Update failed, want 0", n)
		}
	})
}

// labelledKey stores a key of u labelled label and returns the principal
// the Authenticator grants for it.
func labelledKey(t *testing.T, f *fixture, u *access.User, label string) (access.Principal, access.Key) {
	t.Helper()
	g, err := access.GenerateAPIKey("")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	key := &access.Key{
		UserID: u.ID, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix,
		Label: label, Scopes: []string{"read"}, CreatedAt: time.Now(),
	}
	if err := f.mem.CreateAPIKey(t.Context(), key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+g.Plaintext.Reveal())
	p, err := f.authn.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate(key): %v", err)
	}
	return p, *key
}
