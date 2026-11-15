package webauthn

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/cplieger/access"
)

// parseAAGUID parses a UUID string into 16 bytes.
func parseAAGUID(s string) []byte {
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return u[:]
}

func TestPasskeyFriendlyName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		aaguid   string
		want     string
		existing []string
	}{
		{"known", "adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac", nil},
		{"unknown", "ffffffff-ffff-ffff-ffff-ffffffffffff", "Passkey 1", nil},
		{"dup second", "adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac 2", []string{"Chrome on Mac"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			aaguid := parseAAGUID(tc.aaguid)
			got := PasskeyFriendlyName(aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWebAuthnUser_interface_methods(t *testing.T) {
	t.Parallel()
	u := &User{AuthUser: &access.User{ID: 42, Username: "alice", DisplayName: "Alice Smith"}}
	if u.WebAuthnName() != "alice" {
		t.Errorf("WebAuthnName() = %q", u.WebAuthnName())
	}
	if u.WebAuthnDisplayName() != "Alice Smith" {
		t.Errorf("WebAuthnDisplayName() = %q", u.WebAuthnDisplayName())
	}
}

func TestFormatAAGUID_edge_cases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		want  string
		input []byte
	}{
		{"nil", "", nil},
		{"empty", "", []byte{}},
		{"too_short", "", []byte{0x01, 0x02}},
		{"too_long", "", make([]byte, 17)},
		{"valid_zeros", "00000000-0000-0000-0000-000000000000", make([]byte, 16)},
		{"valid_known", "adce0002-35bc-c60a-648b-0b25f1f05503", parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatAAGUID(tt.input)
			if got != tt.want {
				t.Errorf("formatAAGUID(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNew_valid_config(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if wa == nil {
		t.Fatal("New returned nil")
	}
}

// New rejects an RPConfig with an empty ID at construction, naming the
// field, rather than failing every ceremony on an rpIdHash mismatch.
func TestNew_empty_rp_id_rejected(t *testing.T) {
	t.Parallel()
	wa, err := New(RPConfig{DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err == nil {
		t.Fatal("New(RPConfig{ID: \"\"}) error = nil, want error naming RPConfig.ID")
	}
	if !strings.Contains(err.Error(), "RPConfig.ID") {
		t.Errorf("New(RPConfig{ID: \"\"}) error = %q, want it to name RPConfig.ID", err)
	}
	if wa != nil {
		t.Errorf("New(RPConfig{ID: \"\"}) = %v, want nil", wa)
	}
}

func TestNewUser(t *testing.T) {
	t.Parallel()
	t.Run("nil user returns error", func(t *testing.T) {
		t.Parallel()
		u, err := NewUser(nil, nil)
		if err == nil {
			t.Fatal("NewUser(nil, ...) error = nil, want non-nil")
		}
		if u != nil {
			t.Errorf("NewUser(nil, ...) user = %v, want nil", u)
		}
	})
	t.Run("valid user returns populated adapter", func(t *testing.T) {
		t.Parallel()
		au := &access.User{ID: 7, Username: "bob"}
		creds := []access.PasskeyCredential{{CredentialID: []byte{1, 2}}}
		u, err := NewUser(au, creds)
		if err != nil {
			t.Fatalf("NewUser error = %v, want nil", err)
		}
		if u == nil {
			t.Fatal("NewUser user = nil, want non-nil")
		}
		if u.AuthUser != au {
			t.Error("NewUser did not store the provided AuthUser")
		}
		if len(u.Credentials) != 1 {
			t.Errorf("NewUser Credentials len = %d, want 1", len(u.Credentials))
		}
	})
}

func TestPasskeyFriendlyName_unknown_numbered(t *testing.T) {
	t.Parallel()
	aaguid := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	got := PasskeyFriendlyName(aaguid, []string{"Passkey 1", "Passkey 2"})
	if got != "Passkey 3" {
		t.Errorf("PasskeyFriendlyName(unknown, [Passkey 1, Passkey 2]) = %q, want %q", got, "Passkey 3")
	}
}

// TestPasskeyFriendlyName_numbering_gap_no_collision pins the max-suffix fix: the
// numeric suffix is one past the highest existing suffix, not a count of
// matches, so a non-tail deletion that leaves a gap cannot produce a duplicate
// label. The old count-based logic returned "Passkey 2" / "Chrome on Mac 2"
// for the first two cases, colliding with the survivor.
func TestPasskeyFriendlyName_numbering_gap_no_collision(t *testing.T) {
	t.Parallel()
	unknown := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	chrome := parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503") // "Chrome on Mac"
	tests := []struct {
		name     string
		aaguid   []byte
		existing []string
		want     string
	}{
		{"unknown after non-tail delete", unknown, []string{"Passkey 2"}, "Passkey 3"},
		{"known after non-tail delete", chrome, []string{"Chrome on Mac 2"}, "Chrome on Mac 3"},
		{"known bare counts as suffix 1", chrome, []string{"Chrome on Mac", "Chrome on Mac 3"}, "Chrome on Mac 4"},
		{"non-numeric suffix ignored", unknown, []string{"Passkey two"}, "Passkey 1"},
		// A known base ("YubiKey 5") that is a space-prefix of another known
		// base ("YubiKey 5 NFC"): an existing "YubiKey 5 NFC" must NOT be
		// counted as a "YubiKey 5" variant, so the first plain YubiKey 5 stays
		// bare instead of becoming "YubiKey 5 1".
		{"known-prefix sibling not counted", parseAAGUID("2fc0579f-8113-47ea-b116-bb5a8db9202a"), []string{"YubiKey 5 NFC"}, "YubiKey 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PasskeyFriendlyName(tc.aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("PasskeyFriendlyName(%v) = %q, want %q", tc.existing, got, tc.want)
			}
			if slices.Contains(tc.existing, got) {
				t.Errorf("PasskeyFriendlyName returned %q, which collides with an existing name", got)
			}
		})
	}
}

// TestPasskeyFriendlyName_single_numbered_entry pins the lower suffix boundary
// of nameSuffix: a sole "base N" entry with N==1 (reached through the numbered
// "base N" parse path, not the bare name==base path) must count as suffix 1, so
// the next generated label is "base 2" and never re-collides with the existing
// "base 1". The existing numbering tests only pair a "base 1" with a higher
// "base 2", where the larger suffix dominates and masks a regression at the
// N==1 boundary.
func TestPasskeyFriendlyName_single_numbered_entry(t *testing.T) {
	t.Parallel()
	unknown := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	chrome := parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503") // "Chrome on Mac"
	tests := []struct {
		name     string
		aaguid   []byte
		existing []string
		want     string
	}{
		{"unknown sole numbered one", unknown, []string{"Passkey 1"}, "Passkey 2"},
		{"known sole numbered one", chrome, []string{"Chrome on Mac 1"}, "Chrome on Mac 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PasskeyFriendlyName(tc.aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("PasskeyFriendlyName(%v) = %q, want %q", tc.existing, got, tc.want)
			}
			if slices.Contains(tc.existing, got) {
				t.Errorf("PasskeyFriendlyName returned %q, which collides with an existing name", got)
			}
		})
	}
}

// beginFunc begins one kind of ceremony at an origin and returns the
// challenge its options carry.
type beginFunc func(o Origin) (challenge []byte, c Ceremony, err error)

// begins is every Begin function, for rp and user (which must hold a
// passkey for the reauthentication).
func begins(rp *RelyingParty, user *User) map[string]beginFunc {
	assertion := func(begin func(Origin) (*CredentialAssertion, Ceremony, error)) beginFunc {
		return func(o Origin) ([]byte, Ceremony, error) {
			options, c, err := begin(o)
			if err != nil {
				return nil, c, err
			}
			return options.Response.Challenge, c, nil
		}
	}
	return map[string]beginFunc{
		"registration": func(o Origin) ([]byte, Ceremony, error) {
			creation, c, err := BeginRegistration(rp, user, o)
			if err != nil {
				return nil, c, err
			}
			return creation.Response.Challenge, c, nil
		},
		"login":             assertion(func(o Origin) (*CredentialAssertion, Ceremony, error) { return BeginLogin(rp, o) }),
		"conditional_login": assertion(func(o Origin) (*CredentialAssertion, Ceremony, error) { return BeginConditionalLogin(rp, o) }),
		"reauthentication":  assertion(func(o Origin) (*CredentialAssertion, Ceremony, error) { return BeginReauthentication(rp, user, o) }),
	}
}

// TestBegin_WebAuthn13_4_3_challenge checks that every Begin sends a fresh
// 32-byte challenge (§13.4.3 asks for at least 16 random bytes),
// the one its ceremony verifies, expiring CeremonyTimeout after Begin, and
// that the ceremony shares no byte with the options or the user, so neither
// can change it after Begin.
func TestBegin_WebAuthn13_4_3_challenge(t *testing.T) {
	t.Parallel()
	for name, begin := range begins(testRelyingParty(t), optionsUser()) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			before := time.Now()
			first, c, err := begin(exampleOrigin(t))
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			second, _, err := begin(exampleOrigin(t))
			if err != nil {
				t.Fatalf("second Begin: %v", err)
			}
			if len(first) != 32 || len(second) != 32 || bytes.Equal(first, second) {
				t.Errorf("challenges %x and %x, want two different 32-byte challenges", first, second)
			}
			if c.st == nil || !bytes.Equal(c.st.challenge, first) {
				t.Fatalf("ceremony %+v, want one verifying the options' challenge %x", c.st, first)
			}
			if lo, hi := before.Add(CeremonyTimeout), time.Now().Add(CeremonyTimeout); c.Expires().Before(lo) || c.Expires().After(hi) {
				t.Errorf("Expires() = %v, want within [%v, %v]", c.Expires(), lo, hi)
			}
			first[0] ^= 0xff
			if bytes.Equal(c.st.challenge, first) {
				t.Error("the ceremony's challenge aliases the options'")
			}
		})
	}
	t.Run("user_handle_copied", func(t *testing.T) {
		t.Parallel()
		user := optionsUser()
		for name, begin := range begins(testRelyingParty(t), user) {
			_, c, err := begin(exampleOrigin(t))
			if err != nil {
				t.Fatalf("%s Begin: %v", name, err)
			}
			if c.st == nil {
				t.Fatalf("%s Begin returned no ceremony", name)
			}
			if name == "registration" || name == "reauthentication" {
				handle := slices.Clone(user.WebAuthnID())
				user.AuthUser.WebAuthnHandle[0] ^= 0xff
				if !bytes.Equal(c.st.userHandle, handle) {
					t.Errorf("%s ceremony's user handle %x moved with the user's, want %x", name, c.st.userHandle, handle)
				}
				user.AuthUser.WebAuthnHandle[0] ^= 0xff
			}
		}
		_, c, err := BeginReauthentication(testRelyingParty(t), user, exampleOrigin(t))
		if err != nil {
			t.Fatalf("BeginReauthentication: %v", err)
		}
		user.Credentials[0].CredentialID[0] ^= 0xff
		if len(c.st.allowed) != 2 || !bytes.Equal(c.st.allowed[0], []byte{1, 2, 3}) {
			t.Errorf("reauthentication ceremony's allowed IDs %x moved with the user's passkeys, want 010203 first", c.st.allowed)
		}
	})
}

// TestBeginReauthentication_WebAuthn5_5_noPasskeys checks that a user holding
// no passkey cannot begin a reauthentication: its allowCredentials would be
// empty, which §5.5 reads as a discoverable ceremony any credential answers.
func TestBeginReauthentication_WebAuthn5_5_noPasskeys(t *testing.T) {
	t.Parallel()
	user := optionsUser()
	user.Credentials = nil
	options, c, err := BeginReauthentication(testRelyingParty(t), user, exampleOrigin(t))
	if !errors.Is(err, errNoPasskeys) || options != nil || c.st != nil {
		t.Errorf("BeginReauthentication(no passkeys) = %v, %+v, %v; want errNoPasskeys and no ceremony", options, c.st, err)
	}
}

// TestBegin_WebAuthn5_4_3_userHandle checks that the Begins that carry a user
// handle refuse one outside 1 to 64 bytes (§5.4.3: "maximum size of 64
// bytes", and not empty).
func TestBegin_WebAuthn5_4_3_userHandle(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 64, 65} {
		user := optionsUser()
		user.AuthUser.WebAuthnHandle = bytes.Repeat([]byte{7}, size)
		refused := size == 0 || size > 64
		for _, name := range []string{"registration", "reauthentication"} {
			t.Run(name+"_"+strconv.Itoa(size)+"_bytes", func(t *testing.T) {
				t.Parallel()
				_, _, err := begins(testRelyingParty(t), user)[name](exampleOrigin(t))
				if refused != errors.Is(err, errUserHandleSize) || (!refused && err != nil) {
					t.Errorf("Begin with a %d-byte user handle = %v, want refused %v", size, err, refused)
				}
			})
		}
	}
}

// TestFinish_WebAuthn7_ceremonyKind checks that each finish takes only the
// ceremony kind it answers (§7.1, §7.2 pkOptions): registration for
// FinishRegistration, a login or conditional login for CompleteLogin, a
// reauthentication for CompleteReauthentication; and a Ceremony no Begin
// returned is ErrCeremonyUnbound. A matching kind passes on to the response,
// which "{}" fails at its type (§5.1).
func TestFinish_WebAuthn7_ceremonyKind(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := optionsUser()
	finishes := map[string]func(Ceremony) error{
		"FinishRegistration": func(c Ceremony) error {
			_, err := FinishRegistration(rp, user, c, strings.NewReader("{}"))
			return err
		},
		"CompleteLogin": func(c Ceremony) error {
			_, err := CompleteLogin(t.Context(), rp, &loginStore{}, c, strings.NewReader("{}"))
			return err
		},
		"CompleteReauthentication": func(c Ceremony) error {
			_, err := CompleteReauthentication(t.Context(), rp, &loginStore{}, user, c, strings.NewReader("{}"))
			return err
		},
	}
	takes := map[string]string{
		"registration":      "FinishRegistration",
		"login":             "CompleteLogin",
		"conditional_login": "CompleteLogin",
		"reauthentication":  "CompleteReauthentication",
	}
	for kind, begin := range begins(rp, user) {
		_, c, err := begin(exampleOrigin(t))
		if err != nil {
			t.Fatalf("%s Begin: %v", kind, err)
		}
		for name, finish := range finishes {
			t.Run(kind+"_to_"+name, func(t *testing.T) {
				t.Parallel()
				err := finish(c)
				if takes[kind] == name {
					if !errors.Is(err, errCredentialType) {
						t.Errorf("%s(%s ceremony, {}) = %v, want the response refused at its type", name, kind, err)
					}
				} else if !errors.Is(err, errCeremonyKind) {
					t.Errorf("%s(%s ceremony) = %v, want errCeremonyKind", name, kind, err)
				}
			})
		}
	}
	for name, finish := range finishes {
		t.Run("unbound_to_"+name, func(t *testing.T) {
			t.Parallel()
			if err := finish(Ceremony{}); !errors.Is(err, ErrCeremonyUnbound) {
				t.Errorf("%s(Ceremony{}) = %v, want ErrCeremonyUnbound", name, err)
			}
		})
	}
}

// TestBegin_GHSA_22w3_693w_x895 checks GHSA-22w3-693w-x895's class at the
// Begins: under AllowSubdomains for RP ID example.com, https://evilexample.com
// shares the suffix without the dot and is refused (the registrable domain
// suffix rule of §5.1.3 and §5.1.4.1), while a subdomain on any port begins.
func TestBegin_GHSA_22w3_693w_x895(t *testing.T) {
	t.Parallel()
	rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example", AllowSubdomains: true})
	for name, begin := range begins(rp, optionsUser()) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := begin(mustParseOrigin(t, "https://evilexample.com"))
			if oe, ok := errors.AsType[*OriginError](err); !ok || oe.Reason != RejectHostNotCovered {
				t.Errorf("Begin at https://evilexample.com = %v, want an *OriginError %q", err, RejectHostNotCovered)
			}
			sub := mustParseOrigin(t, "https://sub.example.com:8443")
			_, c, err := begin(sub)
			if err != nil || c.st == nil || c.st.origin != sub {
				t.Errorf("Begin at %v = %+v, %v; want a ceremony bound to it", sub, c.st, err)
			}
		})
	}
}
