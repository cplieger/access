package webauthn

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"testing"

	"github.com/cplieger/access"
	"github.com/go-webauthn/webauthn/protocol"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// FuzzFormatAAGUID pins two invariants of formatAAGUID: a 16-byte input always
// formats to a canonical lowercase UUID that parses back to the original bytes,
// and any other length yields the empty string.
func FuzzFormatAAGUID(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 17))

	f.Fuzz(func(t *testing.T, input []byte) {
		result := formatAAGUID(input)

		if len(input) != 16 {
			if result != "" {
				t.Fatalf("formatAAGUID(%d-byte input) = %q, want empty string", len(input), result)
			}
			return
		}

		if !uuidRe.MatchString(result) {
			t.Fatalf("formatAAGUID(% x) = %q, want canonical UUID format", input, result)
		}
		if got := parseAAGUID(result); !bytes.Equal(got, input) {
			t.Fatalf("parseAAGUID(formatAAGUID(% x)) = % x, want round-trip to original", input, got)
		}
	})
}

// countingReader serves body and counts the bytes a reader of it consumed.
type countingReader struct {
	body []byte
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.read == len(c.body) {
		return 0, io.EOF
	}
	n := copy(p, c.body[c.read:])
	c.read += n
	return n, nil
}

// FuzzWebAuthnFinishBody: a body of any size up to 1 MiB is parsed or, past
// MaxResponseBytes, refused with ErrResponseTooLarge, and neither Finish leg
// ever reads more than MaxResponseBytes+1 bytes of it. The body is seed
// repeated to size bytes, so a short seed reaches every length.
func FuzzWebAuthnFinishBody(f *testing.F) {
	f.Add([]byte(`{"id":"AQID","rawId":"AQID","type":"public-key","response":{}}`), uint32(60))
	f.Add([]byte("x"), uint32(MaxResponseBytes))
	f.Add([]byte("x"), uint32(MaxResponseBytes+1))
	f.Add([]byte(" "), uint32(1<<20))
	f.Add([]byte{}, uint32(0))

	rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example"})
	if err != nil {
		f.Fatal(err)
	}
	origin, err := ParseOrigin("https://example.com")
	if err != nil {
		f.Fatal(err)
	}
	user := &User{AuthUser: &access.User{ID: 7, Username: "alex", WebAuthnHandle: access.GenerateWebAuthnHandle()}}
	_, registration, err := BeginRegistration(rp, user, origin)
	if err != nil {
		f.Fatal(err)
	}
	_, login, err := BeginLogin(rp, origin)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, seed []byte, size uint32) {
		size %= 1<<20 + 1
		if len(seed) == 0 {
			seed = []byte{'{'}
		}
		body := bytes.Repeat(seed, int(size)/len(seed)+1)[:size]
		legs := map[string]func(io.Reader) error{
			"FinishRegistration": func(r io.Reader) error {
				_, err := FinishRegistration(rp, user, registration, r)
				return err
			},
			"CompleteLogin": func(r io.Reader) error {
				_, err := CompleteLogin(t.Context(), rp, &fakeStore{}, login, r)
				return err
			},
		}
		for name, leg := range legs {
			r := &countingReader{body: body}
			err := leg(r)
			if r.read > MaxResponseBytes+1 {
				t.Errorf("%s read %d bytes of a %d-byte body, want at most %d", name, r.read, size, MaxResponseBytes+1)
			}
			if tooLarge := errors.Is(err, ErrResponseTooLarge); tooLarge != (size > MaxResponseBytes) {
				t.Errorf("%s(%d-byte body) error = %v, want ErrResponseTooLarge exactly when over %d", name, size, err, MaxResponseBytes)
			}
		}
	})
}

// FuzzCredentialFromAPI pins the stored-to-upstream conversion: each decoded
// flag boolean is the specification's bit of the stored octet, so a swap
// between two flags fails, and identity and counter fields pass through.
func FuzzCredentialFromAPI(f *testing.F) {
	f.Add("", uint32(0), uint8(0))
	f.Add("usb", uint32(1), uint8(0xff))
	f.Add("usb,nfc", uint32(42), uint8(0x15))
	f.Add("internal", uint32(7), uint8(0x0a))
	f.Add("a,,b", uint32(4294967295), uint8(0x1f))

	f.Fuzz(func(t *testing.T, transport string, signCount uint32, flagBits uint8) {
		cred := &access.PasskeyCredential{
			CredentialID: []byte{1, 2, 3},
			PublicKey:    []byte{4, 5, 6},
			AAGUID:       make([]byte, 16),
			Transport:    transport,
			SignCount:    signCount,
			RawFlags:     flagBits,
			CloneWarning: flagBits&16 != 0,
		}

		got := credentialFromAPI(cred)

		if want := flagBits&uint8(protocol.FlagUserPresent) != 0; got.Flags.UserPresent != want {
			t.Errorf("UserPresent = %v, want %v (RawFlags %#08b)", got.Flags.UserPresent, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagUserVerified) != 0; got.Flags.UserVerified != want {
			t.Errorf("UserVerified = %v, want %v (RawFlags %#08b)", got.Flags.UserVerified, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagBackupEligible) != 0; got.Flags.BackupEligible != want {
			t.Errorf("BackupEligible = %v, want %v (RawFlags %#08b)", got.Flags.BackupEligible, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagBackupState) != 0; got.Flags.BackupState != want {
			t.Errorf("BackupState = %v, want %v (RawFlags %#08b)", got.Flags.BackupState, want, flagBits)
		}
		if got.Authenticator.CloneWarning != cred.CloneWarning {
			t.Errorf("CloneWarning = %v, want %v", got.Authenticator.CloneWarning, cred.CloneWarning)
		}
		if !bytes.Equal(got.ID, cred.CredentialID) {
			t.Errorf("ID = %x, want %x", got.ID, cred.CredentialID)
		}
		if got.Authenticator.SignCount != signCount {
			t.Errorf("SignCount = %d, want %d", got.Authenticator.SignCount, signCount)
		}
	})
}
