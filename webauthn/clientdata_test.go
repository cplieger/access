package webauthn

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// clientDataCase is §16.2's registration challenge, the origin it was made
// at, and a clientDataJSON written by the test.
func clientDataCase(t *testing.T) (challenge []byte, origin Origin) {
	t.Helper()
	return s16Section(t, "16.2").Registration.bytes(t, "challenge"), mustParseOrigin(t, vectorOrigin)
}

// TestVerifyClientData_WebAuthn5_8_1 checks §16.2's published client data,
// unknown members included, and that the hash is SHA-256 of the bytes as
// received (§7.1's hash step).
func TestVerifyClientData_WebAuthn5_8_1(t *testing.T) {
	t.Parallel()
	v := s16Section(t, "16.2")
	origin := mustParseOrigin(t, vectorOrigin)
	for _, h := range []struct {
		name string
		half vectorHalf
		typ  clientDataType
	}{
		{"registration", v.Registration, clientDataCreate},
		{"authentication", v.Authentication, clientDataGet},
	} {
		raw := h.half.bytes(t, "clientDataJSON")
		hash, err := verifyClientData(raw, h.typ, h.half.bytes(t, "challenge"), origin)
		if err != nil {
			t.Errorf("%s: verifyClientData = %v, want accepted", h.name, err)
		}
		if hash != sha256.Sum256(raw) {
			t.Errorf("%s: hash = %x, want SHA-256 of clientDataJSON", h.name, hash)
		}
	}
}

// TestVerifyClientData_WebAuthn7_1_BOM checks that a leading byte order mark
// is stripped before parsing (§7.1's UTF-8 decode step) while the hash still
// covers the bytes as received.
func TestVerifyClientData_WebAuthn7_1_BOM(t *testing.T) {
	t.Parallel()
	challenge, origin := clientDataCase(t)
	raw := append([]byte{0xef, 0xbb, 0xbf}, s16Section(t, "16.2").Registration.bytes(t, "clientDataJSON")...)
	hash, err := verifyClientData(raw, clientDataCreate, challenge, origin)
	if err != nil {
		t.Fatalf("verifyClientData with a BOM = %v, want accepted", err)
	}
	if hash != sha256.Sum256(raw) {
		t.Error("hash is not SHA-256 of the bytes as received")
	}
}

func clientDataJSON(typ, challenge, origin, extra string) []byte {
	return []byte(`{"type":"` + typ + `","challenge":"` + challenge + `","origin":"` + origin + `"` + extra + `}`)
}

// TestVerifyClientData_WebAuthn5_8_1_refusals checks each member against the
// ceremony: type, the challenge as the strict unpadded base64url of its
// bytes, the origin byte for byte as the ceremony's Origin serializes it, and
// no frame.
func TestVerifyClientData_WebAuthn5_8_1_refusals(t *testing.T) {
	t.Parallel()
	challenge, origin := clientDataCase(t)
	c := b64(challenge)
	std := strings.NewReplacer("-", "+", "_", "/").Replace(c)
	if std == c {
		t.Fatal("§16.2's challenge has no URL-safe character")
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"type webauthn.get", clientDataJSON("webauthn.get", c, vectorOrigin, ""), errClientDataType},
		{"challenge padded", clientDataJSON("webauthn.create", c+"=", vectorOrigin, ""), errChallenge},
		{"challenge in the standard alphabet", clientDataJSON("webauthn.create", std, vectorOrigin, ""), errChallenge},
		{"another challenge", clientDataJSON("webauthn.create", b64(make([]byte, 32)), vectorOrigin, ""), errChallenge},
		{"origin not serialized", clientDataJSON("webauthn.create", c, "HTTPS://Example.ORG:443/", ""), errOrigin},
		{"origin with an uppercase host", clientDataJSON("webauthn.create", c, "https://EXAMPLE.org", ""), errOrigin},
		{"origin with a trailing slash", clientDataJSON("webauthn.create", c, "https://example.org/", ""), errOrigin},
		{"origin with the default port", clientDataJSON("webauthn.create", c, "https://example.org:443", ""), errOrigin},
		{"another origin", clientDataJSON("webauthn.create", c, "https://sub.example.org", ""), errOrigin},
		{"crossOrigin true", clientDataJSON("webauthn.create", c, vectorOrigin, `,"crossOrigin":true`), errFramed},
		{"topOrigin alone", clientDataJSON("webauthn.create", c, vectorOrigin, `,"topOrigin":"https://example.org"`), errFramed},
		{"topOrigin null", clientDataJSON("webauthn.create", c, vectorOrigin, `,"topOrigin":null`), errFramed},
		{"crossOrigin not a boolean", clientDataJSON("webauthn.create", c, vectorOrigin, `,"crossOrigin":"false"`), errClientData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := verifyClientData(tc.raw, clientDataCreate, challenge, origin); !errors.Is(err, tc.want) {
				t.Errorf("verifyClientData = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyClientData_JSON checks the parse (design step 2 on §5.8.1): at
// most 4 KiB, exact member names (§5.8.1's WebIDL names), no duplicate
// member (RFC 8259 §4), valid UTF-8 (§8.1), and unknown members ignored,
// tokenBinding among them, which Level 3 reserves.
func TestVerifyClientData_JSON(t *testing.T) {
	t.Parallel()
	challenge, origin := clientDataCase(t)
	c := b64(challenge)
	base := clientDataJSON("webauthn.create", c, vectorOrigin, "")
	pad := func(n int) []byte {
		filler := `,"extraData":"`
		return clientDataJSON("webauthn.create", c, vectorOrigin, filler+strings.Repeat("x", n-len(base)-len(filler)-1)+`"`)
	}
	if got := len(pad(4096)); got != 4096 {
		t.Fatalf("pad(4096) is %d bytes", got)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"4 KiB", pad(4096), nil},
		{"4 KiB and 1", pad(4097), errClientData},
		{"type beside TYPE", clientDataJSON("webauthn.create", c, vectorOrigin, `,"TYPE":"webauthn.get"`), nil},
		{"a lone Type", []byte(`{"Type":"webauthn.create","challenge":"` + c + `","origin":"` + vectorOrigin + `"}`), errClientDataType},
		{"a duplicate type", clientDataJSON("webauthn.create", c, vectorOrigin, `,"type":"webauthn.create"`), errClientData},
		{"a duplicate challenge", clientDataJSON("webauthn.create", c, vectorOrigin, `,"challenge":"`+c+`"`), errClientData},
		{"invalid UTF-8", clientDataJSON("webauthn.create", c, vectorOrigin, ",\"x\":\"\xc3\x28\""), errClientData},
		{"a tokenBinding of any status", clientDataJSON("webauthn.create", c, vectorOrigin, `,"tokenBinding":{"status":"bogus"}`), nil},
		{"crossOrigin false", clientDataJSON("webauthn.create", c, vectorOrigin, `,"crossOrigin":false`), nil},
		{"not JSON", []byte("type=webauthn.create"), errClientData},
		{"empty", nil, errClientData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := verifyClientData(tc.raw, clientDataCreate, challenge, origin)
			if tc.want == nil && err != nil {
				t.Errorf("verifyClientData = %v, want accepted", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("verifyClientData = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyClientData_WebAuthn13_4_9_portedOrigin checks that an origin on a
// non-default port is compared with its port, as the ASCII serialization
// writes it.
func TestVerifyClientData_WebAuthn13_4_9_portedOrigin(t *testing.T) {
	t.Parallel()
	challenge, _ := clientDataCase(t)
	origin := mustParseOrigin(t, "https://example.org:8443")
	c := b64(challenge)
	if _, err := verifyClientData(clientDataJSON("webauthn.create", c, "https://example.org:8443", ""), clientDataCreate, challenge, origin); err != nil {
		t.Errorf("the ported origin = %v, want accepted", err)
	}
	if _, err := verifyClientData(clientDataJSON("webauthn.create", c, vectorOrigin, ""), clientDataCreate, challenge, origin); !errors.Is(err, errOrigin) {
		t.Errorf("the origin without its port = %v, want errOrigin", err)
	}
}
