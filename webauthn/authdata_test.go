package webauthn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cose"
)

// authDataParts is §16.4's registration, whose flags are UP, UV and AT
// (0x45), cut at §6.1's and §6.5.1's offsets: rpIdHash (32), flags (1),
// signCount (4), AAGUID (16), credentialIdLength (2), the ID and the key.
type authDataParts struct {
	aaguid, id, key []byte
	count           []byte
	rpIDHash        []byte
}

func s16_4Parts(t *testing.T) authDataParts {
	t.Helper()
	v := s16Section(t, "16.4")
	raw := vectorAuthData(t, v)
	id := v.Registration.bytes(t, "credential_id")
	return authDataParts{
		rpIDHash: raw[:32], count: raw[33:37], aaguid: raw[37:53],
		id: id, key: raw[55+len(id):],
	}
}

// build writes authenticator data with flags; when AT is set it holds the
// parts' attested credential data with id and key, and tail follows.
func (p authDataParts) build(flags byte, id, key, tail []byte) []byte {
	out := append(append(bytes.Clone(p.rpIDHash), flags), p.count...)
	if flags&0x40 != 0 {
		out = append(out, p.aaguid...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(id)))
		out = append(append(out, id...), key...)
	}
	return append(out, tail...)
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParseAuthData_WebAuthn6_1_structure checks authenticator data's layout
// (§6.1): at least 37 bytes; with AT, attested credential data (§6.5.1) whose
// credential ID is 1 to 1023 bytes (§7.1) and whose key is one CBOR item;
// with ED, one CBOR map of extension outputs (§6.1, "extensions"); and no
// byte after the last flagged item.
func TestParseAuthData_WebAuthn6_1_structure(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	const up, uv, at, ed = 0x01, 0x04, 0x40, 0x80
	reg := byte(up | uv | at)
	asrt := byte(up | uv)
	// §16.17.1.2's hmac-secret output_enc (single input, PIN protocol 2), as
	// an assertion's authenticator extension output.
	hmacOutput := cborEnc(cborMap{"hmac-secret", unhexT(t, "3bfaa48f7952330d63e35ff8cd5bca48d2a12823828915749287256ab146272f9fb437bf65691243c3f504bd7ea6d5e6")})
	// Firefox 117's EdDSA key, {1: "OKP", 3: -8, -1: "Ed25519"} declared as
	// three pairs before its x, as py_webauthn and SimpleWebAuthn record it.
	firefox117 := append(unhexT(t, "a301634f4b500327206745643235353139215820"), make([]byte, 32)...)
	long := bytes.Repeat([]byte{9}, 1024)
	for _, c := range []struct {
		name    string
		raw     []byte
		refused bool
	}{
		{"36 bytes", p.build(asrt, nil, nil, nil)[:36], true},
		{"37 bytes", p.build(asrt, nil, nil, nil), false},
		{"AT with nothing after", p.build(reg, nil, nil, nil)[:37], true},
		{"AT with a credential ID past the end", p.build(reg, p.id, nil, nil)[:37+18+10], true},
		{"AT with a credential ID of 0 bytes", p.build(reg, nil, p.key, nil), true},
		{"AT with a credential ID of 1024 bytes", p.build(reg, long, p.key, nil), true},
		{"AT with a credential ID of 1023 bytes", p.build(reg, long[:1023], p.key, nil), false},
		{"AT with the key cut short", p.build(reg, p.id, p.key[:len(p.key)-1], nil), true},
		{"AT with no key", p.build(reg, p.id, nil, nil), true},
		{"a byte after the key", p.build(reg, p.id, p.key, []byte{0}), true},
		{"ED clear with an extensions map", p.build(asrt, nil, nil, hmacOutput), true},
		{"ED with nothing after", p.build(asrt|ed, nil, nil, nil), true},
		{"ED with an integer", p.build(asrt|ed, nil, nil, []byte{0x01}), true},
		{"ED with a duplicate key", p.build(asrt|ed, nil, nil, cborEnc(cborMap{"a", 1, "a", 1})), true},
		{"ED with a byte after the map", p.build(asrt|ed, nil, nil, append(bytes.Clone(hmacOutput), 0)), true},
		{"ED with §16.17.1.2's hmac-secret output", p.build(asrt|ed, nil, nil, hmacOutput), false},
		{"AT and ED", p.build(reg|ed, p.id, p.key, cborEnc(cborMap{"hmac-secret", true})), false},
		{"Firefox 117's EdDSA key", p.build(reg, p.id, firefox117, nil), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseAuthData(c.raw)
			if c.refused && !errors.Is(err, errAuthData) {
				t.Errorf("parseAuthData = %v, want errAuthData", err)
			}
			if !c.refused && err != nil {
				t.Errorf("parseAuthData = %v, want accepted", err)
			}
		})
	}
}

// TestParseAuthData_WebAuthn6_5_1_fields checks the fields read from
// attested credential data followed by extensions: the AAGUID, the ID and
// the key's bytes as received, which end where the extensions map begins,
// and the big-endian signCount (§6.1).
func TestParseAuthData_WebAuthn6_5_1_fields(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	p.count = []byte{0, 0, 1, 2}
	a, err := parseAuthData(p.build(0xc5, p.id, p.key, cborEnc(cborMap{"credProtect", 2})))
	if err != nil {
		t.Fatalf("parseAuthData = %v", err)
	}
	if a.signCount != 258 || a.flags != 0xc5 {
		t.Errorf("signCount %d, flags %#x; want 258 and 0xc5", a.signCount, a.flags)
	}
	if a.attested == nil {
		t.Fatal("no attested credential data")
	}
	if !bytes.Equal(a.attested.aaguid, p.aaguid) || !bytes.Equal(a.attested.id, p.id) || !bytes.Equal(a.attested.publicKey, p.key) {
		t.Errorf("attested credential %x / %x / %x, want %x / %x / %x", a.attested.aaguid, a.attested.id, a.attested.publicKey, p.aaguid, p.id, p.key)
	}
}

// TestParseAuthData_WebAuthn2_4_keyAsReceived checks that a credential key
// not in CTAP2 canonical form, its alg in two bytes and its labels out of
// order, is kept byte for byte and ends where the extensions begin, the
// boundary a parser that re-encodes the key to measure it misplaces (§2.4,
// design 7.2's departure).
func TestParseAuthData_WebAuthn2_4_keyAsReceived(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	// §16.4's key is {1: 2, 3: -7, -1: 1, -2: x, -3: y}; x and y are its last
	// 70 bytes, each a 0x58 0x20 head and 32 bytes, labels -2 and -3.
	x, y := p.key[len(p.key)-67:len(p.key)-35], p.key[len(p.key)-32:]
	// alg's label 3 and value -7 each in two bytes.
	loose := cborEnc(cborMap{-3, y, -2, x, cborRaw{0x18, 0x03}, cborRaw{0x38, 0x06}, -1, 1, 1, 2})
	ext := cborEnc(cborMap{"credProtect", 2})
	a, key, err := registrationAuthData(p.build(0xc5, p.id, loose, ext), vectorRPID, p.id)
	if err != nil {
		t.Fatalf("registrationAuthData = %v", err)
	}
	if !bytes.Equal(a.attested.publicKey, loose) || key.Algorithm() != -7 {
		t.Errorf("key %x (alg %d), want %x as received (alg -7)", a.attested.publicKey, key.Algorithm(), loose)
	}
}

// TestAuthData_WebAuthn7_1_flags checks the steps §7.1 and §7.2 share, in
// their order: the rpIdHash, UP, UV (access requires it), and BS only with
// BE (§6.1.3), at both ceremonies.
func TestAuthData_WebAuthn7_1_flags(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	for _, c := range []struct {
		name  string
		flags byte // UP 0x01, UV 0x04, BE 0x08, BS 0x10
		rpID  string
		want  error
	}{
		{"UP and UV", 0x05, vectorRPID, nil},
		{"BE without BS", 0x0d, vectorRPID, nil},
		{"BE and BS", 0x1d, vectorRPID, nil},
		{"UP clear", 0x04, vectorRPID, errUserPresence},
		{"UV clear", 0x01, vectorRPID, errUserVerification},
		{"UP and UV clear", 0x00, vectorRPID, errUserPresence},
		{"BS without BE", 0x15, vectorRPID, errBackupState},
		{"another RP ID", 0x05, "example.com", errRPIDHash},
		{"another RP ID and UV clear", 0x01, "example.com", errRPIDHash},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, _, regErr := registrationAuthData(p.build(c.flags|0x40, p.id, p.key, nil), c.rpID, p.id)
			_, assertErr := assertionAuthData(p.build(c.flags, nil, nil, nil), c.rpID)
			for name, err := range map[string]error{"registration": regErr, "assertion": assertErr} {
				if c.want == nil && err != nil {
					t.Errorf("%s = %v, want accepted", name, err)
				}
				if c.want != nil && !errors.Is(err, c.want) {
					t.Errorf("%s = %v, want %v", name, err, c.want)
				}
			}
		})
	}
}

// TestAuthData_WebAuthn6_1_attested checks AT by ceremony: a registration
// attests its credential (§7.1, the credential steps), and an assertion
// carries no attested credential data (§6.1, "AT").
func TestAuthData_WebAuthn6_1_attested(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	if _, _, err := registrationAuthData(p.build(0x05, nil, nil, nil), vectorRPID, p.id); !errors.Is(err, errAttestedData) {
		t.Errorf("a registration with AT clear = %v, want errAttestedData", err)
	}
	if _, err := assertionAuthData(p.build(0x45, p.id, p.key, nil), vectorRPID); !errors.Is(err, errAttestedData) {
		t.Errorf("an assertion with AT set = %v, want errAttestedData", err)
	}
}

// TestRegistrationAuthData_WebAuthn7_1_credential checks the attested
// credential against the response and the offer: its ID is rawId (design 7.2
// rule 2), and its key is one cose.ParseKey accepts, which is also §7.1's
// check that its alg was offered.
func TestRegistrationAuthData_WebAuthn7_1_credential(t *testing.T) {
	t.Parallel()
	p := s16_4Parts(t)
	a, key, err := registrationAuthData(p.build(0x45, p.id, p.key, nil), vectorRPID, p.id)
	if err != nil {
		t.Fatalf("registrationAuthData = %v", err)
	}
	if key.Algorithm() != -7 || !bytes.Equal(a.attested.publicKey, p.key) {
		t.Errorf("key alg %d, bytes %x; want -7 and %x", key.Algorithm(), a.attested.publicKey, p.key)
	}
	otherID := bytes.Clone(p.id)
	otherID[0] ^= 1
	if _, _, err := registrationAuthData(p.build(0x45, p.id, p.key, nil), vectorRPID, otherID); !errors.Is(err, errCredentialID) {
		t.Errorf("an attested ID other than rawId = %v, want errCredentialID", err)
	}
	es384 := s16Section(t, "16.8")
	es384Key := vectorAuthData(t, es384)[55+len(es384.Registration.bytes(t, "credential_id")):]
	if _, _, err := registrationAuthData(p.build(0x45, p.id, es384Key, nil), vectorRPID, p.id); !errors.Is(err, errCredentialKey) || !errors.Is(err, cose.ErrUnsupported) {
		t.Errorf("§16.8's ES384 key = %v, want errCredentialKey and cose.ErrUnsupported", err)
	}
	// §6.5.1: the key MUST NOT carry another optional parameter; here a d
	// (-4) label, the private key.
	withD := append([]byte{0xa6}, p.key[1:]...)
	withD = append(append(withD, 0x23, 0x58, 0x20), make([]byte, 32)...)
	if _, _, err := registrationAuthData(p.build(0x45, p.id, withD, nil), vectorRPID, p.id); !errors.Is(err, errCredentialKey) || !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("a key with a d label = %v, want errCredentialKey and cose.ErrMalformed", err)
	}
}
