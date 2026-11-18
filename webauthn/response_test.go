package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

var b64 = base64.RawURLEncoding.EncodeToString

// regMembers is WebAuthn §16.2's registration as a RegistrationResponseJSON
// (WebAuthn §5.1), as a browser's toJSON() writes it.
func regMembers(t testing.TB) map[string]any {
	t.Helper()
	v := s16Section(t, "16.2").Registration
	id := b64(v.bytes(t, "credential_id"))
	return map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(v.bytes(t, "clientDataJSON")),
			"attestationObject": b64(v.bytes(t, "attestationObject")),
			"transports":        []string{"internal", "hybrid"},
		},
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
	}
}

// assertMembers is WebAuthn §16.2's authentication as an
// AuthenticationResponseJSON (WebAuthn §5.1), with the user handle given.
func assertMembers(t testing.TB, userHandle any) map[string]any {
	t.Helper()
	v := s16Section(t, "16.2")
	id := b64(v.Registration.bytes(t, "credential_id"))
	response := map[string]any{
		"clientDataJSON":    b64(v.Authentication.bytes(t, "clientDataJSON")),
		"authenticatorData": b64(v.Authentication.bytes(t, "authenticatorData")),
		"signature":         b64(v.Authentication.bytes(t, "signature")),
	}
	if userHandle != nil {
		response["userHandle"] = userHandle
	}
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key", "response": response,
		"clientExtensionResults": map[string]any{},
	}
}

func marshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withMember puts member, raw JSON, first in body's top-level object, so a
// test can write what encoding/json never would: a duplicate, a name
// differing in case.
func withMember(body []byte, member string) []byte {
	return append([]byte("{"+member+","), body[1:]...)
}

func response(m map[string]any) map[string]any { return m["response"].(map[string]any) }

func TestParseRegistrationResponse_WebAuthn5_1(t *testing.T) {
	t.Parallel()
	v := s16Section(t, "16.2").Registration
	r, err := parseRegistrationResponse(marshal(t, regMembers(t)))
	if err != nil {
		t.Fatalf("parseRegistrationResponse = %v", err)
	}
	if !bytes.Equal(r.rawID, v.bytes(t, "credential_id")) {
		t.Errorf("rawID = %x, want the credential ID", r.rawID)
	}
	if !bytes.Equal(r.clientDataJSON, v.bytes(t, "clientDataJSON")) {
		t.Error("clientDataJSON is not the bytes sent")
	}
	if !bytes.Equal(r.attestationObject, v.bytes(t, "attestationObject")) {
		t.Error("attestationObject is not the bytes sent")
	}
	if !slices.Equal(r.transports, []string{"internal", "hybrid"}) {
		t.Errorf("transports = %q, want internal, hybrid", r.transports)
	}
	if r.attachment != access.AttachmentPlatform {
		t.Errorf("attachment = %q, want platform", r.attachment)
	}
	if r.residentKey == nil || !*r.residentKey {
		t.Errorf("residentKey = %v, want true", r.residentKey)
	}
}

func TestParseAssertionResponse_WebAuthn5_1(t *testing.T) {
	t.Parallel()
	v := s16Section(t, "16.2")
	handle := []byte("user-7")
	r, err := parseAssertionResponse(marshal(t, assertMembers(t, b64(handle))))
	if err != nil {
		t.Fatalf("parseAssertionResponse = %v", err)
	}
	if !bytes.Equal(r.rawID, v.Registration.bytes(t, "credential_id")) {
		t.Errorf("rawID = %x, want the credential ID", r.rawID)
	}
	for _, m := range []struct {
		name      string
		got, want []byte
	}{
		{"clientDataJSON", r.clientDataJSON, v.Authentication.bytes(t, "clientDataJSON")},
		{"authenticatorData", r.authenticatorData, v.Authentication.bytes(t, "authenticatorData")},
		{"signature", r.signature, v.Authentication.bytes(t, "signature")},
		{"userHandle", r.userHandle, handle},
	} {
		if !bytes.Equal(m.got, m.want) {
			t.Errorf("%s = %x, want %x", m.name, m.got, m.want)
		}
	}
}

// TestParseResponse_WebAuthn5_8_1_memberCase checks that member names match
// exactly, as WebIDL names do: type beside TYPE reads type, and a lone Type
// leaves type missing.
func TestParseResponse_WebAuthn5_8_1_memberCase(t *testing.T) {
	t.Parallel()
	body := withMember(marshal(t, regMembers(t)), `"TYPE":"other"`)
	if _, err := parseRegistrationResponse(body); err != nil {
		t.Errorf("type beside TYPE = %v, want type read and TYPE ignored", err)
	}
	m := regMembers(t)
	delete(m, "type")
	m["Type"] = "public-key"
	if _, err := parseRegistrationResponse(marshal(t, m)); !errors.Is(err, errCredentialType) {
		t.Errorf("a lone Type = %v, want errCredentialType", err)
	}
}

// TestParseResponse_RFC8259 checks that a duplicate member at any level
// (RFC 8259 §4) and invalid UTF-8 (§8.1) are refused.
func TestParseResponse_RFC8259(t *testing.T) {
	t.Parallel()
	reg := marshal(t, regMembers(t))
	nested := regMembers(t)
	response(nested)["attestationObject"] = "PLACEHOLDER"
	nestedBody := bytes.Replace(marshal(t, nested), []byte(`"attestationObject":"PLACEHOLDER"`),
		[]byte(`"attestationObject":"oA","attestationObject":"`+response(regMembers(t))["attestationObject"].(string)+`"`), 1)
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"a duplicate top-level member", withMember(reg, `"type":"public-key"`)},
		{"a duplicate response member", nestedBody},
		{"a duplicate member in an ignored member", withMember(reg, `"x":{"a":1,"a":2}`)},
		{"invalid UTF-8", withMember(reg, "\"x\":\"\xff\"")},
		{"not an object", []byte(`["public-key"]`)},
		{"trailing data", append(bytes.Clone(reg), " {}"...)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseRegistrationResponse(c.body); !errors.Is(err, errResponseJSON) {
				t.Errorf("parseRegistrationResponse = %v, want errResponseJSON", err)
			}
		})
	}
	t.Run("a duplicate member in an assertion", func(t *testing.T) {
		t.Parallel()
		body := withMember(marshal(t, assertMembers(t, nil)), `"rawId":"AQ"`)
		if _, err := parseAssertionResponse(body); !errors.Is(err, errResponseJSON) {
			t.Errorf("parseAssertionResponse = %v, want errResponseJSON", err)
		}
	})
}

// TestParseResponse_WebAuthn5_1_8_unknownMembers checks that members the
// parser does not read are ignored, since the JSON forms grow
// (WebAuthn §5.1.8): registration's authenticatorData, publicKey and
// publicKeyAlgorithm conveniences, and an assertion's extension outputs and
// attachment.
func TestParseResponse_WebAuthn5_1_8_unknownMembers(t *testing.T) {
	t.Parallel()
	m := regMembers(t)
	response(m)["authenticatorData"] = "not base64url!"
	response(m)["publicKey"] = 7
	response(m)["publicKeyAlgorithm"] = -7
	m["futureMember"] = map[string]any{"a": []int{1}}
	if _, err := parseRegistrationResponse(marshal(t, m)); err != nil {
		t.Errorf("registration with unread members = %v, want accepted", err)
	}
	a := assertMembers(t, nil)
	a["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": "not a boolean"}, "prf": map[string]any{}}
	a["authenticatorAttachment"] = 5
	if _, err := parseAssertionResponse(marshal(t, a)); err != nil {
		t.Errorf("assertion with unread members = %v, want accepted", err)
	}
}

// TestParseResponse_WebAuthn5_1_credential checks type, rawId and id (§5.1):
// type is public-key, rawId the unpadded base64url of 1 to 1023 bytes, and id
// exactly the unpadded base64url of rawId.
func TestParseResponse_WebAuthn5_1_credential(t *testing.T) {
	t.Parallel()
	long, most := b64(make([]byte, 1024)), b64(make([]byte, 1023))
	cases := []struct {
		name, id, rawID, typ string
		want                 error
	}{
		{"type other than public-key", "AQ", "AQ", "public-key ", errCredentialType},
		{"type empty", "AQ", "AQ", "", errCredentialType},
		{"id disagreeing with rawId", "AQID", "AQIE", "public-key", errIDMismatch},
		{"id padded where rawId is not", "AQI=", "AQI", "public-key", errIDMismatch},
		{"rawId padded", "AQI=", "AQI=", "public-key", errRawID},
		{"rawId in the standard alphabet", "+/8", "+/8", "public-key", errRawID},
		{"rawId with a line break", "AQ\nID", "AQ\nID", "public-key", errRawID},
		{"rawId with nonzero trailing bits", "AR", "AR", "public-key", errRawID},
		{"rawId empty", "", "", "public-key", errRawID},
		{"rawId of 1024 bytes", long, long, "public-key", errRawID},
		{"rawId of 1023 bytes", most, most, "public-key", nil},
		{"rawId of 1 byte", "AQ", "AQ", "public-key", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			reg, assertion := regMembers(t), assertMembers(t, nil)
			for _, m := range []map[string]any{reg, assertion} {
				m["id"], m["rawId"], m["type"] = c.id, c.rawID, c.typ
			}
			_, regErr := parseRegistrationResponse(marshal(t, reg))
			_, assertErr := parseAssertionResponse(marshal(t, assertion))
			for _, err := range []error{regErr, assertErr} {
				if c.want == nil && err != nil {
					t.Errorf("parse = %v, want accepted", err)
				}
				if c.want != nil && !errors.Is(err, c.want) {
					t.Errorf("parse = %v, want %v", err, c.want)
				}
			}
		})
	}
	t.Run("type missing", func(t *testing.T) {
		t.Parallel()
		m := assertMembers(t, nil)
		delete(m, "type")
		if _, err := parseAssertionResponse(marshal(t, m)); !errors.Is(err, errCredentialType) {
			t.Errorf("parseAssertionResponse = %v, want errCredentialType", err)
		}
	})
}

// TestParseAssertionResponse_WebAuthn5_4_3_userHandle checks userHandle: the
// unpadded base64url of 1 to 64 bytes when present, and absent when the
// member is missing or null.
func TestParseAssertionResponse_WebAuthn5_4_3_userHandle(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		handle any
		want   error
		absent bool
	}{
		{"absent", nil, nil, true},
		{"null", json.RawMessage("null"), nil, true},
		{"64 bytes", b64(bytes.Repeat([]byte{7}, 64)), nil, false},
		{"1 byte", "Bw", nil, false},
		{"65 bytes", b64(bytes.Repeat([]byte{7}, 65)), errUserHandle, false},
		{"empty", "", errUserHandle, false},
		{"padded", "Bw==", errUserHandle, false},
		{"standard alphabet", "+w", errUserHandle, false},
		{"not a string", 7, errResponseJSON, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r, err := parseAssertionResponse(marshal(t, assertMembers(t, c.handle)))
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Errorf("parseAssertionResponse = %v, want %v", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAssertionResponse = %v, want accepted", err)
			}
			if (r.userHandle == nil) != c.absent {
				t.Errorf("userHandle = %x, want absent %v", r.userHandle, c.absent)
			}
		})
	}
}

// TestParseResponse_binaryMembers checks the members read as bytes: base64url
// with trailing padding tolerated, anything else refused.
func TestParseResponse_binaryMembers(t *testing.T) {
	t.Parallel()
	m := regMembers(t)
	response(m)["clientDataJSON"] = response(m)["clientDataJSON"].(string) + "=="
	if _, err := parseRegistrationResponse(marshal(t, m)); err != nil {
		t.Errorf("a padded clientDataJSON = %v, want accepted", err)
	}
	a := assertMembers(t, nil)
	response(a)["signature"] = response(a)["signature"].(string) + "="
	if _, err := parseAssertionResponse(marshal(t, a)); err != nil {
		t.Errorf("a padded signature = %v, want accepted", err)
	}
	for _, member := range []string{"clientDataJSON", "attestationObject"} {
		m := regMembers(t)
		response(m)[member] = "a+b/"
		if _, err := parseRegistrationResponse(marshal(t, m)); !errors.Is(err, errResponseJSON) {
			t.Errorf("%s in the standard alphabet = %v, want errResponseJSON", member, err)
		}
	}
	for _, member := range []string{"clientDataJSON", "authenticatorData", "signature"} {
		a := assertMembers(t, nil)
		response(a)[member] = 12
		if _, err := parseAssertionResponse(marshal(t, a)); !errors.Is(err, errResponseJSON) {
			t.Errorf("%s as a number = %v, want errResponseJSON", member, err)
		}
	}
}

// TestParseRegistrationResponse_transports checks what the record keeps of
// getTransports() (WebAuthn §5.2.1.1, §7.1's transports item): at most 8
// values, each non-empty, at most 32 bytes and comma-free, since the record
// joins them with commas; a value outside WebAuthn §5.8.4's enumeration is
// kept as returned.
func TestParseRegistrationResponse_transports(t *testing.T) {
	t.Parallel()
	nine := []string{"usb", "nfc", "ble", "smart-card", "hybrid", "internal", "cable", "t8", "t9"}
	for _, c := range []struct {
		name string
		in   any
		want []string
	}{
		{"nine keep the first eight", nine, nine[:8]},
		{"unfit values dropped", []string{"", strings.Repeat("u", 33), "usb,nfc", strings.Repeat("u", 32), "nfc"}, []string{strings.Repeat("u", 32), "nfc"}},
		{"absent", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m := regMembers(t)
			if c.in == nil {
				delete(response(m), "transports")
			} else {
				response(m)["transports"] = c.in
			}
			r, err := parseRegistrationResponse(marshal(t, m))
			if err != nil {
				t.Fatalf("parseRegistrationResponse = %v", err)
			}
			if !slices.Equal(r.transports, c.want) {
				t.Errorf("transports = %q, want %q", r.transports, c.want)
			}
		})
	}
}

// TestParseRegistrationResponse_WebAuthn2_1_1_attachment checks that the two
// attachment modalities (WebAuthn §5.4.5) are kept and an unknown value is
// ignored (WebAuthn §2.1.1).
func TestParseRegistrationResponse_WebAuthn2_1_1_attachment(t *testing.T) {
	t.Parallel()
	for in, want := range map[any]access.AuthenticatorAttachment{
		"platform":       access.AttachmentPlatform,
		"cross-platform": access.AttachmentCrossPlatform,
		"other":          "",
		"Platform":       "",
	} {
		m := regMembers(t)
		m["authenticatorAttachment"] = in
		r, err := parseRegistrationResponse(marshal(t, m))
		if err != nil {
			t.Fatalf("attachment %q: %v", in, err)
		}
		if r.attachment != want {
			t.Errorf("attachment %q kept as %q, want %q", in, r.attachment, want)
		}
	}
}

// TestParseRegistrationResponse_WebAuthn7_1_extensions checks the client
// extension outputs: credProps.rk is read (WebAuthn §10.1.3), and an
// unsolicited output such as WebAuthn §16.17.1.1's prf is ignored, as §7.1's
// extension step allows.
func TestParseRegistrationResponse_WebAuthn7_1_extensions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		ext  any
		want *bool
	}{
		{"rk false", map[string]any{"credProps": map[string]any{"rk": false}}, new(false)},
		{"no credProps", map[string]any{}, nil},
		{"credProps without rk", map[string]any{"credProps": map[string]any{}}, nil},
		{"an unsolicited prf output", map[string]any{"prf": map[string]any{"enabled": true}, "credProps": map[string]any{"rk": true}}, new(true)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			m := regMembers(t)
			m["clientExtensionResults"] = c.ext
			r, err := parseRegistrationResponse(marshal(t, m))
			if err != nil {
				t.Fatalf("parseRegistrationResponse = %v", err)
			}
			if (r.residentKey == nil) != (c.want == nil) || (r.residentKey != nil && *r.residentKey != *c.want) {
				t.Errorf("residentKey = %v, want %v", r.residentKey, c.want)
			}
		})
	}
}
