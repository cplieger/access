package webauthn

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// checkRPID asserts ValidateRPID's verdict on id, and that a refusal matches
// ErrIllegalRPID and names the value.
func checkRPID(t *testing.T, id string, valid bool) {
	t.Helper()
	err := ValidateRPID(id)
	if valid {
		if err != nil {
			t.Errorf("ValidateRPID(%q) = %v, want nil", id, err)
		}
		return
	}
	if !errors.Is(err, ErrIllegalRPID) {
		t.Fatalf("ValidateRPID(%q) = %v, want an error matching ErrIllegalRPID", id, err)
	}
	if !strings.Contains(err.Error(), strconv.Quote(id)) {
		t.Errorf("ValidateRPID(%q) = %q, want it to name the value", id, err)
	}
}

// TestValidateRPID_goWebAuthnCases runs go-webauthn v0.18.2's TestValidateRPID
// table as data, less the two cases design 7.4 changes on purpose, which
// TestValidateRPID_WHATWG_URL_3_4 re-asserts as refusals.
func TestValidateRPID_goWebAuthnCases(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/rpid/go-webauthn-validate-rpid.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) != 40 {
		t.Fatalf("read %d cases, want the 40 the manifest holds", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			checkRPID(t, c.Value, c.Valid)
		})
	}
}

// TestValidateRPID_WHATWG_URL_3_4 checks the RP ID rule of design 7.4: WebAuthn
// §4 "RP ID" is a valid domain string (WHATWG URL §3.4), which for a lowercase
// ASCII ID is LDH labels (UTS #46 §4.1 UseSTD3ASCIIRules and CheckHyphens) and a
// last label that does not end in a number (WHATWG URL §3.5 "ends in a number").
func TestValidateRPID_WHATWG_URL_3_4(t *testing.T) {
	t.Parallel()
	label63 := strings.Repeat("a", 63)
	id253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61)
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{name: "a domain", id: "example.com", valid: true},
		{name: "a subdomain", id: "sub.example.com", valid: true},
		{name: "localhost, the one single label", id: "localhost", valid: true},
		{name: "digits and an inner hyphen", id: "a1-b2.example", valid: true},
		{name: "an all-digit first label", id: "123.example", valid: true},
		{name: "an A-label, accepted as LDH (UTS #46 §4.1, design 7.4)", id: "xn--bcher-kva.example", valid: true},
		{name: "hyphens in places 4 and 5 (UTS #46 §4.1 CheckHyphens)", id: "abc--d.example", valid: true},
		{name: "a 63-byte label (RFC 1034 §3.1)", id: label63 + ".example", valid: true},
		{name: "253 bytes (RFC 1034 §3.1)", id: id253, valid: true},
		{name: "0x then a non-hex digit is no number (WHATWG URL §3.5)", id: "example.0xg", valid: true},

		{name: "empty", id: ""},
		{name: "upper case (design 7.4, access's own rule)", id: "EXAMPLE.COM"},
		{name: "mixed case", id: "Example.com"},
		{name: "an underscore (WHATWG URL §3.4, UseSTD3ASCIIRules)", id: "exa_mple.com"},
		{name: "an asterisk", id: "exa*mple.com"},
		{name: "a tilde", id: "exa~mple.com"},
		{name: "a space", id: "exa mple.com"},
		{name: "a non-ASCII letter", id: "ex\u00e4mple.com"},
		{name: "hyphens in places 3 and 4 (UTS #46 §4.1 CheckHyphens)", id: "ab--cd.example"},
		{name: "hyphens in places 3 and 4 of an inner label", id: "a.ab--cd.example"},
		{name: "a label starting with a hyphen", id: "a.-b.com"},
		{name: "a label ending with a hyphen", id: "a.b-.com"},
		{name: "a 64-byte label", id: strings.Repeat("a", 64) + ".example"},
		{name: "254 bytes", id: id253 + "b"},
		{name: "a hex last label (WHATWG URL §3.5)", id: "example.0x1"},
		{name: "0x with no digits (WHATWG URL §3.5)", id: "example.0x"},
		{name: "a two-digit hex last label", id: "example.0xff"},
		{name: "an all-digit last label", id: "example.0"},
		{name: "an IPv4 address", id: "1.2.3.4"},
		{name: "a bracketed IPv6 address", id: "[::1]"},
		{name: "an IPv6 address", id: "::1"},
		{name: "a single label other than localhost", id: "nas"},
		{name: "a trailing dot", id: "example.com."},
		{name: "a scheme", id: "http://example.com"},
		{name: "a port", id: "example.com:8443"},
		{name: "a path", id: "example.com/path"},
		{name: "a query", id: "example.com?q"},
		{name: "a fragment", id: "example.com#f"},
		{name: "user information", id: "user@example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checkRPID(t, tt.id, tt.valid)
		})
	}
}

// TestValidateRPID_lowercaseForm checks that a refusal for case alone names the
// lowercase form (design 7.4: the lowercase rule keeps its own refusal), and
// that no refusal offers a lowercase form the rule would still refuse.
func TestValidateRPID_lowercaseForm(t *testing.T) {
	t.Parallel()
	t.Run("case alone", func(t *testing.T) {
		t.Parallel()
		err := ValidateRPID("Sub.EXAMPLE.com")
		if err == nil || !strings.Contains(err.Error(), `"sub.example.com"`) {
			t.Errorf(`ValidateRPID("Sub.EXAMPLE.com") = %v, want it to name "sub.example.com"`, err)
		}
	})
	t.Run("case and an illegal character", func(t *testing.T) {
		t.Parallel()
		err := ValidateRPID("EXA_MPLE.COM")
		if err == nil || strings.Contains(err.Error(), `"exa_mple.com"`) {
			t.Errorf(`ValidateRPID("EXA_MPLE.COM") = %v, want a refusal that does not offer "exa_mple.com"`, err)
		}
	})
}

// TestValidateRPID_statesIPReason checks that an IP address is refused as one
// (WebAuthn §4: an RP ID is a valid domain string, never an IP address), not
// as the port or number its colons and digits would otherwise read as.
func TestValidateRPID_statesIPReason(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"::1", "[::1]", "2001:db8::1", "10.0.0.5"} {
		if err := ValidateRPID(id); err == nil || !strings.Contains(err.Error(), "IP address") {
			t.Errorf("ValidateRPID(%q) = %v, want a refusal naming an IP address", id, err)
		}
	}
}
