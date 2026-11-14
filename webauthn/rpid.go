package webauthn

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// maxRPIDBytes and maxLabelBytes are RFC 1034 §3.1's limits on a domain name
// and on one of its labels.
const (
	maxRPIDBytes  = 253
	maxLabelBytes = 63
)

// ErrIllegalRPID reports a value that cannot be a relying-party ID. Every
// error [ValidateRPID] returns matches it with errors.Is and also states the
// reason.
var ErrIllegalRPID = errors.New("access/webauthn: illegal relying-party ID")

// ValidateRPID reports whether id is a legal relying-party ID: a valid domain
// string (WebAuthn §4 "RP ID", WHATWG URL §3.4) in lowercase, of at most 253
// bytes, with no scheme, port, path, query or fragment, and not an IP address.
// Its labels hold 1 to 63 letters, digits and hyphens, none at a label's ends
// and none in both its third and fourth places unless it starts with "xn--"
// (UTS #46 §4.1); the last label is not a number (WHATWG URL §3.5), and a
// single label is legal only as localhost. A refusal matches [ErrIllegalRPID].
func ValidateRPID(id string) error {
	lower := strings.ToLower(id)
	reason := rpidReason(lower)
	// Lowercase is access's own rule: rpIdHash is computed over the configured
	// bytes, so whether a mixed-case ID verifies would depend on the client.
	if reason == "" && id != lower {
		reason = fmt.Sprintf("the value must be spelled in lowercase, as %q", lower)
	}
	if reason != "" {
		return fmt.Errorf("%w %q: %s", ErrIllegalRPID, id, reason)
	}
	return nil
}

// rpidReason returns why the lowercased id is not a relying-party ID, or ""
// when it is one. Lowercase is checked by the caller, so that a refusal for
// case alone names a lowercase form that is itself legal.
func rpidReason(id string) string {
	if id == "" {
		return "the value is empty"
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(id, "["), "]")); err == nil {
		return "the value is an IP address"
	}
	if strings.ContainsAny(id, ":/?#") {
		return "the value is not a bare domain: it has a scheme, port, path, query or fragment"
	}
	if len(id) > maxRPIDBytes {
		return fmt.Sprintf("the value is longer than %d bytes", maxRPIDBytes)
	}
	labels := strings.Split(id, ".")
	for _, label := range labels {
		if reason := labelReason(label); reason != "" {
			return reason
		}
	}
	if last := labels[len(labels)-1]; isNumber(last) {
		return fmt.Sprintf("the last label %q is a number, which a browser reads as an IPv4 address", last)
	}
	if len(labels) == 1 && id != localhost {
		return "a single label is a relying-party ID only as localhost"
	}
	return ""
}

// labelReason returns why label is not an LDH label of a valid domain, or "".
func labelReason(label string) string {
	switch {
	case label == "":
		return "the value has an empty label"
	case len(label) > maxLabelBytes:
		return fmt.Sprintf("the label %q is longer than %d bytes", label, maxLabelBytes)
	case label[0] == '-' || label[len(label)-1] == '-':
		return fmt.Sprintf("the label %q starts or ends with a hyphen", label)
	case len(label) >= 4 && label[2:4] == "--" && !strings.HasPrefix(label, "xn--"):
		return fmt.Sprintf("the label %q has hyphens in its third and fourth places", label)
	}
	for i := range len(label) {
		if c := label[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Sprintf("the label %q holds %q, which is not a letter, digit or hyphen", label, label[i:i+1])
		}
	}
	return ""
}

// isNumber reports whether a non-empty lowercase label is a number in WHATWG
// URL §3.5's "ends in a number" sense: all digits, or "0x" followed by zero or
// more hex digits, the forms its IPv4 number parser accepts.
func isNumber(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(label, "0123456789") == ""
}
