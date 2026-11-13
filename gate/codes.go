package gate

import (
	"slices"

	"github.com/cplieger/access"
)

// authenticatingCodes is what every row that runs Authenticate can answer:
// ErrorFor's codes, a recovery session's auth_session_required among them.
var authenticatingCodes = []access.Code{
	access.CodeAuthRequired, access.CodeSessionExpired, access.CodeInvalidCredentials, access.CodeKeyInvalid,
	access.CodeSessionRequired, access.CodeUnavailable,
}

// Codes is every code route r can answer, in access.Codes() order.
func Codes(r Route) []access.Code { //nolint:gocritic // hugeParam: a Route is the caller's table row
	can := []access.Code{access.CodeMethodNotAllowed}
	if r.Class != Public {
		can = append(can, authenticatingCodes...)
	}
	switch r.Class {
	case Key:
		can = append(can, access.CodeKeyRequired)
		if r.Scope != "" {
			can = append(can, access.CodeScopeRequired)
		}
	case Scoped:
		can = append(can, access.CodeScopeRequired, access.CodeForbidden)
	default:
	}
	if crossChecked(&r) {
		can = append(can, access.CodeCrossOrigin)
	}
	return inCodesOrder(can)
}

// MountCodes is every code the gate answers outside any row: a request that
// matches no row. An app's error union is every row's Codes and these.
func MountCodes() []access.Code { return []access.Code{access.CodeNotFound} }

func inCodesOrder(can []access.Code) []access.Code {
	var out []access.Code
	for _, c := range access.Codes() {
		if slices.Contains(can, c) {
			out = append(out, c)
		}
	}
	return out
}
