package accesshttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// TestOpCodesFromProducers holds opAnswers against each route's serve
// function: every error chain it can return or hand (*Handler).refusal,
// followed through the module up to the app's Policy and mapped through
// classify, answers a listed code and Reason, or one in its code's open
// family, or is refuted; every listed code, reason and open
// mark has such a producer; every producer error has a producerErrors row
// the error table names; and every refuted row still describes a path.
func TestOpCodesFromProducers(t *testing.T) {
	t.Parallel()
	p := loadProducers(t)
	used := make([]bool, len(refuted))
	refutedAt := func(route string, code access.Code, leaf string) bool {
		for i, r := range refuted {
			if r.route == route && r.code == code && r.leaf == leaf {
				used[i] = true
				return true
			}
		}
		return false
	}
	usedReason := make([]bool, len(refutedReasons))
	reasonRefuted := func(route string, code access.Code, reason string) bool {
		for i, r := range refutedReasons {
			if r.route == route && r.code == code && r.reason == reason {
				usedReason[i] = true
				return true
			}
		}
		return false
	}
	for i := range specs {
		s := &specs[i]
		produced := p.produced(t, p.serveFunc(t, s), s.cer, func(c chain) {
			named := false
			for _, tm := range c {
				named = tm.kind == termLeaf && refutedAt(s.name, "", qualified(tm.obj)) || named
			}
			if !named {
				t.Errorf("%s can return %s, which the error table does not name", s.name, chainString(c))
			}
		})
		listed := listedAnswers(s)
		for code, reasons := range produced {
			rs, ok := listed[code]
			if !ok {
				if !refutedAt(s.name, code, "") {
					t.Errorf("%s can answer %s from %s, which opAnswers[%q] does not list", s.name, code, firstFrom(reasons), s.op)
				}
				continue
			}
			for r, from := range reasons {
				if !rs.admitsProduced(code, r) && !reasonRefuted(s.name, code, r) {
					t.Errorf("%s can answer %s with reason %s from %s, which its answers do not list", s.name, code, reasonLabel(r), from)
				}
			}
		}
		seen := map[access.Code]bool{}
		for _, a := range opAnswers[s.op] {
			if seen[a.code] {
				t.Errorf("opAnswers[%q] lists %s twice", s.op, a.code)
			}
			seen[a.code] = true
			reasons, ok := produced[a.code]
			if !ok {
				t.Errorf("%s: opAnswers[%q] lists %s, which no producer answers", s.name, s.op, a.code)
				continue
			}
			for _, r := range a.listed {
				if _, ok := reasons[r]; !ok {
					t.Errorf("%s: opAnswers[%q] lists reason %q of %s, which no producer gives there", s.name, s.op, r, a.code)
				}
			}
			if a.open && !hasFamily(reasons) {
				t.Errorf("%s: opAnswers[%q] marks %s open, which no producer answers with a reason the route does not fix", s.name, s.op, a.code)
			}
		}
		for _, r := range refuted {
			if r.route == s.name && r.leaf == "" {
				if _, ok := listed[r.code]; ok {
					t.Errorf("refuted %s %s is listed in its Codes", r.route, r.code)
				}
			}
		}
		for _, r := range refutedReasons {
			if rs, ok := listed[r.code]; r.route == s.name && ok && slices.Contains(rs.listed, r.reason) {
				t.Errorf("refuted %s %s reason %q is listed in its answers", r.route, r.code, r.reason)
			}
		}
	}
	for i, r := range refuted {
		if !used[i] {
			t.Errorf("refuted %s %s%s: no producer path reaches it", r.route, r.code, r.leaf)
		}
	}
	for i, r := range refutedReasons {
		if !usedReason[i] {
			t.Errorf("refuted %s %s reason %q: no producer path reaches it", r.route, r.code, r.reason)
		}
	}
	for name := range p.unregistered {
		t.Errorf("%s is a producer error with no producerErrors row", name)
	}
}

// TestFrontAnswersFromProducers holds the guard's and the transport's
// answers against what runs before a serve function (method, origin,
// guard, path value, query) and the body decodes in it: a code listed with
// more than one reason, or open, has a producer for each, and each front
// answer is listed by some route. A code with one reason is
// TestDescriptorCodesReached's, whose boundary cases checkReason holds.
func TestFrontAnswersFromProducers(t *testing.T) {
	t.Parallel()
	p := loadProducers(t)
	front := map[access.Code]map[string]string{}
	unnamed := func(c chain) {
		t.Errorf("the front can return %s, which the error table does not name", chainString(c))
	}
	for _, name := range []string{"guard", "pathValues", "decodeQuery"} {
		for code, reasons := range p.produced(t, p.declNamed(t, name), ceremonyNone, unnamed) {
			for r, from := range reasons {
				addProduced(front, code, r, from)
			}
		}
	}
	for _, err := range []error{errMethodNotAllowed, errCrossOrigin} {
		e, _ := classify(err, ceremonyNone)
		addProduced(front, e.Code, e.Reason, err.Error())
	}
	for name := range p.unregistered {
		t.Errorf("%s is a producer error with no producerErrors row", name)
	}
	anywhere := map[access.Code]reasonSet{}
	for i := range specs {
		s := &specs[i]
		serve := p.produced(t, p.serveFunc(t, s), s.cer, func(chain) {})
		for _, dc := range scopeConfigs {
			class, _ := s.classFor(&dc)
			for code, rs := range slices.Concat(guardAnswers(class), s.transportAnswers()).reasons() {
				anywhere[code] = mergeReasons(anywhere[code], rs)
				if len(rs.listed) == 1 && !rs.open {
					continue // its boundary case answers it, with that one reason
				}
				for _, r := range rs.listed {
					if _, ok := front[code][r]; !ok {
						if _, ok := serve[code][r]; !ok {
							t.Errorf("%s: its guard or transport lists reason %q of %s, which nothing before or in its serve function gives", s.name, r, code)
						}
					}
				}
				if rs.open && !hasFamily(front[code]) && !hasFamily(serve[code]) {
					t.Errorf("%s: its guard or transport marks %s open, which nothing before or in its serve function answers with a reason the route does not fix", s.name, code)
				}
			}
		}
	}
	for code, reasons := range front {
		for r, from := range reasons {
			if !anywhere[code].admitsProduced(code, r) {
				t.Errorf("the front can answer %s with reason %s from %s, which no route's guard or transport lists", code, reasonLabel(r), from)
			}
		}
	}
}

// scopeConfigs is the two key-scope settings every route's class takes.
var scopeConfigs = []DescriptorConfig{{}, {AdminScope: "a", ManageUsersScope: "u", CreateKeysScope: "k"}}

// listedAnswers is s's answers under both scope settings, merged by code.
func listedAnswers(s *routeSpec) map[access.Code]reasonSet {
	out := map[access.Code]reasonSet{}
	for _, dc := range scopeConfigs {
		class, _ := s.classFor(&dc)
		for code, rs := range s.answers(class).reasons() {
			out[code] = mergeReasons(out[code], rs)
		}
	}
	return out
}

func mergeReasons(a, b reasonSet) reasonSet {
	listed := slices.Concat(a.listed, b.listed)
	slices.Sort(listed)
	return reasonSet{listed: slices.Compact(listed), open: a.open || b.open}
}

// produced is every code fn's producers can answer, each with the Reasons
// it carries (producedReason's keys) and the chain that answers it; a
// chain the error table does not name goes to unnamed.
func (p *producers) produced(t *testing.T, fn *ast.FuncDecl, cer ceremony, unnamed func(chain)) map[access.Code]map[string]string {
	t.Helper()
	out := map[access.Code]map[string]string{}
	for _, c := range p.routeErrors(fn) {
		vals, ok := p.values(c)
		if !ok || len(vals) == 0 && cer == ceremonyNone {
			continue
		}
		e, ok := classify(p.joined(c, vals), cer)
		if !ok {
			unnamed(c)
			continue
		}
		r, known := producedReason(e.Code, e.Reason)
		if !known {
			t.Errorf("%s can answer %s with reason %q from %s, which access neither fixes nor leaves open there", fn.Name.Name, e.Code, e.Reason, chainString(c))
			continue
		}
		addProduced(out, e.Code, r, chainString(c))
	}
	return out
}

func addProduced(m map[access.Code]map[string]string, code access.Code, reason, from string) {
	if m[code] == nil {
		m[code] = map[string]string{}
	}
	m[code][reason] = from
}

func firstFrom(reasons map[string]string) string {
	for _, k := range slices.Sorted(maps.Keys(reasons)) {
		return reasons[k]
	}
	return ""
}

// fixedReasons is every Reason access fixes, and "" for none.
var fixedReasons = func() map[string]bool {
	m := map[string]bool{"": true}
	for _, r := range Reasons() {
		m[r] = true
	}
	return m
}()

// producedReason is how a Reason classify gave code stands against the
// route's answers: itself when access fixes it, else the open family that
// leaves it to the request, the IdP or the Policy; false for
// a reason in none.
func producedReason(code access.Code, r string) (string, bool) {
	switch {
	case r == policyReason:
		return familyPolicy, code == access.CodeForbidden
	case code == access.CodeOIDCFailed && strings.HasPrefix(r, providerErrorPrefix):
		return familyProvider, true
	case strings.Contains(r, unresolved) || !fixedReasons[r]:
		return familyField, code == access.CodeBadRequest
	}
	return r, true
}

// familyCode is the one code each open family reaches.
var familyCode = map[string]access.Code{
	familyField:    access.CodeBadRequest,
	familyProvider: access.CodeOIDCFailed,
	familyPolicy:   access.CodeForbidden,
}

// admitsProduced reports whether rs holds r, producedReason's key for
// code: the reason listed, or its family's code marked open.
func (rs reasonSet) admitsProduced(code access.Code, r string) bool {
	if fc, isFamily := familyCode[r]; isFamily {
		return rs.open && fc == code
	}
	return slices.Contains(rs.listed, r)
}

// admits reports whether code may carry r at run time on a route with
// rs: r listed, or, with rs open, r in its code's family: a field's name
// on auth_bad_request, an IdP's error code on auth_oidc_failed, and any
// Policy's reason on auth_forbidden.
func (rs reasonSet) admits(code access.Code, r string) bool {
	if slices.Contains(rs.listed, r) {
		return true
	}
	if !rs.open {
		return false
	}
	switch code {
	case access.CodeForbidden:
		return true
	case access.CodeOIDCFailed:
		return strings.HasPrefix(r, providerErrorPrefix)
	case access.CodeBadRequest:
		return !fixedReasons[r]
	default:
		return false
	}
}

func hasFamily(reasons map[string]string) bool {
	for r := range reasons {
		if _, ok := familyCode[r]; ok {
			return true
		}
	}
	return false
}

func reasonLabel(r string) string {
	switch r {
	case familyField:
		return "naming a field"
	case familyProvider:
		return "carrying an IdP's error code"
	case familyPolicy:
		return "of the app's Policy"
	}
	return fmt.Sprintf("%q", r)
}

// declNamed is accesshttp's function or Handler method name.
func (p *producers) declNamed(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	obj := p.accesshttp().Scope().Lookup(name)
	if obj == nil {
		h, _ := p.accesshttp().Scope().Lookup("Handler").(*types.TypeName)
		obj, _, _ = types.LookupFieldOrMethod(types.NewPointer(h.Type()), false, p.accesshttp(), name)
	}
	fn, ok := obj.(*types.Func)
	if !ok || p.decls[fn] == nil {
		t.Fatalf("no declaration of %s", name)
	}
	return p.decls[fn]
}

// The invariants the analysis cannot read: it follows no condition on a
// Decision's operation, so a refusal account gives one operation reaches
// every route whose operation shares the check.
const (
	singleOwnerRefuted = "authorize refuses single_owner itself only for a Decision addsAccount holds for (a creation other than setup's, an invite, or an enable), and checkRules refuses registration in a single-user app; this route's operation decides none of them there, so only the app's Policy can answer it"
	ownerRoleRefuted   = "ownerGuard answers owner_role only to OpSetRole, which UpdateUser alone decides"
	lastOwnerRefuted   = "ownerGuard answers last_owner only where removesOwner holds: OpDeleteUser, OpSetEnabled to false and OpSetOwner to false"
)

// refutedReasons is each Reason the analysis follows to a route that the
// runtime rules out there, with the invariant that rules it out.
var refutedReasons = func() []refutedReason {
	var out []refutedReason
	add := func(code access.Code, reason, invariant string, routes ...string) {
		for _, r := range routes {
			out = append(out, refutedReason{route: r, code: code, reason: reason, invariant: invariant})
		}
	}
	add(access.CodeForbidden, "single_owner", singleOwnerRefuted,
		"authSetupPassword", "authSetupPasskeyFinish", "authRegisterPassword", "authRegisterPasskeyBegin", "authRegisterPasskeyFinish",
		"authKeys", "authKeyCreate", "authKeyRename", "authKeyRotate", "authKeyRevoke", "authAdminKeys", "authAdminKeyRevoke",
		"authAdminUsers", "authAdminUserDelete", "authAdminOwner", "authAdminSSOReadiness", "authAdminOIDCUnlink", "authAdminOIDCRelink",
		"authAdminTemporaryPassword", "authAdminSecondFactorReset", "authAdminTokens", "authAdminSecurityLog")
	add(access.CodeForbidden, "owner_role", ownerRoleRefuted,
		"authAdminUserDelete", "authAdminOwner", "authAdminOIDCUnlink", "authAdminOIDCRelink", "authAdminTemporaryPassword", "authAdminSecondFactorReset")
	add(access.CodeForbidden, "last_owner", lastOwnerRefuted,
		"authAdminOIDCUnlink", "authAdminOIDCRelink", "authAdminTemporaryPassword", "authAdminSecondFactorReset")
	add(access.CodeBadRequest, "redirect_too_long", "AcceptInviteOIDCBegin answers a BeginRequest with no Redirect, so Begin's ErrRedirectTooLong arm cannot fire there",
		"authInviteAcceptOIDC")
	return out
}()

type refutedReason struct {
	route, reason, invariant string
	code                     access.Code
}

// oidcConfigRefuted is why no validated configuration reaches an
// oidc.ErrConfigInvalid arm of Begin or Finish.
const oidcConfigRefuted = "Begin's and Finish's session-cookie Validate arms are ruled out by access.New validating the Authenticator's cookie config in Config.resolve; Begin's seal arm by NewProvider's checkFlowFits, which seals the largest flow under a cookie Name of at most access.MaxCookieNameBytes, the cap CookieConfig.Validate enforces"

// refuted is each path the analysis follows that the runtime rules out: a
// code the route's producers seem to answer, or, with leaf set, an error
// the error table does not name, each with the invariant that rules it out.
var refuted = []struct {
	route, leaf, invariant string
	code                   access.Code
}{
	{route: "authKeyCreate", code: access.CodeNotFound, invariant: "serveKeyCreate passes account.As(c.p), which is never out of band, so admitMinter picks OpCreateOwnKey and the ErrNotFound arm for OpCreateKeyFor in authorizeMint cannot run"},
	{route: "authOIDCStartSignIn", code: access.CodeBadRequest, invariant: "the sign-in query decode's signInTarget replaces a redirect over oidc.MaxRedirectBytes with /, so Begin's ErrRedirectTooLong arm cannot fire"},
	{route: "authOIDCStartSignIn", code: access.CodeOIDCFailed, invariant: "serveOIDCStartSignIn begins IntentSignIn with no session or user, which BeginRequest.check's sign-in arm accepts, and Begin skips its Sec-Fetch-Site check for a sign-in"},
	{route: "authOIDCStartLink", code: access.CodeOIDCFailed, invariant: "startSessionFlow refuses a Sec-Fetch-Site other than same-origin before Begin and passes the guard's session ID, 32 hex characters under maxSessionIDBytes, and user ID, which BeginRequest.check's session-bound arms accept"},
	{route: "authOIDCStartStepUp", code: access.CodeOIDCFailed, invariant: "startSessionFlow refuses a Sec-Fetch-Site other than same-origin before Begin and passes the guard's session ID, 32 hex characters under maxSessionIDBytes, and user ID, which BeginRequest.check's session-bound arms accept"},
	{route: "authInviteAcceptOIDC", code: access.CodeOIDCFailed, invariant: "serveInviteAcceptOIDC refuses a Sec-Fetch-Site other than same-origin before Begin and passes AcceptInviteOIDCBegin's request, IntentInvite with a 64-byte hex SHA-256 and no redirect, which BeginRequest.check's invite arm accepts"},
	{route: "authOIDCCallback", code: access.CodeUsernameTaken, invariant: "oidcInvite reads the name inside the Update that creates the account and commits nothing when it is taken, so acceptIn's ErrUsernameTaken refusal of a store's CreateUser cannot fire on the callback under a serialisable Update"},
	{route: "authTOTPRemove", code: access.CodeTOTPDisabled, invariant: "RemoveTOTP enters verifyProof only while totpOn holds for the Rules value it began with, the one verifyProof's code arm reads, so that arm's ErrTOTPDisabled cannot fire there"},
	{route: "authSetupPassword", code: access.CodeSecondFactorRequired, invariant: "passwordDraft mints a new account's NextEnrol with ticketMint's unknownDevice false, since only an existing account's enrolment needs a known device, so ticketMethods' ErrEnrolNeedsKnownDevice arm cannot fire there"},
	{route: "authInviteAcceptPassword", code: access.CodeSecondFactorRequired, invariant: "passwordDraft mints a new account's NextEnrol with ticketMint's unknownDevice false, since only an existing account's enrolment needs a known device, so ticketMethods' ErrEnrolNeedsKnownDevice arm cannot fire there"},
	{route: "authRegisterPassword", code: access.CodeSecondFactorRequired, invariant: "passwordDraft mints a new account's NextEnrol with ticketMint's unknownDevice false, since only an existing account's enrolment needs a known device, so ticketMethods' ErrEnrolNeedsKnownDevice arm cannot fire there"},
	{route: "authLoginRecoveryCode", code: access.CodeSecondFactorRequired, invariant: "countRecoveryIn mints its NextEnrol with ticketMint's unknownDevice false, since step 1 settled the device before minting the ticket the recovery code replaces, so ticketMethods' ErrEnrolNeedsKnownDevice arm cannot fire there"},
	{route: "authLoginSetPassword", code: access.CodeSecondFactorRequired, invariant: "stagePassword mints its NextEnrol with ticketMint's unknownDevice false, since a temporary password is the issuer's trust and its step 1 reads no device, so ticketMethods' ErrEnrolNeedsKnownDevice arm cannot fire there"},
	{route: "authSetupPasskeyFinish", code: access.CodeRateLimited, invariant: noPendRefuted},
	{route: "authLoginPasskeyFinish", code: access.CodeRateLimited, invariant: noPendRefuted},
	{route: "authRegisterPasskeyFinish", code: access.CodeRateLimited, invariant: noPendRefuted},
	{route: "authLoginSetPassword", leaf: modulePath + ".ErrHashInvalid", invariant: "chosenPassword verifies against the ticket's temporary-password hash, which step 1 verified on the same Hasher, whose Capacity never changes, so Verify's over-budget ErrHashInvalid arm cannot fire there"},
	{route: "authKeyCreate", leaf: modulePath + ".ErrInvalidKeyPrefix", invariant: "CreateAPIKey's begin validates the Rules value it mints under, and Rules.Validate's KeyPrefix check refuses a KeyPrefix access.ValidateKeyPrefix refuses, so GenerateAPIKey in CreateAPIKey cannot"},
	{route: "authKeyRotate", leaf: modulePath + ".ErrInvalidKeyPrefix", invariant: "admitRotation's begin validates the Rules value RotateAPIKey generates under, and Rules.Validate's KeyPrefix check refuses a KeyPrefix access.ValidateKeyPrefix refuses, so GenerateAPIKey in RotateAPIKey cannot"},
	{route: "authOIDCStartSignIn", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCStartLink", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCStartStepUp", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authInviteAcceptOIDC", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCCallback", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
}

const modulePath = "github.com/cplieger/access"

// noPendRefuted is why no passkey ceremony's finish mints a pending sign-in.
const noPendRefuted = "the finish's sessionOp sets no pend, and only op.pend gives complete a pending sign-in to mint, so mintTicket's full-list refusal cannot fire there"

var producerErrors = map[string]error{
	modulePath + "/accesshttp.errMethodNotAllowed":       errMethodNotAllowed,
	modulePath + "/accesshttp.errCrossOrigin":            errCrossOrigin,
	modulePath + "/accesshttp.errPendingTooLarge":        errPendingTooLarge,
	modulePath + "/accesshttp.requestError":              &requestError{reason: "x"},
	modulePath + ".ErrRecentAuthRequired":                access.ErrRecentAuthRequired,
	modulePath + ".ErrUnauthenticated":                   access.ErrUnauthenticated,
	modulePath + ".ErrAccountDisabled":                   access.ErrAccountDisabled,
	modulePath + ".ErrInvalidAPIKey":                     access.ErrInvalidAPIKey,
	modulePath + ".ErrSessionExpired":                    access.ErrSessionExpired,
	modulePath + ".ErrSessionNotFound":                   access.ErrSessionNotFound,
	modulePath + ".ErrSessionTransport":                  access.ErrSessionTransport,
	modulePath + ".InvalidCredentialError":               &access.InvalidCredentialError{Err: access.ErrAccountDisabled},
	modulePath + ".ErrHashBusy":                          access.ErrHashBusy,
	modulePath + ".ErrHTTPSRequired":                     access.ErrHTTPSRequired,
	modulePath + ".ErrBreachCheckUnavailable":            access.ErrBreachCheckUnavailable,
	modulePath + ".ErrAuthBackend":                       access.ErrAuthBackend,
	modulePath + ".ErrTokenInvalid":                      access.ErrTokenInvalid,
	modulePath + ".PasswordError":                        &access.PasswordError{Reason: access.PasswordCommon},
	modulePath + "/account.ErrSessionRequired":           account.ErrSessionRequired,
	modulePath + "/account.ErrScopeRequired":             account.ErrScopeRequired,
	modulePath + "/account.ErrSSOOnly":                   account.ErrSSOOnly,
	modulePath + "/account.ErrSSOLinked":                 account.ErrSSOLinked,
	modulePath + "/account.ErrTemporaryPasswordExposed":  account.ErrTemporaryPasswordExposed,
	modulePath + "/account.ErrNotAdmitted":               account.ErrNotAdmitted,
	modulePath + "/account.ErrNoUsableMethod":            account.ErrNoUsableMethod,
	modulePath + "/account.ErrEnrolNeedsKnownDevice":     account.ErrEnrolNeedsKnownDevice,
	modulePath + "/account.ErrProvisioningDisabled":      account.ErrProvisioningDisabled,
	modulePath + "/account.ErrUnknownSSOMode":            account.ErrUnknownSSOMode,
	modulePath + "/account.ErrBreachCheckUnavailable":    account.ErrBreachCheckUnavailable,
	modulePath + "/account.ErrServiceClosed":             account.ErrServiceClosed,
	modulePath + "/account.ErrRulesInvalid":              account.ErrRulesInvalid,
	modulePath + "/account.ErrTTLTooLong":                account.ErrTTLTooLong,
	modulePath + "/account.ErrTTLNegative":               account.ErrTTLNegative,
	modulePath + "/account.ErrNoChange":                  account.ErrNoChange,
	modulePath + "/account.ErrKeyExpiryInvalid":          account.ErrKeyExpiryInvalid,
	modulePath + "/account.ErrCurrentPasswordRequired":   account.ErrCurrentPasswordRequired,
	modulePath + "/account.ErrUsernameTaken":             account.ErrUsernameTaken,
	modulePath + "/account.ErrKeyLabelTaken":             account.ErrKeyLabelTaken,
	modulePath + "/account.ErrPasswordLoginDisabled":     account.ErrPasswordLoginDisabled,
	modulePath + "/account.ErrSetupComplete":             account.ErrSetupComplete,
	modulePath + "/account.ErrRegistrationClosed":        account.ErrRegistrationClosed,
	modulePath + "/account.ErrRegistrationFull":          account.ErrRegistrationFull,
	modulePath + "/account.ErrSetupTokenRequired":        account.ErrSetupTokenRequired,
	modulePath + "/account.ErrLastMethod":                account.ErrLastMethod,
	modulePath + "/account.ErrOIDCIdentityTaken":         account.ErrOIDCIdentityTaken,
	modulePath + "/account.ErrAlreadyLinked":             account.ErrAlreadyLinked,
	modulePath + "/account.ErrMethodNotLocked":           account.ErrMethodNotLocked,
	modulePath + "/account.ErrDuplicateCredential":       account.ErrDuplicateCredential,
	modulePath + "/account.ErrUnknownScope":              account.ErrUnknownScope,
	modulePath + "/account.ErrPasskeysUnavailable":       account.ErrPasskeysUnavailable,
	modulePath + "/account.ErrCeremonyInvalid":           account.ErrCeremonyInvalid,
	modulePath + "/account.ErrOIDCUnavailable":           account.ErrOIDCUnavailable,
	modulePath + "/account.ErrSessionGone":               account.ErrSessionGone,
	modulePath + "/account.ErrNotFound":                  account.ErrNotFound,
	modulePath + "/account.ErrInvalidCredentials":        account.ErrInvalidCredentials,
	modulePath + "/account.ErrPolicyRefused":             account.ErrPolicyRefused,
	modulePath + "/account.PolicyError":                  &account.PolicyError{Op: account.OpCreateUser, Reason: account.ReasonAdminTarget},
	modulePath + "/account.RulesError":                   &account.RulesError{Field: "Breach", Reason: "no client"},
	modulePath + "/account.UsernameError":                &account.UsernameError{Reason: account.ReasonTooLong},
	modulePath + "/account.TextError":                    &account.TextError{Field: account.TextFieldLabel, Reason: account.ReasonTooLong},
	modulePath + "/account.LogFilterError":               &account.LogFilterError{Reason: account.ReasonLogKind},
	modulePath + "/account.CodeError":                    &account.CodeError{Reason: account.ReasonCodeInvalid},
	modulePath + "/account.MalformedError":               &account.MalformedError{Field: "code"},
	modulePath + "/account.ErrSecondFactorProofRequired": account.ErrSecondFactorProofRequired,
	modulePath + "/account.ErrLastSecondFactor":          account.ErrLastSecondFactor,
	modulePath + "/account.ErrSecondFactorHeld":          account.ErrSecondFactorHeld,
	modulePath + "/account.ErrPasswordRequired":          account.ErrPasswordRequired,
	modulePath + "/account.ErrTOTPDisabled":              account.ErrTOTPDisabled,
	modulePath + "/account.ErrSecondFactorUnavailable":   account.ErrSecondFactorUnavailable,
	modulePath + "/webauthn.ErrResponseTooLarge":         webauthn.ErrResponseTooLarge,
	modulePath + "/webauthn.ErrNotDiscoverable":          webauthn.ErrNotDiscoverable,
	modulePath + "/webauthn.ErrUnknownCredential":        webauthn.ErrUnknownCredential,
	modulePath + "/webauthn.OriginError":                 &webauthn.OriginError{Reason: webauthn.RejectNotAllowlisted},
	modulePath + "/ratelimit.RefusedError":               &ratelimit.RefusedError{Dimension: "ip", RetryAfter: time.Second},
	modulePath + "/oidc.ErrRedirectTooLong":              oidc.ErrRedirectTooLong,
	modulePath + "/oidc.ErrStaleAuthentication":          oidc.ErrStaleAuthentication,
	modulePath + "/oidc.ErrFlowInvalid":                  oidc.ErrFlowInvalid,
	modulePath + "/oidc.ErrExchange":                     oidc.ErrExchange,
	modulePath + "/oidc.ErrTokenInvalid":                 oidc.ErrTokenInvalid,
	modulePath + "/oidc.ErrNonceMismatch":                oidc.ErrNonceMismatch,
	modulePath + "/oidc.ProviderError":                   &oidc.ProviderError{Code: "access_denied"},
	modulePath + "/oidc.ErrConfigInvalid":                oidc.ErrConfigInvalid,
	modulePath + ".ErrSealTooLarge":                      access.ErrSealTooLarge,
	modulePath + "/webauthn.ErrCeremonyUnbound":          webauthn.ErrCeremonyUnbound,
	modulePath + ".ErrHashInvalid":                       access.ErrHashInvalid,
	modulePath + ".ErrInvalidKeyPrefix":                  access.ErrInvalidKeyPrefix,
	modulePath + ".ErrSealExpired":                       access.ErrSealExpired,
	modulePath + ".ErrSealInvalid":                       access.ErrSealInvalid,
}

// termKind is what one part of an error chain is.
type termKind int

const (
	termLeaf       termKind = iota // a module error: obj is its var or type name
	termOpaque                     // an error no module producer names
	termParam                      // the error parameter obj holds, bound at the call
	termParamCall                  // what calling parameter obj, or its field at path, returns in result res
	termParamField                 // the error parameter obj's field at path holds, bound at the call
	termWrapper                    // an unregistered wrapper type obj, for errors.AsType
	termDeclared                   // refused when it matches a sentinel bound to the slice parameter obj
)

type term struct {
	obj    types.Object
	guards *guardList // the filters a parameter's value passes, applied at its binding
	// fields is the reason-bearing string fields a leaf's or wrapper's
	// literal sets; nil for a leaf no literal built.
	fields *fieldList
	path   string
	kind   termKind
	res    int
}

func (t term) key() string {
	k := fmt.Sprintf("%d:%p:%s:%d", t.kind, t.obj, t.path, t.res)
	if t.guards != nil {
		k += ":" + t.guards.key
	}
	if t.fields != nil {
		k += ":f" + t.fields.key
	}
	return k
}

// strKind is what the analysis knows of a string a typed error's field
// holds.
type strKind int

const (
	strConst strKind = iota // the constant s
	strParam                // parameter obj's value, or its field at path, bound at the call
	strOpen                 // a value the analysis does not follow
)

type strVal struct {
	obj  *types.Var
	s    string
	path string
	kind strKind
}

var openStr = []strVal{{kind: strOpen}}

// fieldVal is one string field a literal sets.
type fieldVal struct {
	name string
	val  strVal
}

// fieldList is an interned list of a literal's reason-bearing fields, so
// equal lists are one pointer and terms stay comparable.
type fieldList struct {
	key  string
	vals []fieldVal
}

// strKey is one string evaluation in progress, for its cycle guard.
type strKey struct {
	at   any // the variable or the called declaration
	path string
}

// The placeholders a built leaf carries for a string the analysis does
// not fix, so classify's Reason shows what it came from.
const (
	unresolved   = "\x00open"   // a value the analysis does not follow
	policyReason = "\x00policy" // whatever the app's Policy answers
)

// The families of reasons a route does not fix, as a
// produced reason's key.
const (
	familyField    = "\x00field"    // auth_bad_request naming a field, path value or query key
	familyProvider = "\x00provider" // auth_oidc_failed carrying an IdP's error code
	familyPolicy   = "\x00policy"   // auth_forbidden carrying the Policy's reason
)

// guardStep is one errors.Is or errors.AsType test a value passed, or
// failed when holds is false.
type guardStep struct {
	test  errTest
	holds bool
}

// guardList is an interned sequence of guard steps, so equal lists are one
// pointer and terms stay comparable.
type guardList struct {
	key   string
	steps []guardStep
}

// chain is the errors one returned value matches: what errors.Is and
// errors.As find in it.
type chain []term

// errValue is every chain an expression can hold, by key.
type errValue map[string]chain

func valueOf(c chain) errValue {
	c = slices.Clone(c)
	slices.SortFunc(c, func(a, b term) int { return strings.Compare(a.key(), b.key()) })
	c = slices.CompactFunc(c, func(a, b term) bool { return a == b })
	keys := make([]string, len(c))
	for i := range c {
		keys[i] = c[i].key()
	}
	return errValue{strings.Join(keys, ","): c}
}

var opaqueValue = valueOf(chain{{kind: termOpaque}})

func (v errValue) add(w errValue) errValue {
	if v == nil {
		v = errValue{}
	}
	maps.Copy(v, w)
	return v
}

// cross is every chain made of one chain of each part; an empty part holds
// no error and adds nothing.
func cross(parts ...errValue) errValue {
	out := valueOf(nil)
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		next := errValue{}
		for _, a := range out {
			for _, b := range part {
				next.add(valueOf(slices.Concat(a, b)))
			}
		}
		out = next
	}
	return out
}

// channel is which errors of a function a summary holds.
type channel int

const (
	chReturned channel = iota // its error result
	chAnswered                // the errors it hands (*Handler).refusal
)

type summaryKey struct {
	n  ast.Node
	ch channel
	// res is the result a chReturned summary follows; lastErr is the last
	// error result, so a function returning (refused, err error) is
	// followed in each.
	res int
}

// lastErr names a function's last error result.
const lastErr = -1

type funcPath struct {
	x    ast.Expr
	path string
	res  int
}

// evalKey is one evaluation of v from the definitions starting at first, n
// of them, so a definition that reads v's earlier value (err = f(err))
// evaluates those earlier definitions instead of stopping at v.
type evalKey struct {
	v     *types.Var
	first ast.Node
	n     int
}

// varDef is one assignment to a local variable.
type varDef struct {
	at    ast.Node // the defining identifier, or the case clause of a type switch
	rhs   ast.Expr
	index int  // the result of a tuple rhs v takes; -1 for a single value
	rng   bool // v ranges over rhs
}

// producers is the module's non-test code, type-checked from source, and
// the summaries of what its functions return or answer.
type producers struct {
	fset         *token.FileSet
	info         *types.Info
	refusal      *types.Func
	pkgs         map[string]*types.Package
	decls        map[*types.Func]*ast.FuncDecl
	defs         map[*types.Var][]varDef
	inits        map[*types.Var]ast.Expr
	sums         map[summaryKey]errValue
	round        map[summaryKey]int
	stack        map[summaryKey]bool
	parent       map[ast.Node]ast.Node
	guardLists   map[string]*guardList
	evaluating   map[evalKey]bool
	resolving    map[funcPath]bool
	impls        map[*types.Func][]*types.Func
	unregistered map[string]bool
	fieldDefs    map[*types.Var]map[string][]varDef // each assignment to a variable's field, by its path
	fieldAssigns map[types.Object][]varDef          // each assignment to a struct field, by the field
	fieldLists   map[string]*fieldList
	strBusy      map[strKey]bool
	bearing      map[string]bool
	policy       *types.TypeName
	policyError  *types.TypeName
	module       string
	root         string
	concrete     []types.Type
	iter         int
	changed      bool
}

var errorType = types.Universe.Lookup("error").Type()

// errResult reports whether a result of type t carries a function's
// error: error itself, or a pointer to an error type, as a helper building
// one *OriginError returns; a value type such as access.Error is an
// answer, not an error the function returns.
func errResult(t types.Type) bool {
	_, ptr := t.(*types.Pointer)
	return types.Identical(t, errorType) || ptr && isError(t)
}

func isError(t types.Type) bool {
	return t != nil && types.Implements(t, errorType.Underlying().(*types.Interface))
}

func loadProducers(t *testing.T) *producers {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	module, _, _ := strings.Cut(strings.TrimPrefix(string(mod), "module "), "\n")
	cmd := exec.CommandContext(t.Context(), "go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", "./account", "./accesstest", "./accesshttp")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		path, file, _ := strings.Cut(sc.Text(), "\t")
		exports[path] = file
	}
	p := &producers{
		fset: token.NewFileSet(),
		info: &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Implicits:  map[ast.Node]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Instances:  map[*ast.Ident]types.Instance{},
		},
		pkgs:         map[string]*types.Package{},
		decls:        map[*types.Func]*ast.FuncDecl{},
		defs:         map[*types.Var][]varDef{},
		inits:        map[*types.Var]ast.Expr{},
		sums:         map[summaryKey]errValue{},
		round:        map[summaryKey]int{},
		stack:        map[summaryKey]bool{},
		parent:       map[ast.Node]ast.Node{},
		guardLists:   map[string]*guardList{},
		evaluating:   map[evalKey]bool{},
		resolving:    map[funcPath]bool{},
		impls:        map[*types.Func][]*types.Func{},
		unregistered: map[string]bool{},
		fieldDefs:    map[*types.Var]map[string][]varDef{},
		fieldAssigns: map[types.Object][]varDef{},
		fieldLists:   map[string]*fieldList{},
		strBusy:      map[strKey]bool{},
		bearing:      map[string]bool{},
		module:       module,
		root:         root,
	}
	gc := importer.ForCompiler(p.fset, "gc", func(path string) (io.ReadCloser, error) {
		file := exports[path]
		if file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	imp := &moduleImporter{p: p, t: t, gc: gc}
	for _, path := range []string{"account", "accesstest", "accesshttp"} {
		if _, err := imp.Import(module + "/" + path); err != nil {
			t.Fatal(err)
		}
	}
	for _, pkg := range p.pkgs {
		for _, name := range pkg.Scope().Names() {
			tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() || types.IsInterface(tn.Type()) {
				continue
			}
			if _, generic := tn.Type().(*types.Named); !generic || tn.Type().(*types.Named).TypeParams().Len() > 0 {
				continue
			}
			p.concrete = append(p.concrete, tn.Type(), types.NewPointer(tn.Type()))
		}
	}
	acct := p.pkgs[module+"/account"].Scope()
	p.policy, _ = acct.Lookup("Policy").(*types.TypeName)
	p.policyError, _ = acct.Lookup("PolicyError").(*types.TypeName)
	if p.policy == nil || p.policyError == nil {
		t.Fatal("no account.Policy or account.PolicyError")
	}
	h, _ := p.accesshttp().Scope().Lookup("Handler").(*types.TypeName)
	m, _, _ := types.LookupFieldOrMethod(types.NewPointer(h.Type()), false, p.accesshttp(), "refusal")
	if p.refusal, _ = m.(*types.Func); p.refusal == nil {
		t.Fatal("no (*Handler).refusal")
	}
	return p
}

type moduleImporter struct {
	p  *producers
	t  *testing.T
	gc types.Importer
}

func (m *moduleImporter) Import(path string) (*types.Package, error) {
	p := m.p
	if path != p.module && !strings.HasPrefix(path, p.module+"/") {
		return m.gc.Import(path)
	}
	if pkg, ok := p.pkgs[path]; ok {
		return pkg, nil
	}
	dir := filepath.Join(p.root, strings.TrimPrefix(path, p.module))
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(p.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	conf := types.Config{Importer: m}
	pkg, err := conf.Check(path, p.fset, files, p.info)
	if err != nil {
		return nil, err
	}
	p.pkgs[path] = pkg
	for _, f := range files {
		p.index(f)
	}
	return pkg, nil
}

// index records f's function bodies, package initializers and every
// assignment to a variable.
func (p *producers) index(f *ast.File) {
	def := func(lhs, rhs ast.Expr, index int) {
		if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
			if s, ok := p.info.Selections[sel]; ok && s.Kind() == types.FieldVal {
				p.fieldAssigns[s.Obj()] = append(p.fieldAssigns[s.Obj()], varDef{at: sel, rhs: rhs, index: index})
			}
			if v, path, ok := p.fieldPath(sel); ok {
				if p.fieldDefs[v] == nil {
					p.fieldDefs[v] = map[string][]varDef{}
				}
				p.fieldDefs[v][path] = append(p.fieldDefs[v][path], varDef{at: sel, rhs: rhs, index: index})
			}
			return
		}
		id, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok {
			return
		}
		if v, ok := p.info.ObjectOf(id).(*types.Var); ok {
			p.defs[v] = append(p.defs[v], varDef{at: id, rhs: rhs, index: index})
		}
	}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			p.parent[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.FuncDecl:
			if fn, ok := p.info.Defs[n.Name].(*types.Func); ok && n.Body != nil {
				p.decls[fn] = n
			}
		case *ast.AssignStmt:
			switch {
			case len(n.Lhs) == len(n.Rhs):
				for i := range n.Lhs {
					def(n.Lhs[i], n.Rhs[i], -1)
				}
			case len(n.Rhs) == 1:
				for i := range n.Lhs {
					def(n.Lhs[i], n.Rhs[0], i)
				}
			}
		case *ast.ValueSpec:
			for i, name := range n.Names {
				v, ok := p.info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				switch {
				case len(n.Values) == len(n.Names) && v.Kind() == types.PackageVar:
					p.inits[v] = n.Values[i]
				case len(n.Values) == len(n.Names):
					def(name, n.Values[i], -1)
				case len(n.Values) == 1:
					def(name, n.Values[0], i)
				}
			}
		case *ast.RangeStmt:
			for _, x := range []ast.Expr{n.Key, n.Value} {
				if id, ok := x.(*ast.Ident); ok {
					if v, ok := p.info.ObjectOf(id).(*types.Var); ok {
						p.defs[v] = append(p.defs[v], varDef{at: id, rhs: n.X, rng: true})
					}
				}
			}
		case *ast.TypeSwitchStmt:
			assign, ok := n.Assign.(*ast.AssignStmt)
			if !ok {
				return true
			}
			x := assign.Rhs[0].(*ast.TypeAssertExpr).X
			for _, cc := range n.Body.List {
				if v, ok := p.info.Implicits[cc].(*types.Var); ok {
					p.defs[v] = append(p.defs[v], varDef{at: cc, rhs: x, index: -1})
				}
			}
		}
		return true
	})
}

func (p *producers) inModule(pkg *types.Package) bool {
	return pkg != nil && (pkg.Path() == p.module || strings.HasPrefix(pkg.Path(), p.module+"/"))
}

// nameable reports whether accesshttp can name obj, an object of the
// module: exported, and outside any internal directory accesshttp is not
// under (go help internal). An exported error it cannot name needs no
// producerErrors row: it stands in by a value of its own (errorValue).
func nameable(obj types.Object) bool {
	if !obj.Exported() {
		return false
	}
	from := modulePath + "/accesshttp"
	segs := strings.Split(obj.Pkg().Path(), "/")
	for k, seg := range segs {
		parent := strings.Join(segs[:k], "/")
		if seg == "internal" && from != parent && !strings.HasPrefix(from, parent+"/") {
			return false
		}
	}
	return true
}

func qualified(obj types.Object) string { return obj.Pkg().Path() + "." + obj.Name() }

// serveFunc is s.serve's declaration in the loaded accesshttp.
func (p *producers) serveFunc(t *testing.T, s *routeSpec) *ast.FuncDecl {
	t.Helper()
	full := runtime.FuncForPC(reflect.ValueOf(s.serve).Pointer()).Name()
	fn, ok := p.accesshttp().Scope().Lookup(full[strings.LastIndex(full, ".")+1:]).(*types.Func)
	if !ok || p.decls[fn] == nil {
		t.Fatalf("%s: no declaration of %s", s.name, full)
	}
	return p.decls[fn]
}

func (p *producers) accesshttp() *types.Package { return p.pkgs[p.module+"/accesshttp"] }

// routeErrors is every chain s's route can answer from its serve function:
// what it returns, and what it hands (*Handler).refusal itself. It iterates
// to a fixed point over recursive calls.
func (p *producers) routeErrors(fn *ast.FuncDecl) errValue {
	for {
		p.iter++
		p.changed = false
		v := errValue{}.add(p.summary(fn, chReturned, lastErr)).add(p.summary(fn, chAnswered, lastErr))
		if !p.changed {
			return v
		}
	}
}

func (p *producers) signature(n ast.Node) (*ast.BlockStmt, *types.Signature) {
	switch n := n.(type) {
	case *ast.FuncDecl:
		return n.Body, p.info.Defs[n.Name].Type().(*types.Signature)
	case *ast.FuncLit:
		return n.Body, p.info.TypeOf(n).(*types.Signature)
	}
	panic(fmt.Sprintf("no function: %T", n))
}

// summary is what n returns in error result res (lastErr for its last), or
// hands refusal, with its parameters left as terms.
func (p *producers) summary(n ast.Node, ch channel, res int) errValue {
	k := summaryKey{n: n, ch: ch, res: res}
	if p.round[k] == p.iter || p.stack[k] {
		return p.sums[k]
	}
	p.stack[k] = true
	var out errValue
	if ch == chReturned {
		out = p.returned(n, res)
	} else {
		out = p.answered(n)
	}
	delete(p.stack, k)
	p.round[k] = p.iter
	if len(out) != len(p.sums[k]) {
		p.changed = true
	}
	p.sums[k] = out
	return out
}

func (p *producers) returned(n ast.Node, res int) errValue {
	body, sig := p.signature(n)
	idx := res
	if res == lastErr {
		for i := range sig.Results().Len() {
			if errResult(sig.Results().At(i).Type()) {
				idx = i
			}
		}
	}
	if idx < 0 || !errResult(sig.Results().At(idx).Type()) {
		return nil
	}
	var out errValue
	ast.Inspect(body, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(x.Results) == 0:
				out = out.add(p.evalVar(sig.Results().At(idx)))
			case len(x.Results) == sig.Results().Len():
				out = out.add(p.eval(x.Results[idx]))
			case len(x.Results) == 1:
				out = out.add(p.evalCall(x.Results[0], idx))
			}
		}
		return true
	})
	return out
}

// answered is what n's body, closures included, hands refusal, directly or
// through another accesshttp function.
func (p *producers) answered(n ast.Node) errValue {
	body, _ := p.signature(n)
	var out errValue
	ast.Inspect(body, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := p.callee(call.Fun).(*types.Func)
		if !ok || fn.Pkg() != p.accesshttp() {
			return true
		}
		if fn == p.refusal {
			out = out.add(p.eval(call.Args[1]))
		} else if decl := p.decls[fn.Origin()]; decl != nil {
			out = out.add(p.bind(p.summary(decl, chAnswered, lastErr), decl, call))
		}
		return true
	})
	return out
}

func (p *producers) eval(e ast.Expr) errValue {
	e = ast.Unparen(e)
	if tv, ok := p.info.Types[e]; ok && (tv.IsNil() || !isError(tv.Type)) {
		return nil
	}
	switch e := e.(type) {
	case *ast.Ident:
		v, ok := p.info.Uses[e].(*types.Var)
		if ok && v.Kind() != types.PackageVar {
			return p.guarded(e, v, p.evalLocal(v, e))
		}
		return p.evalObj(p.info.Uses[e])
	case *ast.SelectorExpr:
		sel, ok := p.info.Selections[e]
		switch {
		case !ok:
			return p.evalObj(p.info.Uses[e.Sel])
		case sel.Kind() == types.FieldVal && isError(p.info.TypeOf(e.X)):
			return p.eval(e.X)
		case sel.Kind() == types.FieldVal:
			if v, path, ok := p.fieldPath(e); ok {
				return p.varField(v, path)
			}
		}
	case *ast.CallExpr:
		return p.evalCall(e, -1)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return p.evalAddr(e.X)
		}
	case *ast.CompositeLit:
		return p.evalLit(e)
	case *ast.TypeAssertExpr:
		return p.eval(e.X)
	}
	return opaqueValue
}

// varField is the error v's field at path holds: a parameter's stays a
// term bound at the call, a local's is every definition's and every
// assignment to the field, flow-insensitively.
func (p *producers) varField(v *types.Var, path string) errValue {
	switch v.Kind() {
	case types.ParamVar, types.RecvVar:
		return valueOf(chain{{kind: termParamField, obj: v, path: path}})
	case types.PackageVar:
		if init := p.inits[v]; init != nil {
			return p.exprField(init, path)
		}
		return opaqueValue
	default:
	}
	k := strKey{at: v, path: "error:" + path}
	if p.strBusy[k] {
		return nil
	}
	p.strBusy[k] = true
	defer delete(p.strBusy, k)
	var out errValue
	for _, d := range p.defs[v] {
		switch {
		case d.rng:
			out = out.add(opaqueValue)
		case d.index >= 0:
			out = out.add(p.calledField(d.rhs, d.index, path))
		default:
			out = out.add(p.exprField(d.rhs, path))
		}
	}
	for _, d := range p.fieldDefs[v][path] {
		if d.index >= 0 {
			out = out.add(p.evalCall(d.rhs, d.index))
		} else {
			out = out.add(p.eval(d.rhs))
		}
	}
	return out
}

// exprField is the error the field at path of the value x holds; a
// literal leaving it out holds none.
func (p *producers) exprField(x ast.Expr, path string) errValue {
	switch e := ast.Unparen(x).(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return p.exprField(e.X, path)
		}
	case *ast.StarExpr:
		return p.exprField(e.X, path)
	case *ast.CompositeLit:
		name, rest, _ := strings.Cut(path, ".")
		for _, elt := range e.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return opaqueValue
			}
			if isIdentNamed(kv.Key, name) {
				if rest == "" {
					return p.eval(kv.Value)
				}
				return p.exprField(kv.Value, rest)
			}
		}
		return nil
	case *ast.Ident:
		if v, ok := p.info.Uses[e].(*types.Var); ok {
			return p.varField(v, path)
		}
	case *ast.SelectorExpr:
		if v, base, ok := p.fieldPath(e); ok {
			return p.varField(v, base+"."+path)
		}
	case *ast.CallExpr:
		return p.calledField(e, -1, path)
	}
	return opaqueValue
}

// calledField is the error the field at path of what x's call of a module
// function returns in result index holds, its only one when index is -1,
// the callee's parameters bound to the call's arguments.
func (p *producers) calledField(x ast.Expr, index int, path string) errValue {
	call, ok := ast.Unparen(x).(*ast.CallExpr)
	if !ok {
		return opaqueValue
	}
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok || p.decls[fn.Origin()] == nil {
		return opaqueValue
	}
	results := fn.Signature().Results().Len()
	if index < 0 && results == 1 {
		index = 0
	}
	if index < 0 || index >= results {
		return opaqueValue
	}
	decl := p.decls[fn.Origin()]
	k := strKey{at: decl, path: fmt.Sprintf("error:%d:%s", index, path)}
	if p.strBusy[k] {
		return nil
	}
	p.strBusy[k] = true
	defer delete(p.strBusy, k)
	var sum errValue
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch r := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(r.Results) == results:
				sum = sum.add(p.exprField(r.Results[index], path))
			case len(r.Results) == 1:
				sum = sum.add(p.calledField(r.Results[0], index, path))
			default:
				sum = sum.add(opaqueValue)
			}
		}
		return true
	})
	return p.bind(sum, decl, call)
}

func registered(obj types.Object) bool {
	_, ok := producerErrors[qualified(obj)]
	return ok
}

// leaf is obj as a chain's leaf; a nameable one with no producerErrors
// row is recorded, for the test to name.
func (p *producers) leaf(obj types.Object) errValue {
	if !registered(obj) && nameable(obj) {
		p.unregistered[qualified(obj)] = true
	}
	return valueOf(chain{{kind: termLeaf, obj: obj}})
}

// standIn is the value of an exported error accesshttp cannot import;
// equal names are equal errors, so errors.Is matches it only with itself.
type standIn string

func (s standIn) Error() string { return string(s) }

// errorValue is obj's value in a chain: its producerErrors row, or the
// stand-in of an exported error accesshttp cannot import.
func errorValue(obj types.Object) (error, bool) {
	if v, ok := producerErrors[qualified(obj)]; ok {
		return v, true
	}
	if nameable(obj) || !obj.Exported() {
		return nil, false
	}
	return standIn(qualified(obj)), true
}

func (p *producers) evalObj(obj types.Object) errValue {
	v, ok := obj.(*types.Var)
	if !ok {
		return opaqueValue
	}
	switch v.Kind() {
	case types.PackageVar:
		switch {
		case !p.inModule(v.Pkg()):
			return opaqueValue
		case registered(v) || v.Exported():
			return p.leaf(v)
		case p.inits[v] != nil:
			return p.eval(p.inits[v])
		}
		return opaqueValue
	case types.ParamVar, types.RecvVar:
		return valueOf(chain{{kind: termParam, obj: v}}).add(p.evalVar(v))
	default:
		return p.evalVar(v)
	}
}

// evalLocal is what local or parameter v holds where ref reads it: the
// definitions before ref, but the one whose right side holds ref, from the
// last one in a block enclosing ref, or, when none precedes it, every
// definition and the parameter's own value.
func (p *producers) evalLocal(v *types.Var, ref ast.Node) errValue {
	var before []varDef
	kill := -1
	for _, d := range p.defs[v] {
		if d.at.Pos() >= ref.Pos() || d.rhs != nil && p.encloses(d.rhs, ref) {
			continue
		}
		if p.encloses(p.block(d.at), ref) {
			kill = len(before)
		}
		before = append(before, d)
	}
	if len(before) == 0 {
		return p.evalObj(v)
	}
	if kill < 0 && (v.Kind() == types.ParamVar || v.Kind() == types.RecvVar) {
		return valueOf(chain{{kind: termParam, obj: v}}).add(p.evalDefs(v, before))
	}
	return p.evalDefs(v, before[max(kill, 0):])
}

// block is the statement list n sits in.
func (p *producers) block(n ast.Node) ast.Node {
	for n = p.parent[n]; n != nil; n = p.parent[n] {
		switch n.(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
			return n
		}
	}
	return nil
}

func (p *producers) encloses(outer, n ast.Node) bool {
	for ; n != nil; n = p.parent[n] {
		if n == outer {
			return true
		}
	}
	return false
}

func (p *producers) evalVar(v *types.Var) errValue { return p.evalDefs(v, p.defs[v]) }

func (p *producers) evalDefs(v *types.Var, defs []varDef) errValue {
	key := evalKey{v: v, n: len(defs)}
	if len(defs) > 0 {
		key.first = defs[0].at
	}
	if p.evaluating[key] {
		return nil
	}
	p.evaluating[key] = true
	defer delete(p.evaluating, key)
	var out errValue
	for _, d := range defs {
		switch {
		case d.rng:
			out = out.add(p.elements(d.rhs))
		case d.index >= 0:
			out = out.add(p.evalCall(d.rhs, d.index))
		default:
			out = out.add(p.eval(d.rhs))
		}
	}
	return out
}

// elements is what ranging over x yields: a package slice literal's
// elements.
func (p *producers) elements(x ast.Expr) errValue {
	elts := p.elementExprs(x, map[types.Object]bool{})
	if elts == nil {
		return opaqueValue
	}
	var out errValue
	for _, elt := range elts {
		out = out.add(p.eval(elt))
	}
	return out
}

// elementExprs is every element a package slice literal x holds, or a
// struct field x every assignment builds from literals and appends; nil
// when x is neither.
func (p *producers) elementExprs(x ast.Expr, seen map[types.Object]bool) []ast.Expr {
	switch x := ast.Unparen(x).(type) {
	case *ast.Ident:
		if v, ok := p.info.Uses[x].(*types.Var); ok {
			if lit, ok := p.inits[v].(*ast.CompositeLit); ok {
				return lit.Elts
			}
		}
	case *ast.SelectorExpr:
		sel, ok := p.info.Selections[x]
		if !ok || sel.Kind() != types.FieldVal || seen[sel.Obj()] {
			return nil
		}
		seen[sel.Obj()] = true
		var out []ast.Expr
		for _, d := range p.fieldAssigns[sel.Obj()] {
			if d.index >= 0 {
				continue
			}
			switch r := ast.Unparen(d.rhs).(type) {
			case *ast.CompositeLit:
				out = append(out, r.Elts...)
			case *ast.CallExpr:
				if b, ok := p.callee(r.Fun).(*types.Builtin); ok && b.Name() == "append" && len(r.Args) > 0 {
					out = append(append(out, p.elementExprs(r.Args[0], seen)...), r.Args[1:]...)
				}
			}
		}
		return out
	}
	return nil
}

// evalLit is an error literal: a registered or exported type is a leaf
// over its error fields, any other is its error fields alone; either
// carries the reason-bearing string fields the literal sets.
func (p *producers) evalLit(lit *ast.CompositeLit) errValue {
	var fields []errValue
	named, ok := p.info.TypeOf(lit).(*types.Named)
	var strs [][]fieldVal
	for _, elt := range lit.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if isKV {
			elt = kv.Value
		}
		fields = append(fields, p.eval(elt))
		if id, isID := ast.Unparen(kvKey(kv)).(*ast.Ident); isID && ok && p.bearingField(named.Obj(), id.Name) {
			var alts []fieldVal
			for _, v := range p.strs(kv.Value) {
				alts = append(alts, fieldVal{name: id.Name, val: v})
			}
			strs = append(strs, alts)
		}
	}
	children := cross(fields...)
	switch {
	case !ok || !p.inModule(named.Obj().Pkg()):
		return opaqueValue
	case registered(named.Obj()) || named.Obj().Exported():
		p.leaf(named.Obj())
		return cross(p.withFields(term{kind: termLeaf, obj: named.Obj()}, strs), children)
	}
	if c, ok := children[""]; ok && len(c) == 0 {
		children = opaqueValue
	}
	return cross(p.withFields(term{kind: termWrapper, obj: named.Obj()}, strs), children)
}

func kvKey(kv *ast.KeyValueExpr) ast.Expr {
	if kv == nil {
		return nil
	}
	return kv.Key
}

// withFields is base under every combination of one value per field of
// alts, a literal's fields; with none it is base with no field set.
func (p *producers) withFields(base term, alts [][]fieldVal) errValue {
	combos := [][]fieldVal{nil}
	for _, field := range alts {
		if len(field) == 0 {
			field = []fieldVal{{val: strVal{kind: strOpen}}}
		}
		var next [][]fieldVal
		for _, combo := range combos {
			for _, f := range field {
				next = append(next, append(slices.Clone(combo), f))
			}
		}
		combos = next
	}
	out := errValue{}
	for _, combo := range combos {
		t := base
		t.fields = p.fieldList(combo)
		out.add(valueOf(chain{t}))
	}
	return out
}

// fieldList interns vals, sorted by name.
func (p *producers) fieldList(vals []fieldVal) *fieldList {
	vals = slices.Clone(vals)
	slices.SortFunc(vals, func(a, b fieldVal) int { return strings.Compare(a.name, b.name) })
	var b strings.Builder
	for _, f := range vals {
		fmt.Fprintf(&b, "%s=%d/%q/%p/%s;", f.name, f.val.kind, f.val.s, f.val.obj, f.val.path)
	}
	k := b.String()
	if l := p.fieldLists[k]; l != nil {
		return l
	}
	l := &fieldList{key: k, vals: vals}
	p.fieldLists[k] = l
	return l
}

// reasonedType is failreason's wrapper, whose reason ErrorFor reads for
// auth_recent_auth_required and auth_https_required.
const reasonedType = modulePath + "/internal/failreason.reasoned"

// bearingField reports whether obj's string field name reaches classify's
// Reason: the wrapper's reason, or a leaf's field whose placeholder the
// Reason carries.
func (p *producers) bearingField(obj types.Object, name string) bool {
	if qualified(obj) == reasonedType {
		return name == "reason"
	}
	k := qualified(obj) + "." + name
	if b, ok := p.bearing[k]; ok {
		return b
	}
	b := false
	if e, ok := buildLeaf(obj, map[string]string{name: unresolved}); ok {
		got, ok := classify(e, ceremonyNone)
		b = ok && strings.Contains(got.Reason, unresolved)
	}
	p.bearing[k] = b
	return b
}

// bearingFields is every reason-bearing string field of type obj.
func (p *producers) bearingFields(obj types.Object) []string {
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return nil
	}
	st, ok := tn.Type().Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	var names []string
	for f := range st.Fields() {
		if b, isBasic := f.Type().Underlying().(*types.Basic); isBasic && b.Kind() == types.String && p.bearingField(obj, f.Name()) {
			names = append(names, f.Name())
		}
	}
	return names
}

// buildLeaf is obj's error with fields set over a zero value, or its
// producerErrors row when fields is empty, as for a type with no
// reason-bearing field.
func buildLeaf(obj types.Object, fields map[string]string) (error, bool) {
	tmpl, ok := errorValue(obj)
	if !ok || len(fields) == 0 {
		return tmpl, ok
	}
	if qualified(obj) == modulePath+"/accesshttp.requestError" {
		return &requestError{reason: fields["reason"]}, true
	}
	v := reflect.ValueOf(tmpl)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return tmpl, true
	}
	nv := reflect.New(v.Elem().Type())
	for name, val := range fields {
		if f := nv.Elem().FieldByName(name); f.CanSet() && f.Kind() == reflect.String {
			f.SetString(val)
		}
	}
	return reflect.TypeAssert[error](nv)
}

// evalAddr is &x for an x whose pointer is the error: a literal, or a
// variable of a registered or exported type, or else what its literals hold.
func (p *producers) evalAddr(x ast.Expr) errValue {
	x = ast.Unparen(x)
	if lit, ok := x.(*ast.CompositeLit); ok {
		return p.evalLit(lit)
	}
	named, ok := p.info.TypeOf(x).(*types.Named)
	switch {
	case !ok || !p.inModule(named.Obj().Pkg()):
		return opaqueValue
	case registered(named.Obj()) || named.Obj().Exported():
		return p.leaf(named.Obj())
	}
	id, ok := x.(*ast.Ident)
	if !ok {
		return opaqueValue
	}
	v, _ := p.info.Uses[id].(*types.Var)
	var out errValue
	for _, d := range p.defs[v] {
		if lit, ok := ast.Unparen(d.rhs).(*ast.CompositeLit); ok && d.index < 0 {
			out = out.add(p.evalLit(lit))
		}
	}
	if out == nil {
		return opaqueValue
	}
	return out
}

// callee is the object fun names, through an instantiation.
func (p *producers) callee(fun ast.Expr) types.Object {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return p.info.Uses[f]
	case *ast.SelectorExpr:
		return p.info.Uses[f.Sel]
	case *ast.IndexExpr:
		return p.callee(f.X)
	case *ast.IndexListExpr:
		return p.callee(f.X)
	}
	return nil
}

// evalCall is the error e's call returns in result index, or in its only
// result when index is -1.
func (p *producers) evalCall(e ast.Expr, index int) errValue {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		if ta, ok := ast.Unparen(e).(*ast.TypeAssertExpr); ok && index == 0 {
			return p.eval(ta.X)
		}
		return opaqueValue
	}
	if p.info.Types[call.Fun].IsType() {
		return p.eval(call.Args[0])
	}
	sig, ok := p.info.TypeOf(call.Fun).Underlying().(*types.Signature)
	index = max(index, 0)
	if !ok || index >= sig.Results().Len() || !isError(sig.Results().At(index).Type()) {
		return nil
	}
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok {
		if lits := p.closures(call.Fun); lits != nil {
			var out errValue
			for _, lit := range lits {
				out = out.add(p.bind(p.summary(lit, chReturned, index), lit, call))
			}
			return out
		}
		return p.callValue(call.Fun, "", index)
	}
	switch qualified(fn.Origin()) {
	case "errors.New":
		return opaqueValue
	case "fmt.Errorf":
		return p.wrap(call.Args[1:])
	case "errors.Join":
		return p.wrap(call.Args)
	case "errors.AsType":
		return p.filter(p.eval(call.Args[0]), asTypeTest(p.info.TypeOf(call)), true)
	case "errors.Unwrap":
		return p.eval(call.Args[0])
	case p.module + "/account.refusedBy":
		return p.declare(p.eval(call.Args[0]), call.Args[1:], call.Ellipsis.IsValid())
	}
	return p.callFunc(fn, call, index)
}

// closures is every function literal a local fun is defined as, so a call
// of it binds its arguments; nil when fun is anything else.
func (p *producers) closures(fun ast.Expr) []*ast.FuncLit {
	id, ok := ast.Unparen(fun).(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := p.info.Uses[id].(*types.Var)
	if !ok || v.Kind() != types.LocalVar || len(p.defs[v]) == 0 {
		return nil
	}
	var lits []*ast.FuncLit
	for _, d := range p.defs[v] {
		lit, isLit := ast.Unparen(d.rhs).(*ast.FuncLit)
		if !isLit || d.index >= 0 || d.rng {
			return nil
		}
		lits = append(lits, lit)
	}
	return lits
}

// declare is account.refusedBy(val, sentinels...): each chain of val that
// matches a sentinel among args gains the refusal wrapper. A forwarded
// parameter slice leaves the decision to its binding.
func (p *producers) declare(val errValue, args []ast.Expr, ellipsis bool) errValue {
	if ellipsis && len(args) == 1 {
		if id, ok := ast.Unparen(args[0]).(*ast.Ident); ok {
			if v, ok := p.info.Uses[id].(*types.Var); ok && v.Kind() == types.ParamVar {
				return cross(val, valueOf(chain{{kind: termDeclared, obj: v}}))
			}
		}
		return val
	}
	var sentinels []types.Object
	for _, a := range args {
		if obj := p.callee(a); obj != nil {
			sentinels = append(sentinels, obj)
		}
	}
	return p.refuseMatching(val, sentinels)
}

func (p *producers) refuseMatching(val errValue, sentinels []types.Object) errValue {
	refusal := p.pkgs[p.module+"/account"].Scope().Lookup("refusal")
	out := errValue{}
	for _, c := range val {
		matched := false
		for _, s := range sentinels {
			if m, _ := p.matches(c, errTest{sentinel: s}); m {
				matched = true
			}
		}
		if matched {
			c = append(slices.Clone(c), term{kind: termWrapper, obj: refusal})
		}
		out.add(valueOf(c))
	}
	return out
}

// wrap is fmt.Errorf's or errors.Join's error over args: every error
// argument's chains joined, or an opaque error when none is an error.
func (p *producers) wrap(args []ast.Expr) errValue {
	var parts []errValue
	for _, a := range args {
		if isError(p.info.TypeOf(a)) {
			parts = append(parts, p.eval(a))
		}
	}
	out := cross(parts...)
	if c, ok := out[""]; ok && len(c) == 0 {
		delete(out, "")
		out.add(opaqueValue)
	}
	return out
}

// callFunc is what calling fn returns in result res: its summary bound to
// call's arguments, over every module implementation of an interface
// method.
func (p *producers) callFunc(fn *types.Func, call *ast.CallExpr, res int) errValue {
	fn = fn.Origin()
	if p.isPolicyAuthorize(fn) {
		return p.withFields(term{kind: termLeaf, obj: p.policyError}, [][]fieldVal{{{name: "Reason", val: strVal{kind: strConst, s: policyReason}}}})
	}
	if decl := p.decls[fn]; decl != nil {
		return p.bind(p.summary(decl, chReturned, res), decl, call)
	}
	var out errValue
	for _, m := range p.implementations(fn) {
		decl := p.decls[m]
		out = out.add(p.bind(p.summary(decl, chReturned, res), decl, call))
	}
	if out == nil {
		return opaqueValue
	}
	return out
}

// isPolicyAuthorize reports whether fn is account.Policy's Authorize, which
// answers the app's own Policy: the analysis stops there, since what a
// built-in Policy answers describes that Policy, not the route.
func (p *producers) isPolicyAuthorize(fn *types.Func) bool {
	recv := fn.Signature().Recv()
	return fn.Name() == "Authorize" && recv != nil && types.Identical(recv.Type(), p.policy.Type())
}

// implementations is every module method an interface method fn
// dispatches to.
func (p *producers) implementations(fn *types.Func) []*types.Func {
	if impls, ok := p.impls[fn]; ok {
		return impls
	}
	var impls []*types.Func
	if recv := fn.Signature().Recv(); recv != nil && types.IsInterface(recv.Type()) {
		iface := recv.Type().Underlying().(*types.Interface)
		for _, typ := range p.concrete {
			if !types.Implements(typ, iface) {
				continue
			}
			m, _, _ := types.LookupFieldOrMethod(typ, false, fn.Pkg(), fn.Name())
			if mf, ok := m.(*types.Func); ok && p.decls[mf.Origin()] != nil && !slices.Contains(impls, mf.Origin()) {
				impls = append(impls, mf.Origin())
			}
		}
	}
	p.impls[fn] = impls
	return impls
}

// callValue is what calling the function value x, or its field at path,
// returns in result res, the function's own parameters unbound.
func (p *producers) callValue(x ast.Expr, path string, res int) errValue {
	x = ast.Unparen(x)
	k := funcPath{x: x, path: path, res: res}
	if p.resolving[k] {
		return nil
	}
	p.resolving[k] = true
	defer delete(p.resolving, k)
	switch x := x.(type) {
	case *ast.FuncLit:
		if path == "" {
			return p.bind(p.summary(x, chReturned, res), x, nil)
		}
	case *ast.UnaryExpr:
		return p.callValue(x.X, path, res)
	case *ast.CompositeLit:
		field, rest, _ := strings.Cut(path, ".")
		for _, elt := range x.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok && isIdentNamed(kv.Key, field) {
				return p.callValue(kv.Value, rest, res)
			}
		}
		return nil
	case *ast.SelectorExpr:
		if sel, ok := p.info.Selections[x]; ok && sel.Kind() == types.FieldVal {
			return p.callValue(x.X, strings.TrimSuffix(x.Sel.Name+"."+path, "."), res)
		}
	case *ast.CallExpr:
		return p.returnedFuncs(x, path, res)
	}
	switch obj := p.callee(x).(type) {
	case *types.Func:
		if path != "" {
			break
		}
		if decl := p.decls[obj.Origin()]; decl != nil {
			return p.bind(p.summary(decl, chReturned, res), decl, nil)
		}
		var out errValue
		for _, m := range p.implementations(obj.Origin()) {
			out = out.add(p.bind(p.summary(p.decls[m], chReturned, res), p.decls[m], nil))
		}
		if out != nil {
			return out
		}
	case *types.Var:
		switch obj.Kind() {
		case types.ParamVar, types.RecvVar:
			return valueOf(chain{{kind: termParamCall, obj: obj, path: path, res: res}})
		case types.PackageVar:
			if init := p.inits[obj]; init != nil {
				return p.callValue(init, path, res)
			}
		default:
			var out errValue
			for _, d := range p.defs[obj] {
				switch {
				case d.rng:
					elts := p.elementExprs(d.rhs, map[types.Object]bool{})
					if elts == nil {
						out = out.add(opaqueValue)
					}
					for _, elt := range elts {
						out = out.add(p.callValue(elt, path, res))
					}
				case d.index < 0:
					out = out.add(p.callValue(d.rhs, path, res))
				}
			}
			return out
		}
	}
	return opaqueValue
}

// returnedFuncs is what calling the function value call returns in result
// res, or its field at path: the values its callee's return statements give.
func (p *producers) returnedFuncs(call *ast.CallExpr, path string, res int) errValue {
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok || p.decls[fn.Origin()] == nil {
		return opaqueValue
	}
	var out errValue
	ast.Inspect(p.decls[fn.Origin()].Body, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(x.Results) == 1 {
				out = out.add(p.callValue(x.Results[0], path, res))
			}
		}
		return true
	})
	return out
}

// bind replaces fn's parameter terms in sum with call's arguments; with no
// call, it drops them.
func (p *producers) bind(sum errValue, fn ast.Node, call *ast.CallExpr) errValue {
	args := p.argsOf(fn, call)
	var out errValue
	for _, c := range sum {
		var fixed chain
		var parts []errValue
		var markers [][]ast.Expr
		for _, tm := range c {
			if bound, ok := p.bindFields(tm, args); ok {
				parts = append(parts, bound)
				continue
			}
			v, _ := tm.obj.(*types.Var)
			bound, isArg := args[v]
			if tm.kind == termDeclared && isArg {
				markers = append(markers, bound)
				continue
			}
			if !isArg || tm.kind == termLeaf || tm.kind == termOpaque || tm.kind == termWrapper || tm.kind == termDeclared {
				fixed = append(fixed, tm)
				continue
			}
			part := errValue{}
			for _, a := range bound {
				switch tm.kind {
				case termParam:
					part.add(p.eval(a))
				case termParamField:
					part.add(p.exprField(a, tm.path))
				default:
					part.add(p.callValue(a, tm.path, tm.res))
				}
			}
			if tm.guards != nil {
				for _, st := range tm.guards.steps {
					part = p.filter(part, st.test, st.holds)
				}
			}
			if len(part) == 0 {
				parts = nil
				fixed = nil
				break
			}
			parts = append(parts, part)
		}
		if fixed == nil && parts == nil {
			continue
		}
		joinedAll := cross(append(parts, valueOf(fixed))...)
		for _, bound := range markers {
			joinedAll = p.declare(joinedAll, bound, call != nil && call.Ellipsis.IsValid())
		}
		for _, joined := range joinedAll {
			if len(joined) > 0 {
				out = out.add(valueOf(joined))
			}
		}
	}
	return out
}

// argsOf is the arguments call binds to each of fn's parameters and its
// receiver; with no call, each is bound to nothing.
func (p *producers) argsOf(fn ast.Node, call *ast.CallExpr) map[*types.Var][]ast.Expr {
	_, sig := p.signature(fn)
	args := map[*types.Var][]ast.Expr{}
	params := sig.Params()
	for v := range params.Variables() {
		args[v] = nil
	}
	if recv := sig.Recv(); recv != nil {
		args[recv] = nil
		if call != nil {
			if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && p.info.Selections[sel] != nil {
				args[recv] = []ast.Expr{sel.X}
			}
		}
	}
	if call != nil && params.Len() > 0 {
		for i, a := range call.Args {
			v := params.At(min(i, params.Len()-1))
			args[v] = append(args[v], a)
		}
	}
	return args
}

// bindFields is tm with each string field naming a parameter in args
// replaced by what its argument holds, one term per combination; false
// when no field names one.
func (p *producers) bindFields(tm term, args map[*types.Var][]ast.Expr) (errValue, bool) {
	if tm.fields == nil || !slices.ContainsFunc(tm.fields.vals, func(f fieldVal) bool {
		_, isArg := args[f.val.obj]
		return f.val.kind == strParam && isArg
	}) {
		return nil, false
	}
	alts := make([][]fieldVal, len(tm.fields.vals))
	for i, f := range tm.fields.vals {
		for _, v := range p.bindStrs([]strVal{f.val}, args) {
			alts[i] = append(alts[i], fieldVal{name: f.name, val: v})
		}
	}
	base := tm
	base.fields = nil
	return p.withFields(base, alts), true
}

// bindStrs is vals with each parameter value in args replaced by what its
// arguments hold where the call is; a parameter bound to nothing is open.
func (p *producers) bindStrs(vals []strVal, args map[*types.Var][]ast.Expr) []strVal {
	var out []strVal
	for _, v := range vals {
		bound, isArg := args[v.obj]
		switch {
		case v.kind != strParam || !isArg:
			out = append(out, v)
		case len(bound) == 0:
			out = append(out, openStr...)
		default:
			for _, a := range bound {
				if v.path == "" {
					out = append(out, p.strs(a)...)
				} else {
					out = append(out, p.fieldStrs(a, v.path)...)
				}
			}
		}
	}
	return out
}

// strs is every value the string expression e can hold where it appears:
// a constant, a parameter or its field, a local's definitions, or what a
// module function returns.
func (p *producers) strs(e ast.Expr) []strVal {
	e = ast.Unparen(e)
	if tv, ok := p.info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return []strVal{{kind: strConst, s: constant.StringVal(tv.Value)}}
	}
	switch e := e.(type) {
	case *ast.Ident:
		if v, ok := p.info.Uses[e].(*types.Var); ok {
			return p.strGuarded(e, v, p.varStrs(v, ""))
		}
	case *ast.SelectorExpr:
		if v, path, ok := p.fieldPath(e); ok {
			return p.varStrs(v, path)
		}
	case *ast.CallExpr:
		if p.info.Types[e.Fun].IsType() && len(e.Args) == 1 {
			return p.strs(e.Args[0])
		}
		return p.calledStrs(e, "", -1)
	}
	return openStr
}

// strGuarded drops from vals, v's values read at id, each constant an
// enclosing if's v != c rules out where id sits in its body.
func (p *producers) strGuarded(id *ast.Ident, v *types.Var, vals []strVal) []strVal {
	for child, n := ast.Node(id), p.parent[id]; n != nil; child, n = n, p.parent[n] {
		switch n := n.(type) {
		case *ast.FuncLit, *ast.FuncDecl:
			return vals
		case *ast.IfStmt:
			be, ok := ast.Unparen(n.Cond).(*ast.BinaryExpr)
			if !ok || child != n.Body || be.Op != token.NEQ {
				continue
			}
			x, isID := ast.Unparen(be.X).(*ast.Ident)
			tv := p.info.Types[be.Y]
			if isID && p.info.Uses[x] == v && tv.Value != nil && tv.Value.Kind() == constant.String {
				ruled := constant.StringVal(tv.Value)
				vals = slices.DeleteFunc(slices.Clone(vals), func(sv strVal) bool { return sv.kind == strConst && sv.s == ruled })
			}
		}
	}
	return vals
}

// fieldPath is sel as a path of direct fields from a variable: v.a.b is v
// and "a.b".
func (p *producers) fieldPath(sel *ast.SelectorExpr) (v *types.Var, path string, ok bool) {
	s, isSel := p.info.Selections[sel]
	if !isSel || s.Kind() != types.FieldVal || len(s.Index()) != 1 {
		return nil, "", false
	}
	switch x := ast.Unparen(sel.X).(type) {
	case *ast.Ident:
		v, ok = p.info.Uses[x].(*types.Var)
		return v, sel.Sel.Name, ok
	case *ast.SelectorExpr:
		if v, path, ok = p.fieldPath(x); ok {
			return v, path + "." + sel.Sel.Name, true
		}
	}
	return nil, "", false
}

// varStrs is what variable v holds, or its field at path: a parameter's
// stays a parameter value, a local's is every definition's and every
// assignment to the field, flow-insensitively.
func (p *producers) varStrs(v *types.Var, path string) []strVal {
	switch v.Kind() {
	case types.ParamVar, types.RecvVar:
		return []strVal{{kind: strParam, obj: v, path: path}}
	case types.PackageVar:
		if init := p.inits[v]; init != nil && path != "" {
			return p.fieldStrs(init, path)
		}
		return openStr
	default:
	}
	k := strKey{at: v, path: path}
	if p.strBusy[k] {
		return nil
	}
	p.strBusy[k] = true
	defer delete(p.strBusy, k)
	var out []strVal
	for _, d := range p.defs[v] {
		switch {
		case d.rng:
			out = append(out, openStr...)
		case d.index >= 0:
			out = append(out, p.calledStrs(d.rhs, path, d.index)...)
		case path == "":
			out = append(out, p.strs(d.rhs)...)
		default:
			out = append(out, p.fieldStrs(d.rhs, path)...)
		}
	}
	for _, d := range p.fieldDefs[v][path] {
		if d.index >= 0 {
			out = append(out, p.calledStrs(d.rhs, "", d.index)...)
		} else {
			out = append(out, p.strs(d.rhs)...)
		}
	}
	if len(out) == 0 {
		return openStr
	}
	return out
}

// fieldStrs is what the field at path of the value x holds.
func (p *producers) fieldStrs(x ast.Expr, path string) []strVal {
	switch e := ast.Unparen(x).(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return p.fieldStrs(e.X, path)
		}
	case *ast.StarExpr:
		return p.fieldStrs(e.X, path)
	case *ast.CompositeLit:
		name, rest, _ := strings.Cut(path, ".")
		for _, elt := range e.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return openStr
			}
			if isIdentNamed(kv.Key, name) {
				if rest == "" {
					return p.strs(kv.Value)
				}
				return p.fieldStrs(kv.Value, rest)
			}
		}
		return []strVal{{kind: strConst}}
	case *ast.Ident:
		if v, ok := p.info.Uses[e].(*types.Var); ok {
			return p.varStrs(v, path)
		}
	case *ast.SelectorExpr:
		if v, base, ok := p.fieldPath(e); ok {
			return p.varStrs(v, base+"."+path)
		}
	case *ast.CallExpr:
		return p.calledStrs(e, path, -1)
	}
	return openStr
}

// calledStrs is what x's call of a module function returns in result
// index, its only one when index is -1, or that result's field at path,
// its parameters bound to the call's arguments.
func (p *producers) calledStrs(x ast.Expr, path string, index int) []strVal {
	call, ok := ast.Unparen(x).(*ast.CallExpr)
	if !ok {
		return openStr
	}
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok || p.decls[fn.Origin()] == nil {
		return openStr
	}
	results := fn.Signature().Results().Len()
	if index < 0 && results == 1 {
		index = 0
	}
	if index < 0 || index >= results {
		return openStr
	}
	decl := p.decls[fn.Origin()]
	k := strKey{at: decl, path: fmt.Sprintf("%d:%s", index, path)}
	if p.strBusy[k] {
		return nil
	}
	p.strBusy[k] = true
	defer delete(p.strBusy, k)
	var vals []strVal
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch r := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(r.Results) == 1 && results > 1:
				vals = append(vals, p.calledStrs(r.Results[0], path, index)...)
			case len(r.Results) != results:
				vals = append(vals, openStr...)
			case path == "":
				vals = append(vals, p.strs(r.Results[index])...)
			default:
				vals = append(vals, p.fieldStrs(r.Results[index], path)...)
			}
		}
		return true
	})
	if len(vals) == 0 {
		return openStr
	}
	return p.bindStrs(vals, p.argsOf(decl, call))
}

// values is c's leaves' errors, each a literal's fields set over its zero
// value, false when a leaf has none.
func (p *producers) values(c chain) ([]error, bool) {
	var vals []error
	for _, tm := range c {
		if tm.kind != termLeaf {
			continue
		}
		v, ok := buildLeaf(tm.obj, p.fieldStrings(tm))
		if !ok {
			return nil, false
		}
		vals = append(vals, v)
	}
	return vals, true
}

// fieldStrings is tm's reason-bearing fields as buildLeaf sets them: a
// literal's constant as it is, its other values unresolved and the fields
// it leaves out zero; a leaf no literal built has every one unresolved.
func (p *producers) fieldStrings(tm term) map[string]string {
	m := map[string]string{}
	for _, name := range p.bearingFields(tm.obj) {
		m[name] = unresolved
		if tm.fields != nil {
			m[name] = ""
		}
	}
	if tm.fields != nil {
		for _, f := range tm.fields.vals {
			m[f.name] = unresolved
			if f.val.kind == strConst {
				m[f.name] = f.val.s
			}
		}
	}
	return m
}

// joined is c's error as classify sees it: its leaves' errors joined,
// under each failreason wrapper the chain carries.
func (p *producers) joined(c chain, vals []error) error {
	err := errors.Join(vals...)
	for _, tm := range c {
		if tm.kind == termWrapper && qualified(tm.obj) == reasonedType {
			err = failreason.Wrap(err, p.fieldStrings(tm)["reason"])
		}
	}
	return err
}

func chainString(c chain) string {
	parts := make([]string, len(c))
	for i, tm := range c {
		switch tm.kind {
		case termLeaf:
			parts[i] = strings.TrimPrefix(strings.Replace(qualified(tm.obj), modulePath+".", "access.", 1), modulePath+"/")
		case termOpaque:
			parts[i] = "opaque"
		case termWrapper:
			parts[i] = "wrapper " + tm.obj.Name()
		case termDeclared:
			parts[i] = "declared " + tm.obj.Name()
		default:
			parts[i] = "param " + tm.obj.Name() + " " + tm.path
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// errTest is a guard's test of one error: errors.Is against a sentinel, or
// errors.AsType for a type.
type errTest struct {
	sentinel types.Object
	typ      *types.TypeName
}

func asTypeTest(result types.Type) errTest {
	tuple, ok := result.(*types.Tuple)
	if !ok || tuple.Len() == 0 {
		return errTest{}
	}
	typ := tuple.At(0).Type()
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return errTest{}
	}
	return errTest{typ: named.Obj()}
}

// matches reports whether test holds for c, and false for known when the
// chain or the test is not one the registry can decide.
func (p *producers) matches(c chain, test errTest) (match, known bool) {
	params := false
	for _, tm := range c {
		if tm.obj != nil && (tm.obj == test.sentinel || tm.obj == test.typ) && (tm.kind == termLeaf || tm.kind == termWrapper) {
			return true, true
		}
		params = params || isParamTerm(tm)
	}
	vals, ok := p.values(c)
	if !ok {
		return false, false
	}
	if params {
		match, known := matchValues(vals, test)
		return match, known && match
	}
	return matchValues(vals, test)
}

func matchValues(vals []error, test errTest) (match, known bool) {
	joined := errors.Join(vals...)
	switch {
	case test.sentinel != nil:
		target, ok := errorValue(test.sentinel)
		return ok && errors.Is(joined, target), ok
	case test.typ != nil:
		target, ok := producerErrors[qualified(test.typ)]
		if !ok {
			return false, !nameable(test.typ)
		}
		ptr := reflect.New(reflect.TypeOf(target))
		return errors.As(joined, ptr.Interface()), true
	}
	return false, false
}

// filter keeps the chains of val for which test holds, or, when holds is
// false, those for which it does not; a chain it cannot decide stays.
func (p *producers) filter(val errValue, test errTest, holds bool) errValue {
	if test.sentinel == nil && test.typ == nil {
		return val
	}
	out := errValue{}
	for k, c := range val {
		match, known := p.matches(c, test)
		switch {
		case known && match == holds:
			out[k] = c
		case known:
		case slices.ContainsFunc(c, isParamTerm) && !match:
			out.add(valueOf(p.deferGuard(c, guardStep{test: test, holds: holds})))
		default:
			out[k] = c
		}
	}
	return out
}

func isParamTerm(t term) bool {
	return t.kind == termParam || t.kind == termParamCall || t.kind == termParamField
}

// deferGuard adds step to each parameter term of c, for its binding.
func (p *producers) deferGuard(c chain, step guardStep) chain {
	out := slices.Clone(c)
	for i, t := range out {
		if !isParamTerm(t) {
			continue
		}
		var steps []guardStep
		if t.guards != nil {
			steps = slices.Clone(t.guards.steps)
		}
		steps = append(steps, step)
		key := ""
		for _, st := range steps {
			key += fmt.Sprintf("%p/%p/%t;", st.test.sentinel, st.test.typ, st.holds)
		}
		if p.guardLists[key] == nil {
			p.guardLists[key] = &guardList{key: key, steps: steps}
		}
		out[i].guards = p.guardLists[key]
	}
	return out
}

// guard is the test cond makes of v: errors.Is(v, S), v == S, or the ok of
// an errors.AsType[T](v) its init assigns; holds is false under a negation.
func (p *producers) guard(v *types.Var, init ast.Stmt, cond ast.Expr) (test errTest, holds bool) {
	isV := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && p.info.Uses[id] == v
	}
	switch c := ast.Unparen(cond).(type) {
	case *ast.UnaryExpr:
		if c.Op == token.NOT {
			test, holds = p.guard(v, init, c.X)
			return test, !holds
		}
	case *ast.BinaryExpr:
		if (c.Op == token.EQL || c.Op == token.NEQ) && isV(c.X) {
			if obj := p.callee(c.Y); obj != nil && obj.Name() != "nil" {
				return errTest{sentinel: obj}, c.Op == token.EQL
			}
		}
	case *ast.CallExpr:
		if fn, ok := p.callee(c.Fun).(*types.Func); ok && qualified(fn) == "errors.Is" && isV(c.Args[0]) {
			if obj, ok := p.callee(c.Args[1]).(*types.Var); ok && obj.Kind() == types.PackageVar {
				return errTest{sentinel: obj}, true
			}
		}
	case *ast.Ident:
		assign, ok := init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || p.info.ObjectOf(c) != p.info.ObjectOf(assign.Lhs[1].(*ast.Ident)) {
			break
		}
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && len(call.Args) == 1 && isV(call.Args[0]) {
			if fn, ok := p.callee(call.Fun).(*types.Func); ok && qualified(fn) == "errors.AsType" {
				return asTypeTest(p.info.TypeOf(call)), true
			}
		}
	}
	return errTest{}, false
}

// guarded filters val, the value of v read at id, by the errors.Is and
// errors.AsType tests control passed to reach id: the if or case it sits
// in, the cases before that, and every terminating if before it in an
// enclosing block.
func (p *producers) guarded(id *ast.Ident, v *types.Var, val errValue) errValue {
	apply := func(init ast.Stmt, cond ast.Expr, taken bool) {
		if test, holds := p.guard(v, init, cond); test.sentinel != nil || test.typ != nil {
			val = p.filter(val, test, holds == taken)
		}
	}
	for child, n := ast.Node(id), p.parent[id]; n != nil; child, n = n, p.parent[n] {
		switch n := n.(type) {
		case *ast.FuncLit, *ast.FuncDecl:
			return val
		case *ast.IfStmt:
			switch child {
			case n.Body:
				apply(n.Init, n.Cond, true)
			case n.Else:
				apply(n.Init, n.Cond, false)
			}
		case *ast.CaseClause:
			sw, ok := p.parent[p.parent[n]].(*ast.SwitchStmt)
			if !ok || sw.Tag != nil || slices.ContainsFunc(n.List, func(e ast.Expr) bool { return e == child }) {
				break
			}
			for _, prior := range sw.Body.List {
				if prior == n {
					break
				}
				for _, cond := range prior.(*ast.CaseClause).List {
					apply(nil, cond, false)
				}
			}
			if len(n.List) == 1 {
				apply(nil, n.List[0], true)
			}
		case *ast.BlockStmt:
			for _, st := range n.List {
				if st == child {
					break
				}
				if is, ok := st.(*ast.IfStmt); ok && is.Else == nil && terminates(is.Body) {
					apply(is.Init, is.Cond, false)
				}
			}
		}
	}
	return val
}

// terminates reports whether b ends in a return or a panic.
func terminates(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		return ok && isIdentNamed(call.Fun, "panic")
	}
	return false
}
