package accesshttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// pendingAfter runs a sign-in flow for the default IdP identity in an env
// under o, after arrange, and returns the env, the browser and the pending
// read's response.
func pendingAfter(t *testing.T, o envOptions, arrange func(e *env)) (*env, *browser, int, []byte) {
	t.Helper()
	e := newEnv(t, o)
	idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
	e.createUser(t, "root", access.RoleAdmin)
	if arrange != nil {
		arrange(e)
	}
	b := newBrowser(t)
	if loc := location(t, e.signInFlow(t, b, idp, "")); loc != "/signin?oidc=not_linked" {
		t.Fatalf("Location %q, want not_linked", loc)
	}
	rt := e.route(t, "authOIDCPending")
	w := b.send(rt, get(rt, ""))
	return e, b, w.Code, w.Body.Bytes()
}

// TestPendingAnswerIsNeutral: design 5.4, two callbacks, one whose hint
// matches a user and one matching nobody, give identical status and body;
// the server never looks a user up by the hint for this answer.
func TestPendingAnswerIsNeutral(t *testing.T) {
	_, _, freeStatus, freeBody := pendingAfter(t, envOptions{}, nil)
	_, _, heldStatus, heldBody := pendingAfter(t, envOptions{}, func(e *env) { e.createUser(t, accesstest.DefaultIdPUsername, access.RoleUser) })
	if freeStatus != http.StatusOK || heldStatus != freeStatus || !bytes.Equal(heldBody, freeBody) {
		t.Errorf("hint held: %d %s; hint free: %d %s; want the same 200 body", heldStatus, heldBody, freeStatus, freeBody)
	}
	var got PendingLinkResponse
	if err := json.Unmarshal(freeBody, &got); err != nil || got.CanCreate || got.SuggestedUsername != "" {
		t.Errorf("pending %+v (%v), want no create offer with provisioning off", got, err)
	}
}

// TestPendingCreate: design 5.4 and 5.23, under provisioning a taken name
// offers can_create with the hint plus a suffix, a taken pick answers
// auth_username_taken and keeps the pending state, and a free pick signs in.
func TestPendingCreate(t *testing.T) {
	prov := envOptions{rules: func(r *account.Rules) { r.Provisioning = account.Provisioning{Enabled: true} }}
	e, b, status, body := pendingAfter(t, prov, func(e *env) { e.createUser(t, accesstest.DefaultIdPUsername, access.RoleUser) })
	var offer PendingLinkResponse
	if status != http.StatusOK || json.Unmarshal(body, &offer) != nil {
		t.Fatalf("pending %d %s, want 200", status, body)
	}
	if !offer.CanCreate || offer.SuggestedUsername != accesstest.DefaultIdPUsername+"_2" || offer.UsernameHint != accesstest.DefaultIdPUsername {
		t.Errorf("pending %+v, want can_create with %s_2", offer, accesstest.DefaultIdPUsername)
	}
	rt := e.route(t, "authOIDCCreatePending")
	w := b.send(rt, request(rt, jsonBody(t, PendingCreateRequest{Username: "root"})))
	if w.Code != http.StatusConflict || cookieNamed(w, e.pendingCookieName()) != nil {
		t.Fatalf("a taken pick: status %d body %s cookies %v, want 409 with the pending cookie kept", w.Code, w.Body.String(), w.Result().Cookies())
	}
	w = b.send(rt, request(rt, jsonBody(t, PendingCreateRequest{Username: offer.SuggestedUsername})))
	var in SignedInResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &in) != nil || in.User.Username != offer.SuggestedUsername || !in.User.OIDCLinked {
		t.Fatalf("a free pick: status %d body %s, want 200 SignedInResponse for %s, linked", w.Code, w.Body.String(), offer.SuggestedUsername)
	}
	if pc := cookieNamed(w, e.pendingCookieName()); pc == nil || pc.MaxAge >= 0 {
		t.Errorf("pending cookie %v, want cleared", pc)
	}
	if got := e.user(t, offer.SuggestedUsername).OIDC; got != idpIdentity(testIssuer) {
		t.Errorf("created account linked to %+v, want the pending identity", got)
	}
}
