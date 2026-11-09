package accesshttp

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

var maskedTypes = []reflect.Type{reflect.TypeFor[access.Secret](), reflect.TypeFor[access.Hash]()}

// heldSecrets names, by field path, every access.Secret or access.Hash t holds
// at any depth.
func heldSecrets(t reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if slices.Contains(maskedTypes, t) {
		return []string{path}
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return heldSecrets(t.Elem(), path+"[]", seen)
	case reflect.Struct:
		if seen[t] {
			return nil
		}
		seen[t] = true
		var out []string
		for f := range t.Fields() {
			out = append(out, heldSecrets(f.Type, path+"."+f.Name, seen)...)
		}
		return out
	default:
		return nil
	}
}

func TestRequestTypesHoldNoSecret(t *testing.T) {
	for i := range specs {
		if specs[i].request == nil {
			continue
		}
		if got := heldSecrets(specs[i].request, specs[i].request.Name(), map[reflect.Type]bool{}); len(got) != 0 {
			t.Errorf("%s request holds %v; request fields are strings the handler wraps", specs[i].name, got)
		}
	}
	t.Run("walker_reports_a_nested_secret", func(t *testing.T) {
		type inner struct{ Key access.Secret }
		type outer struct {
			Name  string
			Items []inner
		}
		got := heldSecrets(reflect.TypeFor[outer](), "outer", map[reflect.Type]bool{})
		if !slices.Equal(got, []string{"outer.Items[].Key"}) {
			t.Errorf("walker = %v, want [outer.Items[].Key]", got)
		}
	})
}

func TestShownOnceWriter(t *testing.T) {
	const plaintext = "shown-once-plaintext-value"
	t.Run("key", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeShownOnce(w, http.StatusCreated, KeyCreatedResponse{Details: KeyView{ID: 7, Label: "ci"}}, access.NewSecret(plaintext))
		if w.Code != http.StatusCreated || strings.Count(w.Body.String(), plaintext) != 1 {
			t.Fatalf("status %d body %s, want 201 holding the plaintext once", w.Code, w.Body.String())
		}
		var got KeyCreatedResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Key != plaintext || got.Details.ID != 7 {
			t.Errorf("decoded %+v, %v; want key %q and details", got, err, plaintext)
		}
	})
	t.Run("token", func(t *testing.T) {
		w := httptest.NewRecorder()
		exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		writeShownOnce(w, http.StatusOK, TokenResponse{ExpiresAt: exp}, access.NewSecret(plaintext))
		if strings.Count(w.Body.String(), plaintext) != 1 {
			t.Fatalf("body %s, want the plaintext once", w.Body.String())
		}
		var got TokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Token != plaintext || !got.ExpiresAt.Equal(exp) {
			t.Errorf("decoded %+v, %v; want token %q expiring %v", got, err, plaintext, exp)
		}
	})
}

// unsetFields names, by field path, every field of v that is zero, or zero
// in every element of a slice, skipping the paths in skip. A fixture with
// none sets every field its view can carry.
func unsetFields(v reflect.Value, path string, skip []string) []string {
	if slices.Contains(skip, path) {
		return nil
	}
	switch {
	case v.Type() == reflect.TypeFor[time.Time]() || v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8:
		if v.IsZero() || v.Kind() == reflect.Slice && v.Len() == 0 {
			return []string{path}
		}
		return nil
	case v.Kind() == reflect.Pointer:
		if v.IsNil() {
			return []string{path}
		}
		return unsetFields(v.Elem(), path, skip)
	case v.Kind() == reflect.Struct:
		var out []string
		for i := range v.NumField() {
			out = append(out, unsetFields(v.Field(i), path+"."+v.Type().Field(i).Name, skip)...)
		}
		return out
	case v.Kind() == reflect.Slice:
		if v.Len() == 0 {
			return []string{path}
		}
		out := unsetFields(v.Index(0), path+"[]", skip)
		for i := 1; i < v.Len(); i++ {
			still := unsetFields(v.Index(i), path+"[]", skip)
			out = slices.DeleteFunc(out, func(p string) bool { return !slices.Contains(still, p) })
		}
		return out
	default:
		if v.IsZero() {
			return []string{path}
		}
		return nil
	}
}

// TestViewsCarryEveryField holds each response view to its account value:
// every field of each want is set, so a view that drops or swaps a field
// fails.
func TestViewsCarryEveryField(t *testing.T) {
	created := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	user := &access.User{
		ID: 7, Username: "alice", DisplayName: "Alice", Role: access.RoleAdmin, Enabled: true,
		OIDC: access.OIDCIdentity{Issuer: testIssuer, Subject: "s"}, CreatedAt: created,
	}
	wantUser := UserView{ID: 7, Username: "alice", DisplayName: "Alice", Role: access.RoleAdmin, Enabled: true, OIDCLinked: true, CreatedAt: created}
	adminListOnly := []string{"UserView.Methods", "UserView.KeyLineage", "SignedInResponse.User.Methods", "SignedInResponse.User.KeyLineage", "MeResponse.User.Methods", "MeResponse.User.KeyLineage"}
	methods := account.Methods{
		Locks: []account.MethodLock{
			{Method: access.MethodPassword, Untrusted: true},
			{Method: access.MethodPasskey, Trusted: true},
		},
		PasskeyCount: 2, HasPassword: true, OIDCLinked: true, OIDCAvailable: true, PasskeysAvailable: true, PasswordLogin: true,
	}
	wantMethods := MethodsView{
		Locks: []MethodLockView{
			{Method: access.MethodPassword, Untrusted: true},
			{Method: access.MethodPasskey, Trusted: true},
		},
		PasskeyCount: 2, Password: true, OIDCLinked: true, OIDCAvailable: true, PasskeysAvailable: true, PasswordLogin: true,
	}
	at := func(h int) time.Time { return created.Add(time.Duration(h) * time.Hour) }
	me := account.Me{
		User: user, Methods: methods, CanLinkOIDC: true, SSOGoverned: true,
		Current: account.CurrentSession{ID: "sess", Method: access.MethodPasskey, AuthTime: at(1), IdleDeadline: at(2), AbsoluteDeadline: at(3)},
	}
	wantMe := MeResponse{
		User: wantUser, Methods: wantMethods, CanLinkOIDC: true, SSOGoverned: true,
		Session: CurrentSessionView{ID: "sess", Method: access.MethodPasskey, AuthTime: at(1), IdleDeadline: at(2), AbsoluteDeadline: at(3)},
	}
	wantSignedIn := SignedInResponse{User: wantUser, SessionID: "sess", CloneWarning: true}
	listed := account.ListedUser{User: *user, KeyLineage: []int64{3, 5}, PasskeyCount: 2}
	listed.User.PasswordHash = access.NewHash("$argon2id$stored")
	wantListed := wantUser
	wantListed.Methods = &UserMethodsView{Password: true, PasskeyCount: 2}
	wantListed.KeyLineage = []int64{3, 5}
	passkey := access.PasskeyCredential{
		ID: 2, Name: "laptop", RPID: testRPID, CreatedAt: at(1), LastUsedAt: at(2),
		BackupEligible: true, BackupState: true, CloneWarning: true,
	}
	wantPasskey := PasskeyView{
		ID: 2, Name: "laptop", RPID: testRPID, CreatedAt: at(1), LastUsedAt: at(2),
		BackupEligible: true, BackedUp: true, CloneWarning: true,
	}
	session := access.Session{
		ID: "sess", Label: "laptop", UserAgent: "Firefox", LastIP: "192.0.2.1", AuthMethod: access.MethodPasskey,
		CreatedAt: at(1), LastActivity: at(2), AuthTime: at(3),
	}
	timeouts := access.SessionTimeouts{Idle: 4 * time.Hour, Absolute: 10 * time.Hour}
	wantSession := SessionView{
		ID: "sess", Label: "laptop", UserAgent: "Firefox", LastIP: "192.0.2.1", Method: access.MethodPasskey,
		CreatedAt: at(1), LastActivity: at(2), AuthTime: at(3), IdleDeadline: at(6), AbsoluteDeadline: at(11), Current: true,
	}
	key := access.Key{
		ID: 5, UserID: 7, Label: "ci", KeyPrefix: "ak_7", KeySuffix: "wxyz", Scopes: []string{"read"},
		CreatedAt: at(1), ExpiresAt: at(4), LastUsedAt: at(2), LineageIDs: []int64{3, 5},
	}
	wantKey := KeyView{
		ID: 5, UserID: 7, Owner: "alice", Label: "ci", Prefix: "ak_7", Suffix: "wxyz", Scopes: []string{"read"},
		CreatedAt: at(1), ExpiresAt: at(4), LastUsedAt: at(2), ParentKeyID: 3,
	}
	token := account.ListedToken{IssuerLineage: []int64{3, 5}, Token: access.OneTimeToken{
		Purpose: access.PurposeInvite, Role: access.RoleUser, Subject: 9, IssuedByKey: 5, CreatedAt: at(1), ExpiresAt: at(5),
	}}
	wantToken := TokenView{
		Purpose: access.PurposeInvite, Role: access.RoleUser, Subject: 9, IssuedByKey: 5, IssuerLineage: []int64{3, 5},
		CreatedAt: at(1), ExpiresAt: at(5),
	}
	logPage := account.LogPage{
		Entries: []account.LogEntry{{
			At: at(2), IP: netip.MustParseAddr("192.0.2.9"), Class: account.LogClassChange,
			ActorLabel: "laptop", ActorUserAgent: "Firefox", ActorKeySuffix: "wxyz", Detail: "d",
			Event: account.Event{
				At: at(1), Kind: account.EventMethodLocked, Method: access.MethodPasskey, Role: access.RoleUser,
				SessionIDs: []string{"s1", "s2"}, UserID: 7, KeyID: 5, PasskeyID: 2, Seq: 11, Trusted: true,
				Actor: account.EventActor{SessionID: "sess", OutOfBand: "cli", UserID: 3, KeyID: 4},
			},
		}},
		Classes: []account.LogClassStats{{Class: account.LogClassChange, Count: 6, Evicted: 8}},
	}
	wantLogPage := SecurityLogView{
		Entries: []LogEntryView{{
			Seq: 11, At: at(2), OccurredAt: at(1), Class: account.LogClassChange, Kind: "method_locked",
			IP: "192.0.2.9", Method: access.MethodPasskey, Role: access.RoleUser, Detail: "d",
			SessionIDs: []string{"s1", "s2"}, UserID: 7, KeyID: 5, PasskeyID: 2, Trusted: true,
			Actor: LogActorView{SessionID: "sess", OutOfBand: "cli", Label: "laptop", UserAgent: "Firefox", KeySuffix: "wxyz", UserID: 3, KeyID: 4},
		}},
		Classes: []LogClassView{{Class: account.LogClassChange, Count: 6, Evicted: 8}},
	}
	for _, tc := range []struct {
		got, want any
		name      string
	}{
		{name: "UserView", got: userView(user), want: wantUser},
		{name: "MethodsView", got: methodsView(methods), want: wantMethods},
		{name: "MeResponse", got: meResponse(&me), want: wantMe},
		{name: "SignedInResponse", got: signedInResponse(account.SignedIn{User: user, Session: access.Session{ID: "sess"}, CloneWarning: true}), want: wantSignedIn},
		{name: "ListedUserView", got: listedUserView(&listed), want: wantListed},
		{name: "PasskeyView", got: passkeyView(&passkey), want: wantPasskey},
		{name: "SessionView", got: sessionView(&session, timeouts, "sess"), want: wantSession},
		{name: "KeyView", got: keyView(&key, "alice"), want: wantKey},
		{name: "TokenView", got: tokenView(&token), want: wantToken},
		{name: "SecurityLogView", got: securityLogView(&logPage), want: wantLogPage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if unset := unsetFields(reflect.ValueOf(tc.want), tc.name, adminListOnly); len(unset) != 0 {
				t.Fatalf("fixture leaves %v unset", unset)
			}
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Errorf("view %+v, want %+v", tc.got, tc.want)
			}
		})
	}
	t.Run("methods_one_field_at_a_time", func(t *testing.T) {
		for _, tc := range []struct {
			in   account.Methods
			want MethodsView
			name string
		}{
			{account.Methods{HasPassword: true}, MethodsView{Password: true}, "password"},
			{account.Methods{OIDCLinked: true}, MethodsView{OIDCLinked: true}, "oidc_linked"},
			{account.Methods{OIDCAvailable: true}, MethodsView{OIDCAvailable: true}, "oidc_available"},
			{account.Methods{PasskeysAvailable: true}, MethodsView{PasskeysAvailable: true}, "passkeys_available"},
			{account.Methods{PasswordLogin: true}, MethodsView{PasswordLogin: true}, "password_login"},
			{account.Methods{PasskeyCount: 3}, MethodsView{PasskeyCount: 3}, "passkey_count"},
		} {
			tc.want.Locks = []MethodLockView{}
			if got := methodsView(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s: view %+v, want %+v", tc.name, got, tc.want)
			}
		}
	})
	t.Run("passkey_flags_one_at_a_time", func(t *testing.T) {
		for _, tc := range []struct {
			in   access.PasskeyCredential
			want PasskeyView
			name string
		}{
			{access.PasskeyCredential{BackupEligible: true}, PasskeyView{BackupEligible: true}, "backup_eligible"},
			{access.PasskeyCredential{BackupState: true}, PasskeyView{BackedUp: true}, "backed_up"},
			{access.PasskeyCredential{CloneWarning: true}, PasskeyView{CloneWarning: true}, "clone_warning"},
		} {
			if got := passkeyView(&tc.in); got != tc.want {
				t.Errorf("%s: view %+v, want %+v", tc.name, got, tc.want)
			}
		}
	})
	t.Run("session_not_current", func(t *testing.T) {
		if got := sessionView(&session, timeouts, "other"); got.Current {
			t.Errorf("view %+v of another session is current", got)
		}
	})
	t.Run("listed_user_without_password", func(t *testing.T) {
		got := listedUserView(&account.ListedUser{User: *user})
		if got.Methods == nil || *got.Methods != (UserMethodsView{}) || got.KeyLineage != nil {
			t.Errorf("view %+v, methods %+v; want no password, no passkey and no lineage", got, got.Methods)
		}
	})
	t.Run("key_scopes_owned_and_never_null", func(t *testing.T) {
		k := key
		k.Scopes = []string{"read"}
		v := keyView(&k, "")
		k.Scopes[0] = "write"
		if v.Scopes[0] != "read" {
			t.Errorf("view scopes %v follow the key's slice", v.Scopes)
		}
		k.Scopes = nil
		b, err := json.Marshal(keyView(&k, ""))
		if err != nil || !strings.Contains(string(b), `"scopes":[]`) {
			t.Errorf("view of a key with no scopes encodes %s (%v), want \"scopes\":[]", b, err)
		}
	})
	t.Run("fixture_check_reports_an_unset_field", func(t *testing.T) {
		v := wantMethods
		v.Locks = []MethodLockView{{Method: access.MethodPassword, Untrusted: true}}
		if got := unsetFields(reflect.ValueOf(v), "MethodsView", nil); !slices.Equal(got, []string{"MethodsView.Locks[].Trusted"}) {
			t.Errorf("unsetFields = %v, want [MethodsView.Locks[].Trusted]", got)
		}
	})
}

// TestLogEntryViewJSON holds the omitempty keys to an entry that sets none
// of them: the golden fixture sets every field, so it cannot catch one.
func TestLogEntryViewJSON(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	e := account.LogEntry{At: at, Class: account.LogClassChange, Event: account.Event{At: at, Kind: account.EventPasswordChanged, Seq: 9}}
	b, err := json.Marshal(logEntryView(&e))
	if err != nil {
		t.Fatal(err)
	}
	keys := jsonKeys(t, b)
	if got, want := slices.Sorted(maps.Keys(keys)), []string{"actor", "at", "class", "kind", "occurred_at", "seq"}; !slices.Equal(got, want) {
		t.Errorf("keys %q of %s, want %q", got, b, want)
	}
	if got := string(keys["actor"]); got != "{}" {
		t.Errorf("actor %s, want {} for the zero actor", got)
	}
}

func TestSecurityLogViewJSON(t *testing.T) {
	page := account.LogPage{Classes: []account.LogClassStats{{Class: account.LogClassChange}, {Class: account.LogClassSession}}}
	b, err := json.Marshal(securityLogView(&page))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"entries":[],"classes":[{"class":"change","count":0,"evicted":0},{"class":"session","count":0,"evicted":0}]}`
	if string(b) != want {
		t.Errorf("empty page encodes %s, want %s", b, want)
	}
}
