package access

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/printcheck"
	"github.com/go-webauthn/webauthn/protocol"
)

// fillReferences sets every slice and pointer field of *p to a fresh
// non-zero value and returns those fields' names.
func fillReferences(t *testing.T, p any) []string {
	t.Helper()
	rv := reflect.ValueOf(p).Elem()
	var names []string
	for i := range rv.NumField() {
		f := rv.Field(i)
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			setNonZero(t, f.Index(0))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
			setNonZero(t, f.Elem())
		case reflect.Map, reflect.Chan, reflect.Func, reflect.Interface:
			t.Fatalf("%s.%s: unhandled reference kind %s", rv.Type(), rv.Type().Field(i).Name, f.Kind())
		default:
			continue
		}
		names = append(names, rv.Type().Field(i).Name)
	}
	return names
}

func setNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint8:
		v.SetUint(1)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	default:
		t.Fatalf("setNonZero: unhandled kind %s", v.Kind())
	}
}

// checkDeepClone fills every reference field of a fresh T, clones it, and
// requires an equal value that shares no slice or pointer with the original.
func checkDeepClone[T any](t *testing.T, clone func(*T) *T, want []string) {
	t.Helper()
	orig := new(T)
	refs := fillReferences(t, orig)
	for _, name := range want {
		if !slices.Contains(refs, name) {
			t.Fatalf("reference fields = %v, want %s among them", refs, name)
		}
	}
	c := clone(orig)
	if !reflect.DeepEqual(c, orig) {
		t.Fatalf("Clone() = %+v, want a value equal to %+v", c, orig)
	}
	ov, cv := reflect.ValueOf(orig).Elem(), reflect.ValueOf(c).Elem()
	for _, name := range refs {
		if ov.FieldByName(name).Pointer() == cv.FieldByName(name).Pointer() {
			t.Errorf("Clone().%s shares its backing storage with the original", name)
		}
	}
	if got := clone(nil); got != nil {
		t.Errorf("Clone() of nil = %+v, want nil", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	t.Parallel()
	t.Run("User", func(t *testing.T) {
		t.Parallel()
		checkDeepClone(t, (*User).Clone, []string{"WebAuthnHandle"})
	})
	t.Run("Key", func(t *testing.T) {
		t.Parallel()
		checkDeepClone(t, (*Key).Clone, []string{"Scopes", "LineageIDs"})
	})
	t.Run("KeyAttribution", func(t *testing.T) {
		t.Parallel()
		checkDeepClone(t, (*KeyAttribution).Clone, []string{"KeyLineage"})
	})
	t.Run("PasskeyCredential", func(t *testing.T) {
		t.Parallel()
		checkDeepClone(t, (*PasskeyCredential).Clone,
			[]string{"Discoverable", "CredentialID", "PublicKey", "AAGUID", "RawAttestation"})
	})
}

func TestKeyPreviousSecretUsable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	previous := APIKeyHash("superseded")
	cases := []struct {
		name string
		key  Key
		want bool
	}{
		{"never_rotated", Key{}, false},
		{"inside_the_overlap_unused", Key{PreviousHash: previous, PreviousUntil: now.Add(time.Second)}, true},
		{"at_the_bound", Key{PreviousHash: previous, PreviousUntil: now}, false},
		{"past_the_bound", Key{PreviousHash: previous, PreviousUntil: now.Add(-time.Second)}, false},
		{"new_secret_used", Key{PreviousHash: previous, PreviousUntil: now.Add(time.Hour), LastUsedAt: now.Add(-time.Second)}, false},
		{"bound_with_no_previous_hash", Key{PreviousUntil: now.Add(time.Hour)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.key.PreviousSecretUsable(now); got != tc.want {
				t.Errorf("PreviousSecretUsable(%v) = %t, want %t", now, got, tc.want)
			}
		})
	}
}

func TestKeyLineage(t *testing.T) {
	t.Parallel()
	parents := []struct {
		name    string
		lineage []int64
		want    int64
	}{
		{"empty", nil, 0},
		{"root", []int64{7}, 0},
		{"child", []int64{7, 9}, 7},
		{"deep", []int64{3, 7, 9, 12}, 9},
	}
	for _, tc := range parents {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := (Key{LineageIDs: tc.lineage}).ParentKeyID(); got != tc.want {
				t.Errorf("Key{LineageIDs: %v}.ParentKeyID() = %d, want %d", tc.lineage, got, tc.want)
			}
		})
	}
	t.Run("contains", func(t *testing.T) {
		t.Parallel()
		a := KeyAttribution{KeyLineage: []int64{3, 7, 9}}
		for _, id := range []int64{3, 7, 9} {
			if !a.Contains(id) {
				t.Errorf("Contains(%d) = false for lineage %v, want true", id, a.KeyLineage)
			}
		}
		for _, id := range []int64{4, 0} {
			if a.Contains(id) {
				t.Errorf("Contains(%d) = true for lineage %v, want false", id, a.KeyLineage)
			}
		}
	})
}

// TestDecodePasskeyFlags checks every octet, so all 16 combinations of the
// four decoded bits and every setting of the others, against go-webauthn's
// own decoder.
func TestDecodePasskeyFlags(t *testing.T) {
	t.Parallel()
	for o := range 256 {
		octet := uint8(o)
		f := protocol.AuthenticatorFlags(octet)
		up, uv, be, bs := DecodePasskeyFlags(octet)
		if up != f.UserPresent() || uv != f.UserVerified() || be != f.HasBackupEligible() || bs != f.HasBackupState() {
			t.Errorf("DecodePasskeyFlags(%#02x) = (%t, %t, %t, %t), want (%t, %t, %t, %t)", octet, up, uv, be, bs,
				f.UserPresent(), f.UserVerified(), f.HasBackupEligible(), f.HasBackupState())
		}
	}
	if up, uv, be, bs := DecodePasskeyFlags(0x1D); !up || !uv || !be || !bs {
		t.Errorf("DecodePasskeyFlags(0x1D) = (%t, %t, %t, %t), want all true", up, uv, be, bs)
	}
}

// recordRenderings prints v through every route a stored record must mask,
// %p of a value included: fmt's bad-verb path prints its fields by
// reflection.
func recordRenderings(t *testing.T, v any) map[string]string {
	t.Helper()
	out := make(map[string]string)
	out["%p"] = fmt.Sprintf(runtimeVerb('p'), v)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%10v", "%T"} {
		out[verb] = fmt.Sprintf(verb, v)
		out["[]any "+verb] = fmt.Sprintf(verb, []any{v})
	}
	out["Sprint"] = fmt.Sprint(v)
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("msg", "v", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("msg", "v", v)
	out["slog.TextHandler"] = text.String()
	out["slog.JSONHandler"] = js.String()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v", v, err)
	}
	out["json.Marshal"] = string(b)
	return out
}

func TestRecordPrinting(t *testing.T) {
	t.Parallel()
	const (
		known  = "kn0wn-st0red-h4sh-0451"
		marker = "4242"
	)
	u := User{ID: 4242, Username: "alice", Role: RoleUser, PasswordHash: NewHash(known)}
	s := Session{ID: "sess-4242", UserID: 1, TokenHash: NewHash(known)}
	k := Key{ID: 4242, UserID: 1, KeyHash: NewHash(known), KeyPrefix: "pfx", Scopes: []string{"read"}}
	tok := OneTimeToken{Purpose: PurposeInvite, Subject: 4242, Hash: NewHash(known)}
	values := map[string]any{
		"User": u, "*User": &u,
		"Session": s, "*Session": &s,
		"Key": k, "*Key": &k,
		"OneTimeToken": tok, "*OneTimeToken": &tok,
	}
	// No marker where fmt prints no decimal: %x and %X print hex, %q runes,
	// %T the type, and %p of a pointer or a []any, or any verb on a []any
	// holding a pointer, an address.
	noMarker := []string{"%T", "%q", "%x", "%X"}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			isPointer := reflect.ValueOf(v).Kind() == reflect.Pointer
			for route, got := range recordRenderings(t, v) {
				if printcheck.Leak(got, known) {
					t.Errorf("%s printed the hash: %s", route, got)
				}
				verb, nested := strings.CutPrefix(route, "[]any ")
				addressOnly := (verb == "%p" && (nested || isPointer)) || (nested && isPointer)
				if !slices.Contains(noMarker, verb) && !addressOnly && !strings.Contains(got, marker) {
					t.Errorf("%s = %s, want the record's %s in it", route, got, marker)
				}
			}
		})
	}
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: recordFields, Types: []string{"time.Time"}}, reflect.TypeFor[*User](), reflect.TypeFor[*Session](),
			reflect.TypeFor[*Key](), reflect.TypeFor[*OneTimeToken]())
	})
}

// recordFields are the stored records' fields that hold text and no secret:
// names, labels, enums, identifiers, the shown parts of a key, and a
// passkey's user handle, which opens nothing.
var recordFields = []string{
	"access.User.Username", "access.User.Email", "access.User.DisplayName", "access.User.Role",
	"access.User.WebAuthnHandle", "access.OIDCIdentity.Issuer", "access.OIDCIdentity.Subject",
	"access.Session.ID", "access.Session.AuthMethod", "access.Session.Kind", "access.Session.UserAgent",
	"access.Session.Label", "access.Session.LastIP",
	"access.Key.KeyPrefix", "access.Key.KeySuffix", "access.Key.Label", "access.Key.Scopes", "access.Key.LineageIDs",
	"access.OneTimeToken.Purpose", "access.OneTimeToken.Role",
}

// logAttrs returns a LogValue group's attributes by key.
func logAttrs(t *testing.T, v slog.LogValuer) map[string]any {
	t.Helper()
	got := make(map[string]any)
	for _, a := range v.LogValue().Group() {
		if _, dup := got[a.Key]; dup {
			t.Fatalf("LogValue() repeats the key %q", a.Key)
		}
		got[a.Key] = a.Value.Any()
	}
	return got
}

func TestRecordLogValue(t *testing.T) {
	t.Parallel()
	at := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		v    slog.LogValuer
		want map[string]any
		name string
	}{
		{
			name: "User linked",
			v: User{
				ID: 5, Username: "alice", Role: RoleAdmin, PasswordHash: NewHash("h"),
				WebAuthnHandle: []byte{1}, OIDC: OIDCIdentity{Issuer: "https://idp.example", Subject: "s"},
			},
			want: map[string]any{
				"id": int64(5), "username": "alice", "role": "admin",
				"has_password": true, "has_webauthn_handle": true, "has_oidc": true,
			},
		},
		{
			name: "User bare",
			v:    User{ID: 6, Username: "bob", Role: RoleUser},
			want: map[string]any{
				"id": int64(6), "username": "bob", "role": "user",
				"has_password": false, "has_webauthn_handle": false, "has_oidc": false,
			},
		},
		{
			name: "Session",
			v: Session{
				ID: "sid", UserID: 5, AuthMethod: MethodPasskey, Kind: SessionRecovery, IssuedByKey: 8,
				IdleCap: 30 * time.Minute, AbsoluteCap: 12 * time.Hour,
				CreatedAt: at, LastActivity: at.Add(time.Minute), AuthTime: at.Add(2 * time.Minute), TokenHash: NewHash("h"),
			},
			want: map[string]any{
				"id": "sid", "user_id": int64(5), "auth_method": "passkey", "kind": "recovery", "issued_by_key": int64(8),
				"created_at": at, "last_activity": at.Add(time.Minute), "auth_time": at.Add(2 * time.Minute),
			},
		},
		{
			name: "Key",
			v:    Key{ID: 3, UserID: 5, KeyPrefix: "pfx", KeySuffix: "sfx", Scopes: []string{"read", "write"}, KeyHash: NewHash("h")},
			want: map[string]any{
				"id": int64(3), "user_id": int64(5), "prefix": "pfx", "suffix": "sfx", "scopes": []string{"read", "write"},
			},
		},
		{
			name: "OneTimeToken",
			v:    OneTimeToken{Purpose: PurposeRecovery, Subject: 5, IssuedByKey: 3, ExpiresAt: at, Hash: NewHash("h")},
			want: map[string]any{
				"purpose": "recovery", "subject": int64(5), "issued_by_key": int64(3), "expires_at": at,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := logAttrs(t, tc.v); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("LogValue() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewOneTimeToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	plain, rec := NewOneTimeToken(PurposeRecovery, 9, time.Hour, now)
	raw, err := hex.DecodeString(plain.Reveal())
	if err != nil || len(raw) != 32 {
		t.Fatalf("plaintext %q decodes to %d bytes (err %v), want 32", plain.Reveal(), len(raw), err)
	}
	if got, want := rec.Hash.Reveal(), HexSHA256(plain.Reveal()); got != want {
		t.Errorf("Hash = %s, want HexSHA256(plaintext) = %s", got, want)
	}
	want := OneTimeToken{
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), Hash: NewHash(HexSHA256(plain.Reveal())),
		Purpose: PurposeRecovery, Subject: 9,
	}
	if !reflect.DeepEqual(rec, want) {
		t.Errorf("record = %+v, want %+v", rec, want)
	}
	if again, _ := NewOneTimeToken(PurposeRecovery, 9, time.Hour, now); again.Reveal() == plain.Reveal() {
		t.Error("two tokens share a plaintext")
	}
}
