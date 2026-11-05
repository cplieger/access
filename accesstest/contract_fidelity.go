package accesstest

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

var (
	hashType = reflect.TypeFor[access.Hash]()
	timeType = reflect.TypeFor[time.Time]()
)

// fidelity: rule 20.
func (c *contract) fidelity(t *testing.T) {
	t.Run("write_read", func(t *testing.T) {
		s := c.store(t)
		checkFidelity(t, writeFilled(t, s), s)
	})
	t.Run("reopen", func(t *testing.T) {
		c.needReopen(t, "rule 20 (fidelity across a reopen)")
		s := c.store(t)
		written := writeFilled(t, s)
		checkFidelity(t, written, c.reopen(t, "rule 20", s))
	})
}

// filler sets every exported field to a distinct non-zero value.
type filler struct {
	t *testing.T
	n int
}

func (f *filler) next() int {
	f.n++
	return f.n
}

// fill fills v, a settable value at path; a kind it cannot fill fails the
// test, so a field a later version adds is never skipped.
func (f *filler) fill(v reflect.Value, path string) {
	switch v.Type() {
	case hashType:
		v.Set(reflect.ValueOf(access.NewHash(fmt.Sprintf("fidelity-%d-%d", fixtureSeq.Add(1), f.next()))))
		return
	case timeType:
		v.Set(reflect.ValueOf(epoch.Add(time.Duration(f.next()) * 1001 * time.Millisecond)))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		f.fillStruct(v, path)
	case reflect.String:
		v.SetString(fmt.Sprintf("%s-%d", path, f.next()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.Set(reflect.ValueOf(f.next()).Convert(v.Type()))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Slice:
		f.fillSlice(v, path)
	case reflect.Pointer:
		e := reflect.New(v.Type().Elem())
		f.fill(e.Elem(), path)
		v.Set(e)
	default:
		f.t.Fatalf("rule 20: the filler cannot fill %s, of kind %s", path, v.Kind())
	}
}

func (f *filler) fillStruct(v reflect.Value, path string) {
	for i := range v.NumField() {
		if sf := v.Type().Field(i); sf.IsExported() {
			f.fill(v.Field(i), path+"."+sf.Name)
		}
	}
}

func (f *filler) fillSlice(v reflect.Value, path string) {
	s := reflect.MakeSlice(v.Type(), 2, 2)
	for i := range 2 {
		f.fill(s.Index(i), fmt.Sprintf("%s[%d]", path, i))
	}
	v.Set(s)
}

func filled[T any](f *filler) *T {
	v := new(T)
	f.fill(reflect.ValueOf(v).Elem(), reflect.TypeFor[T]().Name())
	return v
}

// fidelityRecords holds one written record of each type, as read back must
// show it.
type fidelityRecords struct {
	user        *access.User
	session     *access.Session
	passkey     *access.PasskeyCredential
	key         *access.Key
	token       *access.OneTimeToken
	attribution *access.KeyAttribution
	failure     *account.FailureCount
}

// writeFilled writes one filled record of each type through its SPI write
// and returns each as read back must show it: the store's assigned IDs and
// the LineageIDs append included.
func writeFilled(t *testing.T, s account.Store) fidelityRecords {
	t.Helper()
	ctx, f := t.Context(), &filler{t: t}
	var r fidelityRecords
	r.user = filled[access.User](f)
	check(t, "CreateUser", s.CreateUser(ctx, r.user))
	r.key = filled[access.Key](f)
	r.key.UserID = r.user.ID
	want := slices.Clone(r.key.LineageIDs)
	check(t, "CreateAPIKey", s.CreateAPIKey(ctx, r.key))
	want = append(want, r.key.ID)
	r.key.LineageIDs = want
	r.session = filled[access.Session](f)
	r.session.UserID, r.session.IssuedByKey = r.user.ID, r.key.ID
	check(t, "CreateSession", s.CreateSession(ctx, r.session))
	r.passkey = filled[access.PasskeyCredential](f)
	r.passkey.UserID, r.passkey.RawFlags = r.user.ID, 0x1D
	r.passkey.UserPresent, r.passkey.UserVerified, r.passkey.BackupEligible, r.passkey.BackupState = access.DecodePasskeyFlags(0x1D)
	check(t, "CreatePasskey", s.CreatePasskey(ctx, r.passkey))
	r.token = filled[access.OneTimeToken](f)
	r.token.Subject, r.token.IssuedByKey = r.user.ID, r.key.ID
	check(t, "CreateOneTimeToken", s.CreateOneTimeToken(ctx, *r.token))
	r.attribution = filled[access.KeyAttribution](f)
	r.attribution.UserID, r.attribution.KeyLineage = r.user.ID, slices.Clone(r.key.LineageIDs)
	check(t, "CreateKeyAttribution", s.CreateKeyAttribution(ctx, r.attribution))
	r.failure = filled[account.FailureCount](f)
	check(t, "PutAuthFailure", s.PutAuthFailure(ctx, *r.failure))
	return r
}

func check(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// checkFidelity reads each record of w back from s through its by-key read
// and fails on the first field that differs, by its path.
func checkFidelity(t *testing.T, w fidelityRecords, s account.Store) {
	t.Helper()
	ctx := t.Context()
	user, _, err := s.UserByID(ctx, w.user.ID)
	check(t, "UserByID", err)
	session, _, err := s.SessionByHash(ctx, w.session.TokenHash)
	check(t, opSessionByHash, err)
	key, _, err := s.APIKeyByHash(ctx, w.key.KeyHash)
	check(t, "APIKeyByHash", err)
	token, _, err := s.OneTimeTokenByHash(ctx, w.token.Hash)
	check(t, "OneTimeTokenByHash", err)
	failure, _, err := s.AuthFailure(ctx, w.failure.FailureRef)
	check(t, "AuthFailure", err)
	passkeys, err := s.PasskeysByUserID(ctx, w.user.ID)
	check(t, "PasskeysByUserID", err)
	attributions, err := s.ListKeyAttributions(ctx)
	check(t, "ListKeyAttributions", err)
	pairs := []struct {
		want, got any
	}{
		{w.user, user},
		{w.session, session},
		{w.key, key},
		{w.token, &token},
		{w.failure, &failure},
		{w.passkey, byID(passkeys, w.passkey.ID, func(p access.PasskeyCredential) int64 { return p.ID })},
		{w.attribution, byID(attributions, w.attribution.ID, func(a access.KeyAttribution) int64 { return a.ID })},
	}
	for _, p := range pairs {
		want, got := reflect.ValueOf(p.want), reflect.ValueOf(p.got)
		if path := firstDiff(want.Elem(), got, want.Elem().Type().Name()); path != "" {
			t.Errorf("rule 20: %s does not read back as written", path)
		}
	}
}

func byID[T any](xs []T, id int64, idOf func(T) int64) *T {
	for i := range xs {
		if idOf(xs[i]) == id {
			return &xs[i]
		}
	}
	return nil
}

// firstDiff returns the path of the first field where got, a pointer that
// may be nil, differs from want, or "" when none does.
func firstDiff(want, got reflect.Value, path string) string {
	if got.Kind() == reflect.Pointer {
		if got.IsNil() {
			return path
		}
		got = got.Elem()
	}
	switch want.Type() {
	case hashType:
		w, _ := reflect.TypeAssert[access.Hash](want)
		g, _ := reflect.TypeAssert[access.Hash](got)
		return diffIf(!w.Equal(g), path)
	case timeType:
		w, _ := reflect.TypeAssert[time.Time](want)
		g, _ := reflect.TypeAssert[time.Time](got)
		return diffIf(!w.Equal(g), path)
	}
	switch want.Kind() {
	case reflect.Struct:
		return structDiff(want, got, path)
	case reflect.Slice:
		return sliceDiff(want, got, path)
	case reflect.Pointer:
		return firstDiff(want.Elem(), got, path)
	default:
		return diffIf(!want.Equal(got), path)
	}
}

func structDiff(want, got reflect.Value, path string) string {
	for i := range want.NumField() {
		if sf := want.Type().Field(i); sf.IsExported() {
			if d := firstDiff(want.Field(i), got.Field(i), path+"."+sf.Name); d != "" {
				return d
			}
		}
	}
	return ""
}

func sliceDiff(want, got reflect.Value, path string) string {
	if want.Len() != got.Len() {
		return path
	}
	for i := range want.Len() {
		if d := firstDiff(want.Index(i), got.Index(i), fmt.Sprintf("%s[%d]", path, i)); d != "" {
			return d
		}
	}
	return ""
}

func diffIf(differs bool, path string) string {
	if differs {
		return path
	}
	return ""
}
