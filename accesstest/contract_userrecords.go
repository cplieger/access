package accesstest

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// userRecords: rule 24, the per-user records.
func (c *contract) userRecords(t *testing.T) {
	t.Run("totp", func(t *testing.T) { checkPerUser(t, c.store(t), totpKind) })
	t.Run("recovery_code", func(t *testing.T) { checkPerUser(t, c.store(t), recoveryKind) })
	t.Run("temporary_password", func(t *testing.T) { checkPerUser(t, c.store(t), temporaryKind) })
	t.Run("list_totp", c.listTOTP)
}

// perUser is one record type a user holds at most one of.
type perUser[T any] struct {
	version func(userID int64, n int) T // a distinct record of userID for each n
	get     func(ctx context.Context, s account.Store, userID int64) (T, bool, error)
	set     func(ctx context.Context, s account.Store, rec T) error
	del     func(ctx context.Context, s account.Store, userID int64) error
}

var totpKind = perUser[access.TOTP]{
	version: newTOTP,
	get: func(ctx context.Context, s account.Store, id int64) (access.TOTP, bool, error) {
		return s.TOTPByUserID(ctx, id)
	},
	set: func(ctx context.Context, s account.Store, r access.TOTP) error { return s.SetTOTP(ctx, r) },
	del: func(ctx context.Context, s account.Store, id int64) error { return s.DeleteTOTP(ctx, id) },
}

var recoveryKind = perUser[access.RecoveryCode]{
	version: newRecoveryCode,
	get: func(ctx context.Context, s account.Store, id int64) (access.RecoveryCode, bool, error) {
		return s.RecoveryCodeByUserID(ctx, id)
	},
	set: func(ctx context.Context, s account.Store, r access.RecoveryCode) error {
		return s.SetRecoveryCode(ctx, r)
	},
	del: func(ctx context.Context, s account.Store, id int64) error { return s.DeleteRecoveryCode(ctx, id) },
}

var temporaryKind = perUser[access.TemporaryPassword]{
	version: newTemporaryPassword,
	get: func(ctx context.Context, s account.Store, id int64) (access.TemporaryPassword, bool, error) {
		return s.TemporaryPasswordByUserID(ctx, id)
	},
	set: func(ctx context.Context, s account.Store, r access.TemporaryPassword) error {
		return s.SetTemporaryPassword(ctx, r)
	},
	del: func(ctx context.Context, s account.Store, id int64) error { return s.DeleteTemporaryPassword(ctx, id) },
}

func newTOTP(userID int64, n int) access.TOTP {
	return access.TOTP{CreatedAt: epoch.Add(time.Duration(n) * time.Minute), Sealed: fresh("sealed"), UserID: userID, LastStep: int64(60_000_000 + n)}
}

func newRecoveryCode(userID int64, n int) access.RecoveryCode {
	return access.RecoveryCode{CreatedAt: epoch.Add(time.Duration(n) * time.Minute), Hash: access.NewHash(fresh("recovery")), UserID: userID}
}

func newTemporaryPassword(userID int64, n int) access.TemporaryPassword {
	at := epoch.Add(time.Duration(n) * time.Minute)
	return access.TemporaryPassword{
		CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), Hash: access.NewHash(fresh("temporary")),
		UserID: userID, IssuedByUser: int64(100 + n), IssuedByKey: int64(200 + n), Dormant: n%2 == 1,
	}
}

// checkPerUser: one record per user, written whole over the last, read by
// its user alone, and deleted idempotently.
func checkPerUser[T any](t *testing.T, s account.Store, k perUser[T]) {
	ctx := t.Context()
	u, other := mustUser(t, s, "holder"), mustUser(t, s, "bystander")
	kept := k.version(other.ID, 9)
	check(t, "set the bystander's record", k.set(ctx, s, kept))
	expect := func(when string, id int64, want *T) {
		t.Helper()
		got, found, err := k.get(ctx, s, id)
		switch {
		case err != nil:
			t.Errorf("%s: read = %v", when, err)
		case want == nil && (found || !reflect.ValueOf(got).IsZero()):
			t.Errorf("%s: read = (found %t, zero %t), want nothing", when, found, reflect.ValueOf(got).IsZero())
		case want != nil && !found:
			t.Errorf("%s: read found nothing, want the record", when)
		case want != nil:
			if path := firstDiff(reflect.ValueOf(*want), reflect.ValueOf(got), reflect.TypeFor[T]().Name()); path != "" {
				t.Errorf("%s: %s does not read back as written", when, path)
			}
		}
	}
	expect("before any write", u.ID, nil)
	first, second := k.version(u.ID, 1), k.version(u.ID, 2)
	check(t, "first set", k.set(ctx, s, first))
	expect("after the first set", u.ID, &first)
	check(t, "second set", k.set(ctx, s, second))
	expect("after a second set over the first", u.ID, &second)
	expect("the bystander after the holder's writes", other.ID, &kept)
	check(t, "delete", k.del(ctx, s, u.ID))
	expect("after delete", u.ID, nil)
	expect("the bystander after the holder's delete", other.ID, &kept)
	if err := k.del(ctx, s, u.ID); err != nil {
		t.Errorf("a second delete = %v, want nil", err)
	}
	if err := k.del(ctx, s, 4242); err != nil {
		t.Errorf("delete for a user with no record = %v, want nil", err)
	}
}

// listTOTP: ListTOTP pages by UserID, so ResealTOTP's walk meets every record
// once.
func (c *contract) listTOTP(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	users := make([]*access.User, 6)
	for i := range users {
		users[i] = mustUser(t, s, fresh("list"))
	}
	written := map[int64]access.TOTP{}
	for i, u := range []*access.User{users[2], users[0], users[4], users[1], users[3]} {
		rec := newTOTP(u.ID, i)
		check(t, "SetTOTP", s.SetTOTP(ctx, rec))
		written[u.ID] = rec
	}
	check(t, "DeleteTOTP", s.DeleteTOTP(ctx, users[3].ID))
	delete(written, users[3].ID)
	want := []int64{users[0].ID, users[1].ID, users[2].ID, users[4].ID}
	all := walkTOTP(t, s, 2, len(want)+2)
	walked := make([]int64, 0, len(all))
	for _, rec := range all {
		walked = append(walked, rec.UserID)
		if w, ok := written[rec.UserID]; !ok || firstDiff(reflect.ValueOf(w), reflect.ValueOf(rec), "TOTP") != "" {
			t.Errorf("ListTOTP returned user %d's record unlike the one written", rec.UserID)
		}
	}
	if !slices.Equal(walked, want) {
		t.Errorf("a walk in pages of 2 met users %v, want %v", walked, want)
	}
	if page, err := s.ListTOTP(ctx, users[4].ID, 2); err != nil || len(page) != 0 {
		t.Errorf("ListTOTP after the last record = (%d records, %v), want none", len(page), err)
	}
}

// walkTOTP reads every TOTP record in pages of size, passing each page's
// last UserID, for at most pages pages; a page over size fails the test.
func walkTOTP(t *testing.T, s account.Store, size, pages int) []access.TOTP {
	t.Helper()
	var all []access.TOTP
	after := int64(0)
	for range pages {
		page, err := s.ListTOTP(t.Context(), after, size)
		check(t, "ListTOTP", err)
		if len(page) > size {
			t.Fatalf("ListTOTP(%d, %d) returned %d records", after, size, len(page))
		}
		all = append(all, page...)
		if len(page) < size {
			break
		}
		after = page[len(page)-1].UserID
	}
	return all
}

// waitingUsers: rule 25, the waiting accounts oldest first.
func (c *contract) waitingUsers(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	waiting := func(name string, created time.Time) *access.User {
		u := newUser(name)
		u.CreatedAt, u.Enabled, u.WaitingApproval = created, false, true
		check(t, "CreateUser", s.CreateUser(ctx, u))
		return u
	}
	newest := waiting("newest", epoch.Add(2*time.Hour))
	mustUser(t, s, "enabled")
	disabled := newUser("disabled")
	disabled.Enabled = false
	check(t, "CreateUser", s.CreateUser(ctx, disabled))
	tieFirst := waiting("tie-first", epoch.Add(time.Hour))
	tieSecond := waiting("tie-second", epoch.Add(time.Hour))
	ids := func(limit int) []int64 {
		t.Helper()
		us, err := s.UsersWaiting(ctx, limit)
		check(t, "UsersWaiting", err)
		out := make([]int64, 0, len(us))
		for i := range us {
			if u := &us[i]; !u.WaitingApproval || u.Enabled {
				t.Errorf("UsersWaiting returned user %d with WaitingApproval %t, Enabled %t", u.ID, u.WaitingApproval, u.Enabled)
			}
			out = append(out, us[i].ID)
		}
		return out
	}
	if got, want := ids(10), []int64{tieFirst.ID, tieSecond.ID, newest.ID}; !slices.Equal(got, want) {
		t.Errorf("UsersWaiting(10) = %v, want oldest CreatedAt first, ties by ID: %v", got, want)
	}
	if got, want := ids(2), []int64{tieFirst.ID, tieSecond.ID}; !slices.Equal(got, want) {
		t.Errorf("UsersWaiting(2) = %v, want %v", got, want)
	}
	approved := tieFirst.Clone()
	approved.Enabled, approved.WaitingApproval = true, false
	check(t, "UpdateUser", s.UpdateUser(ctx, approved))
	if got, want := ids(10), []int64{tieSecond.ID, newest.ID}; !slices.Equal(got, want) {
		t.Errorf("UsersWaiting after an approval = %v, want %v", got, want)
	}
}

// ssoMode: rule 26, the stored SSO mode and its set bit.
func (c *contract) ssoMode(t *testing.T) {
	read := func(t *testing.T, s account.SSOModeStore, when string, want account.SSOMode, wantSet bool) {
		t.Helper()
		mode, set, err := s.SSOMode(t.Context())
		if err != nil || mode != want || set != wantSet {
			t.Errorf("%s: SSOMode = (%d, set %t, %v), want (%d, set %t, nil)", when, mode, set, err, want, wantSet)
		}
	}
	t.Run("unset", func(t *testing.T) {
		read(t, c.store(t), "a new store", account.SSOAlongside, false)
	})
	t.Run("set_alongside", func(t *testing.T) {
		s := c.store(t)
		check(t, "SetSSOMode", s.SetSSOMode(t.Context(), account.SSOAlongside))
		read(t, s, "after SetSSOMode(SSOAlongside)", account.SSOAlongside, true)
	})
	t.Run("each_mode", func(t *testing.T) {
		s := c.store(t)
		for _, m := range []account.SSOMode{account.SSOOnly, account.SSOForLinked, account.SSOAlongside} {
			check(t, "SetSSOMode", s.SetSSOMode(t.Context(), m))
			read(t, s, "after a SetSSOMode", m, true)
		}
	})
	t.Run("rolls_back", func(t *testing.T) {
		s := c.store(t)
		err := s.Update(t.Context(), func(tx account.Tx) error {
			if err := tx.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
				return err
			}
			read(t, tx, "inside the Update that set it", account.SSOOnly, true)
			return errContract
		})
		if !errors.Is(err, errContract) {
			t.Fatalf("Update = %v, want the callback's error", err)
		}
		read(t, s, "after a rolled-back SetSSOMode", account.SSOAlongside, false)
	})
	t.Run("reopen", func(t *testing.T) {
		c.needReopen(t, "rule 26 (the mode and its set bit across a reopen)")
		for _, m := range []account.SSOMode{account.SSOAlongside, account.SSOForLinked} {
			s := c.store(t)
			check(t, "SetSSOMode", s.SetSSOMode(t.Context(), m))
			read(t, c.reopen(t, "rule 26", s), "after a reopen", m, true)
		}
	})
}
