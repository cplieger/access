package accesstest

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// recordVariants are the broken stores for rules 24 to 26 and the new
// record fields of rules 5 and 20.
var recordVariants = map[string]variant{
	"totp-delete-keeps-record": {
		make:  memVariant(func(m *MemStore) account.Store { return &totpDeleteNoopStore{m} }),
		fails: []string{"rule_24_user_records/totp", "rule_24_user_records/list_totp"}, only: true,
	},
	"recovery-set-keeps-first": {
		make:  memVariant(func(m *MemStore) account.Store { return &recoveryKeepsFirstStore{m} }),
		fails: []string{"rule_24_user_records/recovery_code"}, only: true,
	},
	"temporary-delete-clears-all": {
		make:  memVariant(func(m *MemStore) account.Store { return &temporaryDeleteAllStore{m} }),
		fails: []string{"rule_24_user_records/temporary_password"}, only: true,
	},
	"list-totp-includes-after": {
		make:  memVariant(func(m *MemStore) account.Store { return &listTOTPInclusiveStore{m} }),
		fails: []string{"rule_24_user_records/list_totp"}, only: true,
	},
	"list-totp-ignores-limit": {
		make:  memVariant(func(m *MemStore) account.Store { return &listTOTPUnlimitedStore{m} }),
		fails: []string{"rule_24_user_records/list_totp"}, only: true,
	},
	"user-delete-keeps-records": {
		make:  memVariant(func(m *MemStore) account.Store { return &userKeepsRecordsStore{m} }),
		fails: []string{"rule_05_atomicity/delete_user_cascade"}, only: true,
	},
	"drops-totp-last-step": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropLastStepStore{m} }),
		fails: []string{"rule_20_fidelity/write_read", "rule_24_user_records/totp"}, mention: []string{"TOTP.LastStep"},
	},
	"drops-temporary-dormant": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropDormantStore{m} }),
		fails: []string{"rule_20_fidelity/write_read", "rule_24_user_records/temporary_password"}, mention: []string{"TemporaryPassword.Dormant"},
	},
	"drops-user-owner": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropOwnerStore{m} }),
		fails: []string{"rule_20_fidelity/write_read"}, mention: []string{"User.Owner"}, only: true,
	},
	"drops-waiting-approval": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropWaitingStore{m} }),
		fails: []string{"rule_20_fidelity/write_read", "rule_25_waiting_users"}, mention: []string{"User.WaitingApproval"},
	},
	"waiting-by-id": {
		make:  memVariant(func(m *MemStore) account.Store { return &waitingByIDStore{m} }),
		fails: []string{"rule_25_waiting_users"}, only: true,
	},
	"sso-set-from-mode": {
		make:  memVariant(func(m *MemStore) account.Store { return &ssoSetFromModeStore{m} }),
		fails: []string{"rule_26_sso_mode/set_alongside", "rule_26_sso_mode/each_mode"}, only: true,
	},
	"sso-set-lost-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = dropSSOSet }),
		fails: []string{"rule_26_sso_mode/reopen"}, only: true,
	},
}

// totpDeleteNoopStore never deletes a TOTP record.
type totpDeleteNoopStore struct{ *MemStore }

func (*totpDeleteNoopStore) DeleteTOTP(context.Context, int64) error { return nil }

// recoveryKeepsFirstStore writes a recovery code only where none is held.
type recoveryKeepsFirstStore struct{ *MemStore }

func (s *recoveryKeepsFirstStore) SetRecoveryCode(ctx context.Context, rec access.RecoveryCode) error {
	if _, found, err := s.RecoveryCodeByUserID(ctx, rec.UserID); found || err != nil {
		return err
	}
	return s.MemStore.SetRecoveryCode(ctx, rec)
}

// temporaryDeleteAllStore deletes every user's temporary password.
type temporaryDeleteAllStore struct{ *MemStore }

func (s *temporaryDeleteAllStore) DeleteTemporaryPassword(context.Context, int64) error {
	return edit(s.MemStore, func(st *state) { clear(st.temporary) })
}

// listTOTPInclusiveStore lists from afterUserID itself.
type listTOTPInclusiveStore struct{ *MemStore }

func (s *listTOTPInclusiveStore) ListTOTP(ctx context.Context, after int64, limit int) ([]access.TOTP, error) {
	return s.MemStore.ListTOTP(ctx, after-1, limit)
}

// listTOTPUnlimitedStore lists every record above afterUserID.
type listTOTPUnlimitedStore struct{ *MemStore }

func (s *listTOTPUnlimitedStore) ListTOTP(ctx context.Context, after int64, _ int) ([]access.TOTP, error) {
	return s.MemStore.ListTOTP(ctx, after, 1<<30)
}

// userKeepsRecordsStore leaves a deleted user's three per-user records.
type userKeepsRecordsStore struct{ *MemStore }

func (s *userKeepsRecordsStore) DeleteUser(ctx context.Context, id int64) error {
	return s.write(func(tx *memTx) (bool, error) {
		totp, recovery, temporary := maps.Clone(tx.s.totp), maps.Clone(tx.s.recovery), maps.Clone(tx.s.temporary)
		err := tx.DeleteUser(ctx, id)
		tx.s.totp, tx.s.recovery, tx.s.temporary = totp, recovery, temporary
		return true, err
	})
}

// dropLastStepStore writes every TOTP record without its LastStep.
type dropLastStepStore struct{ *MemStore }

func (s *dropLastStepStore) SetTOTP(ctx context.Context, rec access.TOTP) error {
	rec.LastStep = 0
	return s.MemStore.SetTOTP(ctx, rec)
}

// dropDormantStore writes every temporary password without Dormant.
type dropDormantStore struct{ *MemStore }

func (s *dropDormantStore) SetTemporaryPassword(ctx context.Context, rec access.TemporaryPassword) error {
	rec.Dormant = false
	return s.MemStore.SetTemporaryPassword(ctx, rec)
}

// dropOwnerStore writes every user without Owner.
type dropOwnerStore struct{ *MemStore }

func (s *dropOwnerStore) CreateUser(ctx context.Context, u *access.User) error {
	cp := u.Clone()
	cp.Owner = false
	err := s.MemStore.CreateUser(ctx, cp)
	u.ID = cp.ID
	return err
}

// dropWaitingStore writes every user without WaitingApproval.
type dropWaitingStore struct{ *MemStore }

func (s *dropWaitingStore) CreateUser(ctx context.Context, u *access.User) error {
	cp := u.Clone()
	cp.WaitingApproval = false
	err := s.MemStore.CreateUser(ctx, cp)
	u.ID = cp.ID
	return err
}

// waitingByIDStore lists waiting users in ID order, ignoring CreatedAt.
type waitingByIDStore struct{ *MemStore }

func (s *waitingByIDStore) UsersWaiting(ctx context.Context, limit int) ([]access.User, error) {
	all, err := s.MemStore.UsersWaiting(ctx, 1<<30)
	slices.SortFunc(all, func(a, b access.User) int { return cmp.Compare(a.ID, b.ID) })
	return all[:min(limit, len(all))], err
}

// ssoSetFromModeStore keeps no set bit and reports any mode but the zero
// one as set.
type ssoSetFromModeStore struct{ *MemStore }

func (s *ssoSetFromModeStore) SSOMode(ctx context.Context) (account.SSOMode, bool, error) {
	mode, _, err := s.MemStore.SSOMode(ctx)
	return mode, mode != account.SSOAlongside, err
}

// dropSSOSet is a medium that never wrote the SSO mode's set bit to disk.
func dropSSOSet(committed *state) *state {
	s := committed.clone()
	s.ssoSet = false
	return s
}
