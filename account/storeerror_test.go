package account_test

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// TestStoreErrorAfterApply runs every writing operation over an Update that
// publishes its writes and then errs (rule 10): the operation answers
// ErrAuthBackend, emits nothing, and makes no write of its own after it.
func TestStoreErrorAfterApply(t *testing.T) {
	t.Parallel()
	for _, op := range operations() {
		if op.readOnly || op.direct {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			mark := len(w.events.all())
			w.fs.resetRecord()
			w.fs.failAfterApply()
			if err := call.run(t.Context()); !errors.Is(err, access.ErrAuthBackend) {
				t.Errorf("%s over an Update that errs after applying = %v, want ErrAuthBackend", op.name, err)
			}
			if n := len(w.events.all()) - mark; n != 0 {
				t.Errorf("%s emitted %d events", op.name, n)
			}
			failed := 0
			for i, c := range w.fs.recorded() {
				if c.name == "Update" {
					if failed != 0 {
						t.Errorf("%s ran Update %d after the failed one", op.name, c.update)
					}
					failed = c.update
					continue
				}
				if failed != 0 && c.update != failed && isWrite(c.name) {
					t.Errorf("%s made write %s (call %d) after the failed Update", op.name, c.name, i)
				}
			}
			if failed == 0 {
				t.Errorf("%s ran no Update", op.name)
			}
		})
	}
}

// isWrite reports whether a recorded store call writes.
func isWrite(name string) bool {
	switch name {
	case "UserByID", "UserByUsername", "UserByOIDC", "UserByWebAuthnHandle", "ListUsers", "UserCount",
		"SessionByHash", "SessionsByUserID", "PasskeysByUserID", "APIKeyByHash", "ListAPIKeysByUserID",
		"ListAPIKeys", "OneTimeTokenByHash", "LiveOneTimeTokens", "ListKeyAttributions", "AuthFailure",
		"UnreportedLocks":
		return false
	}
	return true
}

// storeRefusals is, per operation and per store write, the store sentinel
// the operation answers as its own refusal: a store contract error that no
// read in the same Update rules out.
var storeRefusals = map[string]map[string]error{
	"SetupWithPassword":     {"CreateInitialUser": account.ErrSetupComplete},
	"SetupPasskeyFinish":    {"CreateInitialUser": account.ErrSetupComplete},
	"AcceptInvitePassword":  {"CreateUser": account.ErrUsernameTaken},
	"CreateUser":            {"CreateUser": account.ErrUsernameTaken},
	"RenamePasskey":         {"RenamePasskey": account.ErrNotFound},
	"RenameSession":         {"UpdateSessionLabel": account.ErrNotFound},
	"RevokeSession":         {"DeleteSession": account.ErrNotFound},
	"PasskeyRegisterFinish": {"CreatePasskey": account.ErrDuplicateCredential},
	"RecoverPasskeyFinish":  {"CreatePasskey": account.ErrDuplicateCredential},
}

var storeSentinels = []error{account.ErrNotFound, account.ErrUsernameTaken, account.ErrOIDCIdentityTaken, account.ErrDuplicateCredential, account.ErrSetupComplete}

// TestStoreRefusalsDeclared has each write of every writing operation
// return each store sentinel in turn: the operation answers the one
// storeRefusals declares for that write as it is, and any other as
// ErrAuthBackend, never matching the sentinel, so a store that breaks its
// contract cannot put a refusal in the answer that the operation never
// gives.
func TestStoreRefusalsDeclared(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	exercised := map[string]map[string]bool{}
	for _, op := range operations() {
		if op.readOnly {
			continue
		}
		// run makes op's call with write returning refusal, or with no fault
		// when write is "", and returns its answer and the writes it made. A
		// panic comes back as the answer, so an operation that swallows the
		// fault and then dereferences what the write never made fails its own
		// subtest instead of killing the test binary.
		run := func(t *testing.T, write string, refusal error) (writes []string, err error) {
			t.Helper()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			w.fs.resetRecord()
			if write != "" {
				w.fs.refuseCall(write, refusal)
			}
			err = func() (err error) {
				defer func() {
					if p := recover(); p != nil {
						err = fmt.Errorf("panic: %v", p)
					}
				}()
				return call.run(t.Context())
			}()
			for _, c := range w.fs.recorded() {
				if c.name != "Update" && isWrite(c.name) && !slices.Contains(writes, c.name) {
					writes = append(writes, c.name)
				}
			}
			return writes, err
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			writes, err := run(t, "", nil)
			if err != nil {
				t.Fatalf("%s with no fault = %v", op.name, err)
			}
			for _, write := range writes {
				for _, sentinel := range storeSentinels {
					_, err := run(t, write, sentinel)
					declared := storeRefusals[op.name][write] == sentinel
					switch {
					case declared:
						mu.Lock()
						if exercised[op.name] == nil {
							exercised[op.name] = map[string]bool{}
						}
						exercised[op.name][write] = true
						mu.Unlock()
						if !errors.Is(err, sentinel) || errors.Is(err, access.ErrAuthBackend) {
							t.Errorf("%s returning %v = %v, want it as it is", write, sentinel, err)
						}
					case errors.Is(err, sentinel):
						t.Errorf("%s returning %v = %v, want no match", write, sentinel, err)
					case !errors.Is(err, access.ErrAuthBackend):
						t.Errorf("%s returning %v = %v, want ErrAuthBackend", write, sentinel, err)
					}
				}
			}
		})
	}
	t.Cleanup(func() {
		for name, writes := range storeRefusals {
			for write := range writes {
				if !exercised[name][write] {
					t.Errorf("storeRefusals[%s][%s] names a write the operation does not make", name, write)
				}
			}
		}
	})
}
