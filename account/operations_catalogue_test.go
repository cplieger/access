package account_test

import (
	"reflect"
	"testing"

	"github.com/cplieger/access/account"
)

// notOperations are *account.Service's exported methods that operations()
// does not list, each with why it is not an operation. A method listed here
// is in no test that ranges over operations(), so its reason must be true
// and its behaviour tested on its own.
var notOperations = map[string]string{
	"AdminScope":              "accessor of Config.AdminScope",
	"ManageUsersScope":        "accessor of Config.ManageUsersScope",
	"CreateKeysScope":         "accessor of Config.CreateKeysScope",
	"Authenticator":           "accessor of Config.Authenticator",
	"AdmitOIDC":               "per-request rate-limit admission returning the provider; reads no store (TestAdmitOIDC)",
	"AdmitOIDCSession":        "per-request admission returning the provider; reads no store (TestAdmitOIDCSession)",
	"RequireAdminScope":       "principal guard for accesshttp's key_scope class; reads no store",
	"RequireKeyPermission":    "principal guard for accesshttp's key_permission class; reads no store",
	"RequireRecentAuth":       "principal guard for accesshttp's recent_auth class; reads no store",
	"Shutdown":                "lifecycle: the call every operation's ErrServiceClosed answers to",
	"RevokeTransportMismatch": "the Authenticator's revoke callback; takes no Actor (TestRevokeTransportMismatch)",
	"AppendLog":               "appends through the caller's Tx inside the app's own transaction, asks no Policy and reads no Rules (TestAppendLog)",
	"Owner":                   "a single-user read of the store's owner, asking no Policy (TestServiceOwner)",
	"UsableMethods":           "reads through the caller's Tx inside the app's own transaction, whose store errors are the app's (TestUsableMethodsRefusals)",
}

func TestOperationsCatalogueCoversService(t *testing.T) {
	st := reflect.TypeFor[*account.Service]()
	methods := make(map[string]bool, st.NumMethod())
	for m := range st.Methods() {
		methods[m.Name] = true
	}
	rows := map[string]bool{}
	for _, op := range operations() {
		if rows[op.name] {
			t.Errorf("catalogue row %s is listed twice", op.name)
		}
		rows[op.name] = true
		if !methods[op.name] {
			t.Errorf("catalogue row %s names no exported *account.Service method", op.name)
		}
	}
	for name := range methods {
		_, skipped := notOperations[name]
		switch {
		case rows[name] && skipped:
			t.Errorf("%s is both a catalogue row and in notOperations", name)
		case !rows[name] && !skipped:
			t.Errorf("exported method %s is neither a catalogue row nor in notOperations", name)
		}
	}
	for name := range notOperations {
		if !methods[name] {
			t.Errorf("notOperations entry %s names no exported *account.Service method", name)
		}
	}
}
