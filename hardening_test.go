package access

import "testing"

// --- Role Interface Tests ---

func TestRoleInterface_SessionReader(t *testing.T) {
	t.Parallel()
	var _ SessionReader = newFakeSessionStore()
}

func TestRoleInterface_UserReader(t *testing.T) {
	t.Parallel()
	var _ UserReader = newFakeSessionStore()
}

func TestRoleInterface_APIKeyReader(t *testing.T) {
	t.Parallel()
	var _ APIKeyReader = newFakeSessionStore()
}

func TestRoleInterface_AuthenticatorStore(t *testing.T) {
	t.Parallel()
	var _ AuthenticatorStore = newFakeSessionStore()
}
