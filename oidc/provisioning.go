package oidc

import (
	"fmt"
	"slices"

	"github.com/cplieger/access"
)

// Provisioning gates just-in-time account creation from an OIDC sign-in.
// The zero value is off. An app supplies it as data through
// account.Rules.Provisioning.
type Provisioning struct {
	// Claim names the claim to check, e.g. "groups"; empty admits any
	// authenticated identity.
	Claim string
	// Role is the created account's role; empty means access.RoleUser.
	Role access.Role
	// AllowedValues must share at least one value with Claim.
	AllowedValues []string
	Enabled       bool
}

// Validate refuses a Claim without AllowedValues, AllowedValues without a
// Claim, and a Role other than "", RoleUser or RoleAdmin, each matching
// ErrConfigInvalid.
func (p Provisioning) Validate() error {
	switch {
	case p.Claim != "" && len(p.AllowedValues) == 0:
		return fmt.Errorf("%w: Provisioning.Claim needs AllowedValues", ErrConfigInvalid)
	case p.Claim == "" && len(p.AllowedValues) != 0:
		return fmt.Errorf("%w: Provisioning.AllowedValues needs a Claim", ErrConfigInvalid)
	case p.Role != "" && p.Role != access.RoleUser && p.Role != access.RoleAdmin:
		return fmt.Errorf("%w: Provisioning.Role %q is not a role", ErrConfigInvalid, p.Role)
	}
	return nil
}

// Admit reports whether c may provision an account: ErrProvisioningDisabled
// when p is off, Validate's error for an invalid p, and ErrNotAdmitted when
// Claim is set and c's claim, a string or an array of strings, holds none of
// AllowedValues.
func (p Provisioning) Admit(c Claims) error { //nolint:gocritic // hugeParam: Claims is plain data, passed as the caller holds it
	if !p.Enabled {
		return ErrProvisioningDisabled
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Claim == "" {
		return nil
	}
	values, ok := c.Strings(p.Claim)
	if ok && slices.ContainsFunc(values, func(v string) bool { return slices.Contains(p.AllowedValues, v) }) {
		return nil
	}
	return ErrNotAdmitted
}
