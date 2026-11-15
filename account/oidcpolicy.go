package account

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
)

var (
	// ErrNotAdmitted is an OIDC identity whose token fails
	// Rules.OIDCAdmission, at any intent.
	ErrNotAdmitted = errors.New("account: identity not admitted")
	// ErrProvisioningDisabled is a pending account creation that
	// Rules.Provisioning no longer allows.
	ErrProvisioningDisabled = errors.New("account: provisioning is disabled")
)

// OIDCAdmission gates every OIDC sign-in, link, invite acceptance and
// step-up on a claim the provider asserts. The zero value admits every
// identity.
type OIDCAdmission struct {
	// Claim names the claim to read, e.g. "groups": a string or an array
	// of strings. Any other shape, absent included, is not admitted.
	Claim string
	// AllowedValues admit a token whose Claim holds one of them, compared
	// exactly.
	AllowedValues []string
}

// Validate refuses a Claim without AllowedValues and AllowedValues without
// a Claim.
func (a OIDCAdmission) Validate() error {
	switch {
	case a.Claim != "" && len(a.AllowedValues) == 0:
		return errors.New("a Claim needs AllowedValues")
	case a.Claim == "" && len(a.AllowedValues) != 0:
		return errors.New("an AllowedValues list needs a Claim")
	}
	return nil
}

// admit is nil when a admits claims, else ErrNotAdmitted.
func (a OIDCAdmission) admit(claims oidc.Claims) error { //nolint:gocritic // hugeParam: Claims is plain data, passed as the caller holds it
	if a.Claim == "" {
		return nil
	}
	if values, ok := claims.Strings(a.Claim); ok && slices.ContainsFunc(values, func(v string) bool { return slices.Contains(a.AllowedValues, v) }) {
		return nil
	}
	return ErrNotAdmitted
}

// Provisioning creates an account at the first OIDC sign-in of an admitted
// identity with no linked account, in a multi-user app. The zero value is
// off. Rules.OIDCAdmission decides which identities it may create.
type Provisioning struct {
	// Role is a provisioned account's role when RoleClaim is empty or
	// holds none of AdminValues; empty means access.RoleUser.
	Role access.Role
	// RoleClaim names a claim, a string or an array of strings, whose
	// value in AdminValues makes the account an admin. It must be one the
	// provider asserts, never a profile field the user can edit.
	RoleClaim   string
	AdminValues []string
	Enabled     bool
	// SyncRole re-applies the RoleClaim mapping at each OIDC sign-in of a
	// linked non-owner, whether or not Enabled, while the claim is present
	// and readable; an in-app role change holds until the next sign-in.
	SyncRole bool
}

// Validate refuses a Role other than "", RoleUser or RoleAdmin, and
// AdminValues or SyncRole without a RoleClaim.
func (p Provisioning) Validate() error {
	switch {
	case p.Role != "" && p.Role != access.RoleUser && p.Role != access.RoleAdmin:
		return fmt.Errorf("role %q is not a role", p.Role)
	case p.RoleClaim == "" && len(p.AdminValues) != 0:
		return errors.New("an AdminValues list needs a RoleClaim")
	case p.RoleClaim == "" && p.SyncRole:
		return errors.New("a SyncRole needs a RoleClaim")
	}
	return nil
}

// role is the mapped role for claims. readable is false when RoleClaim is
// set but absent or of another shape: role is then the base Role, which a
// new account takes and a sync leaves unapplied.
func (p Provisioning) role(claims oidc.Claims) (role access.Role, readable bool) { //nolint:gocritic // hugeParam: as Validate, and Claims is plain data
	base := cmp.Or(p.Role, access.RoleUser)
	if p.RoleClaim == "" {
		return base, true
	}
	values, ok := claims.Strings(p.RoleClaim)
	if !ok {
		return base, false
	}
	if slices.ContainsFunc(values, func(v string) bool { return slices.Contains(p.AdminValues, v) }) {
		return access.RoleAdmin, true
	}
	return base, true
}

// syncs reports whether p's role sync applies to u: SyncRole on, and u an
// account the provider owns the role of, linked and not an owner.
func (p Provisioning) syncs(u *access.User) bool {
	return p.SyncRole && !u.OIDC.IsZero() && !u.Owner
}
