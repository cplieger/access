package account

// SSOMode is how single sign-on sits beside local sign-in for a non-owner.
// The store holds it ([SSOModeStore]); owners are exempt under every mode.
// A store persists the number, so a value never changes meaning.
type SSOMode int

const (
	// SSOAlongside lets every user sign in by SSO or locally.
	SSOAlongside SSOMode = 0
	// SSOForLinked keeps a linked non-owner's local methods dormant.
	SSOForLinked SSOMode = 1
	// SSOOnly keeps every non-owner's local methods dormant.
	SSOOnly SSOMode = 2
)
