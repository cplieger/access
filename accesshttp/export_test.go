package accesshttp

// AccountAPI is the account the handlers call, for an external test's fake.
type AccountAPI = accountAPI

// NewWithAccount is New over acct in place of Config.Account.
func NewWithAccount(cfg Config, acct AccountAPI) (*Handler, error) {
	return newHandler(cfg, acct)
}
