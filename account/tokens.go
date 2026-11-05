package account

import (
	"cmp"
	"context"
	"slices"

	"github.com/cplieger/access"
)

// Tokens lists every live invite and recovery token, never a setup token,
// by expiry and then creation, for a principal RequireAdminScope admits and
// Policy allows OpListUsers. Each key-issued row carries its issuer's
// LineageIDs from a second read; an issuer gone by then leaves it nil. It
// writes nothing.
func (s *Service) Tokens(ctx context.Context, p access.Principal) ([]ListedToken, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if err := s.admitAdminScope(p); err != nil {
		return nil, err
	}
	if err := s.policy.Authorize(ctx, Decision{Op: OpListUsers, Actor: As(p)}); err != nil {
		return nil, err
	}
	tokens, err := s.store.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, s.now())
	if err != nil {
		return nil, storeErr(err)
	}
	keys, err := s.store.ListAPIKeys(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	paths := make(map[int64][]int64, len(keys))
	for i := range keys {
		paths[keys[i].ID] = keys[i].LineageIDs
	}
	slices.SortFunc(tokens, func(a, b access.OneTimeToken) int {
		return cmp.Or(a.ExpiresAt.Compare(b.ExpiresAt), a.CreatedAt.Compare(b.CreatedAt))
	})
	listed := make([]ListedToken, 0, len(tokens))
	for i := range tokens {
		listed = append(listed, ListedToken{Token: tokens[i], IssuerLineage: slices.Clone(paths[tokens[i].IssuedByKey])})
	}
	return listed, nil
}
