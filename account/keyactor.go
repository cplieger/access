package account

import (
	"context"
	"slices"

	"github.com/cplieger/access"
)

// currentKeyActor is keyAuthority for the key a change acts as. On success
// it caches the key's Label and Suffix in j from this read, so every entry
// the change logs with the key as its actor carries them.
func (s *Service) currentKeyActor(ctx context.Context, tx Tx, j *journal, op Operation, ref access.KeyRef, scope string) (Actor, *access.Key, error) {
	actor, key, err := s.keyAuthority(ctx, tx, op, ref, scope)
	if err != nil {
		return Actor{}, nil, err
	}
	j.keys[key.ID] = shown{label: key.Label, keySuffix: key.KeySuffix}
	return actor, key, nil
}

// keyAuthority decides a key's authority inside the caller's Update from
// the stored records alone, never from the request's Principal. ref names a
// principal's key by owner and ID, or a token issuer by ID alone. The key
// must exist, be unexpired at Config.Now and carry the non-empty scope, and
// its owner must exist and be enabled; any failure is a refused
// key_not_current, and a store error is returned as it is, for the caller's
// Update. The Actor is rebuilt with the owner's stored role, and the key's
// LineageIDs is the path the write attributes.
func (s *Service) keyAuthority(ctx context.Context, tx Tx, op Operation, ref access.KeyRef, scope string) (Actor, *access.Key, error) {
	notCurrent := refuse(&PolicyError{Op: op, Reason: ReasonKeyNotCurrent})
	if scope == "" || ref.ID == 0 {
		return Actor{}, nil, notCurrent
	}
	var keys []access.Key
	var err error
	if ref.UserID != 0 {
		keys, err = tx.ListAPIKeysByUserID(ctx, ref.UserID)
	} else {
		keys, err = tx.ListAPIKeys(ctx)
	}
	if err != nil {
		return Actor{}, nil, err
	}
	i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == ref.ID })
	if i < 0 {
		return Actor{}, nil, notCurrent
	}
	key := keys[i]
	if (ref.UserID != 0 && key.UserID != ref.UserID) ||
		(!key.ExpiresAt.IsZero() && !key.ExpiresAt.After(s.now())) ||
		!slices.Contains(key.Scopes, scope) {
		return Actor{}, nil, notCurrent
	}
	owner, found, err := tx.UserByID(ctx, key.UserID)
	if err != nil {
		return Actor{}, nil, err
	}
	if !found || !owner.Enabled {
		return Actor{}, nil, notCurrent
	}
	return As(access.Principal{
		User:             owner,
		Method:           access.MethodAPIKey,
		KeyID:            key.ID,
		KeyLabel:         key.Label,
		Scopes:           slices.Clone(key.Scopes),
		AbsoluteDeadline: key.ExpiresAt,
	}), &key, nil
}

// requireUserTarget is the admin-target rule for a key actor: every role it
// sets or acts on, as a value or as a target's stored role, is RoleUser,
// else a refused admin_target.
func requireUserTarget(op Operation, roles ...access.Role) error {
	for _, r := range roles {
		if r != access.RoleUser {
			return refuse(&PolicyError{Op: op, Reason: ReasonAdminTarget})
		}
	}
	return nil
}

// attribute appends the one KeyAttribution of a key's act on userID, with a
// copy of the key's LineageIDs as keyAuthority re-read it. It is the only
// writer of attribution records.
func (s *Service) attribute(ctx context.Context, tx Tx, userID int64, action access.AttributionAction, key *access.Key) error {
	return tx.CreateKeyAttribution(ctx, &access.KeyAttribution{
		UserID:     userID,
		KeyLineage: slices.Clone(key.LineageIDs),
		Action:     action,
		At:         s.now(),
	})
}
