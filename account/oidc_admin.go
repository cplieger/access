package account

import (
	"context"
	"errors"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/crockford"
	"github.com/cplieger/access/ratelimit"
)

// LinkPendingOIDCByAdmin links pl's identity, under SSOOnly, to the account
// username names by the temporary password an admin issued it, and signs it
// in by OIDC. A plain c is access.ErrHTTPSRequired and the zero PendingLink
// ErrNotFound, before any hash. A name, secret, account, issuer or mode
// that cannot link is one ErrInvalidCredentials after one hash, counted on
// c's IP and pl's identity, never on the account; a verified secret meets
// ErrAlreadyLinked and ErrOIDCIdentityTaken. The name's lock is held from
// before the hash through the success Update.
func (s *Service) LinkPendingOIDCByAdmin(ctx context.Context, c Client, pl PendingLink, username string, secret access.Secret) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client and the pending link it read
	r, err := s.beginOver(plainRefused, c.Secure)
	if err != nil {
		return SignedIn{}, err
	}
	if s.provider() == nil {
		return SignedIn{}, ErrOIDCUnavailable
	}
	if pl.Identity.Issuer == "" || pl.Identity.Subject == "" {
		return SignedIn{}, ErrNotFound
	}
	var (
		v      adminLinkVerify
		unlock func()
	)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	return s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodOIDC,
		gate: admission{limit: func() (*ratelimit.Reservation, error) {
			return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP()), Account: ratelimit.IdentityKey(pl.Identity)})
		}},
		prepare: func(res *ratelimit.Reservation) error {
			canonical, nameErr := canonicalUsername(username)
			if nameErr == nil {
				var lockErr error
				if unlock, lockErr = s.lockName(ctx, canonical); lockErr != nil {
					return busy(lockErr)
				}
			}
			return s.verifyAdminLink(ctx, res, &v, canonical, secret)
		},
		in: func(tx Tx) (*access.User, error) { return s.adminLinkUserIn(ctx, tx, &v) },
		pend: func(tx Tx, _ *journal, u *access.User, _ error) (*pending, error, error) {
			return s.adminLinkPend(ctx, tx, u, &v.rec, pl.Identity)
		},
		bind: func(tx Tx, j *journal, u *access.User, _ *access.Session) error {
			return s.adminLinkIn(ctx, tx, j, u, &v.rec, pl.Identity)
		},
	})
}

// adminLinkVerify is what an admin link's verify found: the named user, the
// record hash its secret matched, and the record its success Update re-read.
type adminLinkVerify struct {
	verified access.Hash
	rec      access.TemporaryPassword
	userID   int64
}

// verifyAdminLink compares secret in its normalised form with adminLinkHash's
// hash under a hash permit. nil means it verified a live record, recorded in
// v; every other answer has settled res.
func (s *Service) verifyAdminLink(ctx context.Context, res *ratelimit.Reservation, v *adminLinkVerify, canonical string, secret access.Secret) error {
	permit, err := s.admitCount(ctx, res, !res.Trusted())
	if err != nil {
		return err
	}
	defer permit.Release()
	hash, err := s.adminLinkHash(ctx, canonical, v)
	if err != nil {
		res.Fail()
		return err
	}
	ok, _, err := permit.Verify(crockford.Normalize(secret.Reveal()), hash)
	switch {
	case errors.Is(err, access.ErrHashBusy):
		res.Fail()
		return err
	case err != nil:
		s.logger().Error("account: a stored temporary password hash exceeds the hash budget and can never verify", "user_id", v.userID, "err", err)
		res.Fail()
		return ErrInvalidCredentials
	case !ok:
		res.Fail()
		return ErrInvalidCredentials
	}
	v.verified = hash
	return nil
}

// adminLinkHash reads canonical's user and its temporary password, the
// same two reads whether or not a user has the name, and answers the hash
// to compare: the live record of an enabled non-owner, else the zero hash,
// which fails at full cost. The account's PasswordHash is never one.
func (s *Service) adminLinkHash(ctx context.Context, canonical string, v *adminLinkVerify) (access.Hash, error) {
	u, found, err := s.store.UserByUsername(ctx, canonical)
	if err != nil {
		return access.Hash{}, storeErr(err)
	}
	var id int64
	if found {
		id = u.ID
	}
	rec, held, err := s.store.TemporaryPasswordByUserID(ctx, id)
	switch {
	case err != nil:
		return access.Hash{}, storeErr(err)
	case !found || !u.Enabled || isOwner(u) || !held || !rec.ExpiresAt.After(s.now()):
		return access.Hash{}, nil
	}
	v.userID = u.ID
	return rec.Hash, nil
}

// adminLinkUserIn is the head of the admin link's success Update: the
// verified record re-read, then a user who is no owner, under SSOOnly; any
// other answer is ErrInvalidCredentials, writing nothing. It keeps the
// record in v.
func (s *Service) adminLinkUserIn(ctx context.Context, tx Tx, v *adminLinkVerify) (*access.User, error) {
	u, rec, err := s.liveTemporaryIn(ctx, tx, v.userID, v.verified)
	if err != nil {
		return nil, err
	}
	v.rec = rec
	mode, err := storedMode(ctx, tx)
	switch {
	case err != nil:
		return nil, err
	case isOwner(u) || mode != SSOOnly:
		return nil, refuse(ErrInvalidCredentials)
	}
	return u, nil
}

// adminLinkPend decides, after the record re-read, whether the admin link
// of id to u goes on: the issuer re-check, whose failure deletes rec and
// answers as a wrong secret; then a user already linked and an identity
// linked to another, which refuse writing nothing.
func (s *Service) adminLinkPend(ctx context.Context, tx Tx, u *access.User, rec *access.TemporaryPassword, id access.OIDCIdentity) (entry *pending, refused, err error) {
	current, err := s.temporaryIssuerCurrent(ctx, tx, rec, u)
	switch {
	case err != nil:
		return nil, nil, err
	case !current:
		return nil, ErrInvalidCredentials, tx.DeleteTemporaryPassword(ctx, u.ID)
	case !u.OIDC.IsZero():
		return nil, ErrAlreadyLinked, nil
	}
	_, taken, err := tx.UserByOIDC(ctx, id)
	switch {
	case err != nil:
		return nil, nil, err
	case taken:
		return nil, ErrOIDCIdentityTaken, nil
	}
	return nil, nil, nil
}

// adminLinkIn is the admin link's write for u: the link to id, rec spent,
// and EventOIDCLinked naming rec's issuer. The account's other local
// methods stay as the mode keeps them, dormant.
func (s *Service) adminLinkIn(ctx context.Context, tx Tx, j *journal, u *access.User, rec *access.TemporaryPassword, id access.OIDCIdentity) error {
	u.OIDC, u.UpdatedAt = id, s.now()
	if err := tx.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := tx.DeleteTemporaryPassword(ctx, u.ID); err != nil {
		return err
	}
	j.add(Event{Kind: EventOIDCLinked, At: s.now(), UserID: u.ID, IssuerUserID: rec.IssuedByUser, KeyID: rec.IssuedByKey})
	return nil
}

// AdminRelinkOIDC is AdminUnlinkOIDC then SetTemporaryPassword on userID in
// one Update, under both their Policies and checks, so a refusal of either
// writes nothing; an unlinked user is ErrNotFound. The issue sees the
// unlinked row: under SSOOnly it keeps the dormant methods beside a record
// for the admin link, and under the other modes it replaces them.
func (s *Service) AdminRelinkOIDC(ctx context.Context, a Actor, userID int64, in TemporaryPasswordOptions) (IssuedTemporaryPassword, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, iss, err := s.prepareIssue(ctx, a, userID, in)
	if err != nil {
		return IssuedTemporaryPassword{}, err
	}
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		target, unlinkErr := s.unlinkTargetIn(ctx, tx, j, a, userID)
		if unlinkErr != nil {
			return unlinkErr
		}
		ua, _, issueErr := s.issueTargetIn(ctx, tx, j, a, userID)
		if issueErr != nil {
			return issueErr
		}
		mode, modeErr := storedMode(ctx, tx)
		if modeErr != nil {
			return modeErr
		}
		if writeErr := s.unlinkWriteIn(ctx, tx, j, a, target); writeErr != nil {
			return writeErr
		}
		return s.issueWriteIn(ctx, tx, j, a, &ua, target, iss, mode)
	})
	if err != nil {
		return IssuedTemporaryPassword{}, err
	}
	return s.issuedTo(&r, userID, iss), nil
}
