package account

import (
	"bytes"
	"context"
	"errors"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// SecondFactorProof is a current second factor sent with a change that
// needs one: a TOTP code, or an assertion from a ceremony
// StepUpPasskeyBegin began. The zero value is no proof.
type SecondFactorProof struct {
	code      string
	ceremony  string
	assertion []byte
}

// ProofCode is a proof by TOTP code.
func ProofCode(code string) SecondFactorProof { return SecondFactorProof{code: code} }

// ProofPasskey is a proof by the passkey assertion that answers ceremony.
func ProofPasskey(ceremony string, assertion []byte) SecondFactorProof {
	return SecondFactorProof{ceremony: ceremony, assertion: assertion}
}

// IsZero reports no proof.
func (p SecondFactorProof) IsZero() bool { return p.code == "" && p.ceremony == "" }

// verifyProof is the one proof verifier of every change that needs a
// current second factor of u, p's own user. No proof is
// ErrSecondFactorProofRequired before any count. A code is counted and
// matched once, as StepUpCode's; under a TOTP that is not usable it is
// ErrTOTPDisabled. An assertion needs a secure c and p, and spends its
// ceremony. The caller's Update commits the result and settles it.
func (s *Service) verifyProof(ctx context.Context, r Rules, c Client, p access.Principal, u *access.User, proof SecondFactorProof) (proven, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Principal
	switch {
	case proof.IsZero():
		return proven{}, ErrSecondFactorProofRequired
	case proof.code != "":
		if !s.totpOn(r) {
			return proven{}, ErrTOTPDisabled
		}
		return s.verifyCode(ctx, c, u, proof.code, fieldCode, ReasonCodeInvalid)
	}
	if !c.Secure || !p.Secure {
		return proven{}, access.ErrHTTPSRequired
	}
	rp := s.relyingParty()
	if rp == nil || !passkeysAllowed(ctx, s.store, r, rp.ID(), u) {
		return proven{}, ErrPasskeysUnavailable
	}
	entry, err := s.takeOwn(proof.ceremony, purposeStepUp, p)
	if err != nil {
		return proven{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return proven{}, err
	}
	wu.Credentials = currentRP(wu.Credentials, rp)
	if _, err := webauthn.CompleteReauthentication(ctx, rp, ceremonyStore{s.store}, wu, entry.ceremony, bytes.NewReader(proof.assertion)); err != nil {
		return proven{}, err
	}
	return proven{}, nil
}

// verifyCode counts and matches raw, input field, against u's record for a
// session of u from c, limited on the account and device as a step-up is.
// invalid is the CodeError Reason of a code that matches no step.
func (s *Service) verifyCode(ctx context.Context, c Client, u *access.User, raw, field, invalid string) (proven, error) { //nolint:gocritic // hugeParam: the request's Client
	res, err := s.limiter.Attempt(ratelimit.Attempt{OmitIP: true, Account: ratelimit.AccountKey(u.Username), Device: c.Device})
	if err != nil {
		return proven{}, err
	}
	ch := s.newCodeCheck(res, u, raw)
	ch.field, ch.invalid = field, invalid
	ch.missing = &CodeError{Reason: invalid}
	step, err := s.countCode(ctx, res, &ch)
	if err != nil {
		return proven{}, err
	}
	return proven{res: res, check: &ch, step: step}, nil
}

// heldWithout is secondFactorHeld once gone is gone: a TOTP that is no
// longer read, or one passkey fewer.
func (s *Service) heldWithout(ctx context.Context, tx Tx, r Rules, u *access.User, gone credential) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if gone.method != access.MethodTOTP {
		if held, err := s.usableTOTP(ctx, tx, r, u); err != nil || held {
			return held, err
		}
	}
	if !r.RequireSecondFactor || u.PasswordHash.IsZero() {
		return false, nil
	}
	n, err := usablePasskeys(ctx, tx, r, s.rpID(), u, gone)
	return n > 0, err
}

// guardSecondFactor is ErrLastSecondFactor's guard, inside tx: under
// Rules.RequireSecondFactor, a removal of gone that leaves u, who holds a
// second factor now, none is refused.
func (s *Service) guardSecondFactor(ctx context.Context, tx Tx, r Rules, u *access.User, gone credential) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if !r.RequireSecondFactor {
		return nil
	}
	held, err := s.secondFactorHeld(ctx, tx, r, u)
	if err != nil || !held {
		return err
	}
	if kept, err := s.heldWithout(ctx, tx, r, u, gone); err != nil || kept {
		return err
	}
	return refuse(ErrLastSecondFactor)
}

// removable reports whether a removal of gone would pass both guards, the
// last-method guard for a passkey and the second-factor guard; a store
// error is returned as it is.
func (s *Service) removable(ctx context.Context, tx Tx, r Rules, u *access.User, gone credential) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	err := s.guardSecondFactor(ctx, tx, r, u, gone)
	if err == nil && gone.method == access.MethodPasskey {
		err = s.guardLastMethod(ctx, tx, r, u, gone)
	}
	if _, refused := errors.AsType[*refusal](err); refused {
		return false, nil
	}
	return err == nil, err
}
