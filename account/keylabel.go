package account

import (
	"context"
	"slices"
	"time"

	"github.com/cplieger/access"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// checkKeyLabel is the key label rule at create and at rename: not empty,
// one line of at most maxDisplayRunes runes.
func checkKeyLabel(label string) error {
	if label == "" {
		return &TextError{Field: TextFieldLabel, Reason: ReasonEmpty}
	}
	return checkLine(TextFieldLabel, label, maxDisplayRunes)
}

// requireLabelFree refuses with ErrKeyLabelTaken a label an unexpired key
// of keys other than except carries at now. keys is the owner's keys as
// read in the Update that writes the label, so no other write lands between.
func requireLabelFree(keys []access.Key, label string, now time.Time, except int64) error {
	want := labelKey(label)
	if slices.ContainsFunc(keys, func(k access.Key) bool {
		return k.ID != except && !keyExpired(&k, now) && labelKey(k.Label) == want
	}) {
		return refuse(ErrKeyLabelTaken)
	}
	return nil
}

// labelFreeIn is requireLabelFree for a new key of userID, over the keys
// tx reads.
func labelFreeIn(ctx context.Context, tx Tx, userID int64, label string, now time.Time) error {
	keys, err := tx.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return err
	}
	return requireLabelFree(keys, label, now, 0)
}

// labelKey is the form two key labels are compared in: NFC, then full
// Unicode case folding, so "Agent" and "agent" are one label.
func labelKey(label string) string { return cases.Fold().String(norm.NFC.String(label)) }

// keyExpired reports a key whose ExpiresAt is set and not after now.
func keyExpired(k *access.Key, now time.Time) bool {
	return !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now)
}
