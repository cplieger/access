package accesstest

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// The roles a store plays beside account: every account.Store is the
// Authenticator's store and the webauthn package's.
var (
	_ access.AuthenticatorStore = account.Store(nil)
	_ webauthn.Store            = account.Store(nil)
)

// StoreContract runs every contract rule of account's package doc against
// stores made by newStore; each call must return an empty, independent store.
func StoreContract(t *testing.T, newStore func(t *testing.T) account.Store, cfg ContractConfig) {
	t.Helper()
	c := &contract{newStore: newStore, cfg: cfg}
	for _, r := range []struct {
		run  func(t *testing.T)
		name string
	}{
		{c.absence, "rule_01_absence"},
		{c.ownership, "rule_02_ownership"},
		{c.canonicalUsernames, "rule_03_canonical_usernames"},
		{c.uniqueness, "rule_04_uniqueness"},
		{c.atomicity, "rule_05_atomicity"},
		{c.update, "rule_05_update"},
		{c.scoping, "rule_06_scoping"},
		{c.expiry, "rule_07_expiry"},
		{c.flags, "rule_08_flags"},
		{c.handleProbing, "rule_09_handle_probing"},
		{c.durability, "rule_10_durability"},
		{c.timeRoundTrip, "rule_11_time"},
		{c.callerFaults, "rule_12_errors"},
		{c.concurrency, "rule_13_concurrency"},
		{c.cleanup, "rule_14_cleanup"},
		{c.failureRecords, "rule_15_failure_records"},
		{c.readsNeverWait, "rule_16_reads_never_wait"},
		{c.idsAndLineage, "rule_17_ids_and_lineage"},
		{c.contexts, "rule_18_context"},
		{c.absentRows, "rule_19_absent_rows"},
		{c.fidelity, "rule_20_fidelity"},
		{c.activity, "rule_21_activity"},
		{c.securityLog, "rule_22_log"},
		{c.keySecrets, "rule_23_key_secrets"},
	} {
		t.Run(r.name, r.run)
	}
}

// ContractConfig configures StoreContract. Every zero value is the default:
// the zero ContractConfig runs every case a store with no medium hooks can
// run and skips the rest, each skip naming its rule.
type ContractConfig struct {
	// NewFaulty makes stores whose medium the returned DurabilityFaults can
	// fail and count; rule 10's cases, rule 5's grouped-commit case, the
	// re-run cases of rules 14 and 22 and rule 16's direct-write case run
	// on them. Nil skips those subtests.
	NewFaulty func(t *testing.T) (account.Store, DurabilityFaults)
	// Reopen closes old, a store newStore made and the suite wrote to, and
	// returns a store over the same medium; rule 20's fidelity case, rule
	// 14's deleted-set case, rule 17's never-reused cases for users and
	// keys and rule 22's Seq and stats cases run across it. Nil skips those
	// subtests.
	Reopen func(t *testing.T, old account.Store) account.Store
}

// DurabilityFaults arms one medium fault for the store's next write.
type DurabilityFaults struct {
	// BeforePublish makes the next write fail before its new state is
	// published. Required.
	BeforePublish func()
	// AfterPublish makes the next write publish its new state and then fail
	// to confirm durability. Nil for a medium that reports durability with
	// its commit (bbolt).
	AfterPublish func()
	// Publishes reports how many durable publishes the medium has made.
	// Required.
	Publishes func() int
	// HoldPublish blocks the medium's next publish until release, and
	// pending reports the writes, Updates and single-call writes alike,
	// waiting for a publish. Nil for a store that groups by delay (bbolt's
	// db.Batch), which skips rule 16's direct-write case.
	HoldPublish func() (pending func() int, release func())
}

// cleanupWindow is implemented only by this package's red-check variants: a
// store under test cannot be paused from outside, so rule 14's concurrent
// case reaches a two-step cleanup's window through it. Its method is
// unexported, so no other package's store can implement it.
type cleanupWindow interface {
	// armCleanupWindow makes the next CleanupExpiredSessions close listed
	// once it has listed and released its lock, then wait for release.
	armCleanupWindow() (listed <-chan struct{}, release func())
}

type contract struct {
	newStore func(t *testing.T) account.Store
	cfg      ContractConfig
}

// store makes a fresh store and fails the test when newStore returns nil.
func (c *contract) store(t *testing.T) account.Store {
	t.Helper()
	s := c.newStore(t)
	if s == nil {
		t.Fatal("newStore returned nil")
	}
	return s
}

// faulty makes a store through NewFaulty, or skips naming rule.
func (c *contract) faulty(t *testing.T, rule string) (account.Store, DurabilityFaults) {
	t.Helper()
	if c.cfg.NewFaulty == nil {
		t.Skipf("%s: needs ContractConfig.NewFaulty", rule)
	}
	s, f := c.cfg.NewFaulty(t)
	if s == nil || f.BeforePublish == nil || f.Publishes == nil {
		t.Fatalf("%s: NewFaulty must return a store, BeforePublish and Publishes", rule)
	}
	return s, f
}

// reopen reopens s through Reopen, or skips naming rule.
func (c *contract) reopen(t *testing.T, rule string, s account.Store) account.Store {
	t.Helper()
	r := c.cfg.Reopen(t, s)
	if r == nil {
		t.Fatalf("%s: Reopen returned nil", rule)
	}
	return r
}

// needReopen skips the test naming rule when the config has no Reopen.
func (c *contract) needReopen(t *testing.T, rule string) {
	t.Helper()
	if c.cfg.Reopen == nil {
		t.Skipf("%s: needs ContractConfig.Reopen", rule)
	}
}

// Fixture values more than one rule uses.
const (
	ipA        = "192.0.2.1"
	ipB        = "192.0.2.2"
	mutated    = "mutated"
	unknownID  = "unknown"
	testIssuer = "https://idp"

	opSessionByHash  = "SessionByHash"
	opUserByUsername = "UserByUsername"
	opListAllKeys    = "ListAPIKeys"
	opListUserKeys   = "ListAPIKeysByUserID"
	opDeleteKey      = "DeleteAPIKey"
)

// epoch is the suite's clock origin: millisecond-aligned and in UTC.
var epoch = time.Date(2030, time.March, 1, 9, 0, 0, 0, time.UTC)

var fixtureSeq atomic.Int64

// fresh returns a text no other fixture of the process uses.
func fresh(prefix string) string { return fmt.Sprintf("%s-%d", prefix, fixtureSeq.Add(1)) }

func newUser(name string) *access.User {
	return &access.User{
		CreatedAt:      epoch,
		UpdatedAt:      epoch,
		Username:       name,
		PasswordHash:   access.NewHash(fresh("password")),
		Role:           access.RoleUser,
		WebAuthnHandle: access.GenerateWebAuthnHandle(),
		Enabled:        true,
	}
}

func mustUser(t *testing.T, s account.Store, name string) *access.User {
	t.Helper()
	u := newUser(name)
	if err := s.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser(%q): %v", name, err)
	}
	return u
}

// newSession is a full session of userID created and last active at last.
func newSession(userID int64, last time.Time) *access.Session {
	id := fmt.Sprintf("%032x", fixtureSeq.Add(1))
	return &access.Session{
		CreatedAt:    last,
		LastActivity: last,
		AuthTime:     last,
		ID:           id,
		TokenHash:    access.NewHash(access.HexSHA256(id)),
		AuthMethod:   access.MethodPassword,
		UserID:       userID,
	}
}

func mustSession(t *testing.T, s account.Store, sess *access.Session) {
	t.Helper()
	if err := s.CreateSession(t.Context(), sess); err != nil {
		t.Fatalf("CreateSession(%s): %v", sess.ID, err)
	}
}

func newKey(userID int64) *access.Key {
	return &access.Key{
		CreatedAt: epoch,
		KeyHash:   access.NewHash(fresh("key")),
		KeyPrefix: "ak",
		Label:     "contract",
		Scopes:    []string{"read", "write"},
		UserID:    userID,
	}
}

func mustKey(t *testing.T, s account.Store, k *access.Key) {
	t.Helper()
	if err := s.CreateAPIKey(t.Context(), k); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
}

func newToken(purpose access.TokenPurpose, subject int64, expires time.Time) access.OneTimeToken {
	return access.OneTimeToken{
		CreatedAt: epoch,
		ExpiresAt: expires,
		Hash:      access.NewHash(fresh("token")),
		Purpose:   purpose,
		Subject:   subject,
	}
}

func mustToken(t *testing.T, s account.Store, tok access.OneTimeToken) { //nolint:gocritic // hugeParam: mirrors CreateOneTimeToken
	t.Helper()
	if err := s.CreateOneTimeToken(t.Context(), tok); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}
}

func newPasskey(userID int64) *access.PasskeyCredential {
	return &access.PasskeyCredential{
		CreatedAt:    epoch,
		Name:         "contract",
		CredentialID: []byte(fresh("credential")),
		PublicKey:    []byte{1, 2, 3},
		AAGUID:       make([]byte, 16),
		UserID:       userID,
		RawFlags:     0x45,
	}
}

func mustPasskey(t *testing.T, s account.Store, p *access.PasskeyCredential) {
	t.Helper()
	if err := s.CreatePasskey(t.Context(), p); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
}

func refOf(s *access.Session) access.SessionRef { return access.SessionRef{ID: s.ID, UserID: s.UserID} }

func sessionFound(t *testing.T, s account.Store, h access.Hash) (*access.Session, bool) {
	t.Helper()
	sess, found, err := s.SessionByHash(t.Context(), h)
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	return sess, found
}

func userFound(t *testing.T, s account.Store, name string) bool {
	t.Helper()
	_, found, err := s.UserByUsername(t.Context(), name)
	if err != nil {
		t.Fatalf("UserByUsername(%q): %v", name, err)
	}
	return found
}

// race runs each fn on its own goroutine, all released by one barrier, and
// waits for every one.
func race(fns ...func()) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Go(func() {
			<-start
			fn()
		})
	}
	close(start)
	wg.Wait()
}

// raceN runs fn(i) for i in [0, n) through race.
func raceN(n int, fn func(i int)) {
	fns := make([]func(), n)
	for i := range n {
		fns[i] = func() { fn(i) }
	}
	race(fns...)
}

// within runs fn on its own goroutine and reports whether it returned
// within d; a late fn keeps running.
func within(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// waitFor polls cond until it holds or d passes, and reports which.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		<-tick.C
	}
	return true
}

// errContract is what a callback the suite rolls back returns.
var errContract = errors.New("accesstest: contract callback error")
