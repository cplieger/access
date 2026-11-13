package accesstest

import (
	"maps"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/cplieger/access/account"
)

func TestStoreContractMemStore(t *testing.T) {
	StoreContract(t, func(*testing.T) account.Store { return NewMemStore() }, ContractConfig{})
}

// TestStoreContractMemStoreSkips reads the skip set from a child run, since
// t.Run reports a skipped child as passed.
func TestStoreContractMemStoreSkips(t *testing.T) {
	t.Parallel()
	out, err := rerun(t, "TestStoreContractMemStore")
	if err != nil {
		t.Fatalf("TestStoreContractMemStore failed: %v\n%s", err, out)
	}
	want := []string{
		"TestStoreContractMemStore/rule_05_update/grouped_commit",
		"TestStoreContractMemStore/rule_10_durability",
		"TestStoreContractMemStore/rule_14_cleanup/deleted_set_reopen",
		"TestStoreContractMemStore/rule_14_cleanup/rerun",
		"TestStoreContractMemStore/rule_16_reads_never_wait/direct_write",
		"TestStoreContractMemStore/rule_17_ids_and_lineage/reopen_keys",
		"TestStoreContractMemStore/rule_17_ids_and_lineage/reopen_users",
		"TestStoreContractMemStore/rule_20_fidelity/reopen",
		"TestStoreContractMemStore/rule_22_log/seq_never_reused_reopen",
		"TestStoreContractMemStore/rule_22_log/seq_re_run",
		"TestStoreContractMemStore/rule_22_log/stats_reopen",
	}
	if got := reported(out, "SKIP"); !slices.Equal(got, want) {
		t.Errorf("skipped subtests = %v, want exactly %v", got, want)
	}
}

// TestTxCallsCoverTx pins rule 18's hand list to account.Tx, so a Tx method
// left out of txCalls fails here.
func TestTxCallsCoverTx(t *testing.T) {
	t.Parallel()
	s := NewMemStore()
	calls := map[string]bool{}
	for _, call := range txCalls(s, seedRows(t, s)) {
		if calls[call.name] {
			t.Errorf("txCalls lists %s twice", call.name)
		}
		calls[call.name] = true
	}
	methods := map[string]bool{}
	for m := range reflect.TypeFor[account.Tx]().Methods() {
		methods[m.Name] = true
	}
	for _, name := range slices.Sorted(maps.Keys(methods)) {
		if !calls[name] {
			t.Errorf("txCalls has no call of Tx.%s", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(calls)) {
		if !methods[name] {
			t.Errorf("txCalls lists %s, which is not a Tx method", name)
		}
	}
}

// rerun runs the top-level test name in a child of this test binary, with
// env added, and returns its output and exit error. The child runs another
// top-level test, so it cannot recurse.
func rerun(t *testing.T, name string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^"+name+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var verdictLine = regexp.MustCompile(`^\s*--- (PASS|FAIL|SKIP): (\S+) \(`)

// reported returns, sorted, every test path the output reports with verdict.
func reported(out, verdict string) []string {
	var paths []string
	for _, line := range regexp.MustCompile(`\r?\n`).Split(out, -1) {
		if m := verdictLine.FindStringSubmatch(line); m != nil && m[1] == verdict {
			paths = append(paths, m[2])
		}
	}
	slices.Sort(paths)
	return paths
}
