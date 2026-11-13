package account_test

import (
	"cmp"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

// comparableEvents are evs with At cleared, after checking each is set, and
// SessionIDs sorted, nil when empty.
func comparableEvents(t *testing.T, evs []account.Event) []account.Event {
	t.Helper()
	var out []account.Event
	for _, ev := range evs {
		if ev.At.IsZero() {
			t.Errorf("%s has no At", ev.Kind)
		}
		ev.At, ev.Seq = time.Time{}, 0
		ev.SessionIDs = slices.Sorted(slices.Values(ev.SessionIDs))
		if len(ev.SessionIDs) == 0 {
			ev.SessionIDs = nil
		}
		out = append(out, ev)
	}
	return out
}

func TestEveryOperationEmits(t *testing.T) {
	t.Parallel()
	for _, op := range operations() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			mark := len(w.events.all())
			if err := call.run(t.Context()); err != nil {
				t.Fatalf("%s = %v", op.name, err)
			}
			got := comparableEvents(t, w.events.all()[mark:])
			want := comparableEvents(t, withAt(call.want()))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s emitted\n%+v\nwant\n%+v", op.name, got, want)
			}
		})
	}
}

// withAt sets every event's At, so comparableEvents checks only the
// emitted ones'.
func withAt(evs []account.Event) []account.Event {
	for i := range evs {
		evs[i].At = time.Unix(1, 0)
	}
	return evs
}

func TestOnEventPanicRecovered(t *testing.T) {
	t.Parallel()
	const msg = "account: OnEvent panicked"
	for _, tc := range []struct {
		name    string
		hook    func(account.Event)
		wantErr int
	}{
		{"panicking_hook", func(account.Event) { panic("hook") }, 1},
		{"quiet_hook", func(account.Event) {}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newPW(t, pwOptions{edit: func(c *account.Config) { c.OnEvent = tc.hook }})
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			if _, err := p.login(t.Context(), localClient, "alice", goodPassword); err != nil {
				t.Fatalf("PasswordLogin: %v", err)
			}
			n := 0
			for _, r := range p.logs.Records("") {
				if r.Level == slog.LevelError && r.Message == msg {
					n++
				}
			}
			if n != tc.wantErr {
				t.Errorf("%q ERROR lines = %d, want %d", msg, n, tc.wantErr)
			}
		})
	}
}

// declared is the value of every package-level constant whose type is typ
// in the package's non-test files, in source order (files by name). The
// files are type-checked, not matched by syntax, so that every declaration
// form counts: an untyped spec converting its value (EventKind("x")) or
// naming another constant has no type in the AST.
func declared(t *testing.T, typ string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", ".")
	out, err := cmd.Output()
	if err != nil {
		if exit, isExit := errors.AsType[*exec.ExitError](err); isExit {
			t.Fatalf("go list: %v\n%s", err, exit.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	exports := map[string]string{}
	for line := range strings.Lines(string(out)) {
		path, file, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "\t")
		exports[path] = file
	}
	bp, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file := exports[path]
		if file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})}
	pkg, err := conf.Check("account", fset, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	named, ok := pkg.Scope().Lookup(typ).(*types.TypeName)
	if !ok {
		t.Fatalf("no type %s in the package", typ)
	}
	var consts []*types.Const
	for _, name := range pkg.Scope().Names() {
		if c, isConst := pkg.Scope().Lookup(name).(*types.Const); isConst && types.Identical(types.Unalias(c.Type()), named.Type()) {
			consts = append(consts, c)
		}
	}
	slices.SortFunc(consts, func(a, b *types.Const) int { return cmp.Compare(a.Pos(), b.Pos()) })
	values := make([]string, 0, len(consts))
	for _, c := range consts {
		values = append(values, constant.StringVal(c.Val()))
	}
	return values
}

func TestEventKindsDeclared(t *testing.T) {
	t.Parallel()
	var got []string
	for _, k := range account.EventKinds() {
		got = append(got, string(k))
	}
	if want := declared(t, "EventKind"); !slices.Equal(got, want) {
		t.Errorf("EventKinds() = %v, want every declared EventKind in order, %v", got, want)
	}
}

func TestLogClassesDeclared(t *testing.T) {
	t.Parallel()
	var got []string
	for _, c := range account.LogClasses() {
		got = append(got, string(c))
	}
	if want := declared(t, "LogClass"); !slices.Equal(got, want) {
		t.Errorf("LogClasses() = %v, want every declared LogClass in order, %v", got, want)
	}
}
