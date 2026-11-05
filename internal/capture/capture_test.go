package capture

import (
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestNewCapturesAndCounts(t *testing.T) {
	t.Parallel()
	logger, rec := New()
	logger.Info("session activity update failed")
	logger.Warn("session activity update failed")
	logger.Info("something else")

	if got := rec.CountMsg("session activity update failed"); got != 2 {
		t.Errorf("CountMsg = %d, want 2", got)
	}
	if got := rec.CountMsg("absent"); got != 0 {
		t.Errorf("CountMsg(absent) = %d, want 0", got)
	}
}

func TestRecordsCarryHandlerAttrs(t *testing.T) {
	t.Parallel()
	logger, rec := New()
	logger.With("base", 1).WithGroup("g").With("inner", 2).WithGroup("h").Info("nested", "own", 3)
	logger.WithGroup("").With().Info("plain", "own", 4)
	logger.WithGroup("empty").Info("bare")
	for msg, want := range map[string]string{
		"nested": "level=INFO msg=nested base=1 g.inner=2 g.h.own=3\n",
		"plain":  "level=INFO msg=plain own=4\n",
		"bare":   "level=INFO msg=bare\n",
	} {
		got := rec.Records(msg)
		if len(got) != 1 {
			t.Fatalf("Records(%q) = %d records, want 1", msg, len(got))
		}
		var b strings.Builder
		h := slog.NewTextHandler(&b, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}})
		if err := h.Handle(t.Context(), got[0]); err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if b.String() != want {
			t.Errorf("record %q renders %q, want %q", msg, b.String(), want)
		}
	}
}

func TestDefaultCapturesGlobalAndRestores(t *testing.T) {
	// Not parallel: mutates the global slog default.
	before := slog.Default()
	beforeWriter, beforeFlags := log.Writer(), log.Flags()
	t.Run("captures", func(t *testing.T) {
		rec := Default(t)
		slog.Info("via default")
		if rec.CountMsg("via default") != 1 {
			t.Error("Default did not capture a slog.Default() log")
		}
		if log.Writer() == beforeWriter {
			t.Fatal("slog.SetDefault did not redirect log's writer, so this test cannot observe the restore")
		}
	})
	if slog.Default() != before {
		t.Error("Default did not restore slog.Default() after the subtest ended")
	}
	// The log half is what silences the rest of the binary: the stock default
	// handler emits through log.Output, so a leaked redirect discards every
	// later slog call.
	if log.Writer() != beforeWriter {
		t.Error("Default did not restore log.Writer(); later slog calls write into the Recorder")
	}
	if got := log.Flags(); got != beforeFlags {
		t.Errorf("log.Flags() = %d, want %d", got, beforeFlags)
	}
}
