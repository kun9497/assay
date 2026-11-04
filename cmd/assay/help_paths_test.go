package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/store"
)

// TestRun_HelpFlagsOnSubcommands holds the help paths a first-time user
// actually types. `assay help` and `assay --help` printed the usage and
// exited 0; `assay scan --help` was "error: unknown flag" and `assay db
// --help` was "error: unknown db subcommand", both exit 2 with nothing on
// stdout (QA 2026-11-02 and 2026-11-04, on v0.14.0 and main 1284b32). A
// request for help is not a failed scan: it goes to stdout, exits 0, and
// leaves stderr empty, the same contract `assay help` already keeps.
func TestRun_HelpFlagsOnSubcommands(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--help"},
		{"scan", "-h"},
		{"scan", "--help", "alpine:3.19"},
		{"scan", "alpine:3.19", "--help"},
		{"db", "--help"},
		{"db", "-h"},
		{"db", "help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != exitOK {
				t.Errorf("run(%v) = %d, want %d (stderr: %q)", args, code, exitOK, stderr.String())
			}
			if stdout.String() != usage {
				t.Errorf("run(%v) stdout is not the usage text:\n%s", args, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%v) wrote to stderr: %q", args, stderr.String())
			}
		})
	}
}

// TestRun_DBHelpWithoutCacheDir holds the order, not only the happy path:
// help is answered before the database is located. A machine with no user
// cache dir (a scratch CI container, `docker run` with a numeric uid and no
// HOME, Windows without %LocalAppData%) is where the order shows: when the
// lookup ran first, `assay db --help` was exit 2 with "locate database" on
// stderr and nothing on stdout (review of PR #239), while `assay scan
// --help` on the same machine answered. The dev box and CI both have a
// cache dir, so TestRun_HelpFlagsOnSubcommands cannot see this.
func TestRun_DBHelpWithoutCacheDir(t *testing.T) {
	// Every variable os.UserCacheDir reads on any platform, plus ours.
	for _, name := range []string{"ASSAY_DB_DIR", "LocalAppData", "HOME", "XDG_CACHE_HOME"} {
		t.Setenv(name, "")
	}
	// The row is only a test of the ordering if the lookup really fails
	// here; otherwise it is the happy path again under another name.
	if _, err := store.DefaultPath(); err == nil {
		t.Fatal("store.DefaultPath() succeeded with every cache variable cleared; this test cannot see the ordering")
	}
	for _, args := range [][]string{
		{"db", "--help"},
		{"db", "-h"},
		{"db", "help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != exitOK {
				t.Errorf("run(%v) = %d, want %d (stderr: %q)", args, code, exitOK, stderr.String())
			}
			if stdout.String() != usage {
				t.Errorf("run(%v) stdout is not the usage text:\n%s", args, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%v) wrote to stderr: %q", args, stderr.String())
			}
		})
	}
}
