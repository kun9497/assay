package main

import (
	"bytes"
	"strings"
	"testing"
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
