package scancmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingStdout refuses every write, the way a closed pipe, a full disk or a
// read-only handle does. It is the caller's view of the defect QA 2026-11-02
// found and QA 2026-11-04 reproduced on main 1284b32: with stdout unwritable,
// `--output json`, `--output sarif` and a table WITH findings exited 2 and
// said "error: write report", while a table with NOTHING to list (a clean
// scan, an empty document, an all-waived scan) exited 0 with zero bytes
// written and no reportSha256 -- a CI job read a report that never arrived as
// a pass.
type failingStdout struct{ err error }

func (f failingStdout) Write(p []byte) (int, error) { return 0, f.err }

// TestRun_TableWriteFailureIsExitTwo drives Run, not report.Table: the
// renderer returning an error is only half the fix, and scancmd mapping that
// error to exit 2 with the same "error: write report" line the other
// renderers print is the half a reader of the exit code depends on (CLAUDE.md:
// write the caller's test first). Each row is a table whose headline branch
// used to write unchecked: before the fix every row here returned 0.
func TestRun_TableWriteFailureIsExitTwo(t *testing.T) {
	dbPath := testDB(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	empty := write("empty.cdx.json", `{"bomFormat":"CycloneDX","components":[]}`)
	// Go is a covered ecosystem in testDB and holds no advisory, so this is the
	// "No known vulnerabilities found" headline -- the sentence a reader takes
	// as the clean verdict, and the one that was never checked for delivery.
	clean := write("clean.cdx.json", `{"bomFormat":"CycloneDX","components":[
		{"type":"library","name":"clean","version":"1.0.0","purl":"pkg:golang/example.com/clean@1.0.0"}]}`)
	// A covered package beside an unevaluable one reaches the "NOT a clean
	// result" headline, which was written unchecked the same way.
	partial := write("partial.cdx.json", `{"bomFormat":"CycloneDX","components":[
		{"type":"library","name":"no-purl","version":"1.0.0"},
		{"type":"library","name":"clean","version":"1.0.0","purl":"pkg:golang/example.com/clean@1.0.0"}]}`)

	for _, tc := range []struct{ name, target string }{
		{"empty document", empty},
		{"clean scan", clean},
		{"partially evaluated scan", partial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			stdout := failingStdout{err: errors.New("write /dev/stdout: no space left on device")}
			code := Run(context.Background(), dbPath, tc.target, Options{}, stdout, &stderr)
			if code != 2 {
				t.Errorf("Run with an unwritable stdout = %d, want 2\nstderr:\n%s", code, stderr.String())
			}
			// The same line the json and sarif renderers print, with the
			// cause, so a CI log explains the 2 the same way for every format.
			if !strings.Contains(stderr.String(), "error: write report: write /dev/stdout: no space left on device") {
				t.Errorf("stderr lacks the write-report line with its cause:\n%s", stderr.String())
			}
		})
	}
}
