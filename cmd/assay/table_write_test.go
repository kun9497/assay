package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unwritableStdout refuses every write: a closed pipe, a full disk, a handle
// opened read-only. QA 2026-11-02 found, and QA 2026-11-04 reproduced on main
// 1284b32 with the real binary, that `assay scan <clean sbom>` with such a
// stdout exited 0 having written nothing -- the default table renderer wrote
// its clean headline unchecked -- while `--output json` and `--output sarif`
// exited 2 with "error: write report". A CI job that redirects the table to a
// file it cannot write read an absent report as a pass.
type unwritableStdout struct{}

func (unwritableStdout) Write([]byte) (int, error) {
	return 0, errors.New("write /dev/stdout: no space left on device")
}

// TestRun_TableWriteFailureReachesRealExitCode holds the whole path a
// customer runs -- run() -> scan() -> scancmd.Run -> report.Table -- to exit
// 2 when the table cannot be written, on the inputs whose table carries no
// findings row: the ones that used to exit 0. The JSON row beside them
// already exited 2 and is here so the three formats are held to one answer.
func TestRun_TableWriteFailureReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	// The fixture's database declares Go, so the clean package below is
	// evaluated and prints the clean headline; its own SBOM is not used.
	buildRunSeamFixture(t, dir)
	empty := filepath.Join(dir, "empty.cdx.json")
	if err := os.WriteFile(empty, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.cdx.json")
	if err := os.WriteFile(clean, []byte(`{"bomFormat":"CycloneDX","components":[
		{"type":"library","name":"clean","version":"1.0.0","purl":"pkg:golang/example.com/clean@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"empty document, table", []string{"scan", empty}},
		{"clean scan, table", []string{"scan", clean}},
		{"clean scan, table, --fail-on high", []string{"scan", clean, "--fail-on", "high"}},
		{"clean scan, json", []string{"scan", clean, "--output", "json"}},
		{"clean scan, sarif", []string{"scan", clean, "--output", "sarif"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(tc.args, unwritableStdout{}, &stderr)
			if code != exitError {
				t.Errorf("run(%v) with an unwritable stdout = %d, want %d\nstderr:\n%s",
					tc.args, code, exitError, stderr.String())
			}
			if !strings.Contains(stderr.String(), "error: write report:") ||
				!strings.Contains(stderr.String(), "no space left on device") {
				t.Errorf("stderr lacks the write-report line with its cause:\n%s", stderr.String())
			}
		})
	}
}
