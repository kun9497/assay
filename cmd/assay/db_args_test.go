package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/store"
)

// TestRun_DBStatusOutputJSON drives `db status --output json` through run():
// the output is one JSON document on stdout carrying its own schemaVersion,
// and `--output table` (or no flag) is the existing text. The 2026-10-22
// audit found `db status` had no machine-readable form, and that a monitor
// passing --output json got the table instead, silently.
func TestRun_DBStatusOutputJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	buildRunSeamFixture(t, dir)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "status", "--output", "json"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db status --output json = %d, want %d\nstderr:\n%s", code, exitOK, stderr.String())
	}
	var doc struct {
		SchemaVersion int      `json:"schemaVersion"`
		Schema        int      `json:"schema"`
		Ecosystems    []string `json:"ecosystems"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 || doc.Schema != store.SchemaVersion || !slices.Equal(doc.Ecosystems, []string{"Go"}) {
		t.Errorf("document = %+v, want schemaVersion 1, schema %d, ecosystems [Go]", doc, store.SchemaVersion)
	}
	stdout.Reset()
	if code := run([]string{"db", "status", "--output=json"}, &stdout, &stderr); code != exitOK || !strings.HasPrefix(stdout.String(), "{") {
		t.Errorf("db status --output=json = %d, want the JSON document:\n%s", code, stdout.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--output=json stdout is not one JSON document: %v", err)
	}
	if strings.Contains(stdout.String(), "PROVIDER") {
		t.Errorf("the JSON output carries the table:\n%s", stdout.String())
	}

	for _, args := range [][]string{{"db", "status"}, {"db", "status", "--output", "table"}, {"db", "status", "--output=table"}} {
		stdout.Reset()
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("%v = %d, want %d", args, code, exitOK)
		}
		if !strings.Contains(stdout.String(), "PROVIDER") || strings.HasPrefix(stdout.String(), "{") {
			t.Errorf("%v did not print the table:\n%s", args, stdout.String())
		}
	}
}

// TestRun_DBRejectsUnknownArguments: every db subcommand refuses an argument
// it does not take, with exit 2 and the argument named, instead of running
// as though it were absent -- the audit's "db ignores unknown flags". A
// refusal writes nothing to stdout, so a caller piping the JSON gets nothing
// rather than the wrong format.
func TestRun_DBRejectsUnknownArguments(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	buildRunSeamFixture(t, dir)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"db", "status", "--json"}, `"--json"`},
		{[]string{"db", "status", "--output", "yaml"}, `"yaml"`},
		{[]string{"db", "status", "--output"}, "--output requires"},
		{[]string{"db", "status", "--output", "json", "extra"}, `"extra"`},
		{[]string{"db", "ref", "extra"}, `"extra"`},
		// Refused before PullSeed, so no network call is made.
		{[]string{"db", "build", "--seed", "example.test/assay-db:v9", "extra"}, `"extra"`},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(tc.args, &stdout, &stderr); code != exitError {
			t.Errorf("%v = %d, want %d\nstderr:\n%s", tc.args, code, exitError, stderr.String())
		}
		if !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: stderr does not name %s:\n%s", tc.args, tc.want, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("%v: a refusal wrote to stdout:\n%s", tc.args, stdout.String())
		}
	}
}
