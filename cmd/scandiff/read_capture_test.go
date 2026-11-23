package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-20: a capture directory from before the run record. A stale or
// altered capture is refused; a good one, with or without its state, is read.
func TestReadCapture_WithoutARunRecord(t *testing.T) {
	good := []byte(`{"a":1}`)
	for name, tc := range map[string]struct {
		state  *captureState
		failed bool
		want   string
	}{
		"no state":                  {nil, false, ""},
		"matching state":            {&captureState{Result: captureOK, SHA256: sha256Hex(good)}, false, ""},
		"the last run failed":       {&captureState{Result: captureFailed, Reason: "x"}, false, "the last run failed"},
		"altered bytes":             {&captureState{Result: captureOK, SHA256: "00"}, false, "is not the one its state describes"},
		"a marker and no state":     {nil, true, "sits beside a failed-run marker"},
		"a state naming a lost run": {&captureState{RunID: "r", Result: captureOK, SHA256: sha256Hex(good)}, false, "requires the missing run record"},
	} {
		dir := t.TempDir()
		var errOut bytes.Buffer
		if tc.state != nil {
			writeState(&errOut, dir, "x", "assay", *tc.state)
		}
		path, failed := filepath.Join(dir, "x.assay.json"), filepath.Join(dir, "x.assay.failed.json")
		if err := os.WriteFile(path, good, 0o600); err != nil {
			t.Fatal(err)
		}
		if tc.failed {
			if err := os.WriteFile(failed, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		raw, why := readCapture(dir, "x", "assay", nil)
		if tc.want == "" && (why != "" || !bytes.Equal(raw, good)) || tc.want != "" && !strings.Contains(why, tc.want) {
			t.Errorf("%s: %q, want %q", name, why, tc.want)
		}
	}
}
