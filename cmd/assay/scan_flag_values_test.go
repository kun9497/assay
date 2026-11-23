package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-20. Every valued scan flag took the next argument whatever it
// was. For most a swallowed flag failed downstream, but --provenance accepts
// any path: `--provenance $OUT --fail-on-incomplete` with OUT empty wrote a
// sidecar named "--fail-on-incomplete" and ran WITHOUT the gate.
func TestParseScanArgs_AValuedFlagDoesNotTakeAnotherFlagAsItsValue(t *testing.T) {
	for _, flag := range []string{
		"--fail-on", "--vex", "--config", "--output", "--explain", "--timeout",
		"--platform", "--provenance", "--db-max-age", "--db-max-rating-age", "--fail-on-epss",
	} {
		t.Run(flag, func(t *testing.T) {
			_, opts, err := parseScanArgs([]string{"sbom.json", flag, "--fail-on-incomplete"})
			if err == nil {
				t.Fatalf("%s --fail-on-incomplete parsed (FailOnIncomplete=%v); the gate was swallowed as a value", flag, opts.FailOnIncomplete)
			}
			// The two age flags word it "needs a duration"; either way the
			// error names the flag and says a value is missing.
			if !strings.Contains(err.Error(), flag+" requires a value") && !strings.Contains(err.Error(), flag+" needs a ") {
				t.Errorf("err = %v, want it to say %s is missing its value", err, flag)
			}
			// And at the end of the arguments, as before.
			if _, _, err := parseScanArgs([]string{"sbom.json", flag}); err == nil {
				t.Errorf("%s with nothing after it parsed", flag)
			}
		})
	}
	// The gate in question survives when the value is there.
	_, opts, err := parseScanArgs([]string{"sbom.json", "--provenance", "prov.json", "--fail-on-incomplete"})
	if err != nil || opts.ProvenanceFile != "prov.json" || !opts.FailOnIncomplete {
		t.Errorf("opts = %+v, err = %v; want the sidecar path and the gate", opts, err)
	}
	// A value that really begins with dashes is still expressible.
	_, opts, err = parseScanArgs([]string{"sbom.json", "--provenance=--odd-name.json"})
	if err != nil || opts.ProvenanceFile != "--odd-name.json" {
		t.Errorf("--provenance=--odd-name.json: opts = %+v, err = %v", opts, err)
	}
}

// --provenance writes its file, so naming the scan target would overwrite
// the document being scanned.
func TestParseScanArgs_ProvenanceMayNotNameTheTarget(t *testing.T) {
	for _, args := range [][]string{
		{"sbom.json", "--provenance", "sbom.json"},
		{"--provenance", "./sbom.json", "sbom.json"},
		{"dir/../sbom.json", "--provenance=sbom.json"},
	} {
		if _, _, err := parseScanArgs(args); err == nil || !strings.Contains(err.Error(), "names the scan target itself") {
			t.Errorf("%v: err = %v, want a refusal", args, err)
		}
	}
	if _, _, err := parseScanArgs([]string{"sbom.json", "--provenance", "sbom.json.prov"}); err != nil {
		t.Errorf("a different file was refused: %v", err)
	}
}

// Through run(): the command line that used to drop the gate now exits 2
// before anything is scanned or written.
func TestRun_ProvenanceWithNoValueDoesNotRunTheScan(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", sbom, "--provenance", "--fail-on-incomplete"}, &stdout, &stderr); code != exitError {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--provenance requires a value") {
		t.Errorf("stderr does not say why:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "--fail-on-incomplete")); err == nil {
		t.Error("a sidecar named after the swallowed flag was written")
	}
}
