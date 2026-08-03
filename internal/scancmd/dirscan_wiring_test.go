package scancmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The end-to-end shape of D26: a polyglot directory reports BOTH ecosystems'
// findings, and names what it did not read.
//
// Before this, the same directory reported the Go packages, said
// "0 not evaluated", and exited 0 while the npm and PyPI findings went
// unmentioned — 3 findings where the same packages as an SBOM gave 27.
func TestRun_DirectoryScanReadsLockfilesAndDisclosesTheRest(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "go.mod",
		"module example.com/poly\n\ngo 1.22\n\nrequire example.com/critical v1.0.0\n")
	writeManifest(t, dir, "package-lock.json",
		`{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},`+
			`"node_modules/example.com/medium":{"version":"1.0.0"}}}`)
	writeManifest(t, dir, "requirements.txt", "Django==3.2.12\n")

	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0", vectors: []string{vecCritical}},
		{id: "GHSA-medium", pkg: "medium", fixed: "2.0.0", vectors: []string{vecMedium}},
	})
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
	}

	// Asserted on the rendered pair, not on "requirements.txt" alone: that
	// filename could appear in any path the scan prints, so a bare Contains
	// would pass from the wrong line.
	if !strings.Contains(errOut.String(), "not read: requirements.txt (") {
		t.Errorf("the scan did not name the manifest it declined to read:\n%s", errOut.String())
	}
	// ...and the reason has to travel with it. A reader told only that
	// something was skipped cannot act on it.
	if !strings.Contains(errOut.String(), "not a lockfile") {
		t.Errorf("the disclosure carries no reason:\n%s", errOut.String())
	}
	// Both ecosystems reached the matcher, which is the half that removes the
	// silent miss. The Go one alone would have passed before this slice.
	for _, want := range []string{"example.com/critical", "example.com/medium"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%s is absent from the report — the scan is still reading one "+
				"manifest and ignoring the other:\n%s", want, out.String())
		}
	}
	// Diagnostics stay off stdout so `--output json | jq` keeps working.
	if strings.Contains(out.String(), "not read:") {
		t.Errorf("the disclosure leaked onto stdout:\n%s", out.String())
	}
}

// The D23 caveat is about go.mod specifically, so a directory without one must
// not claim anything about it — and the count it prints must be go.mod's own,
// not the merged total across every manifest.
func TestRun_TheGoModCaveatIsAccurateOrAbsent(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{})
	lock := `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},` +
		`"node_modules/example.com/medium":{"version":"1.0.0"}}}`

	t.Run("no go.mod, no claim about one", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "package-lock.json", lock)
		var out, errOut bytes.Buffer
		// The exit code is deliberately not asserted here. buildMatrixDB covers
		// only "Go", so the npm package this fixture catalogs is correctly
		// reported as unevaluated and the scan exits 2 (D20) — which is the
		// right answer for this database and says nothing about the subject.
		// What matters is that the scan does not claim anything about a go.mod
		// that is not there.
		Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut)
		// Matched on the caveat's own opening, not on the bare string "go.mod".
		// t.TempDir() derives its path from the test's name, which contains
		// "go.mod", so a bare Contains passes from the scanned path echoed in
		// the first stderr line — the assertion would hold whether or not the
		// caveat was printed. Exactly the wrong-column trap CLAUDE.md records,
		// and it caught this test on its first run.
		if strings.Contains(errOut.String(), "go.mod names ") {
			t.Errorf("the scan printed the go.mod caveat for a directory that has "+
				"none:\n%s", errOut.String())
		}
	})

	t.Run("the count is go.mod's own, not the merged total", func(t *testing.T) {
		dir := t.TempDir()
		// Two modules in go.mod, one package in the lockfile. Printing the
		// merged total would say 3; printing go.mod's own says 2. With equal
		// counts this assertion could not tell the two apart.
		writeManifest(t, dir, "go.mod", "module example.com/poly\n\ngo 1.22\n\n"+
			"require (\n\texample.com/critical v1.0.0\n\texample.com/other v1.0.0\n)\n")
		writeManifest(t, dir, "package-lock.json", lock)
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir, Options{}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "go.mod names 2 module(s)") {
			t.Errorf("the go.mod caveat does not carry go.mod's own count "+
				"(2 modules, not the merged 3):\n%s", errOut.String())
		}
	})
}
