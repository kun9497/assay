package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// QA 2026-11-02 P3 #7: the --fail-on-incomplete verdict was the one exit 2
// that printed no `error:` line, so a CI log showed a bare exit code while
// the sibling unread-manifest branch said what fired. The provenance recorder
// carried a private reason for it that named --fail-on-incomplete even when
// =target had fired. Now one line, in the sibling's shape, names the flag
// form that fired; the sidecar reads it like every other exit 2.
func TestRun_FailOnIncompletePrintsAnErrorLineNamingTheFlagForm(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	// Three components: the covered Go package, an npm package this database
	// does not cover (not evaluated: assay's coverage, not the caller's), and
	// a component with no version (not evaluated AND the target's own, so
	// the narrow gate fires on it too).
	path := filepath.Join(dir, "s.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"` + provPkg + `","version":"1.0.0","purl":"` + provPURL + `"},` +
		`{"type":"library","name":"left-pad","version":"1.0.0","purl":"pkg:npm/left-pad@1.0.0"},` +
		`{"type":"library","name":"unpinned","purl":"pkg:golang/example.com/unpinned"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts Options
		line string
	}{
		{"broad", Options{Output: "json", FailOnIncomplete: true},
			"error: 2 package(s) not evaluated and 0 check(s) incomplete (--fail-on-incomplete)\n"},
		{"target", Options{Output: "json", FailOnIncompleteTarget: true},
			"error: 1 package(s) or manifest(s) of the target itself not evaluated (--fail-on-incomplete=target)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, stderr, code := provRun(t, db, path, tc.opts)
			if code != 2 {
				t.Fatalf("Run = %d, want 2\nstderr: %s", code, stderr)
			}
			if !strings.Contains(stderr, tc.line) {
				t.Errorf("stderr lacks the verdict's error line %q:\n%s", tc.line, stderr)
			}
			// Diagnostics went to stderr only: the report is still the whole
			// of stdout.
			var d report.Document
			if err := json.Unmarshal([]byte(out), &d); err != nil {
				t.Errorf("stdout is not the JSON report alone: %v\n%s", err, out)
			}
		})
	}
	// Without a gate the same scan says nothing on the error channel: the
	// line belongs to the verdict, not to incompleteness itself.
	_, stderr, code := provRun(t, db, path, Options{Output: "json"})
	if code != 0 {
		t.Fatalf("Run with no gate = %d, want 0\nstderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "error:") {
		t.Errorf("an ungated scan printed an error line:\n%s", stderr)
	}
}

// QA 2026-11-02 P3 #11: with every finding waived AND something not
// evaluated, the headline took the incomplete branch and said "No
// vulnerabilities found ... NOT a clean result" over a Suppressed block that
// listed one. The incomplete sentence now says the findings were waived.
func TestRun_TableHeadlineWhenEveryFindingIsWaivedAndSomethingWasNotChecked(t *testing.T) {
	db := waiverDB(t, "npm", "wv-lib")
	// wv-lib is matched and waived; the cargo package is in an ecosystem this
	// database does not cover, so it is not evaluated.
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"wv-lib","version":"1.0.0","purl":"pkg:npm/wv-lib@1.0.0"},` +
		`{"type":"library","name":"unchecked","version":"1.0.0","purl":"pkg:cargo/unchecked@1.0.0"}]}`
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), ".assay.yaml")
	if err := os.WriteFile(cfg, []byte("ignore:\n  - vulnerability: CVE-2026-90001\n    reason: wv ignore reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{IgnoreFile: cfg}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	first, _, _ := strings.Cut(out.String(), "\n")
	want := "No unwaived vulnerabilities found in 1 package(s) (1 suppressed), but 1 package(s) were not checked at all - this is NOT a clean result."
	if first != want {
		t.Errorf("headline = %q, want %q", first, want)
	}
	if !strings.Contains(out.String(), "wv-lib  npm  GHSA-wv01-0000-0001  (ignore-file: wv ignore reason)") {
		t.Errorf("table = %q, want the suppressed block to list the finding", out.String())
	}
}

// QA 2026-11-02 P3 #23: an empty --config meant "discover .assay.yaml in
// the working directory", and nothing turned discovery off, so a scan run
// from a directory the operator does not control applied whatever waiver
// list it found there. `--config none` applies no ignore file at all and the
// provenance says so.
func TestRun_ConfigNoneAppliesNoIgnoreFile(t *testing.T) {
	db := waiverDB(t, "npm", "wv-lib")
	sbom := waiverSBOM(t)
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, ".assay.yaml"),
		[]byte("ignore:\n  - vulnerability: CVE-2026-90001\n    reason: planted in the working directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	run := func(t *testing.T, opts Options) report.Document {
		t.Helper()
		opts.Output = "json"
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, sbom, opts, &out, &errOut); code != 0 {
			t.Fatalf("Run(%+v) = %d\nstderr: %s", opts, code, errOut.String())
		}
		var d report.Document
		if err := json.Unmarshal(out.Bytes(), &d); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
		}
		return d
	}
	// The contrast that gives the assertion below its meaning: with no
	// --config the planted file is discovered and waives the finding.
	if d := run(t, Options{}); len(d.Suppressed) != 1 || len(d.Findings) != 0 {
		t.Fatalf("no --config: %d suppressed, %d findings; the planted file was not discovered, so this test proves nothing",
			len(d.Suppressed), len(d.Findings))
	}
	d := run(t, Options{IgnoreFile: IgnoreNone})
	if len(d.Suppressed) != 0 || len(d.Findings) != 1 {
		t.Errorf("--config none: %d suppressed, %d findings; want the planted file ignored", len(d.Suppressed), len(d.Findings))
	}
	if d.Provenance == nil {
		t.Fatal("the JSON report carries no provenance")
	}
	f := d.Provenance.Waivers.IgnoreFile
	if f == nil || f.Path != IgnoreNone || f.Discovered || len(f.Rules) != 0 {
		t.Errorf("provenance.waivers.ignoreFile = %+v, want path %q, not discovered, no rules", f, IgnoreNone)
	}
}
