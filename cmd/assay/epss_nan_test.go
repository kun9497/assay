package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// The 2026-10-22 external review's #6, driven through run() rather than the
// parser alone: with a finding whose EPSS is 0.94, `--fail-on-epss=0.5` exits
// 1, and `--fail-on-epss=NaN` used to print the same finding and exit 0 --
// the gate the user asked for, silently off. A threshold that cannot be
// compared is a scan that cannot be trusted, so it is exit 2 before any scan
// runs, with nothing on stdout (D11: 2 outranks the content of the result).
func TestRun_FailOnEPSSNaNIsRefusedBeforeScanning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	w, err := store.Create(filepath.Join(dir, "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-epss-nan-0001", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Aliases: []string{"CVE-2031-5555"},
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "example.com/exploited",
			Ranges: []advisory.Range{{Type: advisory.RangeSemver,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2031-5555", Source: "EPSS", EPSS: 0.94, EPSSPercentile: 0.99, EPSSModel: "v-test"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sbom := filepath.Join(dir, "target.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"exploited","version":"1.0.0","purl":"pkg:golang/example.com/exploited@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// The control: the gate works on a real threshold.
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", sbom, "--fail-on-epss=0.5"}, &out, &stderr); code != exitFindings {
		t.Fatalf("--fail-on-epss=0.5: exit %d, want %d (stdout %q, stderr %q)", code, exitFindings, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "GHSA-epss-nan-0001") {
		t.Fatalf("--fail-on-epss=0.5: the finding is not in the table:\n%s", out.String())
	}

	for _, v := range []string{"NaN", "nan", "+Inf"} {
		out.Reset()
		stderr.Reset()
		code := run([]string{"scan", sbom, "--fail-on-epss=" + v}, &out, &stderr)
		if code != exitError {
			t.Errorf("--fail-on-epss=%s: exit %d, want %d: a threshold no score compares against must refuse to run, not disable the gate", v, code, exitError)
		}
		if out.Len() != 0 {
			t.Errorf("--fail-on-epss=%s: stdout is not empty -- the scan ran under a dead gate:\n%s", v, out.String())
		}
		if !strings.Contains(stderr.String(), "--fail-on-epss") {
			t.Errorf("--fail-on-epss=%s: stderr does not name the flag:\n%s", v, stderr.String())
		}
	}
}
