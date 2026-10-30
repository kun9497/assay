package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-10-30, end to end: an npm advisory affecting exactly 1.0.0 and
// 3.0.0, its events listed opens first -- [introduced 1.0.0, introduced
// 3.0.0, last_affected 1.0.0, last_affected 3.0.0]. The walk read that as
// [1.0.0, 3.0.0], so 2.0.0 failed --fail-on critical (exit 1) with a finding
// the advisory does not make. The same SBOM against the same events in
// order is the control.
func TestRun_QA1030_EventOrderDoesNotWidenSingleVersionWindows(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"pt-a","version":"2.0.0","purl":"pkg:npm/pt-a@2.0.0"},` +
		`{"type":"library","name":"pt-b","version":"3.0.0","purl":"pkg:npm/pt-b@3.0.0"},` +
		`{"type":"library","name":"pt-c","version":"4.0.0","purl":"pkg:npm/pt-c@4.0.0"}]}`
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		events []advisory.Event
	}{
		{"opens first", []advisory.Event{{Introduced: "1.0.0"}, {Introduced: "3.0.0"}, {LastAffected: "1.0.0"}, {LastAffected: "3.0.0"}}},
		{"in order", []advisory.Event{{Introduced: "1.0.0"}, {LastAffected: "1.0.0"}, {Introduced: "3.0.0"}, {LastAffected: "3.0.0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vulnerability.db")
			w, err := store.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			var affected []advisory.Affected
			for _, name := range []string{"pt-a", "pt-b", "pt-c"} {
				affected = append(affected, advisory.Affected{Ecosystem: "npm", Name: name, Ranges: []advisory.Range{{
					Type: advisory.RangeSemver, Events: tc.events,
				}}})
			}
			if err := w.Put(advisory.Advisory{
				ID: "QA1030-RANGE-0001", Kind: advisory.KindVulnerability, Database: "GHSA",
				Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: affected,
			}); err != nil {
				t.Fatal(err)
			}
			if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"npm"}}}}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			crit := severity.Critical
			var out, errOut bytes.Buffer
			code := Run(context.Background(), path, sbom, Options{Output: "json", FailOn: &crit, FailOnIncomplete: true}, &out, &errOut)
			var r struct {
				Findings []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
				} `json:"findings"`
			}
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatalf("decode: %v\nstderr: %s", err, errOut.String())
			}
			var found []string
			for _, f := range r.Findings {
				found = append(found, f.Package.Name)
			}
			if !slices.Equal(found, []string{"pt-b"}) || code != 1 {
				t.Errorf("exit %d, findings %v; want exit 1 for pt-b (3.0.0) alone: 2.0.0 and 4.0.0 are outside both single-version windows", code, found)
			}
		})
	}
}
