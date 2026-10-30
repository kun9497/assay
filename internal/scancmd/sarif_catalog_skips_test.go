package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 2026-10-22 audit A16: SARIF's not-evaluated results came only from the
// matcher's skips. Components the cataloger could not turn into packages --
// no purl, no version, an ecosystem assay does not cover -- produced no
// result, so GitHub code scanning showed a clean scan where the table said N
// not evaluated. D158: one result per nonzero cataloger counter, with its
// count, at warning for what the target can fix (no purl, no version; both
// count toward targetIncomplete, D36) and note for assay's own coverage (an
// unsupported ecosystem).
func TestRun_D158_SARIFCarriesComponentsTheCatalogerCouldNotRead(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"noversion-fixture","purl":"pkg:npm/noversion-fixture"},` +
		`{"type":"library","name":"nopurl-fixture","version":"1.0.0"},` +
		`{"type":"library","name":"nopurl2-fixture","version":"2.0.0"},` +
		`{"type":"library","name":"swift-fixture","version":"1.0.0","purl":"pkg:swift/example.com/swift-fixture@1.0.0"}]}`
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	Run(context.Background(), testDB(t), sbom, Options{Output: "sarif"}, &out, &errOut)

	var s struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("decode: %v\n%s\nstderr: %s", err, out.String(), errOut.String())
	}
	run := s.Runs[0]
	got := map[string]string{}
	for _, r := range run.Results {
		if r.RuleID == "assay/not-evaluated" {
			got[r.Message.Text] = r.Level
		}
	}
	for _, want := range []struct{ text, level string }{
		{"1 package(s) with no version to compare were not evaluated", "warning"},
		{"2 component(s) without a usable purl were not evaluated", "warning"},
		{"1 package(s) in an unsupported ecosystem were not evaluated", "note"},
	} {
		if lvl, ok := got[want.text]; !ok || lvl != want.level {
			t.Errorf("no %s result %q (got %v)", want.level, want.text, got)
		}
	}
	declared := false
	for _, r := range run.Tool.Driver.Rules {
		declared = declared || r.ID == "assay/not-evaluated"
	}
	if !declared {
		t.Error("results name assay/not-evaluated but the driver declares no such rule (D55)")
	}
	if strings.Count(out.String(), `"ruleId": "assay/not-evaluated"`)+strings.Count(out.String(), `"ruleId":"assay/not-evaluated"`) != 3 {
		t.Errorf("want exactly 3 not-evaluated results, one per counter:\n%s", out.String())
	}
}
