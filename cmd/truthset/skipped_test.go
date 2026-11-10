package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-10: a comparison the scan skipped for the label's package can
// leave the label's CVE unjudged. Each row is one package, one label; the
// skip, when there is one, is the scan's own record. Live and -offline must
// agree, so every row is judged twice.
func TestRun_QA1110_SkippedComparisonIsNotAVerdict(t *testing.T) {
	const purl = "pkg:golang/example.com/partial@v1.0.0"
	skip := func(id string, cves ...string) map[string]any {
		m := map[string]any{"package": map[string]any{"name": "example.com/partial"}, "advisoryId": id, "reason": "bound unreadable", "cause": "advisory"}
		if len(cves) > 0 {
			m["cves"] = cves
		}
		return m
	}
	hit := fakeFinding{name: "example.com/partial", id: "GO-2031-0001", aliases: []string{"CVE-2031-9100"}, fixed: "1.0.1", fixState: "fixed"}
	other := fakeFinding{name: "example.com/partial", id: "GO-2031-0002", aliases: []string{"CVE-2031-9200"}, fixed: "1.0.2", fixState: "fixed"}
	for _, tc := range []struct {
		name, state, fixed string
		scan               fakeScan
		want, detail       string
	}{
		// The QA's capture: another advisory evaluated, the label's CVE skipped.
		{"clean label, its CVE skipped", "clean", "", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "UNEVALUATED", "not reported, but the scan skipped CVE-2031-9100"},
		{"clean label, a GHSA naming its CVE skipped", "clean", "", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{skip("GHSA-aaaa-bbbb-cccc", "CVE-2031-9100")}}, "UNEVALUATED", "which names CVE-2031-9100"},
		{"affected label, its CVE skipped", "affected", "1.0.1", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "UNEVALUATED", "not reported, but"},
		// A capture from before schema 21: the skip is an ALAS-shaped id with
		// no cves list, so it cannot be ruled out.
		{"old capture, unidentified skip", "clean", "", fakeScan{schema: 20, findings: []fakeFinding{other}, skipped: []map[string]any{skip("ALAS2031-0001")}}, "UNEVALUATED", "does not say which CVEs it names"},
		// Before schema 21 even another CVE's skip may alias the label's.
		{"old capture, another CVE skipped", "clean", "", fakeScan{schema: 20, findings: []fakeFinding{other}, skipped: []map[string]any{skip("CVE-2031-0001")}}, "UNEVALUATED", "does not say which CVEs it names"},
		// From schema 21 an absent cves list means the advisory names no CVE.
		{"schema 21, a GHSA naming no CVE skipped", "clean", "", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{skip("GHSA-noid-noid-noid")}}, "TN", ""},
		{"whole-package skip", "clean", "", fakeScan{evaluated: 1, skipped: []map[string]any{skip("")}}, "UNEVALUATED", "skipped the whole package"},
		// Controls: a skip about another CVE changes nothing.
		{"control: skip names another CVE", "clean", "", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{skip("GHSA-dddd-eeee-ffff", "CVE-2031-9300")}}, "TN", ""},
		{"control: no skip", "clean", "", fakeScan{findings: []fakeFinding{other}}, "TN", ""},
		// A skip that names the label's CVE but on another package of the
		// scan is about that package, not this one.
		{"control: the CVE skipped on another package", "clean", "", fakeScan{findings: []fakeFinding{other}, skipped: []map[string]any{{"package": map[string]any{"name": "example.com/other"}, "advisoryId": "CVE-2031-9100", "reason": "r", "cause": "advisory"}}}, "TN", ""},
		// A finding proves the label's CVE affected: the verdict stands...
		{"affected, proven, no fix demanded", "affected", "", fakeScan{findings: []fakeFinding{hit}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "TP", ""},
		// ...but a fix the label demands cannot be confirmed past the skip.
		{"affected, proven, fix demanded", "affected", "1.0.1", fakeScan{findings: []fakeFinding{hit}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "FIX-UNKNOWN", "so the fixed version is undetermined"},
		// A finding naming a different fix is a mismatch, skip or not.
		{"affected, proven, a different fix", "affected", "1.0.9", fakeScan{findings: []fakeFinding{hit}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "MISMATCH", `fixed="1.0.1", label says "1.0.9"`},
		// A confirmed false positive is not hidden by a skip.
		{"clean label reported anyway", "clean", "", fakeScan{findings: []fakeFinding{hit}, skipped: []map[string]any{skip("CVE-2031-9100")}}, "FP", "label says clean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := label("partial", "go", purl, "example.com/partial", "v1.0.0", "CVE-2031-9100", tc.state, tc.fixed)
			labels := writeLabels(t, []Label{l})
			exec, _ := fakeAssay(t, map[string]fakeScan{purl: tc.scan})
			keep := filepath.Join(t.TempDir(), "keep")
			var live, errOut bytes.Buffer
			liveCode := run([]string{"-labels", labels, "-assay", "fake-assay", "-keep", keep}, &live, &errOut, exec)
			var off bytes.Buffer
			offCode := run([]string{"-labels", labels, "-offline", keep}, &off, &errOut, func(string, ...string) ([]byte, int, error) {
				t.Fatal("offline ran assay")
				return nil, 0, nil
			})
			if live.String() != off.String() || liveCode != offCode {
				t.Fatalf("live and offline differ:\n%s(exit %d)\n--\n%s(exit %d)", live.String(), liveCode, off.String(), offCode)
			}
			got := live.String()
			if tc.want == "TN" || tc.want == "TP" {
				if strings.Contains(got, "did not hold") {
					t.Errorf("want %s, got a failure:\n%s", tc.want, got)
				}
				if liveCode != exitOK {
					t.Errorf("exit = %d, want 0", liveCode)
				}
				return
			}
			if !strings.Contains(got, tc.want) || !strings.Contains(got, tc.detail) {
				t.Errorf("want %s with %q:\n%s", tc.want, tc.detail, got)
			}
			if liveCode != exitFindings {
				t.Errorf("exit = %d, want 1", liveCode)
			}
		})
	}
}

// The QA's own capture, re-judged offline: TN before, UNEVALUATED now.
func TestRun_QA1110_PartialCapture(t *testing.T) {
	dir := filepath.Join("testdata", "qa1110-partial")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("capture not present")
	}
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", filepath.Join(dir, "partial.labels.json"), "-offline", dir}, &out, &errOut, nil)
	if code != exitFindings || !strings.Contains(out.String(), "UNEVALUATED partial/CVE-2031-9100") {
		t.Errorf("exit = %d:\n%s", code, out.String())
	}
}
