package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// Main QA of 67e2cf6 (2026-11-13), through Run: one apt listed twice, at
// the top level with distro=ubuntu-22.04 and under metadata.component with
// distro=jammy (distinct bom-refs, no operating-system component). The two
// are one install, and the codename one listing states is the install's
// evidence whichever listing comes first: 67e2cf6 kept the top-level purl
// and lost the codename, so jammy, JAMMY and ubuntu-jammy statements that
// applied with the listings the other way round were refused -- 2
// advisories back, exit 1 for one order and 0 for the other. The numeric
// statement applies in both orders; noble in neither.
func TestRun_VEXUbuntuCodenameSurvivesTheMergeOfTwoListings(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	listing := func(ref, distro string) string {
		return `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"` + ref + `","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=` + distro + `"}`
	}
	sbom := func(name, top, nested string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + top + `],` +
			`"metadata":{"component":{"type":"container","name":"subject","components":[` + nested + `]}}}`
		p := filepath.Join(t.TempDir(), name+".cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	orders := map[string]string{
		"numeric first":  sbom("numeric-first", listing("first", "ubuntu-22.04"), listing("second", "jammy")),
		"codename first": sbom("codename-first", listing("first", "jammy"), listing("second", "ubuntu-22.04")),
	}
	for _, tc := range []struct {
		order, statement string
		suppressed       bool
	}{
		{"numeric first", "jammy", true},
		{"numeric first", "JAMMY", true},
		{"numeric first", "ubuntu-jammy", true},
		{"numeric first", "ubuntu-22.04", true},
		{"numeric first", "noble", false},
		{"codename first", "jammy", true},
		{"codename first", "JAMMY", true},
		{"codename first", "ubuntu-jammy", true},
		{"codename first", "ubuntu-22.04", true},
		{"codename first", "noble", false},
	} {
		t.Run(tc.order+", statement "+tc.statement, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, orders[tc.order], Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode || doc.Summary.Evaluated != 1 || doc.Summary.Components != 1 {
				t.Fatalf("suppressed = %v, kept = %v, exit %d, evaluated %d of %d; want suppressed %v, exit %d, one install\nstderr: %s",
					sup[want], kept[want], code, doc.Summary.Evaluated, doc.Summary.Components, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}
