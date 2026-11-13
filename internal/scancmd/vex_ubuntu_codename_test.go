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

// Main QA of ef0bc1a (2026-11-13), through Run with a gate the one unrated
// fixture advisory trips (--fail-on-unknown; the QA's --fail-on high trips
// on the rated production data): an Ubuntu SBOM with no
// operating-system component whose install purl says distro=ubuntu-22.04,
// and statements that differ only in how they spell the release. A codename
// statement needs codename evidence in the scan, whatever its case or
// prefix, so jammy, JAMMY and ubuntu-jammy are all refused here (ef0bc1a
// refused jammy and accepted the other two: exit 1 against 0 on one
// document); the numeric ubuntu-22.04 applies and noble does not. With the
// install purl spelling the codename, every spelling applies.
func TestRun_VEXUbuntuCodenameSpellingsAgreeOnTheEvidenceRule(t *testing.T) {
	db := vexDB(t, "Ubuntu:22.04:LTS", vexAdv{"UBUNTU-2031-0106", "CVE-2031-9106", "apt", "2.4.99"})
	want := pair{"apt", "CVE-2031-9106"}
	sbom := func(purlDistro string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
			`{"type":"library","name":"apt","version":"2.4.14","purl":"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=` + purlDistro + `"}]}`
		p := filepath.Join(t.TempDir(), "ubuntu-"+purlDistro+".cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	productFor := func(distro string) string {
		return product("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=" + distro)
	}
	for _, tc := range []struct {
		name, purlDistro, statement string
		suppressed                  bool
	}{
		{"numeric purl, jammy statement", "ubuntu-22.04", "jammy", false},
		{"numeric purl, JAMMY statement", "ubuntu-22.04", "JAMMY", false},
		{"numeric purl, ubuntu-jammy statement", "ubuntu-22.04", "ubuntu-jammy", false},
		{"numeric purl, ubuntu-22.04 statement", "ubuntu-22.04", "ubuntu-22.04", true},
		{"numeric purl, noble statement", "ubuntu-22.04", "noble", false},
		{"codename purl, jammy statement", "jammy", "jammy", true},
		{"codename purl, JAMMY statement", "jammy", "JAMMY", true},
		{"codename purl, ubuntu-jammy statement", "jammy", "ubuntu-jammy", true},
		{"codename purl, ubuntu-22.04 statement", "jammy", "ubuntu-22.04", true},
		{"codename purl, noble statement", "jammy", "noble", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, sbom(tc.purlDistro), Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9106", productFor(tc.statement)))}}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode || doc.Summary.Evaluated != 1 {
				t.Fatalf("statement %s on purl %s: suppressed = %v, kept = %v, exit %d, evaluated %d; want suppressed %v, exit %d\nstderr: %s",
					tc.statement, tc.purlDistro, sup[want], kept[want], code, doc.Summary.Evaluated, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}
