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

// PR #322 review, through Run: an etch SBOM spelled as the archive spells
// it. The operating-system component, the purl's distro= or both say 4.0r9,
// and a statement for debian-4.0r9 is a point statement of Debian:4.0 --
// it applies wherever the document names that point (or, under an OS of
// 4.0, where the purl does), and not where it names another point or the
// release alone; the whole-release statement applies throughout.
func TestRun_VEXDebianArchiveRevisionSpelling(t *testing.T) {
	db := vexDB(t, "Debian:4.0", vexAdv{"DSA-2031-1", "CVE-2031-9201", "apt", "0.6.99"})
	want := pair{"apt", "CVE-2031-9201"}
	sbom := func(name, osVersion, purlDistro string) string {
		components := ""
		if osVersion != "" {
			components = `{"type":"operating-system","name":"debian","version":"` + osVersion + `","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"` + osVersion + `"}]},`
		}
		purl := "pkg:deb/debian/apt@0.6.46.4-0.1?arch=amd64"
		if purlDistro != "" {
			purl += "&distro=" + purlDistro
		}
		components += `{"type":"library","name":"apt","version":"0.6.46.4-0.1","purl":"` + purl + `"}`
		p := filepath.Join(t.TempDir(), name+".cdx.json")
		if err := os.WriteFile(p, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[`+components+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	for _, tc := range []struct {
		name, osVersion, purlDistro, statement string
		suppressed                             bool
	}{
		{"OS 4.0r9, purl 4.0r9, statement 4.0r9", "4.0r9", "debian-4.0r9", "debian-4.0r9", true},
		{"OS 4.0r9, purl 4.0, statement 4.0r9", "4.0r9", "debian-4.0", "debian-4.0r9", true},
		{"OS 4.0r9, no purl distro, statement 4.0r9", "4.0r9", "", "debian-4.0r9", true},
		{"OS 4.0r9, statement 4.0r8", "4.0r9", "debian-4.0r9", "debian-4.0r8", false},
		{"OS 4.0r9, statement the whole release", "4.0r9", "debian-4.0r9", "debian-4.0", true},
		{"OS 4.0r9, statement etch", "4.0r9", "debian-4.0r9", "etch", true},
		// The purl alone names the point under an OS of the release: the
		// revision canonicalisation is what relates the two.
		{"OS 4.0, purl 4.0r9, statement 4.0r9", "4.0", "debian-4.0r9", "debian-4.0r9", true},
		{"OS 4.0, purl 4.0, statement 4.0r9", "4.0", "debian-4.0", "debian-4.0r9", false},
		{"no OS, purl 4.0r9, statement 4.0r9", "", "debian-4.0r9", "debian-4.0r9", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, sbom("etch", tc.osVersion, tc.purlDistro), Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9201", product("pkg:deb/debian/apt@0.6.46.4-0.1?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
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
				t.Fatalf("suppressed = %v, kept = %v, exit %d, evaluated %d; want suppressed %v, exit %d\nstderr: %s",
					sup[want], kept[want], code, doc.Summary.Evaluated, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}
