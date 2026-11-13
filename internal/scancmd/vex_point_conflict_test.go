package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Linux QA of v0.18.1 (2026-11-13), through Run: a CycloneDX document whose
// operating-system component says Debian 12.10 while the package's purl says
// distro=debian-12.11. The SBOM contradicts itself about the install's point
// release, so neither point-release statement exonerates it and only the
// shared major's does (D121). Both public releases up to v0.18.1 had
// suppressed the finding on the 12.10 statement and exited 0. The control:
// an SBOM whose OS and purl agree on 12.10 takes the 12.10 statement.
func TestRun_VEXPointReleaseStatementsOnAnSBOMThatDeclaresTwo(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0102", "CVE-2031-9102", "sample", "99"})
	want := pair{"example", "CVE-2031-9102"}
	sbom := func(osVersion, purlRelease string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
			`{"type":"operating-system","name":"debian","version":"` + osVersion + `","properties":[` +
			`{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"` + osVersion + `"}]},` +
			`{"type":"library","name":"example","version":"1.0","purl":"pkg:deb/debian/example@1.0?distro=` + purlRelease + `&upstream=sample%407"}]}`
		p := filepath.Join(t.TempDir(), "os-"+osVersion+"-purl-"+purlRelease+".cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	productFor := func(release string) string {
		return product("pkg:deb/debian/example@1.0?distro=" + release + "&upstream=sample%407")
	}
	conflicting, agreeing := sbom("12.10", "debian-12.11"), sbom("12.10", "debian-12.10")
	for _, tc := range []struct {
		name, target, statement string
		suppressed              bool
	}{
		{"OS 12.10, purl 12.11: the local OS's point release does not apply", conflicting, "debian-12.10", false},
		{"OS 12.10, purl 12.11: the purl's point release does not apply", conflicting, "debian-12.11", false},
		{"OS 12.10, purl 12.11: the shared major applies", conflicting, "debian-12", true},
		{"OS 12.10, purl 12.10: the point release applies", agreeing, "debian-12.10", true},
		{"OS 12.10, purl 12.10: another point release does not", agreeing, "debian-12.11", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, stderr := scanVEXJSON(t, db, tc.target, writeVEX(t, stmt("CVE-2031-9102", productFor(tc.statement))))
			sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed {
				t.Fatalf("statement %s: suppressed = %v, kept = %v; want suppressed %v\nstderr: %s", tc.statement, sup[want], kept[want], tc.suppressed, stderr)
			}
			counted := "0 of 1 statement(s) matched no finding"
			if !tc.suppressed {
				counted = "1 of 1 statement(s) matched no finding"
			}
			if !strings.Contains(stderr, counted) {
				t.Fatalf("stderr lacks %q:\n%s", counted, stderr)
			}
		})
	}
}
