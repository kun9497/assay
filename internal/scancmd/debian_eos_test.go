package scancmd

import (
	"os"
	"path/filepath"
	"testing"
)

// Main QA of ef0bc1a (2026-11-13), through Run: a CycloneDX document with no
// operating-system component whose purl names an end-of-support Debian by
// codename. etch, lenny and squeeze are keyed to the two-part keys the store
// spells them with (Debian:4.0, 5.0, 6.0) and judged; wheezy on the bare
// major as before.
func TestRun_DebianEOSCodenamesReachTheirKeys(t *testing.T) {
	for _, tc := range []struct{ codename, key string }{
		{"etch", "Debian:4.0"}, {"lenny", "Debian:5.0"}, {"squeeze", "Debian:6.0"}, {"wheezy", "Debian:7"}, {"jessie", "Debian:8"}, {"stretch", "Debian:9"},
	} {
		t.Run(tc.codename, func(t *testing.T) {
			db := vexDB(t, tc.key, vexAdv{"DEBIAN-2031-0107", "CVE-2031-9107", "apt", "99"})
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
				`{"type":"library","name":"apt","version":"0.7.20.2","purl":"pkg:deb/debian/apt@0.7.20.2?arch=amd64&distro=` + tc.codename + `"}]}`
			p := filepath.Join(t.TempDir(), tc.codename+".cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			rep, stderr := scanVEXJSON(t, db, "sbom:"+p)
			eco := ""
			if len(rep.Findings) == 1 {
				eco = rep.Findings[0].Package.Ecosystem
			}
			if rep.Summary.Evaluated != 1 || eco != tc.key {
				t.Fatalf("evaluated %d, findings %v (ecosystem %q); want apt judged under %s\nstderr: %s", rep.Summary.Evaluated, pairsOf(rep.Findings), eco, tc.key, stderr)
			}
		})
	}
}
