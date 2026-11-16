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

// Main QA of f554fb2 (2026-11-13), through Run: lenny and squeeze spell
// their point releases with three numbers (5.0.10, 6.0.10), so an "r"
// spelling of them is no release and a statement written with one exempts
// nothing -- it had read 6.0r10 as 6.0.10 and suppressed a squeeze install's
// advisory. The official spelling still applies, another point does not, and
// etch's own 4.0r9 is untouched.
func TestRun_VEXDebianRevisionSpellingIsNotAnAliasAfterEtch(t *testing.T) {
	for _, tc := range []struct {
		name, key, osVersion, pkgVersion, statement string
		suppressed                                  bool
	}{
		{"squeeze 6.0.10, statement 6.0r10", "Debian:6.0", "6.0.10", "0.8.10.3+squeeze2", "debian-6.0r10", false},
		{"squeeze 6.0.10, statement 6.0r9", "Debian:6.0", "6.0.10", "0.8.10.3+squeeze2", "debian-6.0r9", false},
		{"squeeze 6.0.10, statement 6.0.10", "Debian:6.0", "6.0.10", "0.8.10.3+squeeze2", "debian-6.0.10", true},
		{"squeeze 6.0.10, statement 6.0.9", "Debian:6.0", "6.0.10", "0.8.10.3+squeeze2", "debian-6.0.9", false},
		{"lenny 5.0.10, statement 5.0r10", "Debian:5.0", "5.0.10", "0.7.20.2+lenny2", "debian-5.0r10", false},
		{"lenny 5.0.10, statement 5.0.10", "Debian:5.0", "5.0.10", "0.7.20.2+lenny2", "debian-5.0.10", true},
		{"etch 4.0r9, statement 4.0r9", "Debian:4.0", "4.0r9", "0.6.46.4-0.1", "debian-4.0r9", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := vexDB(t, tc.key, vexAdv{"DSA-2031-2", "CVE-2031-9202", "apt", "9.9"})
			want := pair{"apt", "CVE-2031-9202"}
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
				`{"type":"operating-system","name":"debian","version":"` + tc.osVersion + `","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"` + tc.osVersion + `"}]},` +
				`{"type":"library","name":"apt","version":"` + tc.pkgVersion + `","purl":"pkg:deb/debian/apt@` + tc.pkgVersion + `?arch=amd64&distro=debian-` + tc.osVersion + `"}]}`
			p := filepath.Join(t.TempDir(), "sbom.cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "sbom:"+p, Options{Output: "json", FailOnUnknown: true, FailOnIncompleteTarget: true,
				VEXFiles: []string{writeVEX(t, stmt("CVE-2031-9202", product("pkg:deb/debian/apt@"+tc.pkgVersion+"?arch=amd64&distro="+tc.statement)))}}, &out, &errOut)
			var rep report.Document
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\nstderr: %s", err, errOut.String())
			}
			sup, kept := suppressedPairs(rep), pairsOf(rep.Findings)
			wantCode := 1
			if tc.suppressed {
				wantCode = 0
			}
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed || code != wantCode {
				t.Fatalf("suppressed = %v, kept = %v, exit %d; want suppressed %v, exit %d\nstderr: %s",
					sup[want], kept[want], code, tc.suppressed, wantCode, errOut.String())
			}
		})
	}
}
