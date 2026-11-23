package scancmd

import (
	"os"
	"path/filepath"
	"testing"
)

// QA 2026-11-20. Three of the four arms of the rule for a language package's
// distro= qualifier ran in no test; two of them hide a finding when broken.
func TestRun_VEXDistroQualifierOnALanguagePackage(t *testing.T) {
	db := vexDB(t, "npm", vexAdv{"GHSA-x", "CVE-2031-1", "x", "2.0.0"})
	doc := func(purl, os string) string {
		meta := ""
		if os != "" {
			meta = `,{"type":"operating-system","name":"alpine","version":"` + os + `"}`
		}
		return `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x","version":"1.0.0","purl":"` + purl + `"}` + meta + `]}`
	}
	const plain = "pkg:npm/x@1.0.0"
	for _, tc := range []struct {
		name, purl, os, statement string
		kept                      bool
	}{
		{"statement narrower than the package", plain, "", plain + "?distro=alpine-3.19", true},
		{"same qualifier, no OS", plain + "?distro=alpine-3.19", "", plain + "?distro=alpine-3.19", false},
		{"same qualifier, same OS", plain + "?distro=alpine-3.19", "3.19", plain + "?distro=alpine-3.19", false},
		{"same qualifier, the OS disagrees", plain + "?distro=alpine-3.19", "3.20", plain + "?distro=alpine-3.19", true},
		{"another qualifier", plain + "?distro=alpine-3.20", "", plain + "?distro=alpine-3.19", true},
	} {
		p := filepath.Join(t.TempDir(), "s.cdx.json")
		if err := os.WriteFile(p, []byte(doc(tc.purl, tc.os)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := provRun(t, db, p, Options{FailOnUnknown: true, VEXFiles: []string{writeVEX(t, stmt("CVE-2031-1", product(tc.statement)))}})
		if want := map[bool]int{true: 1, false: 0}[tc.kept]; code != want {
			t.Errorf("%s: exit %d, want %d%s%s", tc.name, code, want, string(rune(10)), stderr)
		}
	}
}
