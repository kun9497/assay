package spdx

import (
	"strings"
	"testing"
)

// QA 2026-11-20: call sites whose helpers are tested and which nothing called
// under test.
func TestParse_PurlHelpersAreCalled(t *testing.T) {
	for _, tc := range []struct{ purl, name, version, eco string }{
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "org.apache.logging.log4j:log4j-core", "2.14.1", "Maven"},
		{"pkg:deb/debian/bsdutils@2.33.1-0.1?arch=amd64&distro=debian-10&epoch=1", "bsdutils", "1:2.33.1-0.1", "Debian:10"},
		{"pkg:deb/debian/bsdutils@2.33.1-0.1?ARCH=amd64&DISTRO=debian-10&Epoch=1", "bsdutils", "1:2.33.1-0.1", "Debian:10"},
	} {
		doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-a","name":"a","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + tc.purl + `"}]}]}`
		target, _, err := Parse(strings.NewReader(doc))
		if err != nil || len(target.Packages) != 1 {
			t.Errorf("%s: %d packages, %v", tc.purl, len(target.Packages), err)
			continue
		}
		if p := target.Packages[0]; p.Name != tc.name || p.Version != tc.version || p.Ecosystem != tc.eco {
			t.Errorf("%s: %s %s %s, want %s %s %s", tc.purl, p.Name, p.Version, p.Ecosystem, tc.name, tc.version, tc.eco)
		}
	}
}
