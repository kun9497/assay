package vex

import (
	"testing"

	"github.com/kun9497/assay/internal/matcher"
)

// A marked deb source statement compares the document's version against the
// package's Source.Version when there is one, and against the binary's own
// only when there is none (D8's "empty means the same"). Until QA 2026-11-02
// #1 an SBOM's deb package never had one, so the fallback was the only path
// that ran on SBOM input and a statement at the real source version applied
// to nothing. Held here where the scancmd test cannot: a package with no
// source version still answers to the binary's.
func TestApply_DebSourceStatementComparesTheSourceVersion(t *testing.T) {
	const binary = "1:2.38.1-5+deb12u3"
	withSource := osFinding("CVE-2031-7001", "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5%2Bdeb12u2",
		"bsdutils", binary, "util-linux", "2.38.1-5+deb12u2")
	noSourceVersion := osFinding("CVE-2031-7001", "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=util-linux",
		"bsdutils", binary, "util-linux", "")
	tests := []struct {
		name string
		prod string
		f    matcher.Finding
		want bool
	}{
		{"at the source version", "pkg:deb/debian/util-linux@2.38.1-5+deb12u2?arch=source", withSource, true},
		{"at the binary's version, which is not the source's", "pkg:deb/debian/util-linux@1:2.38.1-5+deb12u3?arch=source", withSource, false},
		{"no source version: the binary's answers", "pkg:deb/debian/util-linux@1:2.38.1-5+deb12u3?arch=source", noSourceVersion, true},
		{"no source version: the source's does not", "pkg:deb/debian/util-linux@2.38.1-5+deb12u2?arch=source", noSourceVersion, false},
	}
	for _, tt := range tests {
		_, sup, _ := doc1(Product{PURLAttr: tt.prod}).Apply([]matcher.Finding{tt.f}, Target{}, func(string) {})
		if got := len(sup) == 1; got != tt.want {
			t.Errorf("%s: suppressed = %v, want %v", tt.name, got, tt.want)
		}
	}
}
