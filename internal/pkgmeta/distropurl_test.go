package pkgmeta

import "testing"

// EVROf's zero-epoch clause was held by nothing in this package until the
// QA 2026-11-02 mutation round: dropping `epoch != "0"` left this suite
// green and was caught only by the two CSAF providers' helper tables, which
// now read their purls through it. The rule is rpmdb's evr(): an epoch is
// written only when present and non-zero, so a "0:" here would hand the
// comparer two spellings of one build.
func TestEVROf(t *testing.T) {
	for _, tc := range []struct {
		purl, want, why string
	}{
		{"pkg:rpm/redhat/nginx@1.30.4-2.hum1?arch=x86_64&epoch=2", "2:1.30.4-2.hum1", "a non-zero epoch is prefixed"},
		{"pkg:rpm/suse/xz@5.6.2-1.1?epoch=0&upstream=xz-5.6.2-1.1.src.rpm", "5.6.2-1.1", "a zero epoch is omitted, as rpmdb omits it"},
		{"pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64", "2.14.3-1.2.hum1", "no epoch qualifier: none is borrowed or assumed"},
		{"pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?epoch=", "2.14.3-1.2.hum1", "an empty epoch qualifier is no epoch"},
		{"pkg:rpm/redhat/nodejs25?arch=src&epoch=2", "", "no version: an epoch is never prefixed onto nothing"},
		{"pkg:rpm/suse/kernel-coco-6.4.0-15061.9.coco15sp6.1@?epoch=1", "", "an empty version (D131's shape) stays empty"},
		{"pkg:deb/debian/bash@5.2.15-2%2Bb7?epoch=1", "1:5.2.15-2+b7", "deb takes the same rule"},
	} {
		p, err := ParsePURL(tc.purl)
		if err != nil {
			t.Fatalf("ParsePURL(%q): %v", tc.purl, err)
		}
		if got := EVROf(p); got != tc.want {
			t.Errorf("EVROf(%q) = %q, want %q -- %s", tc.purl, got, tc.want, tc.why)
		}
	}
}
