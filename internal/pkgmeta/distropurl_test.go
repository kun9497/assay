package pkgmeta

import "testing"

// QA 2026-11-02 #1: the upstream qualifier's source VERSION reaches Source
// on both distro types, in the shape each qualifier states it. The branches
// the scancmd tests cannot tell apart: a deb source version with an epoch
// arrives intact through ParsePURL's percent-decoding, a bare deb name gives
// no version (D8: the same as the binary's), and an rpm qualifier that is
// not an SRPM file name gives neither a Source nor an Upstream.
func TestResolveDistroPURL_SourceVersionFromUpstream(t *testing.T) {
	tests := []struct {
		purl                     string
		wantSrc, wantVer, wantUp string
	}{
		{"pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=amd64&distro=debian-12&upstream=zlib%401%3A1.2.13.dfsg-1",
			"zlib", "1:1.2.13.dfsg-1", ""},
		{"pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5%2Bdeb12u2",
			"util-linux", "2.38.1-5+deb12u2", ""},
		{"pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
			"openssl", "", ""},
		{"pkg:rpm/fedora/mod_ssl@2.4.62-1.fc40?arch=x86_64&epoch=1&distro=fedora-40&upstream=httpd-2.4.62-1.fc40.src.rpm",
			"httpd", "2.4.62-1.fc40", "httpd-2.4.62-1.fc40.src.rpm"},
		{"pkg:rpm/rhel/python3-perf@5.14.0-1.el9?arch=x86_64&distro=rhel-9.4&upstream=kernel-5.14.0-1.el9.src.rpm",
			"kernel", "5.14.0-1.el9", "kernel-5.14.0-1.el9.src.rpm"},
		{"pkg:rpm/rhel/odd@1.0-1.el9?arch=x86_64&distro=rhel-9.4&upstream=not-a-source-rpm",
			"", "", ""},
	}
	for _, tt := range tests {
		p, err := ParsePURL(tt.purl)
		if err != nil {
			t.Fatalf("ParsePURL(%s): %v", tt.purl, err)
		}
		res := ResolveDistroPURL(p, "", "", false)
		gotSrc, gotVer := "", ""
		if res.Source != nil {
			gotSrc, gotVer = res.Source.Name, res.Source.Version
		}
		if gotSrc != tt.wantSrc || gotVer != tt.wantVer || res.Upstream != tt.wantUp {
			t.Errorf("%s: source %q %q upstream %q, want %q %q %q", tt.purl, gotSrc, gotVer, res.Upstream, tt.wantSrc, tt.wantVer, tt.wantUp)
		}
	}
}

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
