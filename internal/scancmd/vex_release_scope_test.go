package scancmd

import (
	"path/filepath"
	"strings"
	"testing"
)

// Independent review of v0.18.0 (2026-11-12). syft spells a Debian image's
// release from /etc/debian_version -- `distro=debian-12.11` -- where
// os-release's VERSION_ID is the bare major, so an OpenVEX document written
// from the image's syft SBOM (the usual way) spells the point release. The
// image path spells it the same way now (D121 parity; Distro.PointRelease),
// so a statement for the image's own point release applies, one for another
// point release of the same major does not (v0.18.0 had accepted it against
// the major alone), and one for another major does not. An image without
// /etc/debian_version spells the major and a point-release statement does
// not reach it: no evidence, no exemption. Goes red when the image path stops
// reading debian_version or the matcher accepts the major alone again.
func TestRun_VEXPointReleaseStatementsOnADebianImage(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0101", "CVE-2031-9101", "openssl", "3.0.99-1"})
	want := pair{"libssl3", "CVE-2031-9101"}
	purl := func(release string) string {
		return "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=" + release + "&upstream=openssl"
	}
	image := func(files map[string]string) string {
		p := filepath.Join(t.TempDir(), "image.tar")
		writeImageTar(t, p, files)
		return "docker-archive:" + p
	}
	withPoint := image(map[string]string{osReleasePath: osReleaseDebian12Bookworm, debianVersionPath: "12.11\n", dpkgDBPath: dpkgOpensslAndGlibc})
	majorOnly := image(map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc})

	for _, tc := range []struct {
		name, target, statement, spelled string
		suppressed                       bool
	}{
		{"the image's own point release applies", withPoint, "debian-12.11", "debian-12.11", true},
		{"its major applies", withPoint, "debian-12", "debian-12.11", true},
		{"another point release of the major does not", withPoint, "debian-12.10", "debian-12.11", false},
		{"another major does not", withPoint, "debian-11.11", "debian-12.11", false},
		{"no debian_version: the major is spelled and a point-release statement does not reach it", majorOnly, "debian-12.11", "debian-12", false},
		{"no debian_version: the major's statement applies", majorOnly, "debian-12", "debian-12", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, stderr := scanVEXJSON(t, db, tc.target, writeVEX(t, stmt("CVE-2031-9101", product(purl(tc.statement)))))
			spelled := false
			for _, f := range doc.Findings {
				if strings.Contains(f.Package.PURL, "distro="+tc.spelled+"&") {
					spelled = true
				}
			}
			for _, s := range doc.Suppressed {
				if strings.Contains(s.Package.PURL, "distro="+tc.spelled+"&") {
					spelled = true
				}
			}
			if !spelled {
				t.Fatalf("no libssl3 purl spelled distro=%s\nfindings: %+v\nsuppressed: %+v", tc.spelled, pairsOf(doc.Findings), suppressedPairs(doc))
			}
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
