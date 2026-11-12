package scancmd

import (
	"path/filepath"
	"strings"
	"testing"
)

// Release review of v0.18.0 (2026-11-12). A Debian image's OS packages carry
// `distro=debian-12` -- os-release's VERSION_ID is the bare major -- while an
// OpenVEX document produced from the image's syft SBOM (the usual way such a
// document is made) spells syft's point release, `distro=debian-12.11`. PR
// #294's rule that a point-release statement needs the point release on the
// installed side had silently dropped every such statement on every Debian
// image ("N of N statement(s) matched no finding", the findings kept,
// --fail-on exit 1 where v0.17.0 exited 0): a regression against D121, which
// is that VEX reaches an image's OS packages. The statement applies when the
// installed release names the statement's major and nothing finer; a
// statement for another major still matches nothing. Goes red when Matches
// stops accepting the broader installed qualifier.
func TestRun_VEXPointReleaseStatementReachesADebianImageSpellingTheMajor(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0101", "CVE-2031-9101", "openssl", "3.0.99-1"})
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc})
	target := "docker-archive:" + p
	const libssl3 = "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12.11&upstream=openssl"

	t.Run("syft's point release applies", func(t *testing.T) {
		doc, stderr := scanVEXJSON(t, db, target, writeVEX(t, stmt("CVE-2031-9101", product(libssl3))))
		sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
		if !sup[pair{"libssl3", "CVE-2031-9101"}] || kept[pair{"libssl3", "CVE-2031-9101"}] {
			t.Fatalf("libssl3 not suppressed by the debian-12.11 statement: suppressed = %v, kept = %v\nstderr: %s", sup, kept, stderr)
		}
		if !strings.Contains(stderr, "0 of 1 statement(s) matched no finding") {
			t.Fatalf("stderr does not count the statement as matched:\n%s", stderr)
		}
	})
	t.Run("another major's point release does not", func(t *testing.T) {
		other := strings.Replace(libssl3, "debian-12.11", "debian-11.11", 1)
		doc, stderr := scanVEXJSON(t, db, target, writeVEX(t, stmt("CVE-2031-9101", product(other))))
		if sup := suppressedPairs(doc); sup[pair{"libssl3", "CVE-2031-9101"}] {
			t.Fatalf("a Debian 11 statement suppressed the Debian 12 install\nstderr: %s", stderr)
		}
		if !strings.Contains(stderr, "1 of 1 statement(s) matched no finding") {
			t.Fatalf("stderr does not say the statement matched nothing:\n%s", stderr)
		}
	})
}
