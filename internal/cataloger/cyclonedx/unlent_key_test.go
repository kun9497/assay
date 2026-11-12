package cyclonedx

import (
	"strings"
	"testing"
)

// Release review of v0.18.0 (2026-11-12). A bare top-level listing that
// contradicts every install it could be is reported as its own unjudged
// listing (D165), keyed as its twins are. Its key had come from whichever
// install the listing matched FIRST -- the document's order -- and with one
// install keyed and the other not, the unlent listing carried `Debian:11` in
// one order and no key in the other, which turned its skip from the target's
// (exit 2 under --fail-on-incomplete=target) into nobody's (exit 0). The key
// is now the one release the identity's installs are keyed to, in every
// order, and the reason names the same install. Goes red when identityKeys
// is no longer consulted.
func TestUnlentBareListingIsKeyedTheSameInEveryInstallOrder(t *testing.T) {
	const libc6 = "pkg:deb/debian/libc6@2.31-13+deb11u14"
	bare := libc6 + "?upstream=glibc%402.31-13%2Bdeb11u14"
	amd := libc6 + "?arch=amd64&upstream=glibc%402.31-13%2Bdeb11u13"
	arm := libc6 + "?arch=arm64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"
	for _, subject := range [][]string{{amd, arm}, {arm, amd}} {
		pkgs := parseListingGroups(t, []string{bare}, subject)
		if len(pkgs) != 3 {
			t.Fatalf("subject %v: got %d packages, want 3 (two installs and the contradicting listing)", subject, len(pkgs))
		}
		var unlent []int
		for i, p := range pkgs {
			if p.Arch == "" {
				unlent = append(unlent, i)
			}
		}
		if len(unlent) != 1 {
			t.Fatalf("subject %v: unlent listings = %d, want 1: %+v", subject, len(unlent), pkgs)
		}
		u := pkgs[unlent[0]]
		if u.Ecosystem != "Debian:11" {
			t.Errorf("subject %v: unlent listing keyed %q, want Debian:11 from the arm64 install", subject, u.Ecosystem)
		}
		if !strings.Contains(u.Unevaluable, "2.31-13+deb11u14") || !strings.Contains(u.Unevaluable, "2.31-13+deb11u13") {
			t.Errorf("subject %v: reason = %q, want both source versions named", subject, u.Unevaluable)
		}
	}
	// Two installs that state different source versions, both contradicting
	// the bare listing: the reason names the lowest, in either order, not
	// whichever install the listing met first.
	amd12 := libc6 + "?arch=amd64&upstream=glibc%402.31-13%2Bdeb11u12"
	for _, subject := range [][]string{{amd12, arm}, {arm, amd12}} {
		pkgs := parseListingGroups(t, []string{bare}, subject)
		var reason string
		for _, p := range pkgs {
			if p.Arch == "" {
				reason = p.Unevaluable
			}
		}
		if !strings.Contains(reason, "2.31-13+deb11u12") || strings.Contains(reason, "deb11u13") {
			t.Errorf("subject %v: reason = %q, want the lowest source version (deb11u12) named in every order", subject, reason)
		}
	}
}
