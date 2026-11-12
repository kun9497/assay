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

// Independent review of v0.18.0 (2026-11-12). Two releases list one name and
// version: Debian 11's bare listing states source 2 against its install's 7,
// Debian 12's states 9 against its install's 2. identityKeys keyed on the
// bare identity had let the Debian 12 install (source 2) name the Debian 11
// listing's reason, "2 and 2" for a conflict of 2 and 7. Each listing's reason
// names an install of ITS release, in every order of installs and listings.
// Goes red when the candidate installs are not held to the listing's key.
func TestUnlentListingsOfTwoReleasesNameTheirOwnInstalls(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	bare11 := example + "?distro=debian-11&upstream=sample-source%402"
	bare12 := example + "?distro=debian-12&upstream=sample-source%409"
	amd11 := example + "?arch=amd64&distro=debian-11&upstream=sample-source%407"
	arm12 := example + "?arch=arm64&distro=debian-12&upstream=sample-source%402"
	for _, top := range [][]string{{bare11, bare12}, {bare12, bare11}} {
		for _, subject := range [][]string{{amd11, arm12}, {arm12, amd11}} {
			pkgs := parseListingGroups(t, top, subject)
			reasons := map[string]string{}
			for _, p := range pkgs {
				if p.Arch == "" {
					reasons[p.Ecosystem] = p.Unevaluable
				}
			}
			if len(pkgs) != 4 || len(reasons) != 2 {
				t.Fatalf("top %v subject %v: got %d packages, reasons %v; want 4 and one unlent listing per release", top, subject, len(pkgs), reasons)
			}
			if r := reasons["Debian:11"]; !strings.Contains(r, "values, 2 and 7;") {
				t.Errorf("top %v subject %v: Debian:11 reason = %q, want 2 and 7", top, subject, r)
			}
			if r := reasons["Debian:12"]; !strings.Contains(r, "values, 2 and 9;") {
				t.Errorf("top %v subject %v: Debian:12 reason = %q, want 2 and 9", top, subject, r)
			}
		}
	}
}
