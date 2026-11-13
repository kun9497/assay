package cyclonedx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

func parseListingGroups(t *testing.T, top, subject []string) []pkgmeta.Package {
	t.Helper()
	components := func(purls []string) []component {
		var records []component
		for _, raw := range purls {
			p, err := pkgmeta.ParsePURL(raw)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, component{Type: "library", Name: p.Name, Version: p.Version, PURL: raw})
		}
		return records
	}
	doc := bom{
		BOMFormat: "CycloneDX", Components: components(top),
		Metadata: metadata{Component: &component{Type: "container", Components: components(subject)}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	target, stats, err := Parse(bytes.NewReader(data))
	if err != nil || stats.Components != len(target.Packages) || stats.Cataloged != len(target.Packages) {
		t.Fatalf("parse: err=%v, stats=%+v, packages=%+v", err, stats, target.Packages)
	}
	return target.Packages
}

func TestPooledBareListingDoesNotBorrowAnArchitectureRelease(t *testing.T) {
	const busybox = "pkg:apk/alpine/busybox@1.36.1-r20"
	const ppc = busybox + "?arch=ppc64le&distro=alpine-3.19"
	top := []string{busybox + "?arch=x86_64", busybox + "?arch=aarch64"}
	for _, subject := range [][]string{{busybox, ppc}, {ppc, busybox}, {busybox + "?distro=alpine-3.19", ppc}} {
		pkgs := parseListingGroups(t, top, subject)
		if len(pkgs) != 3 {
			t.Fatalf("got %d installations, want 3", len(pkgs))
		}
		for _, p := range pkgs {
			want := ""
			if p.Arch == "ppc64le" || strings.Contains(subject[0], "?distro") {
				want = "Alpine:v3.19"
			}
			if p.Ecosystem != want {
				t.Errorf("subject %v: %s got %q, want %q", subject, p.Arch, p.Ecosystem, want)
			}
		}
	}
}

func TestTypedSourceEvidencePrecedesConflictingBareListing(t *testing.T) {
	const p = "pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?"
	const short = p + "arch=amd64&distro=debian-11&upstream=glibc"
	const typed = short + "%402.31-13%2Bdeb11u13"
	const bare = p + "distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u14"
	for _, tc := range []struct{ top, subject []string }{
		{[]string{short}, []string{typed, bare}},
		{[]string{short}, []string{bare, typed}},
		{[]string{typed}, []string{short, bare}},
		{[]string{bare}, []string{short, typed}},
		{[]string{bare}, []string{typed, short}},
	} {
		pkgs := parseListingGroups(t, tc.top, tc.subject)
		if len(pkgs) != 2 {
			t.Fatalf("got %d packages, want the amd64 install and the conflicting bare record", len(pkgs))
		}
		var install, conflict bool
		for _, p := range pkgs {
			if p.Arch == "amd64" && p.Unevaluable == "" && p.Source != nil && p.Source.Version == "2.31-13+deb11u13" {
				install = true
			}
			if p.Arch == "" && strings.Contains(p.Unevaluable, "2.31-13+deb11u13 and 2.31-13+deb11u14") {
				conflict = true
			}
		}
		if !install || !conflict {
			t.Errorf("top %v, subject %v: got %+v", tc.top, tc.subject, pkgs)
		}
	}
}

func TestUnversionedInstallUsesAllOriginalBareSourceRecords(t *testing.T) {
	const p = "pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?"
	const typed = p + "arch=amd64&distro=debian-11&upstream=glibc"
	const bare = p + "distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u"
	for _, tc := range []struct{ top, subject []string }{
		{[]string{bare + "13"}, []string{bare + "14", typed}},
		{[]string{bare + "13"}, []string{typed, bare + "14"}},
		{[]string{bare + "13", bare + "14"}, []string{typed}},
		{[]string{bare + "14", bare + "13"}, []string{typed}},
		{[]string{typed}, []string{bare + "13", bare + "14", bare + "15"}},
		{[]string{typed}, []string{bare + "15", bare + "14", bare + "13"}},
	} {
		pkgs := parseListingGroups(t, tc.top, tc.subject)
		if len(pkgs) != 1 || pkgs[0].Arch != "amd64" ||
			!strings.Contains(pkgs[0].Unevaluable, "2.31-13+deb11u13 and 2.31-13+deb11u14") {
			t.Errorf("top %v, subject %v: got %+v", tc.top, tc.subject, pkgs)
		}
	}
}

func TestMergedLanguageListingPreservesDistroQualifier(t *testing.T) {
	const pkg = "pkg:npm/lodash@4.17.20"
	for _, tc := range [][2]string{{pkg, pkg + "?distro=alpine-3.19"}, {pkg + "?distro=alpine-3.19", pkg}} {
		pkgs := parseListingGroups(t, []string{tc[0]}, []string{tc[1]})
		if len(pkgs) != 1 || pkgs[0].PURL != pkg+"?distro=alpine-3.19" {
			t.Errorf("got %+v, want one lodash with distro=alpine-3.19", pkgs)
		}
	}
}

func TestTypedCopyMatchesItsArchitectureBeforeABareTopRecord(t *testing.T) {
	const base = "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19"
	const arch = base + "&arch=x86_64"
	for _, top := range [][]string{{base, arch}, {arch, base}} {
		pkgs := parseListingGroups(t, top, []string{arch})
		if len(pkgs) != 2 {
			t.Fatalf("got %d packages, want both top-level records", len(pkgs))
		}
		if pkgs[0].Arch == pkgs[1].Arch {
			t.Errorf("top %v: both records have arch %q", top, pkgs[0].Arch)
		}
	}
}

func TestTwoBareReleaseClaimsLeaveUnkeyedInstallUnevaluated(t *testing.T) {
	const busybox = "pkg:apk/alpine/busybox@1.36.1-r20?"
	for _, releases := range [][2]string{{"alpine-3.19", "alpine-3.20"}, {"alpine-3.20", "alpine-3.19"}} {
		bare := []string{busybox + "distro=" + releases[0], busybox + "distro=" + releases[1]}
		typed := []string{bare[0] + "&arch=x86_64", bare[1] + "&arch=aarch64", busybox + "arch=ppc64le"}
		for _, groups := range [][2][]string{{bare, typed}, {typed, bare}} {
			pkgs := parseListingGroups(t, groups[0], groups[1])
			var unkeyed []string
			for _, p := range pkgs {
				if p.Ecosystem == "" {
					unkeyed = append(unkeyed, p.Arch)
				}
			}
			if len(pkgs) != 3 || len(unkeyed) != 1 || unkeyed[0] != "ppc64le" {
				t.Errorf("releases %v: got %+v, want only ppc64le unkeyed", releases, pkgs)
			}
		}
	}
}

// Main QA of 67e2cf6 (2026-11-13): one apt listed with distro=ubuntu-22.04
// in one place and distro=jammy in the other is one install, and the
// merged purl keeps the codename -- the evidence a codename statement
// needs -- whichever listing came first and however the codename is
// spelled. A codename of another release is not the same install's and is
// not taken; a Debian codename is not evidence of anything and the kept
// listing's spelling stands.
func TestMergedUbuntuListingsKeepTheCodename(t *testing.T) {
	const numeric = "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"
	for _, tc := range []struct{ top, subject, want string }{
		{numeric, "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=jammy", "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=jammy"},
		{"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=jammy", numeric, "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=jammy"},
		{numeric, "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY", "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=JAMMY"},
		{numeric, "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-jammy", "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-jammy"},
		{numeric, numeric, numeric},
	} {
		pkgs := parseListingGroups(t, []string{tc.top}, []string{tc.subject})
		if len(pkgs) != 1 || pkgs[0].PURL != tc.want || pkgs[0].Ecosystem != "Ubuntu:22.04:LTS" {
			t.Errorf("top %s, subject %s: got %+v, want one apt with purl %s", tc.top, tc.subject, pkgs, tc.want)
		}
	}
	// noble names another release: two installs, each keyed to its own.
	pkgs := parseListingGroups(t, []string{numeric}, []string{"pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=noble"})
	if len(pkgs) != 2 || pkgs[0].PURL != numeric {
		t.Errorf("noble beside ubuntu-22.04: got %+v, want two installs with the first purl unchanged", pkgs)
	}
	const bookworm = "pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12"
	pkgs = parseListingGroups(t, []string{bookworm}, []string{"pkg:deb/debian/apt@2.6.1?arch=amd64&distro=bookworm"})
	if len(pkgs) != 1 || pkgs[0].PURL != bookworm {
		t.Errorf("bookworm beside debian-12: got %+v, want one apt keeping the kept spelling", pkgs)
	}
}

// A codename of ANOTHER release beside the numeric spelling, both keyed by
// the document's own OS (22.04): the codename is not this install's and is
// not preferred, and a kept `noble` is the contradiction `ubuntu-24.04`
// would be -- the merged purl names the release the package is judged on,
// in either order (mergePURL had read the codename spelling as no release
// at all and let it stand).
func TestMergedUbuntuListingsRefuseAnotherReleasesCodename(t *testing.T) {
	const (
		start   = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`
		ubuntu  = `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionID","value":"22.04"}]}`
		numeric = "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04"
		noble   = "pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=noble"
	)
	listing := func(ref, purl string) string {
		return `{"type":"library","name":"apt","version":"2.4.14","bom-ref":"` + ref + `","purl":"` + purl + `"}`
	}
	for _, tc := range [][2]string{{numeric, noble}, {noble, numeric}} {
		doc := start + `"components":[` + ubuntu + `,` + listing("first", tc[0]) + `],"metadata":{"component":{"type":"container","name":"s","components":[` + listing("second", tc[1]) + `]}}}`
		target, _, err := Parse(strings.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}
		if len(target.Packages) != 1 || target.Packages[0].PURL != numeric || target.Packages[0].Ecosystem != "Ubuntu:22.04:LTS" {
			t.Errorf("top %s, subject %s: got %+v, want one apt keyed Ubuntu:22.04:LTS with purl %s", tc[0], tc[1], target.Packages, numeric)
		}
	}
}

// The codename preference is for deb purls only (PR #324 review): the VEX
// matcher reads an Ubuntu codename as release evidence for deb/ubuntu and
// compares a language package's distro= verbatim, so which spelling the
// merged npm purl carries decides which statement matches. A language
// package keeps the kept listing's spelling, as before, in either order.
func TestMergedLanguageListingsKeepTheKeptUbuntuSpelling(t *testing.T) {
	const (
		numeric = "pkg:npm/lodash@4.17.20?distro=ubuntu-22.04"
		jammy   = "pkg:npm/lodash@4.17.20?distro=jammy"
	)
	for _, tc := range [][2]string{{numeric, jammy}, {jammy, numeric}} {
		pkgs := parseListingGroups(t, []string{tc[0]}, []string{tc[1]})
		if len(pkgs) != 1 || pkgs[0].PURL != tc[0] {
			t.Errorf("top %s, subject %s: got %+v, want one lodash keeping %s", tc[0], tc[1], pkgs, tc[0])
		}
	}
}
