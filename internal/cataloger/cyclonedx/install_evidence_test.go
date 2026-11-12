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
