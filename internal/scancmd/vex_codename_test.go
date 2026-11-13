package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The keying side of the same rule (PR #316 review): a document with no
// operating-system component whose purl says distro=bookworm is keyed to
// Debian 12 and judged, where it had stayed unkeyed and not evaluated.
func TestRun_CycloneDXCodenamePURLKeysTheRelease(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0105", "CVE-2031-9105", "sample", "99"})
	for _, distro := range []string{"bookworm", "debian-bookworm", "Debian-12"} {
		t.Run(distro, func(t *testing.T) {
			doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
				`{"type":"library","name":"example","version":"1.0","purl":"pkg:deb/debian/example@1.0?distro=` + distro + `&upstream=sample%407"}]}`
			p := filepath.Join(t.TempDir(), "os-less.cdx.json")
			if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			rep, stderr := scanVEXJSON(t, db, "sbom:"+p)
			if rep.Summary.Evaluated != 1 || !pairsOf(rep.Findings)[pair{"example", "CVE-2031-9105"}] || !strings.Contains(rep.Findings[0].Package.Ecosystem, "Debian:12") {
				t.Fatalf("evaluated %d, findings %v; want the package keyed Debian:12 and judged\nstderr: %s", rep.Summary.Evaluated, pairsOf(rep.Findings), stderr)
			}
		})
	}
}

// Main QA of 672fe7a (2026-11-13), through Run: the SBOM's package purl
// says `distro=bookworm` (a codename, the shape of the purl spec's own deb
// example `distro=jessie`) beside an
// operating-system component. A codename names the major, so under an OS
// of Debian 12.15 a 12.15 statement applies (as v0.18.1 applied it, and
// 672fe7a refused), while the codename alone proves no point release: an OS
// of 12 or of 12.14, or another codename, is not exonerated by 12.15.
func TestRun_VEXDebianCodenamePURLs(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0104", "CVE-2031-9104", "sample", "99"})
	want := pair{"example", "CVE-2031-9104"}
	sbom := func(osVersion, purlDistro string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
			`{"type":"operating-system","name":"debian","version":"` + osVersion + `","properties":[` +
			`{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"` + osVersion + `"}]},` +
			`{"type":"library","name":"example","version":"1.0","purl":"pkg:deb/debian/example@1.0?distro=` + purlDistro + `&upstream=sample%407"}]}`
		p := filepath.Join(t.TempDir(), "codename.cdx.json")
		if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return "sbom:" + p
	}
	productFor := func(release string) string {
		return product("pkg:deb/debian/example@1.0?distro=" + release + "&upstream=sample%407")
	}
	for _, tc := range []struct {
		name, osVersion, purlDistro, statement string
		suppressed                             bool
	}{
		{"OS 12.15, purl bookworm: the point statement applies", "12.15", "bookworm", "debian-12.15", true},
		{"OS 12.15, purl debian-bookworm: the point statement applies", "12.15", "debian-bookworm", "debian-12.15", true},
		{"OS 12.15, purl bookworm: the major applies", "12.15", "bookworm", "debian-12", true},
		{"OS 12.15, purl bookworm: another point release does not", "12.15", "bookworm", "debian-12.14", false},
		{"OS 12, purl bookworm: a point statement does not", "12", "bookworm", "debian-12.15", false},
		{"OS 12.14, purl bookworm: another point release does not", "12.14", "bookworm", "debian-12.15", false},
		{"OS 12.15, purl bullseye: the point statement does not", "12.15", "bullseye", "debian-12.15", false},
		{"OS 12.15, purl ubuntu-22.04: the point statement does not", "12.15", "ubuntu-22.04", "debian-12.15", false},
		{"OS 12.15, purl bookworm, statement bookworm: applies as the major", "12.15", "bookworm", "bookworm", true},
		{"OS 12.15, purl Debian-12: the point statement applies", "12.15", "Debian-12", "debian-12.15", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, stderr := scanVEXJSON(t, db, sbom(tc.osVersion, tc.purlDistro), writeVEX(t, stmt("CVE-2031-9104", productFor(tc.statement))))
			sup, kept := suppressedPairs(doc), pairsOf(doc.Findings)
			if sup[want] != tc.suppressed || kept[want] == tc.suppressed {
				t.Fatalf("suppressed = %v, kept = %v; want suppressed %v\nstderr: %s", sup[want], kept[want], tc.suppressed, stderr)
			}
		})
	}
}
