package cyclonedx

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Review of v0.18.5 (2026-11-18), at the document level: the codename the
// target carries when a version-less Ubuntu declaration under a generic name
// states one. It lends none (the target's stays as the others gave it) and
// contradicts one that differs, in either order and at either depth.
func TestParse_VersionlessGenericOSCodenameContradictsAndNeverLends(t *testing.T) {
	top := func(codename string) string {
		props := ""
		if codename != "" {
			props = `{"name":"syft:distro:versionCodename","value":"` + codename + `"}`
		}
		return `{"type":"operating-system","name":"ubuntu","version":"22.04","properties":[` + props + `]}`
	}
	for _, tc := range []struct{ name, topCodename, generic, want string }{
		{"differs", "jammy", "noble", pkgmeta.ContradictedCodename},
		{"differs in case only", "jammy", "JAMMY", "jammy"},
		{"agrees", "jammy", "jammy", "jammy"},
		{"nothing to contradict", "", "noble", ""},
		{"nothing to lend", "", "jammy", ""},
	} {
		for _, nested := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				other := fmt.Sprintf(`{"type":"operating-system","name":"linux","properties":[{"name":"syft:distro:id","value":"ubuntu"},{"name":"syft:distro:versionCodename","value":%q}]}`, tc.generic)
				if nested {
					other = `{"type":"library","purl":"pkg:npm/is-number@7.0.0","components":[` + other + `]}`
				}
				components := top(tc.topCodename) + "," + other
				if reverse {
					components = other + "," + top(tc.topCodename)
				}
				target, _, err := Parse(strings.NewReader(`{"bomFormat":"CycloneDX","components":[` + components + `]}`))
				if err != nil {
					t.Fatal(err)
				}
				if target.Distro == nil || target.Distro.VersionID != "22.04" || target.Distro.VersionCodename != tc.want {
					t.Errorf("%s nested=%t reverse=%t: distro %+v, want Ubuntu 22.04 with codename %q", tc.name, nested, reverse, target.Distro, tc.want)
				}
			}
		}
	}
}

// The bare listing that joins its qualifier-only twin is one package that
// keeps everything both listings said: the release identity, the twin's
// purl qualifiers and architecture, and both locations.
func TestParse_BareListingJoinsItsQualifierOnlyUncoveredTwin(t *testing.T) {
	const bare = `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3","properties":[{"name":"syft:location:0:path","value":"/var/lib/dpkg/status"}]}`
	for _, qualifiers := range []string{"distro=debian-sid", "arch=amd64&distro=debian-sid"} {
		twin := `{"type":"library","purl":"pkg:deb/debian/apt@3.0.3?` + qualifiers + `"}`
		for _, pair := range [][2]string{{bare, twin}, {twin, bare}} {
			target, stats, err := Parse(strings.NewReader(`{"bomFormat":"CycloneDX","components":[` + pair[0] + `],"metadata":{"component":` + pair[1] + `}}`))
			if err != nil {
				t.Fatal(err)
			}
			if len(target.Packages) != 1 || stats.Components != 1 || stats.Cataloged != 1 {
				t.Fatalf("%s: %d packages, stats %+v; want one package counted once", qualifiers, len(target.Packages), stats)
			}
			p := target.Packages[0]
			parsed, err := pkgmeta.ParsePURL(p.PURL)
			if err != nil {
				t.Fatal(err)
			}
			if p.UncoveredRelease != "debian-sid" || p.Ecosystem != "" || parsed.Qualifiers["distro"] != "debian-sid" ||
				p.Arch != parsed.Qualifiers["arch"] || len(p.Locations) != 2 {
				t.Errorf("%s: package %+v; want the sid install with both listings' locations", qualifiers, p)
			}
		}
	}
}
