package cyclonedx

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-20. The order of two siblings under metadata.component decided
// whether a listing was keyed, and so the exit code.
func TestParse_SubjectSiblingOrderDoesNotDecideAKey(t *testing.T) {
	c := func(q string) string {
		return `{"type":"library","name":"busybox","version":"1.36.1-r15","purl":"pkg:apk/alpine/busybox@1.36.1-r15` + q + `"}`
	}
	x, a := c("?arch=x86_64"), c("?arch=aarch64&distro=alpine-3.19.1")
	read := func(children string) string {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"type":"container","name":"img","components":[` + children + `]}},
		 "components":[` + c("") + `,` + c("?arch=x86_64&distro=alpine-3.19.1") + `]}`
		target, stats, err := Parse(strings.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}
		keyed := 0
		for _, p := range target.Packages {
			if p.Ecosystem != "" {
				keyed++
			}
		}
		return fmt.Sprintf("%d packages, %d keyed, %d components", len(target.Packages), keyed, stats.Components)
	}
	one, other := read(x+","+a), read(a+","+x)
	if one != other || one != "2 packages, 2 keyed, 2 components" {
		t.Errorf("x86_64 first: %s; aarch64 first: %s; want 2 packages, both keyed, either way", one, other)
	}
}

func TestIndexOfPackage_TheKeyedTwinOfOneArchitecture(t *testing.T) {
	l := func(arch, eco string) pkgmeta.Package {
		return pkgmeta.Package{Type: "apk", Name: "busybox", Version: "1.36.1-r15", Arch: arch, Ecosystem: eco}
	}
	const a319, a320 = "Alpine:v3.19", "Alpine:v3.20"
	for _, tc := range []struct {
		name string
		top  []pkgmeta.Package
		p    pkgmeta.Package
		want int
	}{
		{"another architecture's twin is not it", []pkgmeta.Package{l("", ""), l("aarch64", a319), l("x86_64", a319)}, l("x86_64", ""), 2},
		{"two releases of one architecture are neither", []pkgmeta.Package{l("", ""), l("x86_64", a319), l("x86_64", a320)}, l("x86_64", ""), 0},
		{"a keyed listing keeps its own release", []pkgmeta.Package{l("", a319), l("x86_64", a320)}, l("x86_64", a319), 0},
	} {
		if got := indexOfPackage(tc.top, tc.p, keyedReleases(append(append([]pkgmeta.Package(nil), tc.top...), tc.p))); got != tc.want {
			t.Errorf("%s: index %d, want %d", tc.name, got, tc.want)
		}
	}
}
