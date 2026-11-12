package cyclonedx

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// permutations of a slice's indices.
func permutations(n int) [][]int {
	var out [][]int
	var rec func(cur []int, rest []int)
	rec = func(cur []int, rest []int) {
		if len(rest) == 0 {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := range rest {
			next := append(append([]int(nil), rest[:i]...), rest[i+1:]...)
			rec(append(cur, rest[i]), next)
		}
	}
	rec(nil, func() []int {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		return idx
	}())
	return out
}

func permute(xs []string) [][]string {
	var out [][]string
	for _, p := range permutations(len(xs)) {
		var one []string
		for _, i := range p {
			one = append(one, xs[i])
		}
		out = append(out, one)
	}
	return out
}

// outcome is the order-free shape of a parse: every package's key, arch,
// source version and reason, sorted.
func outcome(pkgs []pkgmeta.Package) string {
	var rows []string
	for _, p := range pkgs {
		src := ""
		if p.Source != nil {
			src = p.Source.Version
		}
		rows = append(rows, fmt.Sprintf("%s|%s|%s|%s", p.Ecosystem, p.Arch, src, p.Unevaluable))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// Review of the v0.18.1 branches (2026-11-12): a document that lists one deb
// name and version under TWO releases. A bare listing that names its release
// is placed with that release's installs however many releases the document
// holds -- refusing it on the document's aggregate had sent it down the
// first-match path, so the inventory, the skip count and the exit code under
// --fail-on-incomplete=target depended on the order of the installs. One
// outcome in every order, and the outcome the one-release case gives.
func TestTwoReleases_AKeyedBareListingIsPlacedWithItsOwnReleaseInEveryOrder(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	bare11 := example + "?distro=debian-11&upstream=sample-source%402"
	top := []string{
		example + "?arch=amd64&distro=debian-11&upstream=sample-source%402",
		example + "?arch=arm64&distro=debian-11&upstream=sample-source%407",
		example + "?arch=amd64&distro=debian-12&upstream=sample-source%409",
	}
	seen := map[string]bool{}
	for _, order := range permute(top) {
		pkgs := parseListingGroups(t, order, []string{bare11})
		seen[outcome(pkgs)] = true
		if len(pkgs) != 3 {
			t.Errorf("order %v: %d packages, want 3 (the listing is lent to the amd64 Debian 11 install it agrees with)", order, len(pkgs))
		}
		for _, p := range pkgs {
			if p.Unevaluable != "" {
				t.Errorf("order %v: %s/%s unjudged: %s", order, p.Ecosystem, p.Arch, p.Unevaluable)
			}
		}
	}
	if len(seen) != 1 {
		t.Fatalf("%d distinct outcomes over %d orders:\n%s", len(seen), len(permute(top)), strings.Join(keysOf(seen), "\n---\n"))
	}
}

// Two bare listings of one release at the top, beside a second release: both
// are weighed against that release's install, in every order, and neither is
// judged on a source the document's own install contradicts.
func TestTwoReleases_TwoBareListingsOfOneReleaseAreBothWeighed(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	top := []string{
		example + "?distro=debian-12&upstream=sample-source%409",
		example + "?distro=debian-12&upstream=sample-source%408",
		example + "?arch=amd64&distro=debian-11&upstream=sample-source%407",
		example + "?distro=debian-11&upstream=sample-source%402",
	}
	subject := []string{
		example + "?arch=amd64&distro=debian-12&upstream=sample-source%402",
		example + "?arch=arm64&distro=debian-11&upstream=sample-source%405",
	}
	seen := map[string]bool{}
	for _, order := range permute(top) {
		for _, sub := range [][]string{subject, {subject[1], subject[0]}} {
			pkgs := parseListingGroups(t, order, sub)
			seen[outcome(pkgs)] = true
			var reasons []string
			for _, p := range pkgs {
				if p.Arch == "" && p.Ecosystem == "Debian:12" {
					reasons = append(reasons, p.Unevaluable)
				}
			}
			sort.Strings(reasons)
			if len(reasons) != 2 || !strings.Contains(reasons[0], "2 and 8") || !strings.Contains(reasons[1], "2 and 9") {
				t.Errorf("order %v: Debian:12 bare listings' reasons = %q, want both unjudged against the install's 2", order, reasons)
			}
		}
	}
	if len(seen) != 1 {
		t.Fatalf("%d distinct outcomes:\n%s", len(seen), strings.Join(keysOf(seen), "\n---\n"))
	}
}

// Bare listings under the subject, two releases times two architectures:
// each reason names the lowest contradicting install of ITS release, in
// every order of the installs and of the listings.
func TestTwoReleases_SubjectBareListingsNameTheLowestInstallOfTheirRelease(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	top := []string{
		example + "?arch=amd64&distro=debian-11&upstream=sample-source%407",
		example + "?arch=arm64&distro=debian-11&upstream=sample-source%405",
		example + "?arch=amd64&distro=debian-12&upstream=sample-source%402",
		example + "?arch=arm64&distro=debian-12&upstream=sample-source%403",
	}
	bares := []string{
		example + "?distro=debian-11&upstream=sample-source%402",
		example + "?distro=debian-12&upstream=sample-source%409",
	}
	seen := map[string]bool{}
	for _, order := range permute(top) {
		for _, sub := range [][]string{bares, {bares[1], bares[0]}} {
			pkgs := parseListingGroups(t, order, sub)
			seen[outcome(pkgs)] = true
			got := map[string]string{}
			for _, p := range pkgs {
				if p.Arch == "" {
					got[p.Ecosystem] = p.Unevaluable
				}
			}
			if !strings.Contains(got["Debian:11"], "2 and 5") || !strings.Contains(got["Debian:12"], "2 and 9") {
				t.Errorf("order %v / %v: reasons %v, want Debian:11 '2 and 5' and Debian:12 '2 and 9'", order, sub, got)
			}
		}
	}
	if len(seen) != 1 {
		t.Fatalf("%d distinct outcomes:\n%s", len(seen), strings.Join(keysOf(seen), "\n---\n"))
	}
}

// An unkeyed bare listing at the top beside installs of two releases belongs
// to neither provably: it stays unkeyed in every order instead of taking the
// release of whichever keyed install came first.
func TestTwoReleases_AnUnkeyedBareListingBesideTwoReleasesStaysUnkeyed(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	top := []string{
		example + "?upstream=sample-source%401",
		example + "?arch=amd64&distro=debian-11&upstream=sample-source%402",
		example + "?arch=ppc64el&distro=debian-12&upstream=sample-source%402",
	}
	subject := []string{example + "?arch=arm64&upstream=sample-source%402"}
	seen := map[string]bool{}
	for _, order := range permute(top) {
		pkgs := parseListingGroups(t, order, subject)
		seen[outcome(pkgs)] = true
		for _, p := range pkgs {
			if p.Arch == "" && p.Ecosystem != "" {
				t.Errorf("order %v: the unkeyed listing took %q", order, p.Ecosystem)
			}
		}
	}
	if len(seen) != 1 {
		t.Fatalf("%d distinct outcomes:\n%s", len(seen), strings.Join(keysOf(seen), "\n---\n"))
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
