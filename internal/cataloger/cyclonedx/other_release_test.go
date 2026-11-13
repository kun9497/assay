package cyclonedx

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Linux QA of v0.18.1 (2026-11-13): one name and version listed bare under
// Debian 11 AND Debian 12 at the top, with the subject installing it on
// Debian 11 only. The Debian 11 listing is lent to the install; the Debian 12
// listing has no install of its release and is a package of its own, judged
// on the source it states -- v0.18.1 had pooled it beside the Debian 11
// install, found no install of its own release to name, fallen back to the
// Debian 11 one and reported it contradicted "7 and 7" (not judged, exit 2
// under --fail-on-incomplete=target), where v0.18.0 judged it. Both source
// shapes, both top orders, and the mirror case with the install on Debian 12.
func TestOtherRelease_ABareListingWithNoInstallOfItsReleaseIsJudgedOnItsOwnStatement(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	for _, tc := range []struct {
		name, src11, src12, installRelease, installSrc string
	}{
		{"same source version on both, install on Debian 11", "7", "7", "debian-11", "7"},
		{"different source versions, install on Debian 11", "7", "2", "debian-11", "7"},
		{"same source version on both, install on Debian 12", "7", "7", "debian-12", "7"},
		{"different source versions, install on Debian 12", "7", "2", "debian-12", "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			top := []string{
				example + "?distro=debian-11&upstream=sample%40" + tc.src11,
				example + "?distro=debian-12&upstream=sample%40" + tc.src12,
			}
			subject := []string{example + "?arch=amd64&distro=" + tc.installRelease + "&upstream=sample%40" + tc.installSrc}
			seen := map[string]bool{}
			for _, order := range permute(top) {
				pkgs := parseListingGroups(t, order, subject)
				seen[outcome(pkgs)] = true
				if len(pkgs) != 2 {
					t.Fatalf("order %v: %d packages, want 2 (the install with its own release's listing lent, the other release's listing on its own):\n%s", order, len(pkgs), outcome(pkgs))
				}
				byKey := map[string]pkgmeta.Package{}
				for _, p := range pkgs {
					if p.Unevaluable != "" {
						t.Errorf("order %v: %s/%q not judged: %s", order, p.Ecosystem, p.Arch, p.Unevaluable)
					}
					byKey[p.Ecosystem] = p
				}
				for key, src := range map[string]string{"Debian:11": tc.src11, "Debian:12": tc.src12} {
					p, ok := byKey[key]
					if !ok {
						t.Fatalf("order %v: no package keyed %s:\n%s", order, key, outcome(pkgs))
					}
					if p.Source == nil || p.Source.Version != src {
						t.Errorf("order %v: %s source = %+v, want sample %s as the document states", order, key, p.Source, src)
					}
					wantArch := ""
					if "debian-"+strings.TrimPrefix(key, "Debian:") == tc.installRelease {
						wantArch = "amd64"
					}
					if p.Arch != wantArch {
						t.Errorf("order %v: %s arch = %q, want %q", order, key, p.Arch, wantArch)
					}
				}
			}
			if len(seen) != 1 {
				t.Fatalf("%d distinct outcomes over the top orders:\n%s", len(seen), strings.Join(keysOf(seen), "\n---\n"))
			}
		})
	}
}

// The rule the fix leaves standing: a bare listing that an install of ITS
// OWN release contradicts is still reported on that install (D165), in
// every order, with the reason naming the two values.
func TestOtherRelease_AContradictedListingOfTheInstallsReleaseStaysUnjudged(t *testing.T) {
	const example = "pkg:deb/debian/example@1.0"
	top := []string{
		example + "?distro=debian-11&upstream=sample%402",
		example + "?distro=debian-12&upstream=sample%407",
	}
	subject := []string{example + "?arch=amd64&distro=debian-11&upstream=sample%407"}
	for _, order := range permute(top) {
		pkgs := parseListingGroups(t, order, subject)
		var unjudged []string
		for _, p := range pkgs {
			if p.Unevaluable != "" {
				unjudged = append(unjudged, p.Ecosystem+": "+p.Unevaluable)
			}
		}
		if len(pkgs) != 3 || len(unjudged) != 1 || !strings.HasPrefix(unjudged[0], "Debian:11: ") || !strings.Contains(unjudged[0], "2 and 7") {
			t.Errorf("order %v: %d packages, unjudged %v; want 3 with the Debian 11 listing alone unjudged on 2 and 7", order, len(pkgs), unjudged)
		}
	}
}
