package version

import "testing"

// TestFor_ResolvesEachLanguageEcosystemToItsOwnComparer drives the CALLER --
// For(), the registry's only entry point -- for the four ecosystems no other
// test ever reaches through it: RubyGems, Packagist, NuGet and Maven each
// carry an exhaustive direct Compare table of their own (gem_test.go,
// composer_test.go, nuget_test.go, maven_test.go), but nothing anywhere
// asserted which comparer For() actually resolves for those four names.
// TestNoUnbackedDistroComparer (semver_test.go) checks only the registry's
// KEY SET, TestComparerName_AgreesWithVersionFor (report/explain_test.go)
// checks only presence agreement with a small local mirror, and the one
// end-to-end test touching any of the four (scancmd's jar_test) compares
// 1.0.0/2.0.0 against a fixed 99.0.0, an input SemVer orders identically to
// the real comparer. Rewiring any of the four to the wrong Comparer -- a
// silent false negative on gem "1.0.0.pre.2", composer "1.0.0-patch1", a
// NuGet fourth version component, or a Maven qualifier -- left the whole
// suite green.
//
// Each row below uses a version pair the real comparer orders one way and a
// SemVer engine either misorders (composer) or refuses outright (the other
// three, whose extra dotted components make it fail the "core needs exactly
// three identifiers" rule) -- so wiring the wrong Comparer into the registry
// fails here even though every table in the sibling _test.go files, which
// call the type directly and never go through For, stays green.
func TestFor_ResolvesEachLanguageEcosystemToItsOwnComparer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ecosystem string
		a, b      string
		want      int
	}{
		// Gem orders a numeric pre-release segment below the release it
		// precedes (gem_test.go). SemVer's grammar has no four-identifier
		// core at all and refuses to parse "1.0.0.pre.2" ("core needs
		// exactly three identifiers"), so a RubyGems package wired to
		// SemVer would report skipped rather than compared.
		{"RubyGems -> Gem", "RubyGems", "1.0.0.pre.2", "1.0.0", -1},
		// Composer reads a bare suffix after "-" as a patch label, NEWER
		// than the version it follows (composer_test.go). SemVer reads the
		// identical syntax as a pre-release marker and puts it BELOW
		// 1.0.0 -- the opposite answer from the same two strings, and the
		// one row here that misorders rather than merely erroring.
		{"Packagist -> Composer", "Packagist", "1.0.0-patch1", "1.0.0", 1},
		// NuGet treats a fourth numeric component as significant
		// (nuget_test.go). SemVer's grammar has no fourth core component
		// and refuses to parse "1.0.0.1".
		{"NuGet -> NuGet", "NuGet", "1.0.0.1", "1.0.0", 1},
		// Maven ranks a bare qualifier ("a") ABOVE the version it
		// qualifies (maven_test.go) -- one of the traps that comparer's
		// own doc comment calls out by name. SemVer reads "-a" as a
		// pre-release marker on a two-identifier core ("1.0") and refuses
		// it outright once the shorthand-padding rule is skipped for a
		// suffixed version.
		{"Maven -> Maven", "Maven", "1.0-a", "1.0", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := For(tc.ecosystem)
			if !ok {
				t.Fatalf("For(%q) = not ok, want a comparer", tc.ecosystem)
			}
			got, err := c.Compare(tc.a, tc.b)
			if err != nil {
				t.Fatalf("Compare(%q, %q) via For(%q) = error %v, want %d with no error -- "+
					"the wrong comparer either refuses this input or gets its order backwards",
					tc.a, tc.b, tc.ecosystem, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("Compare(%q, %q) via For(%q) = %d, want %d", tc.a, tc.b, tc.ecosystem, got, tc.want)
			}
		})
	}
}

// TestFor_ArchRollingResolvesPacman is D97's caller-first proof that
// "Arch:rolling" resolves Pacman{}, not merely that Pacman{} exists and is
// well tested on its own (pacman_test.go). The pair below is one
// pacman.go's own doc comment names as load-bearing: libalpm's "remaining
// alpha string never beats an empty one" rule orders "1.0rc" BELOW "1.0",
// the opposite of RPM{}'s "2.0.1a" > "2.0.1" rule — so wiring "Arch:rolling"
// to RPM{} by mistake (an easy slip, since every other RPM-family distro in
// this registry resolves RPM{}) would get this exact comparison backwards
// while every table in pacman_test.go, which calls the type directly, stays
// green.
func TestFor_ArchRollingResolvesPacman(t *testing.T) {
	c, ok := For("Arch:rolling")
	if !ok {
		t.Fatal(`For("Arch:rolling") = not ok, want a comparer`)
	}
	got, err := c.Compare("1.0rc-1", "1.0-1")
	if err != nil {
		t.Fatalf("Compare: error %v, want -1 with no error", err)
	}
	if got != -1 {
		t.Errorf("Compare(%q, %q) via For(\"Arch:rolling\") = %d, want -1 -- "+
			"RPM{} would answer +1 here, the exact divergence pacman.go's own doc comment measured", "1.0rc-1", "1.0-1", got)
	}
}

// TestFor_HummingbirdResolvesRPM is D98's caller-first proof that
// "Hummingbird" resolves RPM{} through the registry -- not merely that
// RPM{} orders a ".humN" dist tag correctly in isolation (rpm_test.go has no
// such row of its own; this IS that row, driven through the caller). Before
// the registry entry existed, For("Hummingbird") reported not-ok and this
// test failed for that reason alone; the version pair below (real EVRs,
// trimmed from cve-2026-50811.json) is what a Hummingbird point release
// looks like, ordered by rpmvercmp's ordinary trailing-segment rule with no
// new comparer logic -- the same rule Photon's ".phN" and Azure Linux's
// ".azl3" tags already ride.
// TestFor_BitnamiResolvesBitnamiComparer is D99's caller-first proof that
// "Bitnami" resolves Bitnami{} through the registry, not merely that
// Bitnami{} orders a revision correctly in isolation (bitnami_test.go has no
// such row of its own; this IS that row, driven through the caller). Before
// the registry entry existed, For("Bitnami") reported not-ok and this test
// failed for that reason alone.
//
// The pair is D99's own worked example: an installed "18.6.0-3" against a
// bare fixed "18.6.0" resolves EQUAL (0) under Bitnami{}'s own rule that a
// revision is packaging metadata, not a version regression -- SemVer{}
// directly would instead read "-3" as a pre-release marker and rank it BELOW
// 18.6.0 (the opposite direction), so this fails if "Bitnami" were ever
// wired to SemVer{} by mistake.
func TestFor_BitnamiResolvesBitnamiComparer(t *testing.T) {
	c, ok := For("Bitnami")
	if !ok {
		t.Fatal(`For("Bitnami") = not ok, want a comparer`)
	}
	got, err := c.Compare("18.6.0-3", "18.6.0")
	if err != nil {
		t.Fatalf("Compare: error %v, want 0 with no error", err)
	}
	if got != 0 {
		t.Errorf(`Compare("18.6.0-3", "18.6.0") via For("Bitnami") = %d, want 0 -- `+
			"SemVer{} would answer -1 here (reading \"-3\" as a pre-release marker), "+
			"the exact divergence Bitnami{}'s own doc comment measures", got)
	}
}

func TestFor_HummingbirdResolvesRPM(t *testing.T) {
	c, ok := For("Hummingbird")
	if !ok {
		t.Fatal(`For("Hummingbird") = not ok, want a comparer`)
	}
	got, err := c.Compare("2.14.3-1.hum1", "2.14.3-1.2.hum1")
	if err != nil {
		t.Fatalf("Compare: error %v, want -1 with no error", err)
	}
	if got != -1 {
		t.Errorf(`Compare("2.14.3-1.hum1", "2.14.3-1.2.hum1") via For("Hummingbird") = %d, want -1`, got)
	}
}

// TestFor_CleanStartResolvesAPK is D101's caller-first proof that
// "CleanStart" resolves APK{} through the registry -- the matcher calls
// version.For(p.Ecosystem) directly (internal/matcher/matcher.go), so
// before this registry entry existed, For("CleanStart") reported not-ok and
// every CleanStart package would have been reported as skipped rather than
// evaluated, no matter how correct apk.go's own Compare logic is in
// isolation. The pair is a real one, trimmed from CLEANSTART-2026-AI42483's
// own advisory: fixed "17.6-r0" against an installed "18.6-r0" (a later,
// already-patched release) orders above it.
func TestFor_CleanStartResolvesAPK(t *testing.T) {
	c, ok := For("CleanStart")
	if !ok {
		t.Fatal(`For("CleanStart") = not ok, want a comparer`)
	}
	got, err := c.Compare("18.6-r0", "17.6-r0")
	if err != nil {
		t.Fatalf("Compare: error %v, want 1 with no error", err)
	}
	if got != 1 {
		t.Errorf(`Compare("18.6-r0", "17.6-r0") via For("CleanStart") = %d, want 1`, got)
	}
}
