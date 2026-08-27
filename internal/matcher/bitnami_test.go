package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
)

// TestMatch_BitnamiComparerIsWired is the caller-first proof for D99's
// version.go clause, mirroring TestMatch_ArchPacmanComparerIsWired exactly:
// version.For("Bitnami") must actually be reached through Match, not merely
// resolve in isolation (version.TestFor_BitnamiResolvesBitnamiComparer
// already covers that half). Deleting the "Bitnami" entry from version.go's
// registry turns this into a coverage skip (SkipCoverage, "no version
// comparer") instead of a finding, and this is the only test in this package
// that would notice.
//
// The two package rows also pin Bitnami's own revision-strip rule: "17.5.0-14"
// sits BELOW the fixed "17.5.1" (a real gap, ordinary SemVer core compare) and
// "18.6.0-3" sits AT-OR-ABOVE the bare fixed "18.6.0" only because the
// revision is stripped -- SemVer{} directly would read "-3" as a pre-release
// marker and rank it BELOW 18.6.0, producing a finding where none should be.
func TestMatch_BitnamiComparerIsWired(t *testing.T) {
	const eco = "Bitnami"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00postgresql": {{
				ID:       "BIT-postgresql-2026-90001",
				Database: "BIT",
				Aliases:  []string{"CVE-2026-90001"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "postgresql",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "17.5.1"}},
					}},
				}},
			}},
			eco + "\x00redis": {{
				ID:       "BIT-redis-2026-90002",
				Database: "BIT",
				Aliases:  []string{"CVE-2026-90002"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "redis",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "18.6.0"}},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Packages: []pkgmeta.Package{
			// Below the fix -- the ordinary positive control.
			{Name: "postgresql", Version: "17.5.0-14", Ecosystem: eco},
			// At-or-above the bare fixed bound only because the trailing
			// "-3" packaging revision is stripped before the core compare.
			{Name: "redis", Version: "18.6.0-3", Ecosystem: eco},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, s := range res.Skipped {
		if s.Cause == SkipCoverage {
			t.Fatalf("a Bitnami package was skipped for coverage (%q) -- version.For(%q) is not wired", s.Reason, eco)
		}
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want exactly 1 (postgresql 17.5.0-14 is genuinely below 17.5.1; "+
			"redis 18.6.0-3 is at-or-above the bare fixed 18.6.0 once the revision is stripped): %+v",
			len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Package.Name; got != "postgresql" {
		t.Errorf("Findings[0].Package.Name = %q, want postgresql", got)
	}
}

// TestMatch_BitnamiEcosystemIsolatedFromDistroPackageOfSameName is D99's
// D6/D7 isolation proof: a Bitnami advisory named "postgresql" must never
// judge an installed Debian package also named "postgresql" -- the two are
// completely different artifacts (a Bitnami-packaged application versus a
// distro's own binary package) and share a name only coincidentally. The
// ecosystem key is what keeps them apart, exactly as it keeps an Alpine
// "openssl" apart from a PyPI package that happened to be named "openssl".
func TestMatch_BitnamiEcosystemIsolatedFromDistroPackageOfSameName(t *testing.T) {
	s := fakeStore{
		covers: []string{"Bitnami", "Debian:12"},
		byKey: map[string][]advisory.Advisory{
			"Bitnami\x00postgresql": {{
				ID:       "BIT-postgresql-2026-90003",
				Database: "BIT",
				Aliases:  []string{"CVE-2026-90003"},
				Affected: []advisory.Affected{{
					Ecosystem: "Bitnami",
					Name:      "postgresql",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "18.6.0"}},
					}},
				}},
			}},
		},
	}
	// The Debian package sits well below the Bitnami advisory's fixed bound
	// under a naive string compare (deb ordering would also call "1:15.2-1"
	// unaffected, but that is not the point being tested): what matters is
	// that this package's ecosystem key is "Debian:12", so the Bitnami
	// advisory keyed "Bitnami\x00postgresql" must never even be looked up
	// for it.
	target := pkgmeta.Target{
		Packages: []pkgmeta.Package{
			{Name: "postgresql", Version: "1:15.2-1", Ecosystem: "Debian:12",
				Source: &pkgmeta.SourcePackage{Name: "postgresql-15"}},
		},
	}
	res, err := New(s).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("Findings = %d, want 0 -- a Bitnami advisory named %q must not judge a Debian "+
			"package of the same name: %+v", len(res.Findings), "postgresql", res.Findings)
	}
}

// TestMatch_BitnamiUnparseableAdvisoryBoundSkipped drives D99's own refusal
// class through Match: 44 of 4,375 distinct Bitnami advisory version strings
// (PHP-style build-train labels such as "7.4-update41.0") do not parse under
// Bitnami{} (which delegates its core to SemVer{} after stripping any
// trailing packaging revision) and must surface as a skip with the advisory
// blamed (D9's "never guessed" rule), never as a silent clean verdict.
func TestMatch_BitnamiUnparseableAdvisoryBoundSkipped(t *testing.T) {
	const eco = "Bitnami"
	// Sanity-check the fixture is really unparseable before trusting the
	// Match-level assertion below -- otherwise a typo here would make this
	// test pass for the wrong reason.
	if _, err := (version.Bitnami{}).Compare("7.4.0", "7.4-update41.0"); err == nil {
		t.Fatal("fixture bound \"7.4-update41.0\" parses under Bitnami{}; this test needs an unparseable one")
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00php": {{
				ID:       "BIT-php-2026-90004",
				Database: "BIT",
				Aliases:  []string{"CVE-2026-90004"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "php",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "7.4-update41.0"}},
					}},
				}},
			}},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{{Name: "php", Version: "7.4.0", Ecosystem: eco}},
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 -- an unparseable bound must never be silently treated as a match", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1: %+v", len(res.Skipped), res.Skipped)
	}
	if got := res.Skipped[0].Cause; got != SkipAdvisory {
		t.Errorf("Skipped[0].Cause = %q, want %q -- the advisory's own bound is unreadable, not the package's version", got, SkipAdvisory)
	}
}
