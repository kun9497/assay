package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// TestUbuntuLineageOf is the detector D53 rests on, so the table is written
// around the two ways it can be wrong rather than around the two ways it can be
// right.
//
// Missing a marker reports a FIPS or ESM package as mainline-clean, which is the
// silent miss the whole decision exists to prevent. Inventing one turns an
// ordinary package into a skip, which is loud and merely annoying — so the
// negative rows here are the ones chosen to be adversarial.
func TestUbuntuLineageOf(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version string
		want    string
	}{
		// Canonical's own spelling, from the advisory data measured 2026-08-10:
		// a FIPS fixed version is the identical base plus the suffix.
		{"FIPS as Canonical writes it", "3.8.3-1.1ubuntu3.6+Fips1.2", "FIPS"},
		{"FIPS single digit", "1.1.1f-1ubuntu2.16+Fips1", "FIPS"},
		// Case matters and must not: the ecosystem keys say FIPS, the version
		// strings say Fips, and lowercase appears in the wild too. A
		// case-sensitive detector reports FIPS packages clean.
		{"FIPS uppercase", "1.2.3-1ubuntu1+FIPS2", "FIPS"},
		{"FIPS lowercase", "1.2.3-1ubuntu1+fips2", "FIPS"},
		// ESM uses both separators. syft matches [~+]esm\d for the same reason.
		{"ESM with plus", "1.1.1f-1ubuntu2.16+esm1", "ESM"},
		{"ESM with tilde", "2.4.41-4ubuntu3.14~esm2", "ESM"},
		{"ESM uppercase", "1.0-1ubuntu1+ESM3", "ESM"},

		// Real versions off ubuntu:22.04, catalogued 2026-08-10. None is a
		// lineage build and none may be skipped: a detector that fired on these
		// would turn an ordinary scan into 101 skips and exit 2.
		{"plain ubuntu revision", "2.4.4-2ubuntu17.10", ""},
		{"epoch and revision", "1:4.8.1-2ubuntu2.2", ""},
		{"dfsg and a long revision", "1.34+dfsg-1ubuntu0.1.22.04.6", ""},
		{"no revision at all", "0.0.17", ""},

		// Adversarial: the letters are present but not as a marker. The
		// separator and the trailing digit are both required, which is what
		// keeps these out.
		{"a package version merely containing esm", "1.0-1ubuntu1+esmtools", ""},
		{"fips with no digit", "1.0-1ubuntu1+fips", ""},
		{"esm with no separator", "1.0-1ubuntuesm1", ""},
		{"the word inside a revision", "2.0-1ubuntu1.prefixesm", ""},
		{"empty", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ubuntuLineageOf(tt.version); got != tt.want {
				t.Errorf("ubuntuLineageOf(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// TestMatch_UbuntuLineagePackageIsSkippedNotJudged is the behaviour the
// detector exists for, exercised through Match rather than by calling the
// helper — the helper being right proves nothing if nothing calls it.
//
// The fixture is built so that a scanner which IGNORED the lineage would report
// a finding: the store holds a mainline advisory fixed at a version the
// installed one already exceeds, so mainline says clean. The FIPS build is a
// higher version by dpkg ordering (the +Fips suffix sorts above the base), and
// mainline has nothing to say about whether ITS fix has landed.
func TestMatch_UbuntuLineagePackageIsSkippedNotJudged(t *testing.T) {
	const eco = "Ubuntu:22.04:LTS"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssl": {{
				ID:       "UBUNTU-CVE-2026-0001",
				Database: "UBUNTU",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssl",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "3.0.2-0ubuntu1.15"},
						},
					}},
				}},
			}},
		},
	}

	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.5 LTS"},
		Packages: []pkgmeta.Package{
			// A FIPS build. Above the mainline fix, so mainline data says
			// clean — and mainline data is not entitled to an opinion here.
			{Name: "openssl", Version: "3.0.2-0ubuntu1.15+Fips1.1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssl"}},
			// An ordinary package on the same target, to prove the skip is
			// per-package and does not poison the scan.
			{Name: "sed", Version: "4.8-1ubuntu2.1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "sed"}},
		},
	}

	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 — a lineage package must not be judged "+
			"against mainline advisories", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d entries, want exactly 1 (the FIPS package, not sed): %+v",
			len(res.Skipped), res.Skipped)
	}
	s := res.Skipped[0]
	if s.Package.Name != "openssl" {
		t.Errorf("skipped %q, want openssl — sed is a mainline build and must "+
			"still be evaluated", s.Package.Name)
	}
	if s.Cause != SkipCoverage {
		t.Errorf("Cause = %q, want %q", s.Cause, SkipCoverage)
	}
	// The reason has to name the lineage AND the installed version. A message
	// that said only "not covered" would send the reader looking for a database
	// problem they cannot fix by updating it.
	if !strings.Contains(s.Reason, "FIPS") {
		t.Errorf("Reason = %q, want it to name the FIPS lineage", s.Reason)
	}
	if !strings.Contains(s.Reason, "3.0.2-0ubuntu1.15+Fips1.1") {
		t.Errorf("Reason = %q, want it to quote the installed version", s.Reason)
	}
}

// TestMatch_UbuntuMainlinePackageIsEvaluated is the other half, and it is the
// row that fails if the detector is too eager. Without it, a marker pattern that
// matched every Ubuntu revision would turn every scan into skips and the test
// above would still pass.
func TestMatch_UbuntuMainlinePackageIsEvaluated(t *testing.T) {
	const eco = "Ubuntu:22.04:LTS"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssl": {{
				ID:       "UBUNTU-CVE-2026-0002",
				Database: "UBUNTU",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssl",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "3.0.2-0ubuntu1.15"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.5 LTS"},
		Packages: []pkgmeta.Package{
			{Name: "openssl", Version: "3.0.2-0ubuntu1.10", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssl"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none — 3.0.2-0ubuntu1.10 is a mainline build",
			res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Advisory.ID; got != "UBUNTU-CVE-2026-0002" {
		t.Errorf("Advisory.ID = %q, want UBUNTU-CVE-2026-0002", got)
	}
}
