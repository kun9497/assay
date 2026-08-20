package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// TestMatch_OracleLineagePackagesAreSkippedNotJudged drives the D79 detector
// through Match — the helper being right proves nothing if nothing calls it.
//
// Both fixtures are built so that a scanner which IGNORED the lineage would
// report the package CLEAN: rpmvercmp orders `.ksplice1.` and a trailing
// `_fips` segment above the identical mainline base, so the mainline fixed
// version is always the lower bar — the same silent-miss direction D53
// measured on Ubuntu, reproduced here from the ELSA corpus's own EVR shapes.
func TestMatch_OracleLineagePackagesAreSkippedNotJudged(t *testing.T) {
	const eco = "Oracle Linux:8"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00glibc": {{
				ID:       "TEST-ORA-0001",
				Database: "ORACLE",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "glibc",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "2:2.28-251.el8"},
						},
					}},
				}},
			}},
			eco + "\x00opensslpkg": {{
				ID:       "TEST-ORA-0002",
				Database: "ORACLE",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "opensslpkg",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "10:1.0.2k-22.el8"},
						},
					}},
				}},
			}},
		},
	}

	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ol", VersionID: "8.10", PrettyName: "Oracle Linux Server 8.10"},
		Packages: []pkgmeta.Package{
			// A Ksplice userspace build, the corpus's own shape. Above the
			// mainline fix by rpm ordering, so mainline data says clean —
			// and mainline data is not entitled to an opinion here.
			{Name: "glibc", Version: "2:2.28-251.0.4.ksplice1.el8_10.40", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "glibc"}},
			// A FIPS build: the trailing _fips segment also orders above the
			// mainline base.
			{Name: "opensslpkg", Version: "10:1.0.2k-22.el8_fips", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "opensslpkg"}},
			// An ordinary package on the same target, to prove the skip is
			// per-package and does not poison the scan.
			{Name: "sed", Version: "4.5-5.el8", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "sed"}},
		},
	}

	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 — a lineage package must not be judged "+
			"against mainline advisories: %+v", len(res.Findings), res.Findings)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("Skipped = %d entries, want exactly 2 (glibc and opensslpkg, not sed): %+v",
			len(res.Skipped), res.Skipped)
	}
	wantLineage := map[string]string{"glibc": "Ksplice", "opensslpkg": "FIPS"}
	for _, s := range res.Skipped {
		lineage, ok := wantLineage[s.Package.Name]
		if !ok {
			t.Errorf("skipped %q — sed is a mainline build and must still be evaluated",
				s.Package.Name)
			continue
		}
		delete(wantLineage, s.Package.Name)
		if s.Cause != SkipCoverage {
			t.Errorf("%s: Cause = %q, want %q", s.Package.Name, s.Cause, SkipCoverage)
		}
		// The reason has to name the lineage AND quote the installed version;
		// "not covered" alone sends the reader chasing a database problem
		// that `assay db update` cannot fix.
		if !strings.Contains(s.Reason, lineage) {
			t.Errorf("%s: Reason = %q, want it to name the %s lineage",
				s.Package.Name, s.Reason, lineage)
		}
		if !strings.Contains(s.Reason, s.Package.Version) {
			t.Errorf("%s: Reason = %q, want it to quote the installed version %q",
				s.Package.Name, s.Reason, s.Package.Version)
		}
	}
	for name := range wantLineage {
		t.Errorf("%s was never skipped", name)
	}
}

// TestMatch_OracleMainlinePackageIsEvaluated fails if the detector is too
// eager: a marker that fired on ordinary elN releases would turn every Oracle
// scan into skips while the test above stayed green.
func TestMatch_OracleMainlinePackageIsEvaluated(t *testing.T) {
	const eco = "Oracle Linux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00glibc": {{
				ID:       "TEST-ORA-0003",
				Database: "ORACLE",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "glibc",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "2.34-100.el9"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ol", VersionID: "9.4", PrettyName: "Oracle Linux Server 9.4"},
		Packages: []pkgmeta.Package{
			{Name: "glibc", Version: "2.34-60.el9", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "glibc"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none — 2.34-60.el9 is a mainline build", res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Advisory.ID; got != "TEST-ORA-0003" {
		t.Errorf("Advisory.ID = %q, want TEST-ORA-0003", got)
	}
}

// TestMatch_OracleLineageMarkerIsGatedOnTheEcosystem holds the gate itself:
// `_fips` was measured unambiguous only under Oracle's release convention, so
// a version carrying the same letters under another RPM ecosystem must still
// be evaluated. Deleting the ecosystem gate in Match turns this red.
func TestMatch_OracleLineageMarkerIsGatedOnTheEcosystem(t *testing.T) {
	const eco = "AlmaLinux:8"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00gatepkg": {{
				ID:       "TEST-ORA-0004",
				Database: "ALMA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "gatepkg",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "2.0-1.el8"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "almalinux", VersionID: "8.10", PrettyName: "AlmaLinux 8.10"},
		Packages: []pkgmeta.Package{
			{Name: "gatepkg", Version: "1.0-1.el8_fips", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "gatepkg"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none — the Oracle marker must not fire "+
			"under a non-Oracle ecosystem key", res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 — the package is below the fix and must be judged",
			len(res.Findings))
	}
}

// TestOracleLineageOf covers the detector's branches directly, written around
// the two ways it can be wrong: missing a marker reports a lineage package
// mainline-clean (the silent miss), inventing one turns an ordinary package
// into a skip (loud, merely annoying) — so the negative rows are the
// adversarial ones.
func TestOracleLineageOf(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version string
		want    string
	}{
		// The corpus's own spellings, measured 2026-08-20.
		{"ksplice1 userspace", "2:2.28-251.0.4.ksplice1.el8_10.40", "Ksplice"},
		{"ksplice2", "1:1.1.1k-12.ksplice2.el8_6", "Ksplice"},
		{"fips trailing, epoch 10", "10:1.0.2k-22.el7_9_fips", "FIPS"},
		{"fips trailing el8", "10:3.6.16-4.0.1.el8_fips", "FIPS"},
		{"fips trailing el9 minor", "10:3.5.1-4.0.2.el9_7_fips", "FIPS"},
		// Case-insensitive on principle (silent-miss direction), though every
		// measured Oracle spelling is lowercase.
		{"uppercase ksplice", "2:2.28-251.0.4.KSPLICE1.el8", "Ksplice"},
		{"uppercase fips", "10:1.0.2k-22.el7_9_FIPS", "FIPS"},

		// Real mainline shapes off oraclelinux images. None may be skipped.
		{"plain el8 release", "2.28-251.el8", ""},
		{"epoch and el9", "1:4.4.20-4.el9_4", ""},
		{"uek kernel version", "5.15.0-206.153.7.el8uek", ""},
		{"no release at all", "0.0.17", ""},

		// Adversarial: the letters present but not as the measured marker.
		{"fips not at the end", "1.0-1.el8_fips2", ""},
		{"fips mid-release", "1.0-1_fipstools.el8", ""},
		{"ksplice with no digit", "1.0-1.ksplice.el8", ""},
		{"ksplice digit but no closing dot", "1.0-1.ksplice1", ""},
		{"empty", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := oracleLineageOf(tt.version); got != tt.want {
				t.Errorf("oracleLineageOf(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}
