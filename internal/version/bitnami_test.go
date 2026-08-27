package version

import (
	"errors"
	"testing"
)

// TestBitnami_Compare is table-driven over real shapes measured against the
// live Bitnami OSV archive 2026-08-27 (9,059 records, 4,375 distinct advisory
// version strings): the ordinary ordering cases once a revision (if any) is
// stripped, delegate to SemVer{}.
func TestBitnami_Compare(t *testing.T) {
	rows := []struct {
		name string
		a, b string
		want int
	}{
		{"plain semver core, no revision on either side", "1.3.2", "1.3.2", 0},
		{"ordinary upgrade, no revisions", "5.15.11", "5.16.0", -1},
		{"ordinary downgrade, no revisions", "5.16.1", "5.15.14", 1},
		// D99's worked example: an installed revision compares AT-OR-ABOVE a
		// bare fixed bound of the same core -- the revision is packaging
		// metadata, not a version regression.
		{"installed revision vs bare fixed, same core", "18.6.0-3", "18.6.0", 0},
		{"bare fixed vs installed revision, same core (symmetric)", "18.6.0", "18.6.0-3", 0},
		// A real gap: the installed core itself is behind the fix, so the
		// revision is irrelevant.
		{"installed revision genuinely below fixed core", "17.5.0-14", "17.5.1", -1},
		{"fixed core genuinely above, reversed operands", "17.5.1", "17.5.0-14", 1},
		// Both sides carry a revision of the SAME core: numeric tie-break,
		// not lexicographic -- "10" must sort above "3".
		{"same core, revisions order numerically (3 < 10)", "18.6.0-3", "18.6.0-10", -1},
		{"same core, revisions order numerically, reversed", "18.6.0-10", "18.6.0-3", 1},
		{"same core, same revision", "18.6.0-3", "18.6.0-3", 0},
		// A bundled library never carries a revision at all in real Bitnami
		// SPDX docs (geos, proj, gdal all measured bare) -- ordinary SemVer
		// compare once neither side has one.
		{"bundled-lib style, no revisions, equal", "3.14.1", "3.14.1", 0},
		{"bundled-lib style, no revisions, upgrade", "3.13.1", "3.14.1", -1},
		// A hyphen tail that is NOT purely digits is not a revision and must
		// reach SemVer{} unmodified (and there parse as an ordinary
		// pre-release, since none of these examples are among the 44
		// refusals).
		{"non-numeric hyphen tail is not a revision", "1.0.0-rc1", "1.0.0", -1},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, err := Bitnami{}.Compare(r.a, r.b)
			if err != nil {
				t.Fatalf("Compare(%q, %q): %v", r.a, r.b, err)
			}
			if got != r.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", r.a, r.b, got, r.want)
			}
		})
	}
}

// TestBitnami_Refusals pins every one of the 44 real advisory version
// strings measured 2026-08-27 that do NOT parse under Bitnami{} -- PHP-style
// build-train labels ("7.4-update41.0"), four-component cores
// ("7.4.19.0"), and a handful of date-stamped or preview/beta labels. None of
// these carries a purely-numeric trailing hyphen segment, so
// stripBitnamiRevision never rescues them (a deliberate property, checked
// here): they must surface as a skip, never be guessed at (D9).
func TestBitnami_Refusals(t *testing.T) {
	bad := []string{
		"0.15-20200726.0", "2020-07-29.0.0", "2021-09-14.0.0", "2022-07-31.0.0",
		"2022-10-15.0.0", "2023.03-1.0", "3.0-rc.0", "3.0-rc2.0", "3.0-rc3.0",
		"4.0-beta1.0", "4.0-beta2.0", "4.0-rc1.0", "5.0-preview1.0", "5.0-preview2.0",
		"5.0-preview3.0", "5.59-alpha1.0", "5.8-beta1.0", "5.8-beta2.0", "7.0-fix.0",
		"7.1-fix.0", "7.1-sp1.0", "7.2-fix.0", "7.3-fix.0", "7.3-update14.0",
		"7.4-update1.0", "7.4-update21.0", "7.4-update34.0", "7.4-update36.0",
		"7.4-update41.0", "7.4-update48.0", "7.4-update50.0", "7.4-update52.0",
		"7.4-update62.0", "7.4-update67.0", "7.4-update76.0", "7.4-update81.0",
		"7.4-update82.0", "7.4-update83.0", "7.4-update84.0", "7.4-update85.0",
		"7.4-update86.0", "7.4.19.0", "7.5.10.0", "nightly.2026-03-10.0",
	}
	if len(bad) != 44 {
		t.Fatalf("fixture has %d entries, want the full measured 44", len(bad))
	}
	for _, v := range bad {
		if _, err := (Bitnami{}).Compare(v, "1.0.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, ...) error = %v, want ErrInvalid", v, err)
		}
		if _, err := (Bitnami{}).Compare("1.0.0", v); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(..., %q) error = %v, want ErrInvalid", v, err)
		}
	}
}

// TestStripBitnamiRevision is the direct table for the split helper,
// covering the branches TestBitnami_Compare's own rows do not individually
// isolate (empty revision, trailing bare hyphen, no hyphen at all).
func TestStripBitnamiRevision(t *testing.T) {
	rows := []struct {
		in       string
		wantCore string
		wantRev  string
		wantOK   bool
	}{
		{"18.6.0-3", "18.6.0", "3", true},
		{"18.6.0-10", "18.6.0", "10", true},
		{"18.6.0", "18.6.0", "", false},                 // no hyphen at all
		{"18.6.0-", "18.6.0-", "", false},               // trailing bare hyphen, nothing to strip
		{"7.4-update41.0", "7.4-update41.0", "", false}, // non-numeric tail
		{"0", "0", "", false},                           // the OSV introduced sentinel
	}
	for _, r := range rows {
		core, rev, ok := stripBitnamiRevision(r.in)
		if core != r.wantCore || rev != r.wantRev || ok != r.wantOK {
			t.Errorf("stripBitnamiRevision(%q) = (%q, %q, %v), want (%q, %q, %v)",
				r.in, core, rev, ok, r.wantCore, r.wantRev, r.wantOK)
		}
	}
}
