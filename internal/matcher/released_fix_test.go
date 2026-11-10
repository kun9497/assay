package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// D163, at the caller: a finding on an installed build that is at or above
// the fix the advisory released, while the advisory's open range still
// holds it, reads the released build in its reason and keeps the open
// range's fix state -- SUSE's "released, In progress" shape (CVE-2026-34182's
// libopenssl3 3.1.4-150600.5.53.1 on Leap 15.6, the truthset's first
// corrected label).
func TestMatch_D163_ReleasedBuildStillAffectedNamesTheReleasedFix(t *testing.T) {
	adv := advisory.Advisory{
		ID: "SUSE-CVE-2026-34182", Database: "SUSE", Kind: advisory.KindVulnerability, Aliases: []string{"CVE-2026-34182"},
		Affected: []advisory.Affected{{
			Ecosystem: "openSUSE Leap:15.6", Name: "libopenssl3",
			Ranges: []advisory.Range{
				{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.1.4-150600.5.53.1"}}},
				{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}, FixState: advisory.FixStateUnknown},
			},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"openSUSE Leap:15.6\x00libopenssl3": {adv}}}
	for _, tc := range []struct {
		version, wantFixed, wantReason string
		wantState                      advisory.FixState
	}{
		{"3.1.4-150600.5.52.1", "3.1.4-150600.5.53.1", "below the fix 3.1.4-150600.5.53.1", advisory.FixStateFixed},
		{"3.1.4-150600.5.53.1", "", "is at or above the released fix 3.1.4-150600.5.53.1; the advisory also lists the package as affected at every version, with no fix recorded for that", advisory.FixStateUnknown},
	} {
		res, err := New(s).Match(pkgmeta.Target{
			Distro:   &pkgmeta.Distro{ID: "opensuse-leap", VersionID: "15.6"},
			Packages: []pkgmeta.Package{{Name: "libopenssl3", Version: tc.version, Type: "rpm", Ecosystem: "openSUSE Leap:15.6"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("%s: findings = %d, want 1", tc.version, len(res.Findings))
		}
		f := res.Findings[0]
		if f.Evidence.Fixed != tc.wantFixed {
			t.Errorf("%s: Evidence.Fixed = %q, want %q", tc.version, f.Evidence.Fixed, tc.wantFixed)
		}
		if !strings.Contains(f.Evidence.Reason, tc.wantReason) {
			t.Errorf("%s: Evidence.Reason = %q, want it to contain %q", tc.version, f.Evidence.Reason, tc.wantReason)
		}
		if got := f.FixState(); got != tc.wantState {
			t.Errorf("%s: FixState() = %q, want %q (the verdict does not change, only the reason)", tc.version, got, tc.wantState)
		}
	}
}
