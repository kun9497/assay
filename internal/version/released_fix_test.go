package version

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// D163: a fixed range the installed version has cleared, beside an open
// range that still holds it, is a released fix the advisory does not count
// as closing the flaw. The verdict stays affected with the open range's
// state; the reason names the released build.
func TestAffectsVersion_D163_OpenRangeBesideAClearedFixNamesTheReleasedBuild(t *testing.T) {
	a := advisory.Affected{
		Ecosystem: "openSUSE Leap:15.6",
		Name:      "libopenssl3",
		Ranges: []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.1.4-150600.5.53.1"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}, FixState: advisory.FixStateUnknown},
		},
	}
	for _, tc := range []struct {
		v        string
		wantFix  string
		wantText string
	}{
		// Below the released build: the fixed range is the more clearing one
		// and names the fix as before.
		{"3.1.4-150600.5.52.1", "3.1.4-150600.5.53.1", "below the fix 3.1.4-150600.5.53.1"},
		// At and above it: only the open range holds; the reason says which
		// build was released.
		{"3.1.4-150600.5.53.1", "", "3.1.4-150600.5.53.1 is at or above the released fix 3.1.4-150600.5.53.1; the advisory still lists the package as affected, with no later fix recorded"},
		{"3.1.4-150600.5.54.1", "", "is at or above the released fix 3.1.4-150600.5.53.1;"},
	} {
		hit, ev, _, err := AffectsVersion(RPM{}, tc.v, a)
		if err != nil {
			t.Fatal(err)
		}
		if !hit {
			t.Errorf("%s: not affected, want affected", tc.v)
		}
		if ev.Fixed != tc.wantFix {
			t.Errorf("%s: Evidence.Fixed = %q, want %q", tc.v, ev.Fixed, tc.wantFix)
		}
		if !strings.Contains(ev.Reason, tc.wantText) {
			t.Errorf("%s: Reason = %q, want it to contain %q", tc.v, ev.Reason, tc.wantText)
		}
		if tc.wantFix == "" && ev.FixState != advisory.FixStateUnknown {
			t.Errorf("%s: FixState = %q, want the open range's own", tc.v, ev.FixState)
		}
	}
}

// Without a cleared fixed range the open range's reason is unchanged, and a
// last_affected bound is not a released fix.
func TestAffectsVersion_D163_NoReleasedFixKeepsTheOldReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ranges []advisory.Range
	}{
		{"open range alone", []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}}},
		{"fixed range above v", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
		}},
		{"last_affected below v", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {LastAffected: "1.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
		}},
	} {
		hit, ev, _, err := AffectsVersion(RPM{}, "1.5", advisory.Affected{Ecosystem: "x", Name: "p", Ranges: tc.ranges})
		if err != nil {
			t.Fatal(err)
		}
		if !hit {
			t.Errorf("%s: not affected", tc.name)
		}
		if tc.name == "fixed range above v" {
			// 1.5 is below 2.0: that range holds it and is the more clearing one.
			if ev.Fixed != "2.0" || !strings.Contains(ev.Reason, "below the fix 2.0") {
				t.Errorf("%s: Fixed = %q, Reason = %q", tc.name, ev.Fixed, ev.Reason)
			}
			continue
		}
		if ev.Fixed != "" {
			t.Errorf("%s: Fixed = %q, want none", tc.name, ev.Fixed)
		}
		if ev.Reason != "1.5 is at or above any earlier version, with no fixed version recorded" {
			t.Errorf("%s: Reason = %q", tc.name, ev.Reason)
		}
	}
}

// Two released builds: the highest the installed version has cleared is named.
func TestReleasedFixBelow_HighestClearedWins(t *testing.T) {
	ranges := []advisory.Range{
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}}},
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-3"}}},
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-9"}}},
	}
	if got := releasedFixBelow(RPM{}, "1.0-5", ranges); got != "1.0-3" {
		t.Errorf("releasedFixBelow = %q, want 1.0-3", got)
	}
	if got := releasedFixBelow(RPM{}, "0.9-1", ranges); got != "" {
		t.Errorf("releasedFixBelow below every fix = %q, want none", got)
	}
}
