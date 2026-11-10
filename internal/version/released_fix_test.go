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
		{"3.1.4-150600.5.53.1", "", "3.1.4-150600.5.53.1 is at or above the released fix 3.1.4-150600.5.53.1; the advisory also lists the package as affected at every version, with no fix recorded for that"},
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

// Without a cleared [0, fix) window the open range's reason is unchanged, a
// last_affected bound is not a released fix, and a fix still above v is the
// one named.
func TestAffectsVersion_D163_NoReleasedFixKeepsTheOldReason(t *testing.T) {
	open := advisory.Range{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}
	for _, tc := range []struct {
		name      string
		ranges    []advisory.Range
		wantFixed string
		want      string
	}{
		{"open range alone", []advisory.Range{open}, "", "1.5 is at or above any earlier version, with no fixed version recorded"},
		{"fixed range above v", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0"}}}, open,
		}, "2.0", "1.5 is at or above any earlier version and below the fix 2.0"},
		{"last_affected below v", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {LastAffected: "1.0"}}}, open,
		}, "", "1.5 is at or above any earlier version, with no fixed version recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hit, ev, _, err := AffectsVersion(RPM{}, "1.5", advisory.Affected{Ecosystem: "x", Name: "p", Ranges: tc.ranges})
			if err != nil || !hit {
				t.Fatalf("hit=%v err=%v", hit, err)
			}
			if ev.Fixed != tc.wantFixed || ev.Reason != tc.want {
				t.Errorf("Fixed = %q, Reason = %q; want %q, %q", ev.Fixed, ev.Reason, tc.wantFixed, tc.want)
			}
		})
	}
}

// A version below a fix the advisory still offers is told about that fix,
// not about an older released build it has cleared: the rewrite applies to
// an open range only.
func TestAffectsVersion_D163_BelowALaterFixIsNotRewritten(t *testing.T) {
	a := advisory.Affected{Ecosystem: "x", Name: "p", Ranges: []advisory.Range{
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}}},
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-9"}}},
		{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
	}}
	hit, ev, _, err := AffectsVersion(RPM{}, "1.0-5", a)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if ev.Fixed != "1.0-9" || !strings.Contains(ev.Reason, "below the fix 1.0-9") || strings.Contains(ev.Reason, "released") {
		t.Errorf("Fixed = %q, Reason = %q", ev.Fixed, ev.Reason)
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

// The review's shapes (PR #264): none is D163's, and each keeps the walk's
// own sentence rather than naming a "released fix" that is not one.
func TestAffectsVersion_D163_OnlyTheCSAFShapeIsRewritten(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v      string
		ranges []advisory.Range
		want   string
	}{
		{"multi-branch: an open line above an older line's fix", "2.5.0", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.2.0"}, {Introduced: "2.0.0"}}},
		}, "2.5.0 is at or above 2.0.0, with no fixed version recorded"},
		{"separate open range above an older line's fix", "2.5.0", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "2.0.0"}}},
		}, "2.5.0 is at or above 2.0.0, with no fixed version recorded"},
		{"never-affected sentinel beside an open range", "1.5", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
		}, "1.5 is at or above any earlier version, with no fixed version recorded"},
		{"empty window [1.0, 1.0) beside an open range", "1.5", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "1.0"}, {Fixed: "1.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
		}, "1.5 is at or above any earlier version, with no fixed version recorded"},
		{"malformed range with no introduced", "1.5", []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Fixed: "1.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}},
		}, "1.5 is at or above any earlier version, with no fixed version recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hit, ev, _, err := AffectsVersion(RPM{}, tc.v, advisory.Affected{Ecosystem: "x", Name: "p", Ranges: tc.ranges})
			if err != nil || !hit {
				t.Fatalf("hit=%v err=%v", hit, err)
			}
			if ev.Reason != tc.want {
				t.Errorf("Reason = %q, want %q", ev.Reason, tc.want)
			}
		})
	}
}
