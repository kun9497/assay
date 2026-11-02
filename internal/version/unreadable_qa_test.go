package version

import (
	"errors"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// QA 2026-11-02 #2: the ranges path must refuse an installed version the
// comparer cannot read BEFORE any range is walked, because an open-ended
// range resolves the "0" sentinel without a Compare and would otherwise call
// the unreadable version affected -- and a readable sibling range's error was
// then swallowed by that hit.
func TestAffectsVersion_UnreadableInstalledVersionIsRefusedByOpenRanges(t *testing.T) {
	open := advisory.Range{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}
	fixed := advisory.Range{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}}}
	for _, c := range []struct {
		name   string
		v      string
		ranges []advisory.Range
	}{
		{"open range only, empty version", "", []advisory.Range{open}},
		{"open range only, (none)", "(none)", []advisory.Range{open}},
		{"fixed then open", "", []advisory.Range{fixed, open}},
		{"open then fixed", "not a version", []advisory.Range{open, fixed}},
	} {
		hit, ev, unreadable, err := AffectsVersion(Deb{}, c.v, advisory.Affected{Ranges: c.ranges})
		if err == nil {
			t.Errorf("%s: err = nil (hit=%v, evidence %q), want the installed version refused", c.name, hit, ev.Reason)
			continue
		}
		if hit || ev.Reason != "" || unreadable != nil {
			t.Errorf("%s: hit=%v evidence=%q unreadable=%v, want nothing concluded", c.name, hit, ev.Reason, unreadable)
		}
		if CauseOf(err) != CauseTargetVersion {
			t.Errorf("%s: CauseOf = %v, want CauseTargetVersion", c.name, CauseOf(err))
		}
		if !strings.Contains(err.Error(), `"`+c.v+`"`) {
			t.Errorf("%s: error %q does not name the version that could not be read", c.name, err)
		}
	}
}

// An advisory with nothing to evaluate stays clean without error, whatever
// the installed version: there is no comparison to refuse.
func TestAffectsVersion_UnreadableVersionAgainstNothingIsNotAnError(t *testing.T) {
	hit, _, _, err := AffectsVersion(Deb{}, "", advisory.Affected{})
	if hit || err != nil {
		t.Errorf("hit=%v err=%v, want false, nil", hit, err)
	}
}

// QA 2026-11-02 #3: a range with a closing bound but no introduced event
// walked to "not affected" with no error, because the malformed-range guard
// fired only when no event carried any bound. The OSV schema requires an
// introduced event per range; without one the window never opens, which is
// a silent clean verdict on malformed data -- the exact thing the guard's
// own comment promises to surface.
func TestInRange_RangeWithoutIntroducedIsInvalid(t *testing.T) {
	for _, c := range []struct {
		name   string
		events []advisory.Event
	}{
		{"fixed only", []advisory.Event{{Fixed: "1.0.0"}}},
		{"last_affected only", []advisory.Event{{LastAffected: "1.0.0"}}},
		{"two fixed", []advisory.Event{{Fixed: "1.0.0"}, {Fixed: "2.0.0"}}},
	} {
		hit, _, err := InRange(SemVer{}, "0.5.0", advisory.Range{Type: advisory.RangeSemver, Events: c.events})
		if err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v (hit=%v), want ErrInvalid", c.name, err, hit)
			continue
		}
		if !strings.Contains(err.Error(), "introduced") {
			t.Errorf("%s: error %q does not say what the range lacks", c.name, err)
		}
		if hit {
			t.Errorf("%s: hit = true on an invalid range", c.name)
		}
	}
	// The sentinel is an introduced event; a well-formed open range still walks.
	hit, _, err := InRange(SemVer{}, "0.5.0", advisory.Range{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}}})
	if err != nil || !hit {
		t.Errorf("open range: hit=%v err=%v, want true, nil", hit, err)
	}
}
