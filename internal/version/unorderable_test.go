package version

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// QA 2026-11-20. A package installed from a Composer branch is the target's
// unreadable version, not the advisory's.
func TestAffectsVersion_AComposerBranchIsTheTargetsOwnDefect(t *testing.T) {
	aff := func(ev ...advisory.Event) advisory.Affected {
		return advisory.Affected{Ecosystem: "Packagist", Name: "symfony/http-kernel", Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: ev}}}
	}
	fixed := aff(advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "5.4.20"})
	for v, want := range map[string]Cause{"dev-main": CauseTargetVersion, "dev-master": CauseTargetVersion} {
		if _, _, _, err := AffectsVersion(Composer{}, v, fixed); err == nil || CauseOf(err) != want {
			t.Errorf("%s: err %v, cause %v; want %v", v, err, CauseOf(err), want)
		}
	}
	// The mirror case stays the advisory's.
	branch := aff(advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "dev-master"})
	if _, _, _, err := AffectsVersion(Composer{}, "5.4.0", branch); err == nil || CauseOf(err) != CauseAdvisoryData {
		t.Errorf("a branch bound: err %v, cause %v; want the advisory's", err, CauseOf(err))
	}
}

// QA 2026-11-20: a last_affected bound that does not order is an error, not a
// clean verdict.
func TestAffectsVersion_AnUnorderableLastAffectedIsAnError(t *testing.T) {
	a := advisory.Affected{Ecosystem: "Packagist", Name: "x", Ranges: []advisory.Range{{Type: "ECOSYSTEM",
		Events: []advisory.Event{{Introduced: "0"}, {LastAffected: "dev-master"}}}}}
	if hit, _, _, err := AffectsVersion(Composer{}, "1.5.0", a); hit || err == nil || CauseOf(err) != CauseAdvisoryData {
		t.Errorf("hit %v, err %v, cause %v; want the advisory's bound refused", hit, err, CauseOf(err))
	}
}
