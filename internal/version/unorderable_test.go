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
