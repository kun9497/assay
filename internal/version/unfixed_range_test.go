package version

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// A range with an introduced event and NO fixed event means "affected at every
// version", and this is the assertion the Red Hat CSAF VEX provider rests on
// (D48): 1,278,384 of the 1,918,779 affected entries it produces are exactly
// this shape, because Red Hat is saying a package is affected and there is
// nothing to upgrade to.
//
// The machinery already handled it — atLeast short-circuits the "0" sentinel
// and describe() even has the wording — but nothing asserted it. An untested
// load-bearing assumption in a different package from the one that depends on
// it is how a provider ships producing records that match nothing.
func TestInRange_IntroducedWithNoFixAffectsEveryVersion(t *testing.T) {
	unfixed := advisory.Range{
		Type:   advisory.RangeEcosystem,
		Events: []advisory.Event{{Introduced: "0"}},
	}
	// Real RHEL EVRs, spanning twenty years of releases. Every one of them is
	// affected, and the point is that no version can escape.
	for _, v := range []string{
		"0:1.4-1.el5",
		"0:1.30-2.el7",
		"2:1.30-9.el8",
		"0:1.34-7.el9",
		"0:1.35-8.el10",
		"99:999-999.el99",
	} {
		hit, ev, err := InRange(RPM{}, v, unfixed)
		if err != nil {
			t.Errorf("InRange(%q): %v", v, err)
			continue
		}
		if !hit {
			t.Errorf("InRange(%q) = false; a range with no fixed event affects every version, "+
				"and reporting otherwise turns 1.28M Red Hat records into silent misses", v)
		}
		if ev.Fixed != "" {
			t.Errorf("InRange(%q) reported a fix of %q; Red Hat says there is none", v, ev.Fixed)
		}
		// The report reads this. "with no fixed version recorded" is the
		// difference between "upgrade to X" and "there is nothing to upgrade
		// to", and the second is the whole reason the record exists.
		if ev.Reason == "" {
			t.Errorf("InRange(%q) produced no Reason", v)
		}
	}

	// And the shape is still distinguishable from a normal range, so a report
	// can say which kind it is: a fixed range fills Evidence.Fixed and this
	// one does not.
	fixedRange := advisory.Range{
		Type:   advisory.RangeEcosystem,
		Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:1.34-7.el9"}},
	}
	hit, ev, err := InRange(RPM{}, "0:1.30-2.el9", fixedRange)
	if err != nil || !hit {
		t.Fatalf("InRange on a normal range = %v, %v", hit, err)
	}
	if ev.Fixed != "0:1.34-7.el9" {
		t.Errorf("Evidence.Fixed = %q, want the fix; the two shapes must stay distinguishable", ev.Fixed)
	}
	// Above the fix: not affected. The unfixed range has no such escape.
	if hit, _, err := InRange(RPM{}, "0:1.35-1.el9", fixedRange); err != nil || hit {
		t.Errorf("a version above the fix was reported affected (%v, %v)", hit, err)
	}
}

// AffectsVersion is the entry point the matcher actually calls, so the same
// property is asserted one layer up rather than inferred.
func TestAffectsVersion_UnfixedAffectedEntry(t *testing.T) {
	a := advisory.Affected{
		Ecosystem: "Red Hat:9",
		Name:      "tar",
		Ranges: []advisory.Range{{
			Type:   advisory.RangeEcosystem,
			Events: []advisory.Event{{Introduced: "0"}},
		}},
	}
	hit, ev, unreadable, err := AffectsVersion(RPM{}, "2:1.34-7.el9", a)
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Error("AffectsVersion = false on a Red Hat affected-with-no-fix entry")
	}
	if len(unreadable) != 0 {
		t.Errorf("unreadable = %v, want none", unreadable)
	}
	if ev.Fixed != "" {
		t.Errorf("Evidence.Fixed = %q, want empty", ev.Fixed)
	}
}
