package version

import (
	"errors"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func rng(t advisory.RangeType, events ...advisory.Event) advisory.Range {
	return advisory.Range{Type: t, Events: events}
}

func intro(v string) advisory.Event   { return advisory.Event{Introduced: v} }
func fixed(v string) advisory.Event   { return advisory.Event{Fixed: v} }
func lastAff(v string) advisory.Event { return advisory.Event{LastAffected: v} }

func TestInRange_Semver(t *testing.T) {
	cases := []struct {
		name string
		v    string
		r    advisory.Range
		want bool
	}{
		// The "0" sentinel: the regression tests that matter most here.
		{"prerelease of 0.0.0 under sentinel", "0.0.0-experimental-abc",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"go pseudo-version under sentinel", "v0.0.0-20191109021931-daa7c04131f5",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"zero under sentinel", "0.0.0",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},

		// Half-open: introduced is affected, fixed is not.
		{"at introduced", "1.0.0", rng(advisory.RangeSemver, intro("1.0.0"), fixed("1.0.1")), true},
		{"at fixed", "1.0.0", rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), false},
		{"below introduced", "1.0.0-rc1", rng(advisory.RangeSemver, intro("1.0.0"), fixed("1.0.1")), false},
		{"prerelease of fixed is affected", "1.0.0-rc1",
			rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")), true},
		{"below range", "0.9.9", rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")), false},
		{"above range", "2.0.0", rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")), false},

		// last_affected is inclusive, unlike fixed.
		{"at last_affected", "1.0.0", rng(advisory.RangeSemver, intro("0"), lastAff("1.0.0")), true},
		{"above last_affected", "1.0.1", rng(advisory.RangeSemver, intro("0"), lastAff("1.0.0")), false},

		// Open-ended upper bound.
		{"open ended", "99.0.0", rng(advisory.RangeSemver, intro("1.0.0")), true},
		{"open ended below", "0.1.0", rng(advisory.RangeSemver, intro("1.0.0")), false},

		// Multiple introduced/fixed pairs in one range.
		{"second window", "2.5.0", rng(advisory.RangeSemver,
			intro("1.0.0"), fixed("1.5.0"), intro("2.0.0"), fixed("3.0.0")), true},
		{"between windows", "1.7.0", rng(advisory.RangeSemver,
			intro("1.0.0"), fixed("1.5.0"), intro("2.0.0"), fixed("3.0.0")), false},

		// v-prefixed artifact against bare bounds.
		{"v prefix", "v1.2.3", rng(advisory.RangeSemver, intro("1.2.0"), fixed("1.2.4")), true},
		{"incompatible build metadata", "v2.0.0+incompatible",
			rng(advisory.RangeSemver, intro("2.0.0"), fixed("2.0.1")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := InRange(SemVer{}, tc.v, tc.r)
			if err != nil {
				t.Fatalf("InRange(%q) error: %v", tc.v, err)
			}
			if got != tc.want {
				t.Errorf("InRange(%q) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

func TestInRange_PEP440Sentinel(t *testing.T) {
	// The same sentinel trap exists for PyPI: 0.dev0 and 0a1 both sort BELOW
	// the literal version "0", so coercing the sentinel misses them.
	for _, v := range []string{"0.dev0", "0a1", "0.0.0rc1", "0"} {
		got, _, err := InRange(PEP440{}, v, rng(advisory.RangeEcosystem, intro("0"), fixed("1.0")))
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", v, err)
		}
		if !got {
			t.Errorf("InRange(%q) = false, want true (sentinel must be -inf)", v)
		}
	}
}

func TestInRange_GitSkipped(t *testing.T) {
	// GIT ranges carry commit SHAs. Feeding them to a Comparer would error;
	// the range must be skipped instead, with no error surfaced.
	r := rng(advisory.RangeGit, intro("9305c0e12d43c4df999c3301a1f0c742264a657e"))
	got, _, err := InRange(SemVer{}, "1.0.0", r)
	if err != nil {
		t.Fatalf("InRange over GIT range error: %v", err)
	}
	if got {
		t.Error("InRange over GIT range = true, want false")
	}
}

func TestInRange_InvalidVersionErrors(t *testing.T) {
	// An unparseable installed version must surface, not evaluate to false.
	_, _, err := InRange(SemVer{}, "not-a-version",
		rng(advisory.RangeSemver, intro("0"), fixed("1.0.0")))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("InRange err = %v, want ErrInvalid", err)
	}
}

func TestInRange_UnsortedEvents(t *testing.T) {
	// OSV only recommends sorted events, so a later window listed first is
	// well-formed. Walking in file order returns false with no error — a
	// silent miss on valid input.
	r := rng(advisory.RangeSemver,
		intro("2.0.0"), fixed("3.0.0"),
		intro("1.0.0"), fixed("1.5.0"))
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"2.5.0", true},  // inside the window that was listed first
		{"1.2.0", true},  // inside the window that was listed second
		{"1.7.0", false}, // between the two windows
		{"3.0.0", false}, // at the upper fix, exclusive
	} {
		got, _, err := InRange(SemVer{}, tc.v, r)
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("InRange(%q) over unsorted events = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestInRange_BoundlessEventDoesNotBreakSorting(t *testing.T) {
	// An event carrying no bound must not reach the comparer. If it did, the
	// failed comparison would be discarded and the event would report as equal
	// to everything — a violated ordering that can leave the slice unsorted,
	// silently undoing the sort and restoring the original false negative.
	r := rng(advisory.RangeSemver,
		intro("2.0.0"), fixed("3.0.0"),
		advisory.Event{Limit: "1.0.0"},
		intro("1.0.0"), fixed("1.5.0"))
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1.2.0", true},
		{"2.5.0", true},
		{"1.7.0", false},
	} {
		got, _, err := InRange(SemVer{}, tc.v, r)
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("InRange(%q) with a boundless event = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestInRange_RangeWithNoBoundsErrors(t *testing.T) {
	// Every event carries only a limit, so no window can open. Returning "not
	// affected" would be indistinguishable from a real miss.
	r := rng(advisory.RangeSemver, advisory.Event{Limit: "1.0.0"})
	_, _, err := InRange(SemVer{}, "1.2.3", r)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("InRange over a boundless range err = %v, want ErrInvalid", err)
	}
}

func TestInRange_MalformedBoundErrors(t *testing.T) {
	// A bound that cannot be ordered must surface. Sorting on an unorderable
	// bound would otherwise pick an arbitrary order and return a confident
	// wrong verdict.
	_, _, err := InRange(SemVer{}, "1.2.3",
		rng(advisory.RangeSemver, intro("1.0.0"), fixed("not-a-version")))
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("InRange with a malformed bound err = %v, want ErrInvalid", err)
	}
}

func TestInRange_EvidenceNamesTheContainingWindow(t *testing.T) {
	// With several maintenance branches, evidence must cite the fix for the
	// window the version is actually in. Naming a later window's fix sends the
	// user to the wrong upgrade.
	r := rng(advisory.RangeSemver,
		intro("1.0.0"), fixed("1.5.0"),
		intro("2.0.0"), fixed("3.0.0"))
	got, ev, err := InRange(SemVer{}, "1.2.0", r)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("InRange = false, want true")
	}
	if ev.Introduced != "1.0.0" || ev.Fixed != "1.5.0" {
		t.Errorf("Evidence = introduced %q fixed %q, want 1.0.0 / 1.5.0",
			ev.Introduced, ev.Fixed)
	}
}

func TestAffectsVersion_EnumeratedPropagatesCompareError(t *testing.T) {
	// The installed version is the left operand on every iteration, so an
	// unparseable one fails every entry. Skipping would turn a total failure
	// into a silent clean verdict.
	a := advisory.Affected{
		Ecosystem: "Go",
		Name:      "x",
		Versions:  []string{"1.0.0", "2.0.0"},
	}
	_, _, unreadable, err := AffectsVersion(SemVer{}, "not-a-version", a)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("AffectsVersion err = %v, want ErrInvalid", err)
	}
	// D30 skips an unreadable LISTED version and keeps going. It must not do
	// that here: the unreadable operand is the installed version, so every
	// entry would be skipped and the package would come back clean. Asserting
	// the empty slice is what separates the two cases — a signature that
	// reported these two entries as merely "unreadable" would satisfy the
	// error check above only until someone downgraded the abort to a skip.
	if len(unreadable) != 0 {
		t.Errorf("unreadable = %v, want none: an unreadable installed version aborts, it does not skip entries", unreadable)
	}
}

// D30. An unreadable entry in the enumerated list must not take the whole
// advisory down with it: 2,411 of 1,309,665 enumerated versions in the v7
// database do not parse, and one of them was enough to report a package whose
// own version is perfectly readable as unevaluable.
func TestAffectsVersion_EnumeratedSkipsUnreadableEntries(t *testing.T) {
	// "0.9-stable" is real: PyPI advisory data for trac carries it.
	a := advisory.Affected{
		Ecosystem: "PyPI",
		Name:      "trac",
		Versions:  []string{"0.9-stable", "1.0", "2.0"},
	}
	// The junk entry sits BEFORE the match, so a loop that aborts on it never
	// reaches 1.0 and this cannot pass by accident of ordering.
	hit, _, unreadable, err := AffectsVersion(PEP440{}, "1.0", a)
	if err != nil {
		t.Fatalf("AffectsVersion error = %v, want nil: one bad listed version must not fail the advisory", err)
	}
	if !hit {
		t.Error("hit = false, want true: 1.0 is listed, and an earlier unreadable entry must not hide it")
	}
	if len(unreadable) != 1 || unreadable[0] != "0.9-stable" {
		t.Errorf("unreadable = %v, want exactly [0.9-stable]", unreadable)
	}

	// And the same list with no match: the verdict is "not affected", but the
	// caller must still learn the evaluation was incomplete. Returning nil here
	// is the silent-miss failure mode, so it is asserted separately from the
	// hit case above.
	hit, _, unreadable, err = AffectsVersion(PEP440{}, "3.0", a)
	if err != nil {
		t.Fatalf("AffectsVersion error = %v, want nil", err)
	}
	if hit {
		t.Error("hit = true, want false: 3.0 is not listed")
	}
	if len(unreadable) != 1 || unreadable[0] != "0.9-stable" {
		t.Errorf("unreadable on the no-hit path = %v, want [0.9-stable]; a verdict reached over an unread entry is incomplete", unreadable)
	}
}

func TestInRange_Evidence(t *testing.T) {
	_, ev, err := InRange(SemVer{}, "1.2.3",
		rng(advisory.RangeSemver, intro("1.0.0"), fixed("2.0.0")))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Introduced != "1.0.0" || ev.Fixed != "2.0.0" {
		t.Errorf("Evidence = %+v, want introduced=1.0.0 fixed=2.0.0", ev)
	}
	if ev.RangeType != advisory.RangeSemver {
		t.Errorf("Evidence.RangeType = %q, want SEMVER", ev.RangeType)
	}
	if ev.Reason == "" {
		t.Error("Evidence.Reason is empty; a finding must be able to explain itself")
	}
}

func TestAffectsVersion_EnumeratedOnly(t *testing.T) {
	// When an Affected carries no Ranges, the enumerated Versions list is the
	// only matching data available.
	a := advisory.Affected{
		Ecosystem: "PyPI",
		Name:      "django",
		Versions:  []string{"1.0", "1.0.1", "2.0"},
	}
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1.0", true},
		{"1.0.0", true}, // equal under PEP 440 even though the strings differ
		{"1.5", false},
	} {
		got, _, unreadable, err := AffectsVersion(PEP440{}, tc.v, a)
		if err != nil {
			t.Fatalf("AffectsVersion(%q) error: %v", tc.v, err)
		}
		if len(unreadable) != 0 {
			t.Errorf("AffectsVersion(%q) unreadable = %v, want none: every entry here parses", tc.v, unreadable)
		}
		if got != tc.want {
			t.Errorf("AffectsVersion(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// D35. The two failures render as the same "not evaluated" line, and they mean
// opposite things to whoever is reading it: an advisory whose bound is malformed
// is nothing the person running the scan can act on, while an unreadable
// installed version usually means their own inventory. The message has to say
// which, and this is the assertion that makes it a contract rather than
// wording — reverting either string to the old operand-agnostic form turns it
// red.
func TestInRange_ErrorNamesWhoseDataIsBroken(t *testing.T) {
	t.Run("a malformed bound is the advisory's", func(t *testing.T) {
		// The version under test parses perfectly; only the bound does not.
		_, _, err := InRange(APK{}, "1.2.3-r4",
			rng(advisory.RangeEcosystem, intro("0"), fixed("1999-12-14")))
		if err == nil {
			t.Fatal("InRange returned no error for an unreadable bound")
		}
		if !strings.Contains(err.Error(), "advisory") {
			t.Errorf("error = %q, want it to name the advisory as the source of the bad data", err)
		}
		if strings.Contains(err.Error(), "package") {
			t.Errorf("error = %q, blames the package for the advisory's defect", err)
		}
		// D36: the same fact, machine-readable. Asserted here rather than
		// through the matcher, because the matcher defaults an unclassified
		// error to "advisory" — so an untagged error reaches the same verdict
		// there and the tag looks redundant. It is not: CauseOf answering
		// correctly is this package's contract, and a caller that ever chose a
		// different default would silently misclassify every bad bound.
		if got := CauseOf(err); got != CauseAdvisoryData {
			t.Errorf("CauseOf = %v, want CauseAdvisoryData", got)
		}
	})

	t.Run("a malformed installed version is the package's", func(t *testing.T) {
		// Every bound here parses; only the installed version does not.
		_, _, err := InRange(APK{}, "not-a-version",
			rng(advisory.RangeEcosystem, intro("0"), fixed("1.2.3-r4")))
		if err == nil {
			t.Fatal("InRange returned no error for an unreadable installed version")
		}
		if !strings.Contains(err.Error(), "package") {
			t.Errorf("error = %q, want it to name the package's own version", err)
		}
		// The bound is still named for context, so this cannot assert on its
		// absence — it asserts that the ADVISORY is not blamed, which is the
		// half that would be wrong.
		if strings.Contains(err.Error(), "advisory's range bound") {
			t.Errorf("error = %q, blames the advisory for the package's version", err)
		}
		if got := CauseOf(err); got != CauseTargetVersion {
			t.Errorf("CauseOf = %v, want CauseTargetVersion", got)
		}
	})

	t.Run("an unclassified error is not silently assigned a side", func(t *testing.T) {
		// The zero value must stay distinguishable. A new error site that
		// forgets to classify itself has to show up as unknown rather than
		// joining whichever side the zero value happens to name.
		if got := CauseOf(errors.New("something else")); got != CauseUnknown {
			t.Errorf("CauseOf(unclassified) = %v, want CauseUnknown", got)
		}
		if got := CauseOf(nil); got != CauseUnknown {
			t.Errorf("CauseOf(nil) = %v, want CauseUnknown", got)
		}
	})
}
