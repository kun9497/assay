package version

import (
	"errors"
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
	_, _, err := AffectsVersion(SemVer{}, "not-a-version", a)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("AffectsVersion err = %v, want ErrInvalid", err)
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
		got, _, err := AffectsVersion(PEP440{}, tc.v, a)
		if err != nil {
			t.Fatalf("AffectsVersion(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("AffectsVersion(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
