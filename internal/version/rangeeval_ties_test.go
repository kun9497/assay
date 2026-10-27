package version

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

type tieCase struct {
	v                    string
	want                 bool
	introduced, closedAt string // the containing window's bounds, checked when want
	closedByLastAffected bool
}

func checkTies(t *testing.T, name string, r advisory.Range, cases []tieCase) {
	t.Helper()
	for _, tc := range cases {
		got, ev, err := InRange(SemVer{}, tc.v, r)
		if err != nil {
			t.Fatalf("%s: InRange(%q) error: %v", name, tc.v, err)
		}
		if got != tc.want {
			t.Errorf("%s: InRange(%q) = %v, want %v", name, tc.v, got, tc.want)
			continue
		}
		if !tc.want {
			continue
		}
		closed := ev.Fixed
		if tc.closedByLastAffected {
			closed = ev.LastAffected
		}
		if ev.Introduced != tc.introduced || closed != tc.closedAt {
			t.Errorf("%s: InRange(%q) evidence = introduced %q fixed %q last_affected %q, want the window [%s, %s]",
				name, tc.v, ev.Introduced, ev.Fixed, ev.LastAffected, tc.introduced, tc.closedAt)
		}
	}
}

// 2026-10-22 audit A7: one window closing at X and another opening at X tied
// in the sort, and file order broke the tie. With the later window listed
// first, its introduced sorted before the earlier window's close, the close
// shut the window just opened, and every version inside the later window was
// judged clean with empty Evidence -- while the same events listed in order
// returned affected. OSV does not require sorted events (TestInRange_
// UnsortedEvents), so this is valid input. No record in the published
// database has this shape today (measured 2026-10-27: 76 cross-window ties,
// every one listed in order); the verdict must not depend on it.
func TestInRange_A7_ATieAcrossWindowsDoesNotDependOnFileOrder(t *testing.T) {
	cases := []tieCase{
		{v: "2.0.5", want: true, introduced: "2.0.0", closedAt: "3.0.0"},
		{v: "2.0.0", want: true, introduced: "2.0.0", closedAt: "3.0.0"},
		{v: "1.5.0", want: true, introduced: "1.0.0", closedAt: "2.0.0"},
		{v: "3.0.0", want: false},
		{v: "0.9.0", want: false},
	}
	checkTies(t, "fixed, later window first", rng(advisory.RangeSemver,
		intro("2.0.0"), fixed("3.0.0"), intro("1.0.0"), fixed("2.0.0")), cases)
	checkTies(t, "fixed, in order", rng(advisory.RangeSemver,
		intro("1.0.0"), fixed("2.0.0"), intro("2.0.0"), fixed("3.0.0")), cases)

	// last_affected is inclusive, so 2.0.0 sits in both windows; the
	// evidence names the first window it was found in.
	laCases := []tieCase{
		{v: "2.0.5", want: true, introduced: "2.0.0", closedAt: "3.0.0", closedByLastAffected: true},
		{v: "1.5.0", want: true, introduced: "1.0.0", closedAt: "2.0.0", closedByLastAffected: true},
		{v: "3.0.1", want: false},
	}
	checkTies(t, "last_affected, later window first", rng(advisory.RangeSemver,
		intro("2.0.0"), lastAff("3.0.0"), intro("1.0.0"), lastAff("2.0.0")), laCases)
	checkTies(t, "last_affected, in order", rng(advisory.RangeSemver,
		intro("1.0.0"), lastAff("2.0.0"), intro("2.0.0"), lastAff("3.0.0")), laCases)

	// A single-version window opening where another window closes: the same
	// tie, with a degenerate window on one side. Before A7 the close shut the
	// point window, so 2.0.0 was clean, and 1.5.0's evidence named the point
	// window's last_affected instead of its own window's fix.
	pointCases := []tieCase{
		{v: "2.0.0", want: true, introduced: "2.0.0", closedAt: "2.0.0", closedByLastAffected: true},
		{v: "1.5.0", want: true, introduced: "1.0.0", closedAt: "2.0.0"},
		{v: "2.0.1", want: false},
	}
	checkTies(t, "single-version window at a close, listed first", rng(advisory.RangeSemver,
		intro("2.0.0"), lastAff("2.0.0"), intro("1.0.0"), fixed("2.0.0")), pointCases)
	checkTies(t, "single-version window at a close, in order", rng(advisory.RangeSemver,
		intro("1.0.0"), fixed("2.0.0"), intro("2.0.0"), lastAff("2.0.0")), pointCases)
}

// A window that closes at the version it opens at is degenerate, and the
// published database holds 1,906 of them (measured 2026-10-27): an empty
// [X,X) where introduced equals fixed (Bitnami 224, crates.io 5), and a
// single-version [X,X] where introduced equals last_affected (Bitnami 1,657,
// Packagist 20), some repeated dozens of times in one range (Bitnami's
// liferay). Ordering a close before an open at a tie, which is what A7 needs
// across windows, would turn each of these into a window that opens at X and
// never closes. Every case here returned the same verdict before A7.
func TestInRange_A7_DegenerateWindowsKeepTheirMeaning(t *testing.T) {
	checkTies(t, "empty window", rng(advisory.RangeSemver,
		intro("1.0.0"), fixed("1.0.0")), []tieCase{
		{v: "1.0.0", want: false},
		{v: "1.5.0", want: false},
	})
	checkTies(t, "single-version window", rng(advisory.RangeSemver,
		intro("1.0.0"), lastAff("1.0.0")), []tieCase{
		{v: "1.0.0", want: true, introduced: "1.0.0", closedAt: "1.0.0", closedByLastAffected: true},
		{v: "1.0.1", want: false},
		{v: "0.9.0", want: false},
	})
	checkTies(t, "single-version window repeated", rng(advisory.RangeSemver,
		intro("1.0.0"), lastAff("1.0.0"), intro("1.0.0"), lastAff("1.0.0"), intro("1.0.0"), lastAff("1.0.0")), []tieCase{
		{v: "1.0.0", want: true, introduced: "1.0.0", closedAt: "1.0.0", closedByLastAffected: true},
		{v: "2.0.0", want: false},
	})
	// Bitnami discourse's shape: maintenance windows, the newest one empty.
	checkTies(t, "empty newest window", rng(advisory.RangeSemver,
		intro("0"), fixed("3.5.4"), intro("2025.11.0"), fixed("2025.11.2"), intro("2026.1.0"), fixed("2026.1.0")), []tieCase{
		{v: "2025.11.1", want: true, introduced: "2025.11.0", closedAt: "2025.11.2"},
		{v: "2026.1.0", want: false},
		{v: "2026.2.0", want: false},
	})
	// An empty window listed before the window that closes where it opens.
	checkTies(t, "empty window over a close", rng(advisory.RangeSemver,
		intro("2.0.0"), fixed("2.0.0"), intro("1.0.0"), fixed("2.0.0")), []tieCase{
		{v: "1.5.0", want: true, introduced: "1.0.0", closedAt: "2.0.0"},
		{v: "2.0.0", want: false},
	})
}

// The introduced sentinel "0" is negative infinity, not the version 0, so a
// window it opens is never degenerate. PEP 440 compares "0" equal to "0.0";
// taken for an empty window, introduced "0" / fixed "0.0" would drop 0.dev0,
// which sorts below 0.0 and is inside that window.
func TestInRange_A7_TheSentinelNeverOpensADegenerateWindow(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"0.dev0", true},
		{"0a1", true},
		{"0.0", false},
	} {
		got, _, err := InRange(PEP440{}, tc.v, rng(advisory.RangeEcosystem, intro("0"), fixed("0.0")))
		if err != nil {
			t.Fatalf("InRange(%q) error: %v", tc.v, err)
		}
		if got != tc.want {
			t.Errorf("InRange(%q) over introduced 0 / fixed 0.0 = %v, want %v", tc.v, got, tc.want)
		}
	}
}
