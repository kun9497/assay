package gobinary

import (
	"testing"

	"github.com/kun9497/assay/internal/version"
)

// The shapes Go actually stamps into a binary, and what each must become
// before the Go comparer will look at it (D24).
//
// Three of these are rejected by the comparer outright — measured, not
// assumed: "1.26" and "1.21rc1" fail with "core needs exactly three
// identifiers", and "go1.26.4" fails with `core identifier "go1"`. That makes
// a MISSING normalization loud: the package is skipped and counted. The
// danger is the opposite, a normalization that parses but orders wrongly,
// which reports a vulnerable toolchain as clean. That is what the second test
// exists for.
func TestNormalizeGoVersion(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		ok   bool
	}{
		// The ordinary case.
		{"go1.26.4", "1.26.4", true},
		// Go's initial release of a major line had no patch component until
		// 1.21, so "go1.20" is a real toolchain version. The comparer rejects
		// a two-component core, so without the padding every binary built by
		// one of those toolchains is silently skipped.
		{"go1.20", "1.20.0", true},
		{"go1.16", "1.16.0", true},
		// Release candidates and betas. Go writes them with no separator;
		// semver needs a hyphen and a dot, and the result must sort BELOW the
		// release — 1.21.0-rc.1 < 1.21.0 was measured against the comparer.
		{"go1.21rc1", "1.21.0-rc.1", true},
		{"go1.22beta1", "1.22.0-beta.1", true},
		{"go1.21.5rc2", "1.21.5-rc.2", true},
		{"go1.24.0-rc.1", "1.24.0-rc.1", true},
		// Already normalized: Parse must be safe to call on a version some
		// other path already cleaned.
		{"1.26.4", "1.26.4", true},
		// A development toolchain names no released version. Skipping is
		// right; inventing 1.27.0 would claim a version that does not exist
		// and could be on either side of a fix.
		{"devel go1.27-abc123 2026-01-01", "", false},
		{"", "", false},
		{"go", "", false},
		{"gotcha", "", false},
		{"go1.x", "", false},
		{"golang1.26", "", false},
		// A four-component core, and a component Atoi would accept but semver
		// would not. Both produce a string that PARSES here and is then
		// rejected by the comparer, so without these rows the guards that
		// reject them can be deleted with the suite still green - and the
		// result is a package skipped for a reason no reader can see.
		{"go1.2.3.4", "", false},
		{"go1.+2.3", "", false},
		{"go1.007.0", "", false},
	} {
		got, ok := normalizeGoVersion(tt.in)
		if ok != tt.ok {
			t.Errorf("normalizeGoVersion(%q) ok = %v, want %v (got %q)", tt.in, ok, tt.ok, got)
			continue
		}
		if got != tt.want {
			t.Errorf("normalizeGoVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The normalization exists to be compared, so the test compares. Every
// normalized form has to order correctly against the bounds the live stdlib
// advisories actually use — measured shapes: introduced="1.16.0-0",
// fixed="1.16.1".
//
// Checking the string alone would pass for "1.21.0+rc.1", which parses, looks
// plausible, and compares EQUAL to 1.21.0 because build metadata is ignored in
// semver precedence. A release candidate reported as its own release is a
// clean scan on a vulnerable toolchain.
func TestNormalizeGoVersion_OrdersAgainstRealAdvisoryBounds(t *testing.T) {
	c, ok := version.For("Go")
	if !ok {
		t.Fatal("no Go comparer")
	}
	for _, tt := range []struct {
		toolchain string
		bound     string
		want      int
	}{
		{"go1.16.0", "1.16.1", -1}, // vulnerable: below the fix
		{"go1.16.1", "1.16.1", 0},  // exactly the fix
		{"go1.16.2", "1.16.1", 1},  // fixed
		// The .0-padded release sits above the range's own floor...
		{"go1.16", "1.16.0-0", 1},
		{"go1.16rc1", "1.16.0-0", 1},
		// ...and an rc sits below its release, which is the ordering that
		// separates a correct normalization from one that merely parses.
		{"go1.16rc1", "1.16.0", -1},
		{"go1.21rc1", "1.21.0", -1},
		{"go1.21rc1", "1.21rc2", -1},
		{"go1.22beta1", "1.21.0", 1},
		{"go1.22beta1", "1.22.0", -1},
		// A beta precedes a release candidate of the same version.
		{"go1.22beta1", "1.22.0-rc.1", -1},
	} {
		norm, ok := normalizeGoVersion(tt.toolchain)
		if !ok {
			t.Errorf("normalizeGoVersion(%q) refused a real toolchain version", tt.toolchain)
			continue
		}
		bound := tt.bound
		if n, ok := normalizeGoVersion(bound); ok && bound != n {
			bound = n
		}
		got, err := c.Compare(norm, bound)
		if err != nil {
			t.Errorf("Compare(%q->%q, %q): %v", tt.toolchain, norm, bound, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Compare(%q->%q, %q) = %d, want %d",
				tt.toolchain, norm, bound, got, tt.want)
		}
	}
}

// Whatever normalizeGoVersion accepts, the comparer must accept. A normalized
// form the comparer rejects is a package skipped for a reason no reader can
// see, and this is the property that decides it — not any single row above.
func TestNormalizeGoVersion_EverythingItAcceptsIsComparable(t *testing.T) {
	c, ok := version.For("Go")
	if !ok {
		t.Fatal("no Go comparer")
	}
	for _, in := range []string{
		"go1.26.4", "go1.20", "go1.16", "go1.21rc1", "go1.22beta1",
		"go1.21.5rc2", "go1.24.0-rc.1", "1.26.4", "go1.9", "go1.10.15",
		"go1.21alpha1", "go1.100.0",
	} {
		norm, ok := normalizeGoVersion(in)
		if !ok {
			continue
		}
		if _, err := c.Compare(norm, "1.16.1"); err != nil {
			t.Errorf("normalizeGoVersion(%q) = %q, which the comparer rejects: %v", in, norm, err)
		}
	}
}
