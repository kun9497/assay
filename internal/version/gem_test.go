package version

import (
	"errors"
	"testing"
)

// The table mirrors rubygems' own test_gem_version.rb where a row exists there
// (22 of these do), and the canonical source hand-traced where it does not.
// The traps worth naming: a letter tail is a PRERELEASE (smaller), a hyphen
// mints ".pre." so "1.0-beta" > "1.0.beta" because "pre" > "beta"
// alphabetically, uppercase sorts BEFORE lowercase ("RC" < "alpha" < "rc"),
// and empty is an error here where rubygems reads it as 0 — recorded as a
// deliberate divergence, because a package cataloged with no version is
// corrupt input, not release zero.
func TestGem_Compare(t *testing.T) {
	cases := []struct {
		a, b string
		want int // ignored when wantErr
		err  bool
	}{
		{a: "1.0", b: "1.0.0", want: 0},
		{a: "1.0", b: "1", want: 0},
		{a: "  1.0  ", b: "1.0", want: 0},
		{a: "1.0\n", b: "1.0", want: 0},
		{a: "\n1.0\n", b: "1.0", want: 0},
		{a: "3.10", b: "3.2", want: 1},
		{a: "1.8.2", b: "0.0.0", want: 1},
		{a: "1.01", b: "1.1", want: 0},
		{a: "1.0", b: "1.0.a", want: 1},
		{a: "1.8.2.a", b: "1.8.2", want: -1},
		{a: "1.8.2.b", b: "1.8.2.a", want: 1},
		{a: "1.8.2.a10", b: "1.8.2.a9", want: 1},
		{a: "1.0.a1", b: "1.0.a2", want: -1},
		{a: "2.0", b: "2.0.rc1", want: 1},
		{a: "2.0.0.beta1", b: "2.0.0.rc1", want: -1},
		{a: "1.0.0.pre.2", b: "1.0.0.pre.1", want: 1},
		{a: "1.0.0.pre.2", b: "1.0.0", want: -1},
		{a: "1.2.pre.1", b: "1.2.0.pre.1.0", want: 0},
		{a: "1.2.b1", b: "1.2.b.1", want: 0},
		{a: "0.beta.1", b: "0.0.beta.1", want: 0},
		{a: "0.0.beta", b: "0.beta.1", want: -1},
		{a: "5.a", b: "5.0.0.rc2", want: -1},
		{a: "5.x", b: "5.0.0.rc2", want: 1},
		{a: "1.0-beta", b: "1.0.pre.beta", want: 0},
		{a: "1.0-beta", b: "1.0.beta", want: 1},
		{a: "1.2.3-1", b: "1.2.3", want: -1},
		{a: "1-1", b: "1", want: -1},
		{a: "1.0.a", b: "1.0.a0", want: 0},
		{a: "1.0.RC1", b: "1.0.rc1", want: -1},
		{a: "1.a", b: "1.1", want: -1},
		{a: "1.0.0.a.0.0.b", b: "1.0.0.a", want: -1},
		{a: "1.9.3", b: "1.9.2.99", want: 1},
		{a: "1.9.3", b: "1.9.3.1", want: -1},
		// Real advisory shapes. actionview's fix >= 5.0.0.beta1.1 exists
		// BECAUSE beta1.1 > beta1 and < 5.0.0 — invert either and a
		// vulnerable Rails beta clears the gate.
		{a: "5.0.0.beta1.1", b: "5.0.0.beta1", want: 1},
		{a: "5.0.0.beta1.1", b: "5.0.0", want: -1},
		// rack's four-segment security bump: truncate to three and the
		// vulnerable 2.2.3 reads as patched.
		{a: "2.2.3", b: "2.2.3.1", want: -1},
		// nokogiri's prerelease inside a vulnerable range.
		{a: "1.13.0.rc1", b: "1.13.6", want: -1},
		// Bignum segments: an upstream fixture carries 9+ digits, and int64
		// wrapping negative would misorder silently.
		{a: "1.3422222.222.222222222.22222", b: "1.3422222.222.222222222.22221", want: 1},
		{a: "1.23456789012345678901234567890", b: "1.23456789012345678901234567889", want: 1},
		// "-" is legal INSIDE the tail charset: 1.0-- is [1,0,"pre","pre"].
		{a: "1.0--", b: "1.0.pre.pre", want: 0},

		{a: "junk", b: "1.0", err: true},
		{a: "1..2", b: "1.0", err: true},
		{a: "1.2 3.4", b: "1.0", err: true},
		{a: "1.0\n2.0", b: "1.0", err: true},
		{a: "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e.", b: "1.0", err: true},
		{a: "v1.0", b: "1.0", err: true},
		{a: "1.0+build", b: "1.0", err: true},
		{a: "1.0_1", b: "1.0", err: true},
		{a: "-1.0", b: "1.0", err: true},
		{a: ".1", b: "1.0", err: true},
		{a: "1.0-", b: "1.0", err: true},
		{a: "1.0.", b: "1.0", err: true},
		// The divergence: rubygems reads these as version 0, assay refuses.
		{a: "", b: "1.0", err: true},
		{a: "   ", b: "1.0", err: true},
	}

	for _, tc := range cases {
		got, err := Gem{}.Compare(tc.a, tc.b)
		if tc.err {
			if err == nil {
				t.Errorf("Compare(%q, %q) = %d, want error", tc.a, tc.b, got)
			} else if !errors.Is(err, ErrInvalid) {
				t.Errorf("Compare(%q, %q) error %v does not wrap ErrInvalid", tc.a, tc.b, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Compare(%q, %q): %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry: every table row also holds reversed. A comparer
		// that answers 1 both ways passes half the table on its own.
		if rev, err := (Gem{}).Compare(tc.b, tc.a); err != nil || rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, %v — reverse of the row above, want %d", tc.b, tc.a, rev, err, -tc.want)
		}
	}
}
