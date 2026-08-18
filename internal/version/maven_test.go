package version

import (
	"errors"
	"testing"
)

// Rows 1–38 marked MVN are verbatim assertions from ComparableVersionTest
// (testVersionsEqual, testVersionComparing, testMng5568/6572/6964/7644, the
// leading-zero tests) or derived from its pairwise-ordering arrays; the rest
// are oracle-verified against a port that replays that entire suite. The
// traps that bite hardest: "1.0-a" is NEWER than "1.0" (bare 'a' is an
// unknown qualifier; only 'a'+digit is alpha), unknown qualifiers outrank
// "sp", "_" and "+" are ordinary characters, and Spring's ".RELEASE" aliases
// to nothing — miss that and every Spring range mismatches.
func TestMaven_Compare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		err  bool
	}{
		{a: "1", b: "1.0", want: 0},
		{a: "1.0", b: "1.0.0", want: 0},
		{a: "1", b: "1-0", want: 0},
		{a: "2.0.0", b: "2.0.0.0.0.0", want: 0},
		{a: "1a", b: "1-a", want: 0},
		{a: "1x", b: "1.0.0-x", want: 0},
		{a: "1a1", b: "1-alpha-1", want: 0},
		{a: "1m3", b: "1MILESTONE3", want: 0},
		{a: "1ga", b: "1", want: 0},
		{a: "1RELeaSE", b: "1", want: 0},
		{a: "1cr", b: "1rc", want: 0},
		{a: "1-abcdefghijklmnopqrstuvwxyz", b: "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ", want: 0},
		{a: "1.0-alpha-1", b: "1.0", want: -1},
		{a: "1.0-alpha-1", b: "1.0-beta-1", want: -1},
		{a: "1.0-beta-1", b: "1.0-SNAPSHOT", want: -1},
		{a: "1.0-SNAPSHOT", b: "1.0", want: -1},
		{a: "1.0-alpha-1-SNAPSHOT", b: "1.0-alpha-1", want: -1},
		{a: "1-snapshot", b: "1-sp", want: -1},
		{a: "1-m2", b: "1-m11", want: -1},
		{a: "1-sp", b: "1-sp2", want: -1},
		{a: "1-def", b: "1-pom-1", want: -1},
		{a: "1-pom-1", b: "1-1", want: -1},
		{a: "1-sp", b: "1-1", want: -1},
		{a: "1.1", b: "1-1", want: 1},
		{a: "1.0", b: "1.0-1", want: -1},
		{a: "1.0.0", b: "1.0-1", want: -1},
		{a: "2.0-1", b: "2.0.1", want: -1},
		{a: "2.0.1", b: "2.0.1-xyz", want: -1},
		{a: "2.0.1-xyz", b: "2.0.1-123", want: -1},
		{a: "2.0.1-klm", b: "2.0.1-lmn", want: -1},
		{a: "6.1.0rc3", b: "6.1H.5-beta", want: -1},
		{a: "20190126.230843", b: "1234567890.12345", want: -1},
		{a: "123456789012345.1H.5-beta", b: "12345678901234567890.1H.5-beta", want: -1},
		{a: "0000000000000001", b: "1", want: 0},
		{a: "1-0.alpha", b: "1", want: -1},
		{a: "1.0.0.RC1", b: "1.0.0-RC2", want: -1},
		{a: "2-abc", b: "2.0.abc", want: 0},
		{a: "2-a", b: "2.0.0.a", want: 0},
		// log4shell's actual ladder.
		{a: "2.0-beta9", b: "2.0-rc1", want: -1},
		{a: "2.0-rc2", b: "2.0", want: -1},
		{a: "2.3.1", b: "2.12.2", want: -1},
		{a: "2.14.1", b: "2.15.0", want: -1},
		// Spring and JBoss release aliases: get these wrong and every range
		// on those trains mismatches.
		{a: "5.2.20.RELEASE", b: "5.2.20", want: 0},
		{a: "5.2.20.RELEASE", b: "5.2.21", want: -1},
		{a: "5.0.0.M5", b: "5.0.0.RC1", want: -1},
		{a: "5.0.0.RC1", b: "5.0.0", want: -1},
		{a: "1.0.0.Final", b: "1.0.0", want: 0},
		{a: "6.3.0.2", b: "6.3.0", want: 1},
		{a: "9.4.44.v20210927", b: "9.4.44", want: 1},

		// The single-letter gate: bare 'a' is NOT alpha.
		{a: "1.0-alpha", b: "1.0-a", want: -1},
		{a: "1.0-a", b: "1.0", want: 1},
		{a: "1.0-a1", b: "1.0", want: -1},
		{a: "1.0-x", b: "1.0-sp", want: 1},
		{a: "1.0-sp1", b: "1.0", want: 1},
		{a: "1-beta", b: "1.beta", want: 0},
		{a: "1.0-alpha1", b: "1.0-alpha-1", want: 0},
		{a: "1_0", b: "1", want: 1},
		{a: "1.0.0+1", b: "1.0.0", want: 1},
		{a: ".1", b: "0.1", want: 0},
		// Same canonical rendering, different compare: "-1" nests.
		{a: "-1", b: "1", want: -1},
		// BigInteger zero outranks int zero — upstream's oddest true fact.
		{a: "0000000000000000000.1", b: "0.1", want: 1},

		{a: "", b: "1", err: true},
		{a: "   ", b: "1", err: true},
	}

	for _, tc := range cases {
		got, err := Maven{}.Compare(tc.a, tc.b)
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
		if rev, err := (Maven{}).Compare(tc.b, tc.a); err != nil || rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, %v — reverse row, want %d", tc.b, tc.a, rev, err, -tc.want)
		}
	}
}
