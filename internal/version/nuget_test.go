package version

import (
	"errors"
	"testing"
)

// Rows marked in the research as NuGet.Client's own xUnit data are kept
// verbatim. The paired traps to read together: leading zeros are LEGAL in
// the numeric sections (1.0.01 == 1.0.1) and ILLEGAL in an all-digit release
// label (-02 errors); 1.0.0 == 1.0.0.0 but 1.0.0.1 > 1.0.0; BETA == beta.
// Many rows expect 0 — the -1/1 rows beside them are what keep a
// stubbed-to-zero comparer from passing (this repo's vacuous-test rule).
func TestNuGet_Compare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		err  bool
	}{
		{a: "1.0.0", b: "1.0.0", want: 0},
		{a: "0.0.0", b: "1.0.0", want: -1},
		{a: "1.0.1", b: "1.0.0", want: 1},
		{a: "1.999.9999", b: "2.1.1", want: -1},
		{a: "6.0.9", b: "6.0.10", want: -1},
		{a: "1.0", b: "1.0.0", want: 0},
		{a: "1", b: "1.0.0.0", want: 0},
		{a: "0", b: "0.0.0", want: 0}, // OSV's literal introduced:"0"
		{a: "1.0.0", b: "1.0.0.0", want: 0},
		{a: "1.0.0.1", b: "1.0.0", want: 1},
		{a: "1.0.0.1", b: "1.0.0.0", want: 1},
		{a: "1.0", b: "1.0.0.1", want: -1},
		{a: "1.0.01", b: "1.0.1.0", want: 0},
		{a: "1.0.01", b: "1.0.1.2", want: -1},
		{a: "1.00", b: "1.0.0", want: 0},
		{a: " 1.0.0 ", b: "1.0.0", want: 0},
		{a: "1.0.0+meta", b: "1.0.0", want: 0},
		{a: "1.0.0", b: "1.0.0+beta", want: 0},
		{a: "1.0+test", b: "1.0.0.0", want: 0},
		{a: "1.0+test", b: "1.0.0.1", want: -1},
		{a: "1.0.0-BETA+AA", b: "1.0.0-beta+aa", want: 0},
		{a: "1.0.0-beta+AA", b: "1.0.0+aa", want: -1},
		{a: "1.0.0-BETA", b: "1.0.0-beta", want: 0},
		{a: "1.0.0-BETA.X.y.5.77.0+AA", b: "1.0.0-beta.x.y.5.77.0+aa", want: 0},
		{a: "1.0.0.1-1.2.A", b: "1.0.0.1-1.2.a+A", want: 0},
		// The case-fold INVERTS strict semver: ordinal 'a'(0x61) > 'B'(0x42),
		// folded 'A' < 'B'.
		{a: "1.0.0-a", b: "1.0.0-B", want: -1},
		{a: "1.0.0-alpha", b: "1.0.0", want: -1},
		{a: "1.0.0-BETA", b: "1.0.0-beta2", want: -1},
		{a: "1.0.0-BETA", b: "1.0.0-beta.1+AA", want: -1},
		{a: "1.0.0-alpha.10", b: "1.0.0-alpha.2", want: 1},
		{a: "1.0.0-alpha10", b: "1.0.0-alpha2", want: -1},
		{a: "1.2.3-999999", b: "1.2.3-Z", want: -1},
		{a: "1.2.3-A.999999", b: "1.2.3-A.56-2", want: -1},
		{a: "1.2.3-1.50A", b: "1.2.3-1.9A", want: -1},
		{a: "1.0.0-BETA.X.y.5.79.0+AA", b: "1.0.0-beta.x.y.5.790.0+abc", want: -1},
		// int32 overflow on a numeric label falls back to string compare —
		// numerically backwards, and exactly how every NuGet client resolves.
		{a: "1.0.0-10000000000", b: "1.0.0-9999999999", want: -1},
		{a: "0.1.2-02A", b: "0.1.2-02B", want: -1},
		// System.Text.Json's real fix pair: lexical comparison breaks it.
		{a: "6.0.9", b: "6.0.10", want: -1},

		{a: "1.0.0.0.0", b: "1.0.0", err: true},
		{a: "", b: "1.0.0", err: true},
		{a: "not.a.version", b: "1.0.0", err: true},
		{a: "1.0.0-", b: "1.0.0", err: true},
		{a: "1.0.0.", b: "1.0.0", err: true},
		{a: "0.1.2-02", b: "0.1.2-2", err: true},
		{a: "1.2147483648", b: "1.0.0", err: true},
		{a: "-1.0.0", b: "1.0.0", err: true},
		{a: "1.0.0-alpha..1", b: "1.0.0", err: true},
		{a: "1.0.0+meta_data", b: "1.0.0", err: true},
		// Upstream tolerates "1. 2 .3"; assay rejects all internal
		// whitespace — recorded divergence, a skip beats a guess.
		{a: "1. 2 .3", b: "1.0.0", err: true},
		{a: "1 9", b: "1.0.0", err: true},
	}

	for _, tc := range cases {
		got, err := NuGet{}.Compare(tc.a, tc.b)
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
		if rev, err := (NuGet{}).Compare(tc.b, tc.a); err != nil || rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, %v — reverse row, want %d", tc.b, tc.a, rev, err, -tc.want)
		}
	}
}
