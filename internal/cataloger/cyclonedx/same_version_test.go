package cyclonedx

import "testing"

// sameVersion's arms the CLI test cannot reach one at a time. A key with no
// comparer is reached by an unkeyed package, which the matcher reports as a
// coverage skip before it reads Unevaluable, so only this test holds it.
func TestSameVersion(t *testing.T) {
	for _, tc := range []struct {
		eco, a, b string
		want      bool
	}{
		{"Debian:11", "2.31-13+deb11u13", "2.31-13+deb11u13", true},
		{"Debian:11", "2.31-13+deb11u13", "0:2.31-13+deb11u13", true},
		{"Debian:11", "2.31-13+deb11u13", "1:2.31-13+deb11u13", false},
		{"Debian:11", "2.31-13+deb11u12", "2.31-13+deb11u13", false},
		// An epoch Debian cannot parse is not shown equal to anything.
		{"Debian:11", "x:2.31-13", "y:2.31-13", false},
		{"Red Hat:9", "3.0.7-27.el9", "0:3.0.7-27.el9", true},
		{"", "1.0", "0:1.0", false},
	} {
		if got := sameVersion(tc.eco, tc.a, tc.b); got != tc.want {
			t.Errorf("sameVersion(%q, %q, %q) = %v, want %v", tc.eco, tc.a, tc.b, got, tc.want)
		}
	}
}
