package osv

import "testing"

// The exact set of substitutions D35 authorizes, and the ones it must refuse.
// Pinned as a table because the repair rewrites upstream data: "what did this
// change?" has to be answerable by reading rather than by trusting, and this
// table is that answer (D13's cost, paid here).
func TestRepairBound(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ecosystem string
		in, want  string
		why       string
	}{
		// The whole reason this exists. Every apk `fixed` bound in the v7
		// database that will not parse is one of these three strings.
		{"irssi", "Alpine:v3.5", "0.8.21.r2", "0.8.21-r2", "the measured case, 6 occurrences"},
		{"mariadb r0", "Alpine:v3.8", "10.2.22.r0", "10.2.22-r0", "2 occurrences"},
		{"mariadb r0 again", "Alpine:v3.8", "10.2.24.r0", "10.2.24-r0", "3 occurrences"},

		// Never rewrite something that already parses. Without this guard the
		// function would be free to rewrite valid data on a future edit, and
		// nothing downstream could tell.
		{"already a version", "Alpine:v3.19", "1.2.3-r4", "1.2.3-r4", "parses; untouched"},
		{"already a version with a letter", "Alpine:v3.19", "1.1.1k-r0", "1.1.1k-r0", "parses; untouched"},
		{"D31 patch level", "Alpine:v3.14", "3.3.3p1-r3", "3.3.3p1-r3", "parses since D31; untouched"},

		// D31 named these as the line NOT to cross: apk-tools 2.x parses them
		// through a tolerance for empty digit runs, and we deliberately do not.
		// A repair that swallowed them would quietly adopt that tolerance
		// through the back door.
		{"empty digit run", "Alpine:v3.8", "1.18.-r2", "1.18.-r2", "'.-r' is not '.r'; stays broken"},
		{"empty digit run 2", "Alpine:v3.8", "4.8.0.-r1", "4.8.0.-r1", "same shape"},

		// Other malformed apk bounds this rule must not touch. They are real
		// (imagemagick 18 occurrences, libdwarf 7) and none of them is a `.rN`
		// typo, so a rule that "helpfully" reached them would be inventing data.
		{"debian revision", "Alpine:v3.2", "7.0.0-0", "7.0.0-0", "'-0' is not '-rN'; a foreign version string"},
		{"a date", "Alpine:v3.19", "1999-12-14", "1999-12-14", "no reading exists"},

		// Ecosystem-gated. The substitution is apk syntax and means nothing
		// elsewhere; running it on a PyPI or npm bound could rewrite a version
		// that is valid there.
		{"PyPI untouched", "PyPI", "0.8.21.r2", "0.8.21.r2", "not an apk bound"},
		{"Go untouched", "Go", "0.8.21.r2", "0.8.21.r2", "not an apk bound"},
		{"npm untouched", "npm", "0.8.21.r2", "0.8.21.r2", "not an apk bound"},

		// A ".r" whose repair still does not parse must leave the original
		// alone, so the error the scan reports names what upstream published
		// rather than a string this function made up. Without this row, deleting
		// the second parse check changes nothing observable.
		{"repair does not help", "Alpine:v3.8", "1..0.r2", "1..0.r2", "'1..0-r2' has an empty component too"},
		{"repair of nonsense", "Alpine:v3.8", "abc.r2", "abc.r2", "'abc-r2' does not start with a digit"},

		// The empty bound is the ordinary case — most events carry only one of
		// introduced/fixed/last_affected — and must survive as empty rather
		// than becoming a string.
		{"empty", "Alpine:v3.19", "", "", "an absent bound stays absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := repairBound(tc.ecosystem, tc.in); got != tc.want {
				t.Errorf("repairBound(%q, %q) = %q, want %q (%s)",
					tc.ecosystem, tc.in, got, tc.want, tc.why)
			}
		})
	}
}

// The bare family key. Alpine ecosystems arrive release-qualified
// ("Alpine:v3.19", D6), but the OSV archive also carries the bare form, and a
// prefix test has to accept both or the repair silently stops firing on
// whichever one this code did not think of.
func TestRepairBound_BareAlpineKey(t *testing.T) {
	if got := repairBound("Alpine", "0.8.21.r2"); got != "0.8.21-r2" {
		t.Errorf("repairBound(\"Alpine\", …) = %q, want the repair to fire on the unqualified key too", got)
	}
}
