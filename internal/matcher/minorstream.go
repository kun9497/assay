package matcher

import (
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// rhelMinorTag is a RHEL release's minor, as a z-stream build's dist tag names
// it: "el10_2" in 8.12.1-4.el10_2.7. A build of no particular minor carries a
// bare ".el10", and a module build's "+el8.5.0+" is not this.
var rhelMinorTag = regexp.MustCompile(`\.(el[0-9]+_[0-9]+)(?:\.|$)`)

func minorTag(evr string) string {
	if m := rhelMinorTag.FindStringSubmatch(evr); m != nil {
		return m[1]
	}
	return ""
}

// ownMinorOnly leaves aff the fixes of the installed build's own RHEL minor,
// when it names one (D175).
//
// Red Hat fixes one CVE once per live minor, and its CSAF keys every one of
// those builds to the major, each a [0, fix) of its own: curl's CVE-2026-1965
// is 8.12.1-4.el10_2.3 and, since 10.3, 8.12.1-9.el10_3. A union of the two
// reports 4.el10_2.7, which carries the fix, for being below another minor's
// build. The installed release says which of them is its own, so that fix
// alone decides it, and a build below it is told the one its minor ships.
//
// Nothing is taken from a build whose release names no minor, or a minor the
// record has no fix for: every fix still counts there. Ranges other than a
// fixed window are kept, so an open one (D48) still says affected. Red Hat's
// own data only: a rebuild's advisory holds one build per record.
func ownMinorOnly(aff advisory.Affected, installed string) advisory.Affected {
	if len(aff.Ranges) < 2 || !strings.HasPrefix(aff.Ecosystem, "Red Hat:") {
		return aff
	}
	own := minorTag(installed)
	if own == "" {
		return aff
	}
	var kept []advisory.Range
	named := false
	for _, r := range aff.Ranges {
		fix := fixOf(r)
		if fix != "" && minorTag(fix) != own {
			continue
		}
		named = named || fix != ""
		kept = append(kept, r)
	}
	if !named {
		return aff
	}
	aff.Ranges = kept
	return aff
}

// fixOf is the fixed version of a range, or "" when it has none.
func fixOf(r advisory.Range) string {
	for _, e := range r.Events {
		if e.Fixed != "" {
			return e.Fixed
		}
	}
	return ""
}
