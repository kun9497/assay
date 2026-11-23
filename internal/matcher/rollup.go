package matcher

import (
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// isRollup reports whether id is a distributor's notice that announces an
// update rather than describing one vulnerability: a USN, a DSA or a DLA. OSV
// links it to the per-CVE records of the same distributor through `upstream`,
// which is not identity, so the two never group by identifier.
func isRollup(id string) bool {
	return strings.HasPrefix(id, "USN-") || strings.HasPrefix(id, "DSA-") || strings.HasPrefix(id, "DLA-")
}

// cveOf is the CVE an id is, reading the distributors' own per-CVE ids as the
// CVE they name; "" for anything else.
func cveOf(id string) string {
	u := strings.ToUpper(id)
	u = strings.TrimPrefix(u, "UBUNTU-")
	u = strings.TrimPrefix(u, "DEBIAN-")
	if strings.HasPrefix(u, "CVE-") {
		return u
	}
	return ""
}

// foldRollups removes a finding that is only a notice (isRollup) whose every
// CVE is already reported for the same package, and names the notice on the
// findings it announced (Notices). One vulnerability was reported twice with
// one fix, the second time with no severity of its own, so --fail-on-unknown
// failed on a set in which every vulnerability was rated (D172).
//
// Nothing may be lost by it, so the notice stays whenever any part of it is
// not said elsewhere: it names no CVE, or an upstream id that is not one; a
// CVE it names is not reported for this package, which includes one whose
// record could not be evaluated; or it states a fix and one of its CVEs'
// findings states none.
func foldRollups(fs []Finding) []Finding {
	type key struct {
		pkg int
		cve string
	}
	// Which findings report a CVE for a package, and whether with a fix.
	reports := map[key][]int{}
	fixed := map[key]bool{}
	for i, f := range fs {
		for _, r := range f.Ratings {
			if c := cveOf(r.AdvisoryID); c != "" {
				k := key{f.pkg, c}
				reports[k] = append(reports[k], i)
				fixed[k] = fixed[k] || r.Fixed != ""
			}
		}
	}
	drop := make([]bool, len(fs))
	for i, f := range fs {
		if len(f.Ratings) != 1 || !isRollup(f.Ratings[0].AdvisoryID) || len(f.Advisory.Upstream) == 0 {
			continue
		}
		covered := true
		var members []int
		for _, id := range f.Advisory.Upstream {
			c := cveOf(id)
			k := key{f.pkg, c}
			if c == "" || len(reports[k]) == 0 || (f.Ratings[0].Fixed != "" && !fixed[k]) {
				covered = false
				break
			}
			members = append(members, reports[k]...)
		}
		if !covered {
			continue
		}
		drop[i] = true
		for _, m := range members {
			fs[m].Notices = append(fs[m].Notices, f.Ratings[0].AdvisoryID)
		}
	}
	live := fs[:0]
	for i, f := range fs {
		if drop[i] {
			continue
		}
		f.Notices = dedupSorted(f.Notices)
		live = append(live, f)
	}
	return live
}

// selfOf and relatedOf are the two halves of a record's names as a waiver
// reads them (D171). A notice IS its own id and stands for the CVEs in its
// upstream; read as names of its own, one CVE's waiver suppressed the notice
// and the CVEs beside it.
func selfOf(a advisory.Advisory) []string {
	if isRollup(a.ID) {
		return append([]string{a.ID}, a.Aliases...)
	}
	return selfIDs(a)
}

func relatedOf(a advisory.Advisory) []string {
	if isRollup(a.ID) {
		return append(a.Related[:len(a.Related):len(a.Related)], a.Upstream...)
	}
	return a.Related
}
