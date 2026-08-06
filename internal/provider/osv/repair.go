package osv

import (
	"strings"

	"github.com/kun9497/assay/internal/version"
)

// repairBound fixes one documented defect in Alpine's advisory data at
// ingestion: a revision written `.rN` where apk's grammar has only `-rN`.
// Measured on the v7 database, this is every apk `fixed` bound that will not
// parse — 11 occurrences, all of them irssi (`0.8.21.r2`) and mariadb
// (`10.2.22.r0`, `10.2.24.r0`) on Alpine v3.3 through v3.8.
//
// **Repaired here rather than accepted by the comparer**, which is the same
// split D16 draws for withdrawn advisories: fix it once, where the data enters,
// so no query path can forget. D31 declined to teach the apk grammar about this
// string and named the reason — apk-tools 2.x does parse `0.8.21.r2`, via a
// tolerance for empty digit runs, and orders it **above** the `0.8.21-r2` it is
// a typo for. Teaching the comparer to accept it would mean either adopting
// that ordering, which is wrong, or contradicting the only reference that reads
// the string at all. Neither belongs in a comparer. Calling it a typo and
// repairing the datum does.
//
// D31 already recorded the reading this depends on, in the roadmap and in the
// invalid-input table: `.r2` is a typo for `-r2`. This asserts nothing new.
//
// **Two guards, and both are load-bearing.** The original must not parse, so a
// version that is already valid can never be rewritten; and the replacement
// must parse, so a failed repair leaves the original in place and the error
// message still names what upstream actually published rather than something
// this function invented.
//
// **On D13's losslessness.** This does write something upstream did not
// publish, and that is a real cost. It is taken because the alternative shapes
// are worse: storing both forms complicates every reader for two EOL packages,
// and threading a repair count out through Convert, Fetch and the Provider
// interface is three signature changes for eleven bounds. The visibility this
// gets instead is that the rule is one substitution, in one pure function, with
// the exact affected set pinned by a test — so "what did this change?" is
// answerable by reading, not by trusting.
//
// **Two mutations of this function survive, and both are equivalents rather
// than gaps.** Deleting the already-parses guard changes nothing observable: no
// valid apk version can contain ".r" at all, because a '.' must be followed by
// digits, so LastIndex returns -1 for every version that parses and the
// function returns it unchanged regardless. It is kept as depth against a
// future edit that changes what follows. Likewise Index in place of LastIndex:
// replacing an earlier ".r" leaves a later one in the string, which cannot
// parse, so the second guard rejects the result and the original is returned
// either way. LastIndex is the honest spelling of the intent — the revision is
// the tail — not a behaviour the tests can distinguish.
func repairBound(ecosystem, v string) string {
	if v == "" || !strings.HasPrefix(ecosystem, "Alpine") {
		return v
	}
	c := version.APK{}
	if _, err := c.Compare(v, v); err == nil {
		return v // already a version; never rewrite one
	}
	i := strings.LastIndex(v, ".r")
	if i < 0 {
		return v
	}
	fixed := v[:i] + "-r" + v[i+2:]
	if _, err := c.Compare(fixed, fixed); err != nil {
		return v // the repair did not produce a version either; keep the original
	}
	return fixed
}
