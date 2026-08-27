package version

import (
	"fmt"
	"strings"
)

// Bitnami wraps SemVer with D99's own packaging convention: an installed
// Bitnami component's version carries a trailing numeric build revision that
// the upstream project's own version does not — a syft purl reads
// pkg:bitnami/postgresql@18.6.0-3, and Bitnami's own vulndb writes its fixed
// bound against the bare upstream release, "18.6.0" (measured 2026-08-27:
// 98.99% of 4,375 distinct advisory version strings parse as plain SemVer
// with no such suffix at all). Comparing "18.6.0-3" against "18.6.0" under
// SemVer{} directly would read the "-3" as a semver PRE-RELEASE marker,
// which SemVer{} ranks BELOW the release it qualifies (§11.3) — the exact
// opposite of the truth, since "18.6.0-3" is a later, more-patched build of
// 18.6.0, not an earlier one.
//
// The fix is to strip the revision from EITHER side before delegating to
// SemVer{}, not just the installed one: a handful of Bitnami's own advisory
// bounds (measured: 31 of 4,375, e.g. mariadb-galera's fixed "11.8.7-0")
// carry the identical shape, because Bitnami's vulndb sometimes tracks a
// vulnerability against its OWN packaged version rather than the upstream
// one. Stripping symmetrically handles both without the comparer needing to
// know which operand is the installed version and which is the advisory
// bound (the Comparer interface does not say, and rangeeval.go calls this
// with either in either position).
type Bitnami struct{}

func (Bitnami) Compare(a, b string) (int, error) {
	coreA, revA, hasRevA := stripBitnamiRevision(a)
	coreB, revB, hasRevB := stripBitnamiRevision(b)

	cmp, err := SemVer{}.Compare(coreA, coreB)
	if err != nil {
		return 0, fmt.Errorf("bitnami %q vs %q: %w", a, b, err)
	}
	if cmp != 0 {
		return cmp, nil
	}

	// Cores are equal. Two revisions on ONE version (18.6.0-3 vs 18.6.0-10)
	// order numerically -- rpmvercmp-style, not lexicographically, so "10"
	// sorts above "3" (compareNumeric orders by digit-string LENGTH first,
	// the same rule semver.go's own core-identifier comparison uses).
	if hasRevA && hasRevB {
		return compareNumeric(trimLeadingZeros(revA), trimLeadingZeros(revB)), nil
	}

	// Exactly one side carries a revision (or neither does, which this
	// branch also covers trivially since hasRevA == hasRevB == false already
	// implies equal, unrevisioned cores). A bare fixed bound ("18.6.0") is
	// deliberately treated as equal to ANY revision of that same core
	// ("18.6.0-3", "18.6.0-10", ...): the revision is Bitnami's own
	// repackaging metadata, not an upstream release, and an advisory that
	// names no revision at all is naming the whole build train, not "only
	// the unrevisioned one". This is what makes "18.6.0-3 at-or-above fixed
	// 18.6.0" resolve NOT VULNERABLE, the D99 worked example.
	//
	// Documented trade-off: this also makes a genuine SemVer pre-release
	// with a bare numeric identifier ("1.19.0-0", measured on
	// BIT-golang-2022-32190's own "introduced" bound, one of 31 such
	// advisory strings) compare EQUAL to its own release ("1.19.0") rather
	// than strictly below it, where real SemVer orders the release above the
	// pre-release. Every real call site in this codebase only ever asks
	// "at or above" / "at or below" (rangeeval.go), for which equal and
	// strictly-above give the identical answer, so this is inert in
	// practice — but it is a real, named simplification, not an oversight.
	return 0, nil
}

// stripBitnamiRevision splits s into its semver core and Bitnami's own
// trailing packaging revision: "18.6.0-3" -> ("18.6.0", "3", true). Only the
// LAST hyphen-separated segment is tried, and only when it is entirely
// digits — a pre-release or build-train label like "7.4-update41.0" or
// "4.0-beta1.0" (measured among the 44 advisory strings SemVer{} refuses
// outright) has a non-numeric tail and is left untouched, so this never
// rescues a string D99 deliberately leaves as a skip.
func stripBitnamiRevision(s string) (core, revision string, ok bool) {
	i := strings.LastIndexByte(s, '-')
	if i < 0 || i == len(s)-1 {
		return s, "", false
	}
	rev := s[i+1:]
	if !isNumericID(rev) {
		return s, "", false
	}
	return s[:i], rev, true
}
