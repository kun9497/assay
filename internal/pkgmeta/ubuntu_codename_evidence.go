package pkgmeta

import "strings"

// ContradictedCodename is the codename evidence of an install whose own
// declarations disagree about it: an operating-system component carrying two
// different codenames, two declarations of one release that name different
// ones, a codename that names another release than the version beside it, or
// two releases in one context. It is never a codename (no table names it, and
// UbuntuCodenameEvidence reads it as none), so it exempts nothing; it exists
// so a merge cannot let a later, consistent listing paper over the
// contradiction (MergeCodename).
const ContradictedCodename = "!contradicted"

// ubuntuRetiredReleases is the codename of every Ubuntu release the tracker
// table (UbuntuReleases) deliberately leaves out -- the EOL'd interims and
// the LTS releases before trusty -- for validating codename evidence only.
// Without it a codename the build does not know was taken at its word: an
// SBOM whose 22.04 operating system said versionCodename=kinetic (22.10)
// exempted the 22.04 install under a kinetic statement, while the numeric
// ubuntu-22.10 statement was refused (main QA of f554fb2, 2026-11-13).
// Source: releases.ubuntu.com / old-releases.ubuntu.com.
var ubuntuRetiredReleases = map[string]string{
	"warty": "4.10", "hoary": "5.04", "breezy": "5.10", "dapper": "6.06",
	"edgy": "6.10", "feisty": "7.04", "gutsy": "7.10", "hardy": "8.04",
	"intrepid": "8.10", "jaunty": "9.04", "karmic": "9.10", "lucid": "10.04",
	"maverick": "10.10", "natty": "11.04", "oneiric": "11.10", "precise": "12.04",
	"quantal": "12.10", "raring": "13.04", "saucy": "13.10", "utopic": "14.10",
	"vivid": "15.04", "wily": "15.10", "yakkety": "16.10", "zesty": "17.04",
	"artful": "17.10", "cosmic": "18.10", "disco": "19.04", "eoan": "19.10",
	"groovy": "20.10", "hirsute": "21.04", "impish": "21.10", "kinetic": "22.10",
	"lunar": "23.04", "mantic": "23.10",
}

// ubuntuCodenameRelease is the YY.MM release a codename names, from either
// table, or "".
func ubuntuCodenameRelease(codename string) string {
	if r := UbuntuReleases()[codename]; r != "" {
		return r
	}
	return ubuntuRetiredReleases[codename]
}

// ubuntuReleaseHasCodename reports whether either table names release.
func ubuntuReleaseHasCodename(release string) bool {
	for _, table := range []map[string]string{UbuntuReleases(), ubuntuRetiredReleases} {
		for _, r := range table {
			if r == release {
				return true
			}
		}
	}
	return false
}

// UbuntuCodenameOf is the codename evidence d states for its packages: its
// VERSION_CODENAME in lower case when d is Ubuntu and the codename names the
// release d's VERSION_ID is -- or, for a codename neither table knows, when
// the release is one neither table names either (a release newer than this
// build) -- ContradictedCodename when d contradicts itself, and "" when d
// states none or is not Ubuntu.
func UbuntuCodenameOf(d Distro) string {
	if !strings.EqualFold(d.ID, "ubuntu") || d.VersionCodename == "" {
		return ""
	}
	// An equivalent of the general path below, kept for the reader: the
	// sentinel is in neither table, so it would come back either way (a
	// mutation dropping this survives; PR #328 review).
	if d.VersionCodename == ContradictedCodename {
		return ContradictedCodename
	}
	codename := strings.ToLower(d.VersionCodename)
	parts := strings.SplitN(d.VersionID, ".", 3)
	if len(parts) < 2 {
		// No version to hold it to: a codename either table names is the
		// release it names, and the matcher holds that release to the
		// package's key; one neither names proves nothing (PR #328 review:
		// an OS of versionCodename=jammy alone had stopped counting).
		if ubuntuCodenameRelease(codename) != "" {
			return codename
		}
		return ""
	}
	release := parts[0] + "." + parts[1]
	if named := ubuntuCodenameRelease(codename); named != "" {
		if named != release {
			return ContradictedCodename
		}
		return codename
	}
	if ubuntuReleaseHasCodename(release) {
		return ContradictedCodename
	}
	return codename
}

// MergeCodename is the codename evidence of two listings of one install: the
// one either states when the other states none, the shared one when they
// agree, and ContradictedCodename when they disagree or either is already
// contradicted.
func MergeCodename(a, b string) string {
	a, b = strings.ToLower(a), strings.ToLower(b)
	switch {
	case a == "":
		return b
	case b == "" || a == b:
		return a
	default:
		return ContradictedCodename
	}
}

// UbuntuCodenameEvidence is s as codename evidence: "" for none and for a
// contradiction, the codename otherwise.
func UbuntuCodenameEvidence(s string) string {
	if s == ContradictedCodename {
		return ""
	}
	return s
}
