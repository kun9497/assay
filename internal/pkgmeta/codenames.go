package pkgmeta

import "strings"

// DebianReleases maps Debian codenames to the release number os-release's
// VERSION_ID carries, for the purl `distro=` qualifier (a codename, the
// shape of the purl spec's own deb example `distro=jessie`) and os-release's
// VERSION_CODENAME.
// Releases before etch carried a two-part number and no advisory data this
// store holds, so they are left out; a codename not listed is not a
// release and is compared as written.
func DebianReleases() map[string]string {
	return map[string]string{
		"etch":     "4",
		"lenny":    "5",
		"squeeze":  "6",
		"wheezy":   "7",
		"jessie":   "8",
		"stretch":  "9",
		"buster":   "10",
		"bullseye": "11",
		"bookworm": "12",
		"trixie":   "13",
		"forky":    "14",
		"duke":     "15",
	}
}

// UbuntuCodename is the Ubuntu codename a purl distro qualifier spells --
// bare or behind the family, in any case (`jammy`, `JAMMY`, `ubuntu-jammy`)
// -- or "" when the qualifier is not one. The VEX matcher asks it for the
// statement's and the purl's spelling alike, so the evidence rule for a
// codename (the scan must have seen it in os-release or in the purl) holds
// for every spelling: the main QA of ef0bc1a (2026-11-13) had `jammy`
// refused for want of evidence while `JAMMY` and `ubuntu-jammy` slipped past
// the rule and were normalised to the release further on, suppressing two
// advisories and turning exit 1 into 0 on the same document.
func UbuntuCodename(q string) string {
	name := strings.ToLower(q)
	if i := strings.IndexByte(name, '-'); i > 0 {
		if name[:i] != "ubuntu" {
			return ""
		}
		name = name[i+1:]
	}
	if UbuntuReleases()[name] == "" {
		return ""
	}
	return name
}

// CanonicalDistroQualifier spells a purl distro qualifier the way the scope
// rules compare releases: a Debian or Ubuntu codename, bare (`bookworm`,
// `jammy`) or behind its family (`debian-bookworm`, `ubuntu-jammy`), as the
// release it names (`debian-12`, `ubuntu-22.04`). Any other qualifier is
// returned as given, except that a numbered release of a family this build
// routes is folded to lower case (`Debian-12` compares as `debian-12`), as
// the codenames are. A codename names the major only -- bookworm is every
// 12.N -- so it refines nothing finer than the major and contradicts
// nothing within it (main QA of 672fe7a, 2026-11-13: an OS of Debian 12.15
// beside `distro=bookworm` had been read as two releases, and a 12.15
// statement v0.18.1 applied was refused).
func CanonicalDistroQualifier(q string) string {
	name := strings.ToLower(q)
	family := ""
	if i := strings.IndexByte(name, '-'); i > 0 {
		family, name = name[:i], name[i+1:]
	}
	if (family == "" || family == "debian") && DebianReleases()[name] != "" {
		return "debian-" + DebianReleases()[name]
	}
	if (family == "" || family == "ubuntu") && UbuntuReleases()[name] != "" {
		return "ubuntu-" + UbuntuReleases()[name]
	}
	if KnownDistroID(family) {
		return strings.ToLower(q)
	}
	return q
}
