package pkgmeta

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNoEcosystem means the target's distro has no ecosystem we can look up.
// Callers must surface the affected packages as skipped: a distro we cannot key
// is not a distro with no vulnerabilities.
var ErrNoEcosystem = errors.New("no vulnerability ecosystem for distro")

// Distro identifies the operating system of a Target. It belongs to the target,
// not to each package (D7): an image is Alpine 3.19; its packages are not.
// Fields mirror /etc/os-release, which is also what syft reports.
type Distro struct {
	ID        string // os-release ID, e.g. "alpine"
	VersionID string // os-release VERSION_ID, e.g. "3.19.9"
	// PrettyName is os-release PRETTY_NAME. It was reporting-only until D53,
	// which reads the word LTS out of it: OSV's Ubuntu keys carry the
	// suffix and nothing else on this struct distinguishes a long-term
	// release from an interim one.
	PrettyName string
}

// Ecosystem returns the OSV ecosystem key for this distro — "Alpine:v3.19".
//
// The release is part of the key (D6) because the fixed version of a package
// differs per release. OSV publishes one ecosystem per Alpine minor release and
// nothing for edge, so anything that is not an X.Y release is an error rather
// than a best-effort key: a key nothing is stored under matches nothing, and a
// scan that matches nothing looks exactly like a clean one.
//
// syft reports VersionID as a patch release ("3.19.9") while OSV keys on the
// minor ("Alpine:v3.19"), so the trailing component is dropped here rather than
// at each call site.
// ubuntuRelease is Ubuntu's YY.MM version, the shape every OSV Ubuntu key
// is built on. Anchored: a VERSION_ID this does not match is refused rather
// than concatenated into a key that would look plausible and match nothing.
var ubuntuRelease = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`)

func (d Distro) Ecosystem() (string, error) {
	if d.ID == "" {
		return "", fmt.Errorf("%w: distro has no ID", ErrNoEcosystem)
	}
	switch d.ID {
	case "alpine":
	case "debian":
		// OSV keys modern Debian releases on the bare major — Debian:11 through
		// Debian:14 hold 200,082 of the archive's 211,021 affected entries,
		// and /etc/os-release's VERSION_ID is that same bare major ("12").
		// The ancient releases OSV spells Debian:3.0 / 5.0 / 6.0 are not
		// reachable this way and are not worth a special case: no supported
		// image ships them.
		//
		// testing and sid carry NO VERSION_ID at all, and OSV publishes no
		// ecosystem for them, so they fall through to the error below. That is
		// deliberate: a scan of a sid image must say it could not be checked,
		// because inventing Debian:14 for it would compare against a release
		// whose fixed versions are not the ones sid ships.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID (testing or sid), "+
				"and OSV publishes no ecosystem for it", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Debian:" + major, nil
	case "ubuntu":
		// D53. OSV keys Ubuntu as "Ubuntu:22.04:LTS" for a long-term release and
		// "Ubuntu:25.10" for an interim one, so the suffix is part of the key
		// rather than decoration. It is read from PRETTY_NAME, which is the
		// system's own statement about itself — the alternative, inferring
		// LTS from an even year and an .04 month, is a rule Canonical has
		// never promised and every key would silently move the day they
		// break it.
		//
		// Getting the suffix wrong is safe in the way that matters: the key
		// would name an ecosystem the database does not hold, and D20's
		// coverage check turns that into a whole-package skip and exit 2,
		// never a clean verdict. That is why this reads a free-text field at
		// all: the failure is loud.
		//
		// Only the mainline lineage is keyed here. Ubuntu's Pro, FIPS and
		// Realtime lineages have OSV keys of their own describing the SAME
		// release, and which one a system is entitled to is not a fact
		// /etc/os-release carries. Packages built from one of them are
		// detected by the matcher from their own version string and reported
		// as not evaluated (D53).
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		if !ubuntuRelease.MatchString(d.VersionID) {
			return "", fmt.Errorf("%w: distro %q version %q is not a YY.MM release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		if strings.Contains(d.PrettyName, "LTS") {
			return "Ubuntu:" + d.VersionID + ":LTS", nil
		}
		return "Ubuntu:" + d.VersionID, nil
	case "rhel":
		// D50. `rhel` and nothing else. Red Hat's CSAF VEX feed describes Red
		// Hat's own builds, keyed on the mainline major (D47), and
		// /etc/os-release's VERSION_ID is "9.8" — the minor is dropped because
		// the key is not release-qualified below the major.
		//
		// The other RPM distributions are NOT routed here, and each is a
		// different reason rather than one blanket caution:
		//
		//   - almalinux: a rebuild, but not a byte-identical one. It writes
		//     module builds as `module_el8.5.0+119+9a9ec082` where Red Hat
		//     writes `module+el8.5.0+12582+56d94c81`, and its own rebuilds
		//     carry `.alma` release suffixes. Comparing Alma's installed
		//     versions against Red Hat's advisory versions is the hazard
		//     docs/deferred-decisions.md records.
		//   - centos: the ID covers CentOS Linux, which trailed RHEL, AND
		//     CentOS Stream, which runs AHEAD of it. A fixed version that has
		//     not reached RHEL yet is already in Stream, so the same key would
		//     be wrong in opposite directions for the two.
		//   - fedora, amzn: different version schemes and their own advisory
		//     feeds (FEDORA-*, ALAS-*). Red Hat's errata do not describe them.
		//
		// Rocky left this list under D71 below: it has its own OSV archive
		// now, so it no longer needs (or wants) Red Hat's errata routed at it
		// — the byte-identity hazard above never applied to Rocky's own data
		// the way it does to Alma's.
		//
		// Every one of those still reaches the cataloger and is reported as
		// not evaluated, so an unrouted distro is a loud skip and never a
		// clean verdict.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Red Hat:" + major, nil
	case "rocky":
		// D71. Rocky ingests from its OWN OSV archive ("Rocky Linux/all.zip",
		// measured 2026-08-19), not Red Hat's CSAF feed — unlike AlmaLinux,
		// whose module-build spelling and `.alma` release suffixes make
		// matching against another distro's advisory versions a hazard
		// (the "rhel" case above, and docs/deferred-decisions.md), Rocky's
		// OSV records describe Rocky's own builds, so nothing here is
		// borrowed from another distro's data.
		//
		// The key is release-qualified at the major, because that is the
		// shape the archive's own ecosystem keys carry ("Rocky Linux:9",
		// "Rocky Linux:10") and /etc/os-release's VERSION_ID ("9.4") needs
		// the same truncation D47 already applies to Red Hat's.
		//
		// AlmaLinux stays unrouted (D50) until its own feed lands: it has no
		// archive of its own ingested yet, and its `related`-only CVE
		// linkage and 0% CVSS coverage are hazards this routing does not fix.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Rocky Linux:" + major, nil
	default:
		return "", fmt.Errorf("%w: distro %q is not supported yet", ErrNoEcosystem, d.ID)
	}

	major, rest, ok := strings.Cut(d.VersionID, ".")
	if !ok {
		return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	minor, _, _ := strings.Cut(rest, ".")
	if !allDigits(major) || !allDigits(minor) {
		// edge and pre-releases land here. They have no OSV ecosystem at all,
		// so there is no key to fall back to.
		return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	return "Alpine:v" + major + "." + minor, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
