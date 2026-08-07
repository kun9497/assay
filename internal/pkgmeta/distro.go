package pkgmeta

import (
	"errors"
	"fmt"
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
	ID         string // os-release ID, e.g. "alpine"
	VersionID  string // os-release VERSION_ID, e.g. "3.19.9"
	PrettyName string // os-release PRETTY_NAME; reporting only, never a lookup key
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
	case "rhel":
		// D50. `rhel` and nothing else. Red Hat's CSAF VEX feed describes Red
		// Hat's own builds, keyed on the mainline major (D47), and
		// /etc/os-release's VERSION_ID is "9.8" — the minor is dropped because
		// the key is not release-qualified below the major.
		//
		// The other RPM distributions are NOT routed here, and each is a
		// different reason rather than one blanket caution:
		//
		//   - almalinux, rocky: rebuilds, but not byte-identical ones. Alma
		//     writes module builds as `module_el8.5.0+119+9a9ec082` where Red
		//     Hat writes `module+el8.5.0+12582+56d94c81`, and its own rebuilds
		//     carry `.alma` release suffixes. Comparing one distro's installed
		//     versions against another's advisory versions is the hazard
		//     docs/deferred-decisions.md records against both.
		//   - centos: the ID covers CentOS Linux, which trailed RHEL, AND
		//     CentOS Stream, which runs AHEAD of it. A fixed version that has
		//     not reached RHEL yet is already in Stream, so the same key would
		//     be wrong in opposite directions for the two.
		//   - fedora, amzn: different version schemes and their own advisory
		//     feeds (FEDORA-*, ALAS-*). Red Hat's errata do not describe them.
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
