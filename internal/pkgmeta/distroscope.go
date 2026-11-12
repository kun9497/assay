package pkgmeta

import "strings"

// DistroScope is the OS declared alongside a package in a CycloneDX branch.
// Different point releases may share an advisory database.
type DistroScope struct {
	Qualifier string
	Mixed     bool
}

// ForInstallation retains the local OS when an SBOM purl contradicts it.
// Keep an installed subrelease under a broader local declaration, so later
// duplicate records can detect conflicting point releases in either order.
func (s DistroScope) ForInstallation(installed string) DistroScope {
	if !s.Mixed && installed != "" && (s.Qualifier == "" || releaseIncludes(s.Qualifier, installed)) {
		return DistroScope{Qualifier: installed}
	}
	return s
}

func (s DistroScope) Merge(other DistroScope) DistroScope {
	switch {
	case s.Mixed || other.Mixed:
		return DistroScope{Mixed: true}
	case s.Qualifier == "" || releaseIncludes(s.Qualifier, other.Qualifier):
		return other
	case other.Qualifier == "" || releaseIncludes(other.Qualifier, s.Qualifier):
		return s
	default:
		return DistroScope{Mixed: true}
	}
}

// Matches checks the scope of a VEX OS release against the evaluated key
// and any finer release identified by the installation or its local OS.
func (s DistroScope) Matches(want, installed, ecosystem string) bool {
	d, ok := distroFromQualifier(want)
	if !ok {
		return false
	}
	key, err := d.Ecosystem()
	if err != nil || key != ecosystem {
		return false
	}
	// A statement for the whole keyed release (e.g. alpine-3.19)
	// also applies when the SBOM supplied only the advisory key.
	if releaseIsFullyKeyed(d, key) {
		return true
	}
	if s.Mixed {
		return false
	}
	if s.Qualifier != "" {
		if releaseIncludes(want, s.Qualifier) {
			return true
		}
		// A broad local OS (rhel-9) may be refined by the installed
		// purl. A different declared point release cannot be refined.
		if !releaseIncludes(s.Qualifier, want) {
			return false
		}
	}
	// A statement finer than the installed evidence does not apply: the
	// installed purl must state the point release the statement names (or
	// a release that includes it). v0.18.0 had accepted a point-release
	// statement against an installed purl naming the major alone, because a
	// Debian image's purls spelled only os-release's major while a VEX
	// written from the image's syft SBOM spelled debian-12.11; the image
	// path now spells the point release syft spells, from /etc/debian_version
	// (Distro.PointRelease, D121), so the evidence is there and a statement
	// for 12.10 no longer exonerates a 12.11 image (independent review of
	// v0.18.0, 2026-11-12). An SBOM whose purls carry the major alone still
	// matches whole-release statements and the ones that spell its major.
	return releaseIncludes(want, installed)
}

// A rolling database does not identify a version at all. For a versioned
// database, a qualifier is finer than the key if dropping its last version
// component still identifies the same database (rhel-9.4, alpine-3.19.9).
func releaseIsFullyKeyed(d Distro, key string) bool {
	family := Distro{ID: d.ID}
	if familyKey, _ := family.Ecosystem(); familyKey == key {
		return false
	}
	if i := strings.LastIndexByte(d.VersionID, '.'); i >= 0 {
		d.VersionID = d.VersionID[:i]
		parentKey, _ := d.Ecosystem()
		return parentKey != key
	}
	return true
}

func releaseIncludes(broad, specific string) bool {
	if broad == specific {
		return true
	}
	// A known OS without a version establishes the family. An explicit
	// installed release can refine it, including a hyphenated family ID.
	if strings.HasPrefix(specific, broad+"-") && KnownDistroID(broad) {
		d, ok := distroFromQualifier(specific)
		return ok && d.ID == broad
	}
	if !strings.HasPrefix(specific, broad+".") {
		return false
	}
	broadKey, knownBroad := EcosystemForDistroQualifier(broad)
	specificKey, knownSpecific := EcosystemForDistroQualifier(specific)
	return knownBroad && knownSpecific && broadKey == specificKey
}
