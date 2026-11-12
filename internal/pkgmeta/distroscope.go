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
	case s.Qualifier == "":
		return other
	case other.Qualifier == "" || s == other:
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
	return broad == specific || strings.HasPrefix(specific, broad+".")
}
