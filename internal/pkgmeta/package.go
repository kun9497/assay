// Package pkgmeta holds the normalized package inventory: what a scan found,
// independent of where it came from.
package pkgmeta

import "strings"

type Target struct {
	// Distro belongs to the target, not to each package (D7): an image is
	// Alpine 3.19, its packages are not. nil for language-only targets.
	Distro   *Distro
	Packages []Package
}

type Package struct {
	Name      string
	Version   string
	Type      string // purl type: golang | npm | pypi | apk | deb
	Ecosystem string // OSV ecosystem key, resolved at catalog time
	PURL      string
	// Source is the source package an advisory may be keyed on (D8). Distro
	// advisories target source packages while installed packages are binary
	// packages; without this the miss is a false negative, which is silent.
	Source    *SourcePackage
	Locations []Location
	// ModuleStream is the RPM module stream this package was installed from,
	// as "name:stream" — the first two fields of RPMTAG_MODULARITYLABEL
	// (tag 5096) — or "" for a non-modular package (D80). Only those two
	// fields are kept: the label's VERSION and CONTEXT vary between builds
	// of ONE installed stream (measured on real ubi8/ubi9 AppStream images),
	// so keying on them would split a stream into phantom streams. The
	// module name is not derivable from the package name or SOURCERPM
	// (perl-Mozilla-CA carries label perl-libwww-perl:6.34:...) — the tag is
	// the only signal. A label that is present but unparseable is mapped to
	// "" by the cataloger; the matcher catches that case anyway, because a
	// module-tagged VERSION with no stream is reported not evaluated rather
	// than judged (the release marker and the tag agreed 13/13 and 0/1,049
	// on real images, so their disagreement is the anomaly).
	ModuleStream string
}

type SourcePackage struct {
	Name    string
	Version string
}

type Location struct {
	Path        string
	LayerDigest string // empty outside image scans
}

// SourceRPMName strips a SOURCERPM-shaped filename back to the bare source
// package name: "audit-3.0.7-104.el9.src.rpm" -> "audit". This is the one
// core both rpm readers share (D83) — the rpmdb cataloger reads it off an
// installed header's SOURCERPM tag, and the cyclonedx cataloger reads the
// same string off a purl's "upstream" qualifier, which syft writes in the
// identical shape. A single function here is what keeps the two readings
// from drifting apart; it used to live only in rpmdb, taking a parsed header,
// before the cyclonedx cataloger needed the same stripping logic on a plain
// string with no header to read it from.
//
// The last TWO hyphen-separated fields are the version and release, so they
// are what comes off — not everything after the first hyphen, which would
// turn "python3-perf-3.10.0-1.el9.src.rpm" into "python3". Roughly a third of
// the names in a real image carry an interior hyphen, so that is the common
// case rather than the edge one.
//
// Returns "" for anything that is not that shape, including gpg-pubkey's
// literal "(none)".
func SourceRPMName(s string) string {
	s, ok := strings.CutSuffix(s, ".src.rpm")
	if !ok {
		return ""
	}
	i := strings.LastIndexByte(s, '-')
	if i < 0 {
		return ""
	}
	j := strings.LastIndexByte(s[:i], '-')
	if j <= 0 {
		return ""
	}
	return s[:j]
}
