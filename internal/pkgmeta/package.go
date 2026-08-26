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
	// Provides is the bare package names this package's apk `p:` (provides)
	// clause declares (D95) — e.g. a BellSoft Alpaquita "liberica26-lite" apk
	// package provides "openjdk26-lite", the name BellSoft's own Alpaquita
	// advisories are written against. Measured against a real Liberica JDK
	// image and the live Alpaquita OSV feed, 2026-08-26: every Liberica CVE
	// names a package (e.g. "openjdk26-lite") that is never an installed
	// package's own Name, and the apk `o:` origin (D8's Source field, below)
	// does not bridge it either — the installed "liberica26-lite-jdk"
	// package's own origin is "liberica26-lite", not "openjdk26-lite". The
	// advisory's name is reachable ONLY through a sibling package's provides
	// clause, accounting for 10.74% of the measured corpus.
	//
	// cmd:/so:/pc:-prefixed entries are command, shared-library-soname and
	// pkg-config capabilities, not package names, and are dropped by the apk
	// cataloger before this field is populated — no advisory is ever authored
	// against a soname, and joining on one would be a different, unsound
	// mechanism from the name join this field exists for.
	//
	// Populated ONLY by the apk cataloger (internal/cataloger/apkdb). dpkg's
	// and rpm's own "Provides" concepts are virtual-package capabilities
	// resolved at install time, a different mechanism entirely, and are out
	// of scope for this field.
	Provides []string
	// ProvidesVersion carries the version a Provides entry named, keyed by
	// entry (D95). An apk `p:` clause may write a provide bare
	// ("java-jdk") or version-qualified ("openjdk26-lite=26.0.2.1_p1-r0"),
	// and both shapes appear side by side in one real package's own provides
	// clause (measured on a Liberica JDK image's "liberica26-lite-jdk"
	// package). A name absent from this map carried no version at all; the
	// matcher falls back to this package's own Version for those, the same
	// way an empty Source.Version means "same as the binary version" (D8).
	ProvidesVersion map[string]string
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
