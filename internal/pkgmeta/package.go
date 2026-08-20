// Package pkgmeta holds the normalized package inventory: what a scan found,
// independent of where it came from.
package pkgmeta

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
