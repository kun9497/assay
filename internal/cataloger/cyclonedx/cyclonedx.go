// Package cyclonedx turns a CycloneDX SBOM into the normalized inventory.
//
// This is a Cataloger like any other: later slices add image and binary
// catalogers that produce the same pkgmeta.Target, so nothing downstream
// changes when they arrive.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Stats records what the cataloger could not use. Reported rather than
// discarded: a package silently dropped here is indistinguishable from a
// package with no vulnerabilities.
type Stats struct {
	Components                  int
	Cataloged                   int
	SkippedNoPURL               int
	SkippedNoVersion            int
	SkippedUnsupportedEcosystem int
}

type bom struct {
	BOMFormat  string      `json:"bomFormat"`
	Components []component `json:"components"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	// CycloneDX lets a component carry its own components array. Reading only
	// the top level would make those packages invisible — not skipped, but
	// absent from every counter, which is worse than a counted skip because
	// nothing in the report hints they existed.
	Components []component `json:"components"`
	Properties []property  `json:"properties"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Parse(r io.Reader) (pkgmeta.Target, Stats, error) {
	var doc bom
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("decode CycloneDX: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}

	var (
		target pkgmeta.Target
		stats  Stats
	)
	// syft emits the distro as a component of type "operating-system", not on
	// metadata.component — and the real fixture puts it last (components[16] of
	// 17), after the packages that need its release. So the whole document is
	// read for the distro in a first pass, before packages are cataloged in a
	// second: a single forward pass would catalog every apk package unkeyed.
	target.Distro = distroFrom(doc.Components)

	// The ecosystem key for a distro package needs the release, which lives on
	// the target rather than the package (D6, D7). Resolve it once so every
	// apk component in the second pass reuses it instead of re-deriving it.
	var distroEcosystem string
	if target.Distro != nil {
		if eco, err := target.Distro.Ecosystem(); err == nil {
			distroEcosystem = eco
		}
		// On error distroEcosystem stays empty and apk packages are cataloged
		// unkeyed below, so the matcher reports them as skipped with a reason.
		// Guessing a key here would turn "we cannot check this" into "this is
		// clean".
	}

	catalog(doc.Components, distroEcosystem, &target, &stats)
	return target, stats, nil
}

// catalog walks components depth-first so nested ones are seen. Every path out
// of catalogOne increments exactly one counter, which is what lets the report's
// summary account for every component the document contained.
func catalog(components []component, distroEcosystem string, target *pkgmeta.Target, stats *Stats) {
	for _, c := range components {
		catalogOne(c, distroEcosystem, target, stats)
		catalog(c.Components, distroEcosystem, target, stats)
	}
}

func catalogOne(c component, distroEcosystem string, target *pkgmeta.Target, stats *Stats) {
	if c.Type == "operating-system" {
		// Described the target in the first pass (D7); it is not a package to
		// scan, and counting it here would inflate the component total.
		return
	}
	if c.Type == "file" {
		// Modern syft emits thousands of purl-less "file" components per
		// image — content-scanned files, not packages (6,161 of 6,306
		// top-level components measured on a real rockylinux:9 syft 1.51.0
		// SBOM). Counting them as SkippedNoPURL used to inflate Components
		// enough on its own to trip --fail-on-incomplete=target on a scan
		// that was otherwise complete. Excluded here the same way the
		// operating-system component is above: not counted anywhere, rather
		// than adding a Stats field for a bucket nothing needs to gate on —
		// the least new machinery, and consistent with the one exclusion
		// this file already had.
		return
	}
	stats.Components++
	if c.PURL == "" {
		stats.SkippedNoPURL++
		return
	}
	p, err := pkgmeta.ParsePURL(c.PURL)
	if err != nil {
		stats.SkippedNoPURL++
		return
	}

	var eco string
	switch p.Type {
	case "apk":
		// The purl carries no release (D6); apk's ecosystem key comes from the
		// target's distro instead. purlTypeToEcosystem deliberately has no apk
		// entry for the same reason. An apk package is never dropped for
		// lacking a distro — it is cataloged unkeyed so it is still counted and
		// later reported as skipped, rather than silently absent.
		eco = distroEcosystem
	case "rpm", "deb":
		// D83. Same reasoning as apk above: no release on the purl itself, so
		// the ecosystem key comes from the target's distro — with a
		// document-level fallback to the purl's own "distro" qualifier for the
		// (D7) documents that carry no operating-system component at all.
		if p.Type == "rpm" && isPubkeyPURL(p) {
			// gpg-pubkey is a keyring entry, not an installed package (mirrors
			// rpmdb's isPubkey, header.go). Routed into the existing
			// "unsupported ecosystem" bucket rather than a new Stats field —
			// the least new machinery, and it is, like an unsupported purl
			// type, a component this cataloger deliberately never turns into
			// a package.
			stats.SkippedUnsupportedEcosystem++
			return
		}
		eco = distroEcosystemFor(p, target, distroEcosystem)
	default:
		var ok bool
		eco, ok = pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			stats.SkippedUnsupportedEcosystem++
			return
		}
	}

	version := p.Version
	if version == "" {
		version = c.Version
	} else if p.Type == "rpm" || p.Type == "deb" {
		// The purl's own @version is version-release WITHOUT the epoch —
		// evr()'s shape (rpmdb/header.go) omits it the same way when zero —
		// and Qualifiers["epoch"] carries it separately, written only when
		// present and non-zero. Prepending it here, in that same condition,
		// is what makes the two sides comparable.
		if epoch, ok := p.Qualifiers["epoch"]; ok && epoch != "" && epoch != "0" {
			version = epoch + ":" + version
		}
	}
	if version == "" {
		// Nothing for a comparer to place inside a range. Counting it as
		// cataloged would claim the package was evaluated when it was not.
		stats.SkippedNoVersion++
		return
	}

	// apk, rpm and deb purls carry the distro name as their namespace
	// (pkg:apk/alpine/..., pkg:rpm/rhel/...), which is not part of the
	// package identity: OSV's advisories name the bare package ("openssl",
	// not "alpine/openssl"), and the rpm namespace itself is not even stable
	// — syft 0.84.1 writes "rhel", syft 1.51.0 writes "redhat", for the same
	// distro. Prefixing either into the name here would make every distro
	// lookup miss its advisory, or miss it only on some SBOMs.
	name := p.Name
	if p.Namespace != "" && p.Type != "apk" && p.Type != "rpm" && p.Type != "deb" {
		// The purl spec always separates namespace and name with "/"
		// (pkg:maven/group/artifact), but OSV's Maven advisories name the
		// package "group:artifact" — measured 12,457/12,457 live records.
		// Joining with "/" here would build a name OSV never publishes and
		// every Maven package would silently miss its advisory.
		sep := "/"
		if p.Type == "maven" {
			sep = ":"
		}
		name = p.Namespace + sep + p.Name
	}

	loc := pkgmeta.Location{Path: "sbom"}
	if path := propValue(c, "syft:location:0:path"); path != "" {
		loc.Path = path
	}
	if layer := propValue(c, "syft:location:0:layerID"); layer != "" {
		loc.LayerDigest = layer
	}

	pkg := pkgmeta.Package{
		Name:      name,
		Version:   version,
		Type:      p.Type,
		Ecosystem: eco,
		PURL:      c.PURL,
		Locations: []pkgmeta.Location{loc},
	}
	switch p.Type {
	case "apk":
		// syft reports the origin package name only (D8). Alpine binary
		// packages carry their source package's version, so leaving Version
		// empty here is correct rather than a gap: the binary's own version is
		// the one the comparer uses.
		if origin := propValue(c, "syft:metadata:originPackage"); origin != "" {
			pkg.Source = &pkgmeta.SourcePackage{Name: origin}
		}
	case "rpm":
		// D8/D83. The "upstream" qualifier is a source-RPM filename
		// ("audit-3.0.7-104.el9.src.rpm"), stripped back to the bare name by
		// the same core rpmdb's own cataloger uses (pkgmeta.SourceRPMName).
		if upstream := p.Qualifiers["upstream"]; upstream != "" {
			if src := pkgmeta.SourceRPMName(upstream); src != "" {
				pkg.Source = &pkgmeta.SourcePackage{Name: src}
			}
		}
		// D80. Only NAME:STREAM is kept, exactly as rpmdb/header.go reads it
		// off RPMTAG_MODULARITYLABEL: the label's VERSION and CONTEXT differ
		// between builds of one installed stream. Fewer than four
		// colon-separated fields leaves ModuleStream "" rather than guessed
		// at, so the D80 matcher still refuses to judge a module build it
		// cannot name a stream for.
		if label := propValue(c, "syft:metadata:modularityLabel"); label != "" {
			parts := strings.SplitN(label, ":", 4)
			if len(parts) == 4 && parts[0] != "" && parts[1] != "" {
				pkg.ModuleStream = parts[0] + ":" + parts[1]
			}
		}
	case "deb":
		// D8/D83. syft's "upstream" qualifier is "name" or "name@version"
		// (percent-encoded '@'); only the name half identifies the source
		// package, the same as dpkgdb's own Source: field reading (D8).
		if upstream := p.Qualifiers["upstream"]; upstream != "" {
			srcName, _, _ := strings.Cut(upstream, "@")
			if srcName != "" {
				pkg.Source = &pkgmeta.SourcePackage{Name: srcName}
			}
		}
	}
	target.Packages = append(target.Packages, pkg)
	stats.Cataloged++
}

// isPubkeyPURL mirrors rpmdb's isPubkey (header.go): a gpg-pubkey row is a
// keyring entry, not an installed package, and the "arch" qualifier is what
// tells it apart from a hypothetical real package of that name — a real one
// always carries an architecture, syft's own gpg-pubkey purls never do.
func isPubkeyPURL(p pkgmeta.PURL) bool {
	if p.Name != "gpg-pubkey" {
		return false
	}
	_, hasArch := p.Qualifiers["arch"]
	return !hasArch
}

// distroEcosystemFor resolves the ecosystem key for an rpm or deb package
// (D83). docEcosystem is the document-wide key already resolved once from the
// operating-system component (D6, D7) — mirroring how the apk branch uses it
// — with a per-package fallback for documents that carry no such component at
// all: syft's own purl "distro" qualifier is the only place the release
// survives there.
//
// An operating-system component that IS present always wins, even when its
// own Ecosystem() resolution failed and left docEcosystem "" — falling back
// to the qualifier at that point would let one document disagree with
// itself, keying some of its own packages on a release the document's own
// stated distro does not have.
func distroEcosystemFor(p pkgmeta.PURL, target *pkgmeta.Target, docEcosystem string) string {
	if target.Distro != nil {
		return docEcosystem
	}
	dq, ok := p.Qualifiers["distro"]
	if !ok {
		return ""
	}
	d, ok := distroFromQualifier(dq)
	if !ok {
		return ""
	}
	eco, err := d.Ecosystem()
	if err != nil {
		return ""
	}
	return eco
}

// distroFromQualifier builds a Distro from a purl's "distro" qualifier. syft
// writes it "id-versionID" — "rhel-9.8", "amzn-2023", and "opensuse-leap-15.6"
// where the id itself is hyphenated — so it is split on the LAST hyphen
// rather than the first: everything before is the id, everything after is
// the release. A value with no hyphen (or one ending in a hyphen) has no
// release to split off and fails rather than building a Distro with an empty
// half.
func distroFromQualifier(s string) (pkgmeta.Distro, bool) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 || i == len(s)-1 {
		return pkgmeta.Distro{}, false
	}
	return pkgmeta.Distro{ID: s[:i], VersionID: s[i+1:]}, true
}

// propValue returns the value of the first property named name, or "" if the
// component does not carry it. Every syft extension property read by this
// package goes through here so a missing one degrades to empty rather than a
// panic.
func propValue(c component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// distroFrom reads the operating-system component syft emits alongside the
// package inventory. This is a syft extension, not part of the CycloneDX
// specification, so an SBOM from another tool — or one with no distro at all —
// may omit it, in which case Distro stays nil rather than being guessed.
func distroFrom(components []component) *pkgmeta.Distro {
	for _, c := range components {
		if c.Type != "operating-system" {
			continue
		}
		var d pkgmeta.Distro
		for _, p := range c.Properties {
			switch p.Name {
			case "syft:distro:id":
				d.ID = p.Value
			case "syft:distro:versionID":
				d.VersionID = p.Value
			case "syft:distro:prettyName":
				d.PrettyName = p.Value
			}
		}
		// Fall back to the component's own fields: the properties are a syft
		// extension, but name/version are spec and carry the same thing.
		if d.ID == "" {
			d.ID = c.Name
		}
		if d.VersionID == "" {
			d.VersionID = c.Version
		}
		if d.ID == "" {
			return nil
		}
		return &d
	}
	return nil
}
