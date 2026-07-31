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
	if p.Type == "apk" {
		// The purl carries no release (D6); apk's ecosystem key comes from the
		// target's distro instead. purlTypeToEcosystem deliberately has no apk
		// entry for the same reason. An apk package is never dropped for
		// lacking a distro — it is cataloged unkeyed so it is still counted and
		// later reported as skipped, rather than silently absent.
		eco = distroEcosystem
	} else {
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
	}
	if version == "" {
		// Nothing for a comparer to place inside a range. Counting it as
		// cataloged would claim the package was evaluated when it was not.
		stats.SkippedNoVersion++
		return
	}

	// apk purls carry the distro name as their namespace (pkg:apk/alpine/...),
	// which is not part of the package identity: OSV's Alpine advisories name
	// the bare package ("openssl", not "alpine/openssl"). Prefixing it here
	// would make every apk lookup miss its advisory.
	name := p.Name
	if p.Type != "apk" && p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
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
	if p.Type == "apk" {
		// syft reports the origin package name only (D8). Alpine binary
		// packages carry their source package's version, so leaving Version
		// empty here is correct rather than a gap: the binary's own version is
		// the one the comparer uses.
		if origin := propValue(c, "syft:metadata:originPackage"); origin != "" {
			pkg.Source = &pkgmeta.SourcePackage{Name: origin}
		}
	}
	target.Packages = append(target.Packages, pkg)
	stats.Cataloged++
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
