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
	BOMFormat string `json:"bomFormat"`
	Metadata  struct {
		Component struct {
			Properties []property `json:"properties"`
		} `json:"component"`
	} `json:"metadata"`
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
	target.Distro = distroFrom(doc.Metadata.Component.Properties)
	catalog(doc.Components, &target, &stats)
	return target, stats, nil
}

// catalog walks components depth-first so nested ones are seen. Every path out
// of catalogOne increments exactly one counter, which is what lets the report's
// summary account for every component the document contained.
func catalog(components []component, target *pkgmeta.Target, stats *Stats) {
	for _, c := range components {
		catalogOne(c, target, stats)
		catalog(c.Components, target, stats)
	}
}

func catalogOne(c component, target *pkgmeta.Target, stats *Stats) {
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
	eco, ok := pkgmeta.EcosystemForPURLType(p.Type)
	if !ok {
		// Distro packages land here in slice 1: their ecosystem key needs
		// a release (D6) that a purl does not carry.
		stats.SkippedUnsupportedEcosystem++
		return
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
	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	target.Packages = append(target.Packages, pkgmeta.Package{
		Name:      name,
		Version:   version,
		Type:      p.Type,
		Ecosystem: eco,
		PURL:      c.PURL,
		Locations: []pkgmeta.Location{{Path: "sbom"}},
	})
	stats.Cataloged++
}

// distroFrom reads syft's CycloneDX properties. These are a syft extension,
// not part of the CycloneDX specification, so an SBOM from another tool may
// omit them — in which case Distro stays nil rather than being guessed.
func distroFrom(props []property) *pkgmeta.Distro {
	var d pkgmeta.Distro
	for _, p := range props {
		switch p.Name {
		case "syft:distro:id":
			d.ID = p.Value
		case "syft:distro:versionID":
			d.VersionID = p.Value
		}
	}
	// Both halves are required. An ID without a version would build the
	// ecosystem key "Alpine:" (D6), which matches nothing — and would do so
	// without any error, since a lookup miss is indistinguishable from a
	// package having no advisories.
	if d.ID == "" || d.VersionID == "" {
		return nil
	}
	return &d
}
