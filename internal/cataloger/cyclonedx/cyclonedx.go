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
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	PURL       string     `json:"purl"`
	Properties []property `json:"properties"`
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

	for _, c := range doc.Components {
		stats.Components++
		if c.PURL == "" {
			stats.SkippedNoPURL++
			continue
		}
		p, err := pkgmeta.ParsePURL(c.PURL)
		if err != nil {
			stats.SkippedNoPURL++
			continue
		}
		eco, ok := pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			// Distro packages land here in slice 1: their ecosystem key needs
			// a release (D6) that a purl does not carry.
			stats.SkippedUnsupportedEcosystem++
			continue
		}
		version := p.Version
		if version == "" {
			version = c.Version
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
	return target, stats, nil
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
	if d.ID == "" {
		return nil
	}
	return &d
}
