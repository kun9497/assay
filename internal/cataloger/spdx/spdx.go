// Package spdx turns an SPDX 2.2/2.3 JSON SBOM into the normalized
// inventory — the second SBOM parser (D84), reusing the same purl->Package
// core (internal/pkgmeta) that CycloneDX ingestion (D83) built. The two
// formats disagree about almost everything else — SPDX has no
// operating-system entity, carries several purls per package, and its own
// version field lies — but neither format gets to judge one installed
// package differently from the other, which is the entire reason that core
// moved out of cyclonedx.go instead of being copied.
package spdx

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// document is the subset of SPDX 2.2/2.3 JSON this cataloger reads. files[]
// is ignored entirely — this is a package inventory, not a file manifest.
type document struct {
	SPDXVersion string `json:"spdxVersion"`
	// SPDXID is the document's OWN identifier, almost always
	// "SPDXRef-DOCUMENT" but read rather than assumed: it is what the
	// DESCRIBES relationship below is anchored to.
	SPDXID        string         `json:"SPDXID"`
	Packages      []pkg          `json:"packages"`
	Relationships []relationship `json:"relationships"`
}

type pkg struct {
	Name         string        `json:"name"`
	SPDXID       string        `json:"SPDXID"`
	VersionInfo  string        `json:"versionInfo"`
	ExternalRefs []externalRef `json:"externalRefs"`
	// PrimaryPackagePurpose ("CONTAINER" on syft's own document-root
	// package) is decoded for the shape's own documentation but never
	// consulted: root detection goes through the DESCRIBES relationship
	// below, which is uniform across generators, rather than a purpose
	// string only syft writes.
	PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
}

type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// Parse reads an SPDX 2.2 or 2.3 JSON document. cyclonedx.Stats is reused
// rather than a package-local type — every cataloger in this codebase
// reports through that one shape (gobinary, jar, dirscan and every lockfile
// parser already do), and scancmd's TargetSBOM branch assigns straight into
// a variable of that type.
func Parse(r io.Reader) (pkgmeta.Target, cyclonedx.Stats, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("decode SPDX: %w", err)
	}
	if doc.SPDXVersion != "SPDX-2.2" && doc.SPDXVersion != "SPDX-2.3" {
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf(
			"not a supported SPDX version (spdxVersion=%q, want SPDX-2.2 or SPDX-2.3)", doc.SPDXVersion)
	}

	// Target.Distro stays nil for every SPDX document (D84): the format has
	// no operating-system entity the way a CycloneDX syft extension does, so
	// every apk/rpm/deb package below keys via its OWN purl qualifiers
	// (pkgmeta.ResolveDistroPURL's hasDocDistro is always false here) rather
	// than a document-wide release.
	var target pkgmeta.Target
	var stats cyclonedx.Stats

	rootID := findRootPackageID(doc)

	for _, p := range doc.Packages {
		if rootID != "" && p.SPDXID == rootID {
			// The document-root pseudo-package — syft 1.51's
			// SPDXRef-DocumentRoot-*, or Red Hat's own container/product
			// package (a pkg:oci purl). Excluded exactly like CycloneDX's
			// operating-system component: not a package to scan, and not
			// counted anywhere, rather than landing as a skip and inflating
			// the denominator.
			continue
		}
		catalogPackage(p, &target, &stats)
	}
	return target, stats, nil
}

// findRootPackageID returns the SPDXID the document's own DESCRIBES
// relationship points at. syft 0.84 points this at the document itself
// (SPDXElementID == RelatedSPDXElement == doc.SPDXID), which never matches
// any entry in doc.Packages — so on that shape there is naturally nothing to
// exclude, with no special case needed here.
func findRootPackageID(doc document) string {
	for _, r := range doc.Relationships {
		if r.RelationshipType == "DESCRIBES" && r.SPDXElementID == doc.SPDXID {
			return r.RelatedSPDXElement
		}
	}
	return ""
}

// catalogPackage turns one SPDX package entry into zero or more
// pkgmeta.Package values. "Zero or more" rather than "zero or one" because a
// single SPDX package can carry several purls — Red Hat's own SBOMs emit one
// per repository the package is published from — which resolve, dedupe, and
// land as one entry the overwhelming majority of the time, but the shape
// itself does not guarantee exactly one.
func catalogPackage(p pkg, target *pkgmeta.Target, stats *cyclonedx.Stats) {
	stats.Components++

	var purls []string
	for _, ref := range p.ExternalRefs {
		// referenceCategory is NEVER filtered on: real vendor documents from
		// the SAME tool have been observed writing both "PACKAGE-MANAGER"
		// and "PACKAGE_MANAGER" for referenceType "purl" (measured against
		// Red Hat's own SPDX examples). referenceType is the only field the
		// spec actually promises a fixed spelling for.
		if ref.ReferenceType == "purl" {
			purls = append(purls, ref.ReferenceLocator)
		}
	}
	if len(purls) == 0 {
		stats.SkippedNoPURL++
		return
	}

	type tuple struct{ ecosystem, name, version string }
	seen := make(map[tuple]bool, len(purls))
	var candidates []pkgmeta.Package
	anyParsed := false
	anyNoVersion := false

	for _, raw := range purls {
		parsed, err := pkgmeta.ParsePURL(raw)
		if err != nil {
			continue
		}
		anyParsed = true

		candidate, status := resolvePURL(parsed, raw)
		switch status {
		case statusOK:
			key := tuple{candidate.Ecosystem, candidate.Name, candidate.Version}
			if !seen[key] {
				seen[key] = true
				candidates = append(candidates, candidate)
			}
		case statusNoVersion:
			anyNoVersion = true
		case statusSkip, statusUnsupported:
			// gpg-pubkey, arch=src (D84), or a purl type with no ecosystem
			// mapping. Counted below only if NOTHING about this package ever
			// produced a candidate.
		}
	}

	if !anyParsed {
		// Every purl this package carried was unparseable — the same bucket
		// CycloneDX's own badpurl case uses, since "purl present but
		// garbage" and "no purl at all" both mean nothing here could be
		// looked up.
		stats.SkippedNoPURL++
		return
	}
	if len(candidates) > 0 {
		target.Packages = append(target.Packages, candidates...)
		stats.Cataloged += len(candidates)
		return
	}
	if anyNoVersion {
		stats.SkippedNoVersion++
		return
	}
	// Every purl was gpg-pubkey, arch=src, or an unsupported ecosystem type.
	// Routed into the same bucket CycloneDX routes gpg-pubkey into — the
	// least new machinery, and it is, like an unsupported purl type, a
	// package this cataloger deliberately never turns into an entry.
	stats.SkippedUnsupportedEcosystem++
}

type purlStatus int

const (
	statusSkip purlStatus = iota
	statusUnsupported
	statusNoVersion
	statusOK
)

// resolvePURL maps one already-parsed purl to a candidate Package.
//
// Version comes from the purl alone, NEVER from the package's versionInfo
// field (D84): versionInfo lies three ways on real vendor data — RH
// container SBOMs omit the release entirely, RH product SBOMs write ""/
// "UNKNOWN", and syft's own versionInfo includes the epoch its OWN purl
// leaves out. componentVersion is passed "" to the shared core below for
// exactly that reason — SPDX has no trustworthy per-component fallback the
// way CycloneDX's component.Version field is.
func resolvePURL(p pkgmeta.PURL, raw string) (pkgmeta.Package, purlStatus) {
	loc := []pkgmeta.Location{{Path: "sbom"}}

	switch p.Type {
	case "apk", "rpm", "deb", "alpm":
		res := pkgmeta.ResolveDistroPURL(p, "", "", false)
		if res.Skip {
			return pkgmeta.Package{}, statusSkip
		}
		if res.Version == "" {
			return pkgmeta.Package{}, statusNoVersion
		}
		return pkgmeta.Package{
			Name:         p.Name,
			Version:      res.Version,
			Type:         p.Type,
			Ecosystem:    res.Ecosystem,
			PURL:         raw,
			Source:       res.Source,
			ModuleStream: res.ModuleStream,
			Locations:    loc,
		}, statusOK
	default:
		eco, ok := pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			return pkgmeta.Package{}, statusUnsupported
		}
		if p.Version == "" {
			return pkgmeta.Package{}, statusNoVersion
		}
		name := p.Name
		if p.Namespace != "" {
			// Mirrors cyclonedx.go's own join exactly (D1: OSV's Maven
			// advisories are keyed "group:artifact", never "group/artifact",
			// measured 12,457/12,457 live records) — kept as a small,
			// deliberate duplication rather than moved into the shared core,
			// which D84's fixed design scopes to the apk/rpm/deb branches
			// only.
			sep := "/"
			if p.Type == "maven" {
				sep = ":"
			}
			name = p.Namespace + sep + p.Name
		}
		return pkgmeta.Package{
			Name: name, Version: p.Version, Type: p.Type, Ecosystem: eco,
			PURL: raw, Locations: loc,
		}, statusOK
	}
}
