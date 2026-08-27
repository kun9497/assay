// Package bitnamidb catalogs Bitnami-packaged applications inside a
// container image (D99). Bitnami is not a distro (D7): its packages are
// cataloged ALONGSIDE whatever os-release-driven distro cataloger already
// ran for the image (Photon for current images, Debian for frozen legacy
// ones), giving a dual inventory the same way a Wolfi/Chainguard image's apk
// packages sit beside nothing else, but here beside a real distro.
//
// Two on-image markers name a Bitnami component:
//
//   - /opt/bitnami/**/.spdx-*.spdx — an SPDX 2.3 JSON document (despite the
//     ".spdx" extension) per component, parsed with D84's existing SPDX
//     machinery (internal/cataloger/spdx). One directory can hold several of
//     these at once (a real redis image carries both
//     common/.spdx-nss-wrapper.spdx and common/.spdx-wait-for-port.spdx),
//     which is why discovering them needs source.FilesMatching rather than
//     source.FilesUnder or source.FilesNamed.
//   - /opt/bitnami/.bitnami_components.json — a legacy, frozen-image
//     fallback: a flat name -> {version, ...} map with no bundled-library
//     detail. Measured to carry the SAME (name, version) pair the SPDX
//     marker in the same image already gives for the main application.
package bitnamidb

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/kun9497/assay/internal/cataloger/spdx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// ParseSPDXMarker reads one Bitnami SPDX marker document and returns the
// Bitnami-purled packages it names — the main application AND any bundled
// libraries the same document lists (a real postgresql marker also lists
// geos, proj, and gdal, each with its own pkg:bitnami purl).
//
// Reuses spdx.Parse whole rather than duplicating its purl-resolution logic:
// a Bitnami marker is a complete, freestanding SPDX document exactly like a
// syft-emitted SBOM is, so Parse's own per-package resolution (version read
// from the purl, never versionInfo — D84's rule, unchanged here) already
// does the right thing. What this function adds on top is narrowing the
// result to "Bitnami"-ecosystem packages only — the same document also
// carries plain Maven purls for a bundled Java library's own jars
// (org.postgresql:pljava), which route to "Maven" through
// EcosystemForPURLType and are deliberately dropped here, per D99's scope —
// and pointing every kept package's Location at the real on-image path
// rather than spdx.Parse's own placeholder "sbom" (which is the right answer
// for an actual whole-image SBOM scan, but not for one marker file found
// deep inside an image being catalogued directly).
func ParseSPDXMarker(r io.Reader, path string) ([]pkgmeta.Package, error) {
	target, _, err := spdx.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var out []pkgmeta.Package
	for _, p := range target.Packages {
		if p.Ecosystem != "Bitnami" {
			continue
		}
		p.Locations = []pkgmeta.Location{{Path: path}}
		out = append(out, p)
	}
	return out, nil
}

// legacyComponent is the value half of .bitnami_components.json's flat
// name -> value map. Only Version is read; arch/distro/type are present in
// the real file but carry nothing this cataloger needs.
type legacyComponent struct {
	Version string `json:"version"`
}

// ParseLegacyComponents reads a frozen-image ".bitnami_components.json" —
// NAMI's own flat map, one entry per installed component, carrying no
// bundled-library detail the way an SPDX marker does (D99's own measurement:
// a real legacy image's json has exactly one entry, the main application;
// every bundled library there is named only in the SPDX marker sitting
// alongside it).
//
// Sorted by name before returning: the source map has no order of its own,
// and an inventory whose order changed between two scans of the same image
// would make every report look like a diff for no reason.
func ParseLegacyComponents(r io.Reader, path string) ([]pkgmeta.Package, error) {
	var raw map[string]legacyComponent
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]pkgmeta.Package, 0, len(names))
	for _, name := range names {
		c := raw[name]
		if c.Version == "" {
			// Nothing for a comparer to place inside a range; skipping here
			// mirrors every other cataloger's "no version, no package" rule
			// (apkdb.Parse, dpkgdb.Parse) rather than emitting an entry the
			// matcher can never evaluate.
			continue
		}
		out = append(out, pkgmeta.Package{
			Name:      name,
			Version:   c.Version,
			Type:      "bitnami",
			Ecosystem: "Bitnami",
			PURL:      fmt.Sprintf("pkg:bitnami/%s@%s", name, c.Version),
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}
	return out, nil
}

// packageKey identifies a package for Merge's dedup — (name, version), not
// (name, version, path): the same application named at the same version by
// both an SPDX marker and the legacy JSON is one installed thing, not two,
// regardless of which file said so.
type packageKey struct{ name, version string }

// Merge combines SPDX-derived and legacy-JSON-derived packages into one
// inventory, deduping by (Name, Version) with the SPDX side always kept over
// a legacy-JSON duplicate of the same pair.
//
// The rule is "always read both, dedupe on the result" rather than
// "SPDX-first, JSON only as a fallback when SPDX found nothing": D99's own
// measurement found a real legacy image carries BOTH files for the SAME
// component at the SAME version (postgresql 17.5.0-14 in both
// .bitnami_components.json and postgresql/.spdx-postgresql.spdx), so a
// per-directory "prefer SPDX, fall back to JSON" rule would have to reason
// about which directory a whole-image, non-per-directory JSON file
// "belongs" to — a distinction the file's own flat shape does not support.
// Reading both and deduping the union is simpler and cannot lose a
// component either source names alone: a hypothetical legacy image whose
// JSON names a component with NO matching SPDX marker still gets that
// component catalogued, from the JSON side.
func Merge(spdxPkgs, legacyPkgs []pkgmeta.Package) []pkgmeta.Package {
	seen := make(map[packageKey]bool, len(spdxPkgs))
	out := make([]pkgmeta.Package, 0, len(spdxPkgs)+len(legacyPkgs))
	for _, p := range spdxPkgs {
		out = append(out, p)
		seen[packageKey{p.Name, p.Version}] = true
	}
	for _, p := range legacyPkgs {
		k := packageKey{p.Name, p.Version}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}
