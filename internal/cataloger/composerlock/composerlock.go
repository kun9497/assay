// Package composerlock turns a composer.lock file into the normalized
// package inventory the matcher consumes.
package composerlock

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// lockDoc is the part of composer.lock this parser reads. Composer writes
// many more top-level keys - a content hash, platform requirements, aliases
// - that name no package and are not declared here.
type lockDoc struct {
	Packages    []entry `json:"packages"`
	PackagesDev []entry `json:"packages-dev"`
}

// entry is one resolved package. Version is kept exactly as Composer wrote
// it; see the "v" prefix comment in Parse for why.
type entry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Parse reads the composer.lock at path and returns the packages it
// resolves. path is what every returned Package's single Location names and
// what any returned error names, the same as the other per-file catalogers.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	var doc lockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		// encoding/json's error carries no file identity, so the real path is
		// added here - not a hard-coded "composer.lock", which would satisfy
		// a naive substring check while dropping which file failed.
		return nil, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		// seen dedupes across packages and packages-dev, the same as
		// pipfilelock's default/develop: a package pinned to the same
		// version in both is one component, not two, and emitting it twice
		// would double it in every finding the matcher produces.
		seen = map[string]bool{}
	)

	// packages before packages-dev. Both are read - packages-dev installs in
	// CI too, the same reasoning Pipfile's develop section gets - and unlike
	// pipfilelock's object keys these are JSON arrays, so there is no map to
	// sort for determinism.
	for _, section := range [][]entry{doc.Packages, doc.PackagesDev} {
		for _, e := range section {
			if e.Name == "" {
				// No name at all names no component - nothing to count,
				// the same treatment npm's own "" project-root key gets.
				continue
			}

			if e.Version == "" || strings.HasPrefix(e.Version, "dev-") {
				// "dev-main", "dev-feature/x": a branch alias, not a
				// released version. Composer resolves it to whatever commit
				// HEAD was at install time, and the Packagist Comparer
				// refuses branches by design (D9) - there is no ordering
				// rule for a name, only for a version. Counted, not
				// dropped: a component silently discarded here is
				// indistinguishable from one that never existed.
				stats.Components++
				stats.SkippedNoVersion++
				continue
			}

			key := e.Name + "@" + e.Version
			if seen[key] {
				// Not counted again either: it is the same component, so
				// incrementing Components here would break the
				// Components == Cataloged + skips invariant by counting one
				// component twice against a single Cataloged.
				continue
			}
			seen[key] = true

			stats.Components++
			stats.Cataloged++
			pkgs = append(pkgs, pkgmeta.Package{
				Name: e.Name,
				// Kept verbatim, "v" prefix and all. Composer writes both
				// "v1.2.3" and "1.2.3" depending on how the tag was cut, and
				// the Packagist Comparer normalizes that at comparison time
				// (D9) - stripping the prefix here would be a second
				// definition of a rule that comparer already owns.
				Version: e.Version,
				Type:    "composer",
				// Plain concatenation, as pipfilelock and poetrylock do:
				// normalization happens once, at match time
				// (pkgmeta.NormalizeName), not duplicated here.
				Ecosystem: "Packagist",
				PURL:      "pkg:composer/" + e.Name + "@" + e.Version,
				Locations: []pkgmeta.Location{{Path: path}},
			})
		}
	}

	return pkgs, stats, nil
}
