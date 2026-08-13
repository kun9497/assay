// Package cargolock turns a Cargo.lock file into the normalized package
// inventory the matcher consumes.
//
// Cargo.lock is TOML, and this reads it through tomlblock's line scanner
// rather than a TOML parser, the same way poetrylock does for poetry.lock.
// That is a deliberate limit rather than an oversight: the file is a flat
// sequence of [[package]] blocks whose two interesting fields are bare quoted
// strings, so the subset needed here is small and stable. It is also why
// pnpm-lock.yaml is refused instead (D61) - YAML's is neither.
package cargolock

import (
	"os"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/tomlblock"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Parse reads the Cargo.lock at path and returns the packages it resolves.
// path is what every returned Package's single Location names and what any
// returned error names.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	for _, b := range tomlblock.Scan(data) {
		stats.Components++
		if b.Name == "" || b.Version == "" {
			// Counted, then skipped. cyclonedx.Stats has no separate
			// "missing name" bucket, so both route through SkippedNoVersion
			// as poetrylock does for the same reason.
			stats.SkippedNoVersion++
			continue
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:    b.Name,
			Version: b.Version,
			Type:    "cargo",
			// The purl type and the ecosystem key are different strings:
			// pkg:cargo/<crate>, but OSV keys the ecosystem "crates.io".
			// Writing "cargo" here would send every lookup to a bucket that
			// does not exist, and a lookup that finds nothing reports clean.
			Ecosystem: "crates.io",
			PURL:      "pkg:cargo/" + b.Name + "@" + b.Version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	return pkgs, stats, nil
}
