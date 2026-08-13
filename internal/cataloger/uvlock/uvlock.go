// Package uvlock turns a uv.lock file into the normalized package inventory
// the matcher consumes.
//
// uv.lock is the same flat [[package]] shape as Cargo.lock and poetry.lock, so
// it shares tomlblock's scanner rather than carrying a second copy of it. D61
// claimed this file needed a TOML library; that was reasoning from the format's
// name rather than from the file, and D62 records the measurement that
// corrected it — 77 of 77 blocks on uv's own 1,650-line lockfile.
package uvlock

import (
	"os"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/tomlblock"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Parse reads the uv.lock at path and returns the packages it resolves.
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
			// Counted, then skipped: there is nothing here for a comparer to
			// place inside an advisory range, and a block dropped silently is
			// indistinguishable from one that was never in the file.
			stats.SkippedNoVersion++
			continue
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:    b.Name,
			Version: b.Version,
			Type:    "pypi",
			// Plain concatenation, as in poetrylock: PEP 503 normalization
			// happens once, at match time (pkgmeta.NormalizeName). uv already
			// writes normalized names, but relying on that here would put a
			// second definition of the rule in the tree.
			Ecosystem: "PyPI",
			PURL:      "pkg:pypi/" + b.Name + "@" + b.Version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	return pkgs, stats, nil
}
