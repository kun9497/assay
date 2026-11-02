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
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/tomlblock"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Skipped is one [[package]] block this parser saw and declined to catalog,
// with why - the shape pnpmlock and yarnlock return, so dirscan can name it.
type Skipped struct {
	Name   string
	Reason string
}

// sourceKey returns the one key of a uv.lock inline source table
// (`{ git = "..." }` gives "git"). uv writes exactly one key there - registry,
// git, url, path, directory, editable or virtual - so the first is the kind.
// Anything that is not an inline table gives "".
func sourceKey(raw string) string {
	inner, ok := strings.CutPrefix(raw, "{")
	if !ok {
		return ""
	}
	eq := strings.Index(inner, "=")
	if eq < 0 {
		return ""
	}
	return strings.TrimSpace(inner[:eq])
}

// Parse reads the uv.lock at path and returns the packages it resolves,
// alongside every block it refused because it does not come from a registry.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, []Skipped, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, nil, err
	}

	var (
		pkgs    []pkgmeta.Package
		stats   cyclonedx.Stats
		skipped []Skipped
	)
	for _, b := range tomlblock.Scan(data) {
		switch sourceKey(b.Source) {
		case "git", "url", "path", "directory":
			// The version beside a git checkout, a URL archive or a path to
			// another tree is the one that tree's own metadata declares, not a
			// PyPI release: reporting it risks both a false positive and a
			// false negative. Counted and named, as pipfilelock counts its
			// git/path entries and pnpm its causeGit.
			stats.Components++
			stats.SkippedNoVersion++
			skipped = append(skipped, Skipped{
				Name:   b.Name,
				Reason: "resolves to a git, URL or path source; its version is not a PyPI release",
			})
			continue
		case "editable":
			// The project itself (when it is a package) and every workspace
			// member: uv writes all of them as editable. Shown, not counted -
			// pnpm's causeLocal (D103) - because counting would make every
			// healthy uv scan incomplete, the defect npmlock's root "" key
			// once had. "virtual" (a project that is not a package) is left
			// cataloged as before.
			skipped = append(skipped, Skipped{
				Name:   b.Name,
				Reason: "an editable source in this checkout (the project or a workspace member), nothing to evaluate",
			})
			continue
		}

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

	return pkgs, stats, skipped, nil
}
