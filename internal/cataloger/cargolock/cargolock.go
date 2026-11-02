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

// Parse reads the Cargo.lock at path and returns the packages it resolves,
// alongside every block it refused because it does not come from a registry.
// path is what every returned Package's single Location names and what any
// returned error names.
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
		stats.Components++
		if b.Name == "" || b.Version == "" {
			// Counted, then skipped. cyclonedx.Stats has no separate
			// "missing name" bucket, so both route through SkippedNoVersion
			// as poetrylock does for the same reason.
			stats.SkippedNoVersion++
			continue
		}
		if strings.HasPrefix(b.Source, "git+") {
			// A git dependency's version is the FORK's own Cargo.toml
			// version, not a crates.io release: reporting it risks both a
			// false positive (the fork may carry the fix under the old
			// number) and a false negative (it may sit at a "fixed" number
			// without the fix). Counted and named, as pnpm's causeGit and
			// gemlock's GIT section are.
			//
			// A registry+ (or sparse+) source stays: an alternate registry
			// is still a registry release. A block with NO source stays
			// too, as before: Cargo writes none for the workspace's own
			// crates, the root project included, so counting those would
			// make every healthy Cargo scan incomplete - the defect
			// npmlock's root "" key once had. A path crate outside the
			// workspace is the same unsourced shape and cannot be told
			// apart here; its name rarely collides with a published crate,
			// which is the accepted cost.
			stats.SkippedNoVersion++
			skipped = append(skipped, Skipped{
				Name:   b.Name,
				Reason: "resolves to a git source; its version is the fork's own, not a crates.io release",
			})
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

	return pkgs, stats, skipped, nil
}
