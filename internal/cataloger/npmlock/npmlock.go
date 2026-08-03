// Package npmlock turns a package-lock.json file into the normalized package
// inventory, using nothing but the standard library.
//
// npm has written two incompatible shapes under the same filename: v2/v3
// (npm 7+) carry a flat "packages" object keyed by install path, v1 (npm 6)
// carries a "dependencies" tree keyed by bare name and nested recursively.
// Which is present is decided by which field actually holds data rather than
// by lockfileVersion - real repositories contain files whose declared
// version does not match their actual shape, and the field that is there is
// the one that is true.
package npmlock

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// lockDoc is the top-level shape shared by every lockfileVersion. Only one of
// Packages/Dependencies is ever populated in a well-formed file; both are
// decoded so Parse can pick whichever has entries rather than trusting the
// version number.
type lockDoc struct {
	Packages     map[string]packageEntry `json:"packages"`
	Dependencies map[string]depEntry     `json:"dependencies"`
}

// packageEntry is one value in the v2/v3 "packages" object.
type packageEntry struct {
	Version string `json:"version"`
	// Link marks a workspace entry that points at a local directory rather
	// than a registry-resolved package - there is no published version to
	// place inside an advisory range.
	Link bool `json:"link"`
}

// depEntry is one value in the v1 "dependencies" tree. Dependencies nests
// recursively: a package's own transitive dependencies are listed under it,
// keyed the same way as the top level.
type depEntry struct {
	Version      string              `json:"version"`
	Dependencies map[string]depEntry `json:"dependencies"`
}

// Parse reads the package-lock.json at path and returns the packages it
// resolves. path is also what every returned Package's single Location
// names, and what any returned error names - the caller may be scanning many
// lockfiles in one pass, and a bare "package-lock.json" in an error would not
// say which one.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's own error already names the full path ("open <path>:
		// ..."), so wrapping it again here would only double it up.
		return nil, cyclonedx.Stats{}, err
	}

	var doc lockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		// Unlike os.ReadFile's, encoding/json's error carries no file
		// identity at all ("unexpected end of JSON input"), so the path must
		// be added here. It must be the real path, not a hard-coded
		// "package-lock.json" - a wrapper that spells the filename in its own
		// format string would satisfy a naive substring check while still
		// dropping both the actual path and the cause (CLAUDE.md's
		// "substring assertions" note).
		return nil, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	switch {
	case len(doc.Packages) > 0:
		catalogPackages(doc.Packages, path, &pkgs, &stats)
	case len(doc.Dependencies) > 0:
		catalogDependencies(doc.Dependencies, path, &pkgs, &stats)
	}
	return pkgs, stats, nil
}

// catalogPackages walks the v2/v3 "packages" object in sorted key order, so
// the returned slice does not vary between runs of the same file - a map
// range here would reach the report.
func catalogPackages(entries map[string]packageEntry, path string, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	for _, key := range sortedKeys(entries) {
		e := entries[key]
		stats.Components++

		// The "" key is the root project itself, not a dependency; "link"
		// marks a workspace symlink to a local directory; an empty version
		// means the entry has nothing a comparer can place inside a range.
		// All three are real entries with nothing to match on, not absences
		// - counted here rather than dropped, so the invariant
		// (Components == Cataloged + skips) still accounts for them.
		if key == "" || e.Link || e.Version == "" {
			stats.SkippedNoVersion++
			continue
		}

		name := nameFromInstallPath(key)
		*pkgs = append(*pkgs, pkgmeta.Package{
			Name:      name,
			Version:   e.Version,
			Type:      "npm",
			Ecosystem: "npm",
			PURL:      "pkg:npm/" + name + "@" + e.Version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
		stats.Cataloged++
	}
}

// catalogDependencies walks the v1 "dependencies" tree, recursing into each
// entry's own nested "dependencies" so transitive packages are not missed -
// reading only the top level would silently return the direct dependencies
// alone. Keys are sorted at every level for the same determinism reason as
// catalogPackages.
func catalogDependencies(entries map[string]depEntry, path string, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	for _, name := range sortedKeys(entries) {
		e := entries[name]
		stats.Components++

		if name == "" || e.Version == "" {
			stats.SkippedNoVersion++
		} else {
			*pkgs = append(*pkgs, pkgmeta.Package{
				Name:      name,
				Version:   e.Version,
				Type:      "npm",
				Ecosystem: "npm",
				PURL:      "pkg:npm/" + name + "@" + e.Version,
				Locations: []pkgmeta.Location{{Path: path}},
			})
			stats.Cataloged++
		}

		if len(e.Dependencies) > 0 {
			catalogDependencies(e.Dependencies, path, pkgs, stats)
		}
	}
}

// nameFromInstallPath returns the segment after the LAST "node_modules/" in
// an install-path key. A nested install
// ("node_modules/a/node_modules/lodash") is package lodash, not "a/lodash" -
// taking the whole key as the name would produce a package nothing has
// advisories for. A scoped package's own segment ("@scope/pkg") is returned
// whole: stripping the scope produces a different package with different
// advisories.
func nameFromInstallPath(key string) string {
	const marker = "node_modules/"
	if i := strings.LastIndex(key, marker); i >= 0 {
		return key[i+len(marker):]
	}
	return key
}

// sortedKeys returns m's keys in sorted order. Both entry map types are
// generic-instantiated through this so every map range in this package - v3
// flat, v1 top level, v1 nested - goes through the same sort.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
