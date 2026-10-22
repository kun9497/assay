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
	// Name is the package's registry identity, written by npm only when it
	// differs from the install path's last segment: an alias
	// (`utility-alias: npm:lodash@4.17.20` installs lodash under
	// node_modules/utility-alias and records "name": "lodash") or a
	// workspace whose directory is not its package name. Advisories are
	// written against this, never the alias -- a lockfile read by install
	// path alone cataloged "utility-alias", a package nothing is written
	// against, and judged the installed lodash clean (2026-10-22 external
	// review, #1).
	Name    string `json:"name"`
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

		// The "" key is the root project itself. It is not a component at
		// all, so it is skipped BEFORE the count - the same way gomod.Parse
		// counts requires but not the `module` line, and cyclonedx.Parse
		// counts components but not metadata.component.
		//
		// Counting it was measurably wrong, not merely untidy: every npm 7+
		// lockfile carries this key, so it put NotEvaluated at 1 on every
		// healthy npm scan and made `--fail-on-incomplete` exit 2 on a
		// directory where nothing had gone wrong. A lockfile with no
		// dependencies went further - one component, none evaluated, so
		// Trustworthy() was false and the scan exited 2 outright.
		if key == "" {
			continue
		}
		stats.Components++

		// "link" marks a workspace symlink to a local directory, and an empty
		// version means the entry has nothing a comparer can place inside a
		// range. Both ARE dependencies, unlike the root, so they are counted
		// and then skipped - the invariant (Components == Cataloged + skips)
		// accounts for them, and the report says they were seen and could not
		// be evaluated.
		if e.Link || e.Version == "" {
			stats.SkippedNoVersion++
			continue
		}

		name := nameFromInstallPath(key)
		loc := pkgmeta.Location{Path: path}
		if e.Name != "" && e.Name != name {
			// The registry identity is what is matched and what the purl
			// spells; the install path is kept beside the lockfile as the
			// place the aliased copy lives, so the report can still say
			// where it is.
			name = e.Name
			loc.Install = key
		}
		*pkgs = append(*pkgs, pkgmeta.Package{
			Name:      name,
			Version:   e.Version,
			Type:      "npm",
			Ecosystem: "npm",
			PURL:      "pkg:npm/" + name + "@" + e.Version,
			Locations: []pkgmeta.Location{loc},
		})
		stats.Cataloged++
	}
}

// aliasSpec reads npm 6's spelling of an alias, where the v1 "version" field
// carries the whole target spec: "npm:lodash@4.17.20". It returns the
// registry name and version, or ok=false when version is not an alias spec.
// Split on the LAST '@', because a scoped target ("npm:@scope/real@2.0.0")
// carries one in its name. A spec with no version part ("npm:lodash")
// returns the name and an empty version, which the caller counts the way it
// counts any versionless entry.
func aliasSpec(version string) (name, ver string, ok bool) {
	spec, ok := strings.CutPrefix(version, "npm:")
	if !ok {
		return "", "", false
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:], true
	}
	return spec, "", true
}

// catalogDependencies walks the v1 "dependencies" tree, recursing into each
// entry's own nested "dependencies" so transitive packages are not missed -
// reading only the top level would silently return the direct dependencies
// alone. Keys are sorted at every level for the same determinism reason as
// catalogPackages.
func catalogDependencies(entries map[string]depEntry, path string, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	catalogDependenciesUnder("", entries, path, pkgs, stats)
}

// catalogDependenciesUnder is catalogDependencies with the install directory
// the tree so far resolves to ("" at the top, "node_modules/a" for a's own
// nested dependencies), so an alias's recorded location is its real path.
func catalogDependenciesUnder(dir string, entries map[string]depEntry, path string, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	for _, key := range sortedKeys(entries) {
		e := entries[key]
		stats.Components++

		// An alias in the v1 shape: the key is the install name and the
		// version field carries "npm:<name>@<version>" (see aliasSpec). The
		// registry identity is cataloged, the install name kept as the
		// location, matching catalogPackages' reading of the v3 "name" field.
		name, version := key, e.Version
		loc := pkgmeta.Location{Path: path}
		install := dir + "node_modules/" + key
		if n, v, ok := aliasSpec(e.Version); ok {
			name, version = n, v
			loc.Install = install
		}

		if name == "" || version == "" {
			stats.SkippedNoVersion++
		} else {
			*pkgs = append(*pkgs, pkgmeta.Package{
				Name:      name,
				Version:   version,
				Type:      "npm",
				Ecosystem: "npm",
				PURL:      "pkg:npm/" + name + "@" + version,
				Locations: []pkgmeta.Location{loc},
			})
			stats.Cataloged++
		}

		if len(e.Dependencies) > 0 {
			catalogDependenciesUnder(install+"/", e.Dependencies, path, pkgs, stats)
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
