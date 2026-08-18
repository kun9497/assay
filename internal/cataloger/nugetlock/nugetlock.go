// Package nugetlock turns a packages.lock.json file into the normalized
// package inventory the matcher consumes.
//
// packages.lock.json is NuGet's opt-in lockfile, and it nests every resolved
// dependency under its own target framework moniker - a multi-target project
// can resolve the same package to a different version per framework - so
// this walks every framework rather than just the first, and dedupes what it
// finds across them.
package nugetlock

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// lockDoc is the part of packages.lock.json this parser reads. "version" is
// the lockfile schema version, not a package's, and is not declared here.
type lockDoc struct {
	Dependencies map[string]map[string]entry `json:"dependencies"`
}

// entry is one resolved dependency under one framework. Resolved is absent
// for a "type": "Project" entry - a reference to another project in the same
// solution, not a package with a released version a comparer can place
// inside an advisory range.
type entry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// Parse reads the packages.lock.json at path and returns the packages it
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
		// added here - not a hard-coded "packages.lock.json", which would
		// satisfy a naive substring check while dropping which file failed.
		return nil, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		// seenPkg dedupes a resolved package across frameworks on (name,
		// resolved): net6.0 and net7.0 routinely resolve the same package to
		// the same version, and counting each framework's copy would
		// inflate every finding the matcher produces off it.
		seenPkg = map[string]bool{}
		// seenProject dedupes a "type": "Project" reference by name alone -
		// it carries no resolved version to key on, and the same project
		// reference reappears under every framework a multi-target project
		// targets, but must still be counted (and skipped) exactly once,
		// not once per framework.
		seenProject = map[string]bool{}
	)

	// Frameworks in sorted order, then each framework's package names in
	// sorted order, so the returned slice does not vary between runs of the
	// same file - a map range here would reach the report.
	for _, framework := range sortedFrameworks(doc.Dependencies) {
		for _, name := range sortedNames(doc.Dependencies[framework]) {
			e := doc.Dependencies[framework][name]

			if e.Resolved == "" {
				// A "Project" reference (or any other entry NuGet writes
				// with no resolved version) names no released package.
				// Counted, not dropped: a component silently discarded here
				// is indistinguishable from one that never existed.
				if seenProject[name] {
					continue
				}
				seenProject[name] = true
				stats.Components++
				stats.SkippedNoVersion++
				continue
			}

			key := name + "@" + e.Resolved
			if seenPkg[key] {
				// Not counted again either: it is the same component
				// resolved identically under another framework, so
				// incrementing Components here would break the
				// Components == Cataloged + skips invariant by counting one
				// component twice against a single Cataloged.
				continue
			}
			seenPkg[key] = true

			stats.Components++
			stats.Cataloged++
			pkgs = append(pkgs, pkgmeta.Package{
				// Kept exactly as NuGet wrote it. pkgmeta.NormalizeName
				// lowercases at match time; duplicating that rule here is
				// how it drifts out of sync with the one definition the
				// store and matcher both use (the same reasoning
				// poetrylock's PURL comment gives for PEP 503
				// normalization).
				Name:      name,
				Version:   e.Resolved,
				Type:      "nuget",
				Ecosystem: "NuGet",
				PURL:      "pkg:nuget/" + name + "@" + e.Resolved,
				Locations: []pkgmeta.Location{{Path: path}},
			})
		}
	}

	return pkgs, stats, nil
}

func sortedFrameworks(m map[string]map[string]entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedNames(m map[string]entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
