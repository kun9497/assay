// Package pipfilelock turns a Pipfile.lock file into the normalized package
// inventory the matcher consumes.
//
// Pipfile.lock is JSON and pins every resolved dependency with "==", so unlike
// requirements.txt (D26) there is nothing to guess at: a version here is a
// single resolved version, which is exactly what a comparer needs.
package pipfilelock

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// lockDoc is the part of Pipfile.lock this parser reads. "_meta" carries the
// hash of the Pipfile it was resolved from and names no packages, so it is
// not declared at all.
type lockDoc struct {
	Default map[string]entry `json:"default"`
	Develop map[string]entry `json:"develop"`
}

// entry is one resolved dependency. Version is absent for dependencies pinned
// to a VCS ref or a local path, which pipenv records as "git"/"ref" or "path"
// instead - those name no released version a comparer can place inside an
// advisory range.
type entry struct {
	Version string `json:"version"`
}

// Parse reads the Pipfile.lock at path and returns the packages it resolves.
// path is what every returned Package's single Location names and what any
// returned error names, the same as the other per-file catalogers.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already carries the full path.
		return nil, cyclonedx.Stats{}, err
	}

	var doc lockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		// encoding/json's error carries no file identity, so the real path is
		// added here - not a hard-coded "Pipfile.lock", which would satisfy a
		// naive substring check while dropping which file failed.
		return nil, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		// seen dedupes across the two sections. A package listed in both
		// default and develop is one component, not two, and emitting it
		// twice would double it in every finding the matcher produces.
		seen = map[string]bool{}
	)

	// default before develop, each in sorted key order, so the returned slice
	// does not vary between runs of the same file - a map range here would
	// reach the report.
	for _, section := range []map[string]entry{doc.Default, doc.Develop} {
		for _, name := range sortedKeys(section) {
			e := section[name]

			version, ok := pinnedVersion(e.Version)
			if !ok {
				// Counted and skipped rather than dropped: a VCS-pinned or
				// path dependency IS a dependency, and one silently discarded
				// here is indistinguishable from one that never existed.
				stats.Components++
				stats.SkippedNoVersion++
				continue
			}

			key := name + "@" + version
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
				Name:    name,
				Version: version,
				Type:    "pypi",
				// Plain concatenation, as in poetrylock: PEP 503
				// normalization happens once, at match time
				// (pkgmeta.NormalizeName), not duplicated here.
				Ecosystem: "PyPI",
				PURL:      "pkg:pypi/" + name + "@" + version,
				Locations: []pkgmeta.Location{{Path: path}},
			})
		}
	}

	return pkgs, stats, nil
}

// pinnedVersion turns a Pipfile.lock version string into the bare version it
// pins, and reports whether it pins exactly one.
//
// pipenv writes "==3.2.19". Anything else - an empty string from a VCS entry,
// or a range that a hand-edited file might carry - names more than one version
// or none, and D26's argument against requirements.txt applies unchanged:
// choosing a version the file did not resolve fabricates precision, and doing
// so is wrong in both directions (a false positive against a version nobody
// installed, or a false negative that clears one they did).
func pinnedVersion(raw string) (string, bool) {
	const pin = "=="
	if !strings.HasPrefix(raw, pin) {
		return "", false
	}
	v := strings.TrimSpace(raw[len(pin):])
	if v == "" {
		return "", false
	}
	// A second operator or a comma means the string is a range expression
	// ("==3.2,!=3.2.1"), not a pin, however it came to be in the file.
	if strings.ContainsAny(v, ",<>=!~ ") {
		return "", false
	}
	return v, true
}

func sortedKeys(m map[string]entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
