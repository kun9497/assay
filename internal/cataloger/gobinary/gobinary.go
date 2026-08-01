// Package gobinary turns a Go executable's embedded build info into the
// normalized package inventory. Unlike an SBOM, nobody hands us a manifest for
// a binary — the module list has to be read back out of the binary itself.
package gobinary

import (
	"debug/buildinfo"
	"fmt"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// isUnversioned reports whether version is not a real, comparable version:
// either empty, or "(devel)" - what an un-stamped main module reports. Split
// out as its own function so both halves can be tested directly against
// values debug/buildinfo has never been observed to produce from a fixture
// this package can build (an empty string in particular - every reachable
// build shape reports either "(devel)" or a real version, never ""), rather
// than leaving one arm of the check exercised only by luck.
func isUnversioned(version string) bool {
	return version == "" || version == "(devel)"
}

// Parse reads path as a Go executable and returns its module inventory: the
// main module plus every dependency the linker actually kept. Distro stays
// nil — a binary is not a distro (D7).
func Parse(path string) (pkgmeta.Target, cyclonedx.Stats, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		// No %s for path here: buildinfo.ReadFile's own message already
		// names it in every rejection shape this cataloger cares about (not
		// a Go binary, a directory, a missing file - verified directly
		// against each), so adding our own would only double it up ("read
		// build info from X: ...from X: ..."). TestParse_Rejects still
		// fails if a future standard library version ever stops mentioning
		// the path in its own error.
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("read Go build info: %w", err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	add := func(name, version string) {
		stats.Components++
		if isUnversioned(version) {
			// Not a version any advisory range can be compared against, so
			// it is a counted skip rather than a package with a version
			// that looks real.
			stats.SkippedNoVersion++
			return
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:      name,
			Version:   version,
			Type:      "golang",
			Ecosystem: "Go",
			PURL:      "pkg:golang/" + name + "@" + version,
			Locations: []pkgmeta.Location{{Path: path}},
		})
	}

	add(bi.Main.Path, bi.Main.Version)
	for _, d := range bi.Deps {
		// A replaced module is a different module: reporting the path that
		// was replaced away would look up advisories against code that is
		// not in this binary (false positive) while missing the advisories
		// for what IS in this binary (false negative, silent).
		if d.Replace != nil {
			d = d.Replace
		}
		add(d.Path, d.Version)
	}
	// stdlib is added in Task 3, together with the version normalization it
	// needs (D24).
	return pkgmeta.Target{Packages: pkgs}, stats, nil
}
