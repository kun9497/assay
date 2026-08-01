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

// Parse reads path as a Go executable and returns its module inventory: the
// main module plus every dependency the linker actually kept. Distro stays
// nil — a binary is not a distro (D7).
func Parse(path string) (pkgmeta.Target, cyclonedx.Stats, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		// path is interpolated directly rather than left to ride along on
		// err alone: buildinfo.ReadFile's own message happens to name it
		// today, but that is the standard library's wording to change, not
		// a contract this cataloger can depend on. "not a Go binary" / "a
		// directory" / "does not exist" all need to say which file, because
		// the user's next step differs for each.
		return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("read build info from %s: %w", path, err)
	}

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	add := func(name, version string) {
		stats.Components++
		if version == "" || version == "(devel)" {
			// "(devel)" is what an un-stamped main module reports. It is not
			// a version any advisory range can be compared against, so it is
			// a counted skip rather than a package with a version that looks
			// real.
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
