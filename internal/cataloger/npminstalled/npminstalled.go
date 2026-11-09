// Package npminstalled reads the npm packages INSTALLED in a container image
// -- node_modules/<pkg>/package.json files under the image's global
// node_modules roots -- into the normalized inventory (D160, the first
// fixed-location probe for application packages inside an image).
//
// It is not a lockfile reader. A lockfile declares what a project depends
// on; an installed tree is what is actually on disk, nested copies and all,
// and an image has no lockfile to prefer (dirscan prunes node_modules for
// the opposite reason, D26: a checkout's installed tree is not its declared
// dependencies). Measured 2026-11-09 on the 26 scanner-diff targets: every
// installed package.json on every image sits under one of Roots -- 236 on
// ubi8/nodejs-18, npm's own bundled tree -- and none anywhere else.
package npminstalled

import (
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Roots are the node_modules directories the image probe reads, fixed in
// code like D112's limits: a configurable root would be a number nobody
// could reason about in a bug report. The three are where a global npm
// install lands on the measured images (usr/lib for RPM- and deb-packaged
// node, usr/local/lib for an upstream node tarball, opt/app-root/src for
// Red Hat's s2i layout). A tree anywhere else is disclosed as not read.
var Roots = []string{"usr/lib/node_modules", "usr/local/lib/node_modules", "opt/app-root/src/node_modules"}

// IsInstalledPackageJSON reports whether p (an image path, no leading slash)
// is the package.json of an INSTALLED package: node_modules/<pkg>/package.json
// or node_modules/@<scope>/<pkg>/package.json, at any depth. A package's own
// nested files (esm/package.json saying {"type":"module"}, a test fixture, a
// template) are not packages, and syft draws the line in the same place.
func IsInstalledPackageJSON(p string) bool {
	if path.Base(p) != "package.json" {
		return false
	}
	pkgDir := path.Dir(p)
	if strings.HasPrefix(path.Base(pkgDir), "@") {
		// node_modules/@types is a scope directory holding packages, not a
		// package; a package.json directly in it is nobody's.
		return false
	}
	parent := path.Dir(pkgDir)
	if path.Base(parent) == "node_modules" {
		return true
	}
	return strings.HasPrefix(path.Base(parent), "@") && path.Base(path.Dir(parent)) == "node_modules"
}

// Catalog turns the installed package.json files in files (path -> bytes, as
// the image probe collected them) into packages, in path order so two runs
// over one image are byte-identical. A path that is not an installed
// package.json is not a component and is ignored; an installed one that
// cannot be read, or names no name or no version, is a counted skip (D36's
// SkippedNoVersion: a component whose version is unknown), never a package
// with an empty field.
//
// Nested trees are packages in their own right -- node_modules/npm/node_modules/
// minimatch is minimatch at that version, located at that path -- and two
// copies of one name at two versions are two packages, each carrying its own
// location, so a reader sees which copy a finding is about.
func Catalog(files map[string][]byte) ([]pkgmeta.Package, cyclonedx.Stats) {
	paths := make([]string, 0, len(files))
	for p := range files {
		if IsInstalledPackageJSON(p) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	for _, p := range paths {
		stats.Components++
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(files[p], &pj); err != nil {
			stats.SkippedNoVersion++
			continue
		}
		switch {
		case pj.Name == "":
			stats.SkippedNoVersion++
			continue
		case pj.Version == "":
			stats.SkippedNoVersion++
			continue
		}
		stats.Cataloged++
		pkgs = append(pkgs, pkgmeta.Package{
			Name:      pj.Name,
			Version:   pj.Version,
			Type:      "npm",
			Ecosystem: "npm",
			// The lockfile cataloger's spelling, so a VEX statement written
			// against either reaches the package (D121).
			PURL:      "pkg:npm/" + pj.Name + "@" + pj.Version,
			Locations: []pkgmeta.Location{{Path: p}},
		})
	}
	return pkgs, stats
}
