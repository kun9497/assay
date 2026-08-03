// Package dirscan turns a directory tree into the normalized package
// inventory by dispatching every manifest Walk finds to the cataloger for its
// Kind, then merging the results.
//
// This is the integration point that fixes the defect the walk alone cannot:
// without it, a repository holding both go.mod and package-lock.json is
// scanned as Go-only, because a directory Source hands its root to exactly
// one cataloger. Dispatching to all of them, and merging what comes back, is
// what makes `assay scan dir:.` see every ecosystem a repository actually
// carries.
package dirscan

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/gomod"
	"github.com/kun9497/assay/internal/cataloger/npmlock"
	"github.com/kun9497/assay/internal/cataloger/poetrylock"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Unread is a manifest that Walk recognized but Parse deliberately did not
// turn into packages — either because the file is not a lockfile at all
// (requirements.txt, D26) or because reading it failed. Reason distinguishes
// the two: "we did not look" and "we looked and could not read it" are
// different facts, and a reader needs to know which one happened before they
// can act on it.
type Unread struct {
	Path   string
	Reason string
}

// requirementsReason explains why requirements.txt is never parsed, so the
// reason a reader sees is specific rather than a bare "skipped". It is not a
// lockfile: pip's requirements format allows a version range (or no version
// at all) rather than a single resolved version, so there is no fixed
// version here for a comparer to place inside an advisory range - parsing it
// anyway would fabricate a precision the file does not carry.
const requirementsReason = "not a lockfile: versions may be ranges, not resolved versions"

// Parse walks root for recognized manifests and returns one merged
// inventory. Distro stays nil - a directory is not an operating system (D7).
//
// A manifest that fails to parse becomes an Unread entry rather than
// aborting the scan: one bad lockfile in a large repository should not cost
// the rest of the tree. A root with no recognized manifest at all is
// different - there is nothing here this scan understands, and that must
// read as an error, not as a clean scan of zero packages, matching what
// gomod.Parse already does for a directory with no go.mod.
func Parse(root string) (pkgmeta.Target, cyclonedx.Stats, []Unread, error) {
	manifests, err := Walk(root)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, nil, err
	}
	if len(manifests) == 0 {
		return pkgmeta.Target{}, cyclonedx.Stats{}, nil, fmt.Errorf("%s: no recognized manifest found", root)
	}

	var (
		target pkgmeta.Target
		stats  cyclonedx.Stats
		unread []Unread
	)

	for _, m := range manifests {
		full := filepath.Join(root, filepath.FromSlash(m.Path))

		switch m.Kind {
		case KindGoMod:
			// gomod.Parse takes the directory holding go.mod, not the
			// manifest's own path, unlike the other two catalogers below -
			// the asymmetry the brief calls out. full is the manifest file
			// itself, so its parent directory is what gomod.Parse wants.
			t, s, perr := gomod.Parse(filepath.Dir(full))
			if perr != nil {
				unread = append(unread, Unread{Path: m.Path, Reason: perr.Error()})
				continue
			}
			relocate(t.Packages, m.Path)
			target.Packages = append(target.Packages, t.Packages...)
			addStats(&stats, s)

		case KindNPMLock:
			pkgs, s, perr := npmlock.Parse(full)
			if perr != nil {
				unread = append(unread, Unread{Path: m.Path, Reason: perr.Error()})
				continue
			}
			relocate(pkgs, m.Path)
			target.Packages = append(target.Packages, pkgs...)
			addStats(&stats, s)

		case KindPoetryLock:
			pkgs, s, perr := poetrylock.Parse(full)
			if perr != nil {
				unread = append(unread, Unread{Path: m.Path, Reason: perr.Error()})
				continue
			}
			relocate(pkgs, m.Path)
			target.Packages = append(target.Packages, pkgs...)
			addStats(&stats, s)

		case KindRequirements:
			// Recognized by Walk so the disclosure can name it (D26), but
			// never read: see requirementsReason.
			unread = append(unread, Unread{Path: m.Path, Reason: requirementsReason})
		}
	}

	sortPackages(target.Packages)
	return target, stats, unread, nil
}

// relocate overwrites every package's location with relPath, the manifest's
// path relative to the scanned root (forward-slashed, as Walk produces it).
// Each per-manifest cataloger stamps its own Location.Path with the absolute
// filesystem path it was invoked with (npmlock.Parse and poetrylock.Parse
// take that path directly; gomod.Parse joins its directory argument with
// "go.mod"). An absolute path is specific to the machine the scan ran on and
// would make two scans of the identical tree, rooted at two different
// directories, produce different output - the opposite of what
// TestParse_PackageOrderIsDeterministic requires. relPath is what Walk
// already computed for exactly this reason, so reuse it as the location for
// every package the manifest produced rather than deriving a second, looser
// notion of "where this came from".
func relocate(pkgs []pkgmeta.Package, relPath string) {
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			pkgs[i].Locations[j].Path = relPath
		}
	}
}

// addStats folds one manifest's Stats into the running total. Every field is
// summed, never overwritten, which is what lets the Components == Cataloged
// + skips invariant survive the merge: if it holds for each manifest's own
// Stats, it holds for the sum (cyclonedx.go:16-25).
func addStats(total *cyclonedx.Stats, s cyclonedx.Stats) {
	total.Components += s.Components
	total.Cataloged += s.Cataloged
	total.SkippedNoPURL += s.SkippedNoPURL
	total.SkippedNoVersion += s.SkippedNoVersion
	total.SkippedUnsupportedEcosystem += s.SkippedUnsupportedEcosystem
}

// sortPackages orders the merged inventory by ecosystem, then name, then
// version, then location path - a total order so two scans of the same tree
// cannot differ, regardless of which order Walk's manifests were dispatched
// in or which per-manifest cataloger happened to run first.
func sortPackages(pkgs []pkgmeta.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return locationPath(a) < locationPath(b)
	})
}

// locationPath returns a package's first location path, or "" if it carries
// none, so sortPackages has a stable key even for a package with an empty
// Locations slice.
func locationPath(p pkgmeta.Package) string {
	if len(p.Locations) == 0 {
		return ""
	}
	return p.Locations[0].Path
}
