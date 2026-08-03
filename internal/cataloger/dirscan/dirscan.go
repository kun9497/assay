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
// (requirements.txt, D26), because reading it failed, or because it is a
// Kind this dispatch has no parser for at all. Reason distinguishes these:
// "we did not look", "we looked and could not read it", and "we do not know
// how to read this yet" are different facts, and a reader needs to know
// which one happened before they can act on it.
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
		pkgs, s, u := parseManifest(root, m)
		if u != nil {
			unread = append(unread, *u)
			continue
		}
		target.Packages = append(target.Packages, pkgs...)
		addStats(&stats, s)
	}

	sortPackages(target.Packages)
	return target, stats, unread, nil
}

// parseManifest dispatches one manifest to the cataloger for its Kind. It
// returns either the packages that manifest produced (with stats non-zero
// only on success), or a non-nil unread explaining why it was not cataloged
// - never both. u == nil is what signals "cataloged", not len(pkgs) == 0:
// a manifest can legitimately produce zero packages (an empty lockfile)
// without being unread.
//
// The default case exists because Kind and this switch are two separate
// declarations that nothing forces to stay in lockstep: walk.go's Kind enum
// can grow a value this switch has no case for (a new manifest type Task 1
// learns to recognize before this dispatch learns to read it, or simply a
// typo in a future edit). Without a default, that manifest would vanish
// silently - no packages, no Unread, no error - which is exactly the class
// of silent false negative this whole slice exists to remove, reproduced
// inside the slice's own dispatch code. Recording it as Unread instead keeps
// it visible in the disclosure a reader actually sees.
func parseManifest(root string, m Manifest) ([]pkgmeta.Package, cyclonedx.Stats, *Unread) {
	full := filepath.Join(root, filepath.FromSlash(m.Path))

	switch m.Kind {
	case KindGoMod:
		// gomod.Parse takes the directory holding go.mod, not the
		// manifest's own path, unlike the other two catalogers below -
		// the asymmetry the brief calls out. full is the manifest file
		// itself, so its parent directory is what gomod.Parse wants.
		t, s, perr := gomod.Parse(filepath.Dir(full))
		if perr != nil {
			return nil, cyclonedx.Stats{}, &Unread{Path: m.Path, Reason: perr.Error()}
		}
		relocate(t.Packages, m.Path)
		return t.Packages, s, nil

	case KindNPMLock:
		pkgs, s, perr := npmlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, &Unread{Path: m.Path, Reason: perr.Error()}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil

	case KindPoetryLock:
		pkgs, s, perr := poetrylock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, &Unread{Path: m.Path, Reason: perr.Error()}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil

	case KindRequirements:
		// Recognized by Walk so the disclosure can name it (D26), but
		// never read: see requirementsReason.
		return nil, cyclonedx.Stats{}, &Unread{Path: m.Path, Reason: requirementsReason}

	default:
		return nil, cyclonedx.Stats{}, &Unread{
			Path:   m.Path,
			Reason: fmt.Sprintf("recognized manifest kind %q has no parser", m.Kind),
		}
	}
}

// relocate overwrites every package's location with relPath, the manifest's
// path relative to the scanned root (forward-slashed, as Walk produces it).
// Each per-manifest cataloger stamps its own Location.Path with the absolute
// filesystem path it was invoked with (npmlock.Parse and poetrylock.Parse
// take that path directly; gomod.Parse joins its directory argument with
// "go.mod"). An absolute path is specific to the machine the scan ran on and
// would make two scans of the identical tree, rooted at two different
// directories, produce different output - the opposite of what
// TestParse_PackageOrderIsDeterministic requires. It would also leak the
// scanning machine's checkout directory into --output json, making two CI
// runs' evidence incomparable, where relPath (frontend/package-lock.json) is
// exactly what a reader of D10 evidence needs. relPath is what Walk already
// computed for exactly this reason, so reuse it as the location for every
// package the manifest produced rather than deriving a second, looser
// notion of "where this came from".
//
// This is lossless today because every one of the three catalogers this
// package calls stamps exactly one Location per package, all naming the
// manifest itself. It stops being lossless the moment that is no longer
// true: a future cataloger recording more than one Location per package, or
// a location more specific than the manifest that produced it (a workspace
// member's own sub-path, say), would have every one of those locations
// silently flattened to the single manifest path here. Revisit this
// function, not just its caller, before relying on Locations having more
// than one meaningful entry.
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

// sortPackages orders the merged inventory by lessPackage - ecosystem, then
// name, then version, then location path - so two scans of the same tree
// cannot differ, regardless of which order Walk's manifests were dispatched
// in or which per-manifest cataloger happened to run first. sort.Slice does
// not guarantee any particular order for two elements lessPackage considers
// equal (sort.SliceStable is the one that does), so a comparator that
// silently stopped consulting one of the four keys would not necessarily
// fail loud here - see lessPackage's own tests, which check each key
// directly rather than relying on sort.Slice's tie-breaking behaviour.
func sortPackages(pkgs []pkgmeta.Package) {
	sort.Slice(pkgs, func(i, j int) bool { return lessPackage(pkgs[i], pkgs[j]) })
}

// lessPackage is the total order sortPackages sorts by: ecosystem, then
// name, then version, then the first location path. Each key is compared
// only once the keys before it have tied, so the order is total rather than
// partial - two packages differing only in Locations still sort
// deterministically instead of falling back to whatever order sort.Slice's
// algorithm happens to leave them in.
func lessPackage(a, b pkgmeta.Package) bool {
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
}

// locationPath returns a package's first location path, or "" if it carries
// none, so lessPackage has a stable key even for a package with an empty
// Locations slice.
func locationPath(p pkgmeta.Package) string {
	if len(p.Locations) == 0 {
		return ""
	}
	return p.Locations[0].Path
}
