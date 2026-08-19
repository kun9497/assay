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
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cargolock"
	"github.com/kun9497/assay/internal/cataloger/composerlock"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/gemlock"
	"github.com/kun9497/assay/internal/cataloger/gomod"
	"github.com/kun9497/assay/internal/cataloger/jar"
	"github.com/kun9497/assay/internal/cataloger/npmlock"
	"github.com/kun9497/assay/internal/cataloger/nugetlock"
	"github.com/kun9497/assay/internal/cataloger/pipfilelock"
	"github.com/kun9497/assay/internal/cataloger/poetrylock"
	"github.com/kun9497/assay/internal/cataloger/requirements"
	"github.com/kun9497/assay/internal/cataloger/uvlock"
	"github.com/kun9497/assay/internal/cataloger/yarnlock"
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
	// Failed separates "we looked and could not read it" from "we did not
	// look". Only the first is a statement about coverage the scan cannot
	// stand behind: requirements.txt being unread is a documented, deliberate
	// limit, while a lockfile that would not parse means there could be
	// findings in this tree that this run did not see.
	//
	// The exit code needs the distinction. Without it an unreadable manifest
	// reached no gate at all - a directory whose only lockfile was truncated
	// printed "not read: ..." and then exited 0, which is a regression from
	// the behaviour before this cataloger existed, where gomod.Parse's error
	// returned 2.
	Failed bool
}

// requirementsReason explains why requirements.txt is never parsed, so the
// reason a reader sees is specific rather than a bare "skipped". It is not a
// lockfile: pip's requirements format allows a version range (or no version
// at all) rather than a single resolved version, so there is no fixed
// version here for a comparer to place inside an advisory range - parsing it
// anyway would fabricate a precision the file does not carry.
const requirementsReason = "not a lockfile: versions may be ranges, not resolved versions"

// Read is a manifest Parse did turn into packages, and how many components it
// yielded on its own.
//
// The per-manifest count exists because the merged Stats cannot answer a
// question the report has to answer: D23's caveat is about go.mod
// specifically - it names what the module REQUIRES, not what a build links -
// and stating it with the merged total would attribute every lockfile's
// packages to go.mod. A caveat carrying the wrong number is worse than none,
// because it reads as precise.
type Read struct {
	Path       string
	Kind       Kind
	Components int
}

// Manifests is what a scan read and what it did not. The two travel together
// because a reader needs both to know how much of the tree was covered:
// either half alone is a partial answer that looks complete.
type Manifests struct {
	Read   []Read
	Unread []Unread
	// Unusable is every requirement line a manifest WAS read but could not
	// use (D38). It is a third state and not a variant of Unread: the file
	// parsed, some of it became packages, and these lines did not. Folding it
	// into Unread would say the file went unread, which is the opposite of
	// what happened and would hide the packages it did yield.
	Unusable []Unusable
}

// Unusable names one requirement line a parser refused, and where it was. The
// path travels with the line because a directory scan reads several manifests
// and "Django>=3.2" on its own does not say which file to go and pin.
type Unusable struct {
	Path   string
	Line   string
	Reason string
}

// AnyFailed reports whether any manifest was found and could not be read.
// requirements.txt does not count: not reading it is a decision, not a
// failure, and the two must not reach the exit code as the same thing.
func (m Manifests) AnyFailed() bool {
	for _, u := range m.Unread {
		if u.Failed {
			return true
		}
	}
	return false
}

// GoMod returns the go.mod entry and whether one was read at all. The caller
// is the D23 disclosure, which must not claim anything about a go.mod in a
// directory that has none.
func (m Manifests) GoMod() (Read, bool) {
	for _, r := range m.Read {
		if r.Kind == KindGoMod {
			return r, true
		}
	}
	return Read{}, false
}

// Parse walks root for recognized manifests and returns one merged
// inventory. Distro stays nil - a directory is not an operating system (D7).
//
// A manifest that fails to parse becomes an Unread entry rather than
// aborting the scan: one bad lockfile in a large repository should not cost
// the rest of the tree. A root with no recognized manifest at all is
// different - there is nothing here this scan understands, and that must
// read as an error, not as a clean scan of zero packages, matching what
// gomod.Parse already does for a directory with no go.mod.
func Parse(root string) (pkgmeta.Target, cyclonedx.Stats, Manifests, error) {
	manifests, err := Walk(root)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, Manifests{}, err
	}
	if len(manifests) == 0 {
		return pkgmeta.Target{}, cyclonedx.Stats{}, Manifests{},
			fmt.Errorf("%s: no recognized manifest found", root)
	}

	var (
		target pkgmeta.Target
		stats  cyclonedx.Stats
		found  Manifests
	)

	for _, m := range manifests {
		pkgs, s, un, u := parseManifest(root, m)
		if u != nil {
			found.Unread = append(found.Unread, *u)
			continue
		}
		found.Unusable = append(found.Unusable, un...)
		found.Read = append(found.Read, Read{Path: m.Path, Kind: m.Kind, Components: s.Components})
		target.Packages = append(target.Packages, pkgs...)
		addStats(&stats, s)
	}

	sortPackages(target.Packages)
	return target, stats, found, nil
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
func parseManifest(root string, m Manifest) ([]pkgmeta.Package, cyclonedx.Stats, []Unusable, *Unread) {
	full := filepath.Join(root, filepath.FromSlash(m.Path))
	var unusable []Unusable

	switch m.Kind {
	case KindGoMod:
		// gomod.Parse takes the directory holding go.mod, not the
		// manifest's own path, unlike the other two catalogers below -
		// the asymmetry the brief calls out. full is the manifest file
		// itself, so its parent directory is what gomod.Parse wants.
		t, s, perr := gomod.Parse(filepath.Dir(full))
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(t.Packages, m.Path)
		return t.Packages, s, nil, nil

	case KindNPMLock, KindNPMShrinkwrap:
		// One arm for both: npm-shrinkwrap.json is package-lock.json's schema
		// under another filename, so a second case calling the same parser
		// would be two places to keep in step for no gain.
		pkgs, s, perr := npmlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindPoetryLock:
		pkgs, s, perr := poetrylock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindRequirements:
		// D38: read, but only the lines that name exactly one version. The
		// rest are counted and named rather than guessed at — see the
		// requirements package for why a fabricated version is worse than a
		// refusal in both directions.
		t, s, un, perr := requirements.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(t.Packages, m.Path)
		for _, u := range un {
			unusable = append(unusable, Unusable{Path: m.Path, Line: u.Line, Reason: u.Reason})
		}
		return t.Packages, s, unusable, nil

	case KindYarnLock:
		pkgs, s, perr := yarnlock.Parse(full)
		if perr != nil {
			// A berry lockfile is not a read failure in the usual sense -
			// nothing is corrupt - but it reaches the exit code the same way
			// on purpose. The file resolves every dependency in the tree and
			// this scan read none of them, so the result cannot be stood
			// behind whatever the reason.
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindCargoLock:
		pkgs, s, perr := cargolock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindPipfileLock:
		pkgs, s, perr := pipfilelock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindUVLock:
		pkgs, s, perr := uvlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindGemfileLock:
		pkgs, s, perr := gemlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindComposerLock:
		pkgs, s, perr := composerlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindNuGetLock:
		pkgs, s, perr := nugetlock.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		relocate(pkgs, m.Path)
		return pkgs, s, nil, nil

	case KindJarArchive:
		pkgs, s, perr := jar.Parse(full)
		if perr != nil {
			return nil, cyclonedx.Stats{}, nil, &Unread{Path: m.Path, Reason: perr.Error(), Failed: true}
		}
		// Not relocate(): jar.Parse can stamp a Location with more than the
		// manifest path alone — a nested entry's composite
		// "<jar path>!<inner path>" (jar.go's own doc comment on
		// jarLocationSeparator) — and relocate() would flatten that suffix
		// away entirely, exactly the loss its own doc comment warns a future
		// caller about. relocateJar rewrites only the absolute prefix
		// jar.Parse stamped, to this manifest's repo-relative path, and
		// keeps whatever "!nested/entry" suffix follows it.
		relocateJar(pkgs, full, m.Path)
		return pkgs, s, nil, nil

	case KindPnpmLock:
		// Recognized, and deliberately unread: neither YAML nor TOML is in
		// the standard library, and taking a parser for either is a
		// dependency decision this slice does not make (walk.go's Kind
		// comment records the reasoning).
		//
		// Failed is true, and that is the substance of this arm rather than
		// an implementation detail. requirements.txt goes unread because the
		// FILE cannot answer the question - it carries ranges, not resolved
		// versions - and no tool could do better. These files answer it
		// perfectly and assay cannot read them, so a scan whose only manifest
		// is one of them has looked at none of the tree's dependencies. That
		// is an untrustworthy result, not a clean one, and D11 puts 2 above
		// both 1 and 0 for exactly this case.
		return nil, cyclonedx.Stats{}, nil, &Unread{
			Path: m.Path,
			// The reason does not repeat the filename: every renderer of
			// Unread already prints Path in front of it, and "not read:
			// pnpm-lock.yaml (pnpm-lock.yaml: ...)" is the doubling that
			// produces.
			Reason: fmt.Sprintf("no parser for this format (it needs a %s reader, which assay does not have)", markupOf(m.Kind)),
			Failed: true,
		}

	default:
		return nil, cyclonedx.Stats{}, nil, &Unread{
			Path: m.Path,
			// Failed, because this arm means Kind grew a value the dispatch
			// was never taught: the manifest was found, nothing read it, and
			// the run cannot tell whether it held findings. A silent 0 here
			// would be the same defect one level up from the one this whole
			// cataloger exists to remove.
			Reason: fmt.Sprintf("recognized manifest kind %q has no parser", m.Kind),
			Failed: true,
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

// relocateJar is relocate's counterpart for KindJarArchive: it performs the
// same absolute-to-repo-relative rewrite, but as a PREFIX replacement rather
// than a full overwrite, so a nested entry's "!inner/path" suffix (jar.Parse
// stamped it onto Location.Path, composed with full, the absolute path
// jar.Parse was called with) survives the rewrite instead of being discarded.
// A package with no such suffix — every top-level component in the jar
// itself — ends up identical to what relocate would have produced.
func relocateJar(pkgs []pkgmeta.Package, full, relPath string) {
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			if rest, ok := strings.CutPrefix(pkgs[i].Locations[j].Path, full); ok {
				pkgs[i].Locations[j].Path = relPath + rest
				continue
			}
			// Defensive fallback: jar.Parse's own Location construction
			// always starts with the path it was called with (full), so this
			// arm is not expected to be reached — but falling back to the
			// same behaviour relocate() has, rather than leaving an absolute
			// path in the output, is the safer failure mode if that ever
			// stops being true.
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

// markupOf names the file format a Kind is written in, for the reason string
// an unread manifest carries. It exists so the message says what would be
// needed to read the file rather than only that it was not read: "needs a YAML
// reader" is actionable, "no parser" is not.
func markupOf(k Kind) string {
	switch k {
	case KindPnpmLock:
		return "YAML"
	}
	// Unreachable from the one arm that calls this, and returning a wrong
	// concrete name would be worse than admitting the gap if that changes.
	return "format"
}
