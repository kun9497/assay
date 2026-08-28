// Package dirscan finds manifest files under a directory root, bounded so
// that a scan cannot be made arbitrarily slow or misled by files that are not
// this project's own. It does not read or parse any manifest - that is each
// per-ecosystem cataloger's job - it only locates them.
package dirscan

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Kind identifies which recognized manifest a Manifest is.
type Kind string

const (
	KindGoMod      Kind = "go.mod"
	KindNPMLock    Kind = "package-lock.json"
	KindPoetryLock Kind = "poetry.lock"
	// KindRequirements is recognized so the disclosure in a later task can
	// name it, but requirements.txt is never read (D26): it has no lockfile
	// semantics - no resolved versions, no way to tell a direct dependency
	// from a transitive one - so parsing it would fabricate precision the
	// file does not carry.
	KindRequirements Kind = "requirements.txt"

	// KindNPMShrinkwrap is package-lock.json's schema under another name: npm
	// writes it when a project wants its lockfile published with the package.
	// It routes to the same parser.
	KindNPMShrinkwrap Kind = "npm-shrinkwrap.json"
	KindPipfileLock   Kind = "Pipfile.lock"
	KindYarnLock      Kind = "yarn.lock"
	KindCargoLock     Kind = "Cargo.lock"

	// KindPnpmLock is read since D103 (dirscan.go's dispatch calls
	// pnpmlock.Parse) - gopkg.in/yaml.v3 became a direct dependency for the
	// D102 ignore file, which removed the reason it was ever left unread.
	//
	// KindUVLock stays recognized and NOT read: uv.lock is TOML, and the
	// standard library parses none, so reading it would need a fourth direct
	// dependency, which is a decision rather than a detail (see the
	// conventions section of CLAUDE.md). It is named anyway, and that is the
	// whole point of keeping this entry at all: before KindPnpmLock had a
	// parser, a repository whose only lockfile was pnpm-lock.yaml scanned to
	// completion, found nothing, and exited 0 - nothing in the report said a
	// lockfile had been passed over. "Found nothing" and "did not look" are
	// the two facts this project exists to keep apart, and uv.lock is the
	// shape that still needs it.
	KindPnpmLock Kind = "pnpm-lock.yaml"
	KindUVLock   Kind = "uv.lock"

	// KindGemfileLock is bundler's lockfile. Capitalized as bundler writes
	// it, the same as Pipfile.lock - matching is by exact equality, so a
	// lowercase "gemfile.lock" is not recognized.
	KindGemfileLock  Kind = "Gemfile.lock"
	KindComposerLock Kind = "composer.lock"
	// KindNuGetLock is packages.lock.json, NuGet's opt-in lockfile - opt-in
	// because unlike the other ecosystems here, a bare NuGet project has no
	// lockfile at all until "RestorePackagesWithLockFile" is turned on.
	KindNuGetLock Kind = "packages.lock.json"

	// KindJarArchive is a Java archive (.jar or .war), D70 — Maven's path
	// into a directory scan, since unlike the lockfile ecosystems above a
	// checked-out Maven project has no lockfile at all (D69's own note on
	// why it has no entry there). One Kind for both extensions: a .war is a
	// jar with a servlet-container layout, not a different archive format,
	// and jar.Parse reads either the same way.
	KindJarArchive Kind = "jar-archive"
)

// Manifest is one recognized file found by the walk.
type Manifest struct {
	Path string // relative to the scanned root, always forward-slashed
	Kind Kind
}

// excludedDirs are never descended into. A lockfile inside a dependency tree
// describes that dependency's own requirements, not this project's -
// node_modules alone can hold tens of thousands of them - and .git holds no
// manifests at all, only history.
var excludedDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
}

// manifestKinds maps a recognized filename to its Kind. Matching is by exact
// equality only: "package-lock.json.bak" and "my-go.mod" are not manifests,
// and a prefix/suffix match would wrongly claim they are.
var manifestKinds = map[string]Kind{
	"go.mod":              KindGoMod,
	"package-lock.json":   KindNPMLock,
	"poetry.lock":         KindPoetryLock,
	"requirements.txt":    KindRequirements,
	"npm-shrinkwrap.json": KindNPMShrinkwrap,
	// Capitalized as pipenv writes it. Matching is by exact equality, so a
	// lowercase "pipfile.lock" is not recognized - on a case-insensitive
	// filesystem the walk sees whatever name the directory entry actually
	// carries, and inventing a case-folding rule here would diverge from
	// every other name in this map.
	"Pipfile.lock":   KindPipfileLock,
	"yarn.lock":      KindYarnLock,
	"Cargo.lock":     KindCargoLock,
	"pnpm-lock.yaml": KindPnpmLock,
	"uv.lock":        KindUVLock,

	"Gemfile.lock":       KindGemfileLock,
	"composer.lock":      KindComposerLock,
	"packages.lock.json": KindNuGetLock,
}

// maxDepth is how many directory levels below root are descended into. A
// manifest exactly at the limit is included; one level past it is not. The
// cap exists so a deeply (or maliciously) nested tree cannot make a scan
// arbitrarily slow.
const maxDepth = 6

// Walk returns every recognized manifest under root, sorted by Path.
//
// A per-entry error - an unreadable subdirectory, most often - is swallowed
// so that one bad subtree does not abandon the rest of an otherwise-readable
// scan; only a failure reading root itself is returned, since at that point
// there is nothing to report at all.
func Walk(root string) ([]Manifest, error) {
	var manifests []Manifest

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			// An entry below root could not even be stat'd (a permission
			// error surfacing here rather than on a later ReadDir, on some
			// platforms). Skip just this entry rather than aborting the walk
			// - the rest of the tree may still be readable and worth
			// reporting.
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}

		if d.IsDir() {
			if path == root {
				return nil
			}
			if excludedDirs[d.Name()] {
				return fs.SkipDir
			}
			// A directory at exactly maxDepth separators below root is one
			// level below the deepest directory allowed to contribute a
			// manifest (see the file case below), so descending into it
			// would only ever surface files past the cap. Pruning here -
			// rather than relying only on the file-side check - is what
			// keeps a maliciously deep tree from being walked at all.
			if depth(rel) >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}

		kind, ok := manifestKinds[d.Name()]
		if !ok && isJarOrWar(d.Name()) {
			// The one Kind in this package matched by suffix rather than
			// exact name: unlike a lockfile, a jar's filename is chosen by
			// whoever built it (mylib-1.2.3.jar, app.war), not fixed by the
			// tool that produced it, so there is no single exact string to
			// put in manifestKinds.
			kind, ok = KindJarArchive, true
		}
		if !ok {
			return nil
		}
		// depth(rel) for a file equals how many directory levels below root
		// its containing directory sits (the file's own path segment does
		// not count as a level). A manifest exactly at the cap is included;
		// one level past it is not.
		if depth(rel) > maxDepth {
			return nil
		}
		manifests = append(manifests, Manifest{Path: filepath.ToSlash(rel), Kind: kind})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Path < manifests[j].Path })
	return manifests, nil
}

// isJarOrWar reports whether name ends in .jar or .war, case-insensitively —
// a build tool can write "app.WAR" on a case-preserving filesystem, and a
// checked-out repository's filenames are not under this project's control.
func isJarOrWar(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")
}

// depth counts filepath.Separator occurrences in rel (root-relative,
// OS-separated). An entry directly in root has depth 0; each additional
// path segment before it adds one - so depth is exactly the number of
// directory levels below root that rel's containing directory sits at.
func depth(rel string) int {
	n := 0
	for _, r := range rel {
		if r == filepath.Separator {
			n++
		}
	}
	return n
}
