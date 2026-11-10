package scancmd

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/gobinary"
	"github.com/kun9497/assay/internal/cataloger/npminstalled"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
)

// D160: the two fixed-location probes for application packages inside an
// image. An image scan inventories the OS and Bitnami's markers (D70, D99);
// the 2026-11-09 measurement of all 26 scanner-diff targets put every
// grype-only application tuple in exactly two places -- the global npm tree
// under usr/lib/node_modules and Go binaries directly in the standard bin
// directories -- and nothing in a lockfile, a jar or a Python dist-info. So
// the probes read those two places and nothing else, under D112's existing
// budget, and the scope record says per ecosystem what was probed, where, and
// what is still not read.

// goBinDirs are the directories the Go-binary probe reads, direct children
// only, fixed like npminstalled.Roots. The measured binaries (bci156's
// container-suseconnect, cleanstart's gosu, archlinux's captree) all sit in
// usr/bin; the other six are where a distro or an image author puts an
// executable they mean to be on PATH. A Go binary anywhere else -- /opt,
// /app, a language runtime's own tree -- is disclosed as not read.
var goBinDirs = []string{"usr/bin", "usr/local/bin", "bin", "sbin", "usr/sbin", "usr/libexec", "usr/local/sbin"}

// applicationEcosystemsNotRead are the application ecosystems the image path
// knows exist inside images and does not read, named so the disclosure can
// list them rather than say "others". Python's dist-info files on the
// measured images are all OS-package-owned (reading them without the package
// manager's file ownership would report every RPM-installed module twice),
// and 0 grype-only java or python tuples were measured; each is the next
// probe the day its D117 ceiling trips.
var applicationEcosystemsNotRead = []string{"PyPI", "Maven"}

// isELF is the sniff the Go probe hands ExecutablesIn: the four-byte ELF
// magic. A non-ELF executable in a bin directory (a shell script, a Python
// entry point) costs four bytes and is never read.
func isELF(head []byte) bool {
	return len(head) == 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
}

// catalogApplicationProbes runs both probes over img and returns their
// packages (each located at its image path with the layer it came from),
// their counts and the per-ecosystem scope records, in a stable order.
//
// Not finding anything is not an error, for catalogBitnami's reason: most
// images have no global npm tree and no Go binary in /usr/bin, and the probe
// says so with ScopeNone. An installed package.json with no version is
// counted in SkippedNoVersion (D36): a component whose version is unknown,
// not one silently dropped.
//
// owned is the file ownership the OS database already yielded (rpm, apk);
// osPkgs the OS inventory, for the dpkg and pacman lists this pass reads
// (D162). Both may be nil: the probes then locate without an owner.
func catalogApplicationProbes(ctx context.Context, img *source.Image, owned *fileOwners, osPkgs []pkgmeta.Package) ([]pkgmeta.Package, cyclonedx.Stats, []report.ApplicationScopeRecord, error) {
	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		scope []report.ApplicationScopeRecord
	)

	// ONE pass over the layers for both probes (D123 makes every pass a full
	// read of every layer): package.json at any depth under the npm roots,
	// and executables directly in the bin directories whose first bytes are
	// ELF. A package.json is accepted at the sniff unread; a non-ELF
	// executable is declined there and costs four bytes. D162 adds the two
	// ownership roots to the same pass: dpkg's `.list` files and pacman's
	// `files`, accepted unread like a package.json.
	roots := append(append([]string{}, npminstalled.Roots...), goBinDirs...)
	roots = append(roots, dpkgdb.InfoDir, pacmanLocalDir)
	// The exact names are the top-level layout links (D162) and the npm
	// roots themselves: a root that is a symlink holds every package behind
	// it, and the pass sees nothing under its name (PR #271 review).
	exact := append(append([]string{}, mergedUsrDirs...), npminstalled.Roots...)
	files, links, err := img.FilesProbedLinks(ctx, roots, exact, probeCandidate, probeSniff)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("application probes: %w", err)
	}

	if owned == nil {
		owned = newFileOwners(img)
	}
	// D162, revised by the 2026-11-10 QA: a path is spelled through this
	// image's own top-level directory links (bin -> usr/bin on a merged-/usr
	// Debian, sbin -> usr/bin on Fedora and Arch, lib64 -> usr/lib), never
	// through a table that assumes them. The same pass recorded those links
	// (mergedUsrDirs are its exact names), so this costs no extra read.
	owned.links = topLevelLinks(links, owned.layerOf)
	npmFiles := map[string][]byte{}
	layerOf := map[string]string{}
	type goBin struct {
		path string
		file source.FileFromLayer
	}
	var bins []goBin
	for _, p := range source.SortedNames(files) {
		f := files[p]
		switch {
		case isOwnershipList(p):
			owned.addList(p, f, osPkgs)
		case path.Base(p) == "package.json":
			npmFiles[p] = f.Data
			layerOf[p] = f.DiffID
		default:
			bins = append(bins, goBin{p, f})
		}
	}

	// QA 2026-11-10: a package.json that is a link, or a package directory
	// under node_modules that is a link, is still an installed package at
	// that logical path. The pass recorded those links; they are resolved
	// here, through the image's own resolver (layers, D123; hardlinks by the
	// layer that made them, D130; the link bound and cycles), reading
	// exactly one package.json per candidate -- a directory link's target
	// is resolved through the recorded links (resolveLink) and not walked (D160's unit is the logical install candidate under a
	// fixed root, not a new root). One that does not resolve is unread with
	// its reason, so the strict gate sees it, and the npm scope is partial
	// rather than none.
	unresolvedNpm, err := resolveNpmLinks(ctx, img, links, npmFiles, layerOf, owned.layerOf)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, err
	}
	npmPkgs, npmStats := npminstalled.Catalog(npmFiles)
	for i := range npmPkgs {
		for j := range npmPkgs[i].Locations {
			npmPkgs[i].Locations[j].LayerDigest = layerOf[npmPkgs[i].Locations[j].Path]
		}
	}
	pkgs = append(pkgs, npmPkgs...)
	addStats(&stats, npmStats)
	npmState := scopeState(npmStats.Components > 0)
	if unresolvedNpm > 0 {
		npmState = report.ScopePartial
	}
	scope = append(scope, report.ApplicationScopeRecord{
		Ecosystem: "npm", State: npmState, Roots: npminstalled.Roots,
	})

	// Sorted, so two scans of one image list the binaries' packages in one
	// order (design goal #3 reaches the inventory too).
	sort.Slice(bins, func(i, j int) bool { return bins[i].path < bins[j].path })
	goFound := false
	for _, b := range bins {
		t, s, err := gobinary.ParseBytes(b.file.Data, b.path)
		if err != nil {
			// An ELF that carries no Go build info is not a Go binary -- a C
			// program, a stripped runtime -- and so not a package: skipped
			// without a count, the way a non-ELF executable was skipped at
			// the sniff.
			continue
		}
		goFound = true
		for i := range t.Packages {
			for j := range t.Packages[i].Locations {
				t.Packages[i].Locations[j].LayerDigest = b.file.DiffID
			}
		}
		pkgs = append(pkgs, t.Packages...)
		addStats(&stats, s)
	}
	scope = append(scope, report.ApplicationScopeRecord{Ecosystem: "Go", State: scopeState(goFound), Roots: goBinDirs})

	for _, eco := range applicationEcosystemsNotRead {
		scope = append(scope, report.ApplicationScopeRecord{Ecosystem: eco, State: report.ScopeNotRead})
	}
	// D162: every probed location the OS inventory owns says so.
	owned.stamp(pkgs)
	return pkgs, stats, scope, nil
}

// probeCandidate is the one pass's match: a package.json anywhere under an
// npm root, or a regular file of at least a kilobyte with an execute bit
// directly inside a bin directory. The roots are told apart by the path
// itself, so one match serves both probes; which root a name is under was
// already decided by FilesProbed.
func probeCandidate(name string, h *tar.Header) bool {
	// D162: a dpkg `.list` or a pacman `files` under its root, a regular
	// file; anything else under those roots (a `.md5sums`, a `desc`) is
	// declined here and never read.
	if isOwnershipList(name) {
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
			return h.Size <= source.MaxFileBytes
		}
		return false
	}
	if path.Base(name) == "package.json" {
		return underAny(name, npminstalled.Roots)
	}
	// A package directory that is a symlink -- usr/lib/node_modules/x, or
	// a scoped @s/x -- or a scope directory that is one is recorded for
	// resolveNpmLinks; nothing is read from it here.
	if h.Typeflag == tar.TypeSymlink && underAny(name, npminstalled.Roots) && (isPackageDir(name) || isScopeDir(name)) {
		return true
	}
	switch h.Typeflag {
	case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
	default:
		return false
	}
	if h.Mode&0o111 == 0 || h.Size < minExecutableBytes {
		return false
	}
	// An executable the per-file limit would refuse is declined here, before
	// a byte of it is read: it cannot be a Go binary this scan may read, and
	// reading it only to fail the whole scan (the OS verdict with it) would
	// turn a 600 MiB C++ program in /usr/bin into exit 2 for the image. The
	// decline still shadows a lower layer's file at the name (FilesProbed's
	// scope rule), so nothing else surfaces in its place. Not disclosed as a
	// skip: it is not a package, and nothing says it is a Go binary.
	if h.Size > source.MaxFileBytes {
		return false
	}
	d := path.Clean(path.Dir(name))
	for _, dir := range goBinDirs {
		if d == dir {
			return true
		}
	}
	return false
}

// probeSniff accepts every package.json unread and an executable only when
// its first four bytes are the ELF magic.
func probeSniff(name string, head []byte) bool {
	if isOwnershipList(name) || path.Base(name) == "package.json" {
		return true
	}
	return isELF(head)
}

// isPackageDir reports whether name is a package's own directory inside a
// node_modules tree: its parent is node_modules, or a scope directory
// (@scope) whose parent is.
func isPackageDir(name string) bool {
	parent := path.Dir(name)
	if path.Base(parent) == "node_modules" {
		return !strings.HasPrefix(path.Base(name), "@")
	}
	return strings.HasPrefix(path.Base(parent), "@") && path.Base(path.Dir(parent)) == "node_modules"
}

// isScopeDir reports whether name is a scope directory (@scope) directly
// under node_modules: a directory of packages, not a package.
func isScopeDir(name string) bool {
	return strings.HasPrefix(path.Base(name), "@") && path.Base(path.Dir(name)) == "node_modules"
}

// resolveNpmLinks reads, for every link the probe pass found at an npm
// candidate, the one package.json it leads to, and adds it to files under
// its logical path -- the path under the fixed root the package is
// installed at -- with the layer of the file actually read. A package.json
// that is itself a link is read through the image's resolver at its own
// path; a package directory that is a link is resolved from the root the
// way the kernel resolves it and its package.json read. Links outside the
// npm roots (bin directories, the top-level layout links) are not npm
// candidates and are left alone. It returns how many candidates did not
// resolve; each is recorded on the image as unread, with its reason.
//
// A directory link's target is resolved through the links the pass recorded
// (the npm-root links themselves and the top-level layout links such as
// lib -> usr/lib), component by component as the kernel would; a link
// elsewhere in the target's path was not recorded and is not followed, and
// the candidate is then unread with that reason. A target already read at
// its own path under a root (pnpm's node_modules/x -> .pnpm/x@v/node_modules/x)
// is that package, not a second copy, and is skipped. Packages nested under a
// linked directory's target are node_modules outside the roots and are not
// read (D160 revised) -- the scope sentence's "node_modules elsewhere".
//
// An error reading the image (the scan's budget, its deadline, a layer) is
// returned, as the probe pass returns it: D112's "an error, never a shorter
// result".
func resolveNpmLinks(ctx context.Context, img *source.Image, links map[string]source.Link, files map[string][]byte, layerOf map[string]string, layerIndex func(string) int) (int, error) {
	type cand struct {
		logical, read, link string
		linkLayer           string
	}
	var cands []cand
	unresolved := 0
	names := make([]string, 0, len(links))
	for n := range links {
		names = append(names, n)
	}
	sort.Strings(names)
	// A root the image replaced with a link has nothing under its name: a
	// lower layer's packages there are gone from the filesystem (a symlink
	// over a directory carries no whiteout, so the pass did not shadow
	// them), and so are the links it recorded there (PR #271 review).
	var linkedRoots []string
	for _, n := range names {
		if isNpmRoot(n) && !links[n].Hard {
			linkedRoots = append(linkedRoots, n)
		}
	}
	for _, r := range linkedRoots {
		for f := range files {
			if strings.HasPrefix(f, r+"/") {
				delete(files, f)
				delete(layerOf, f)
			}
		}
	}
	for _, n := range names {
		l := links[n]
		if underAny(n, linkedRoots) {
			continue
		}
		switch {
		case isNpmRoot(n):
			// A global node_modules root that is itself a link: every
			// package lives behind it, and enumerating them means walking
			// the target, which D160's fixed roots do not do. Unread with
			// the reason, so npm is partial rather than none -- unless the
			// link leads to another root the pass read in full, which makes
			// it an alias with nothing left unread.
			if t := resolveLink(path.Dir(n), l.Target, links); l.Hard || !aliasOfReadRoot(t, links) {
				unresolved++
				img.NoteUnresolved(n, fmt.Sprintf("npm root is a link to %q; the packages behind it are not enumerated", l.Target))
			}
		case !underAny(n, npminstalled.Roots):
			// Equivalent today, kept as the statement of scope: probeCandidate
			// admits npm links only under the roots, and the pass's other
			// links are the top-level layout names (bin, lib), which match no
			// arm below. A mutation removing this case survives for that reason.
		case !l.Hard && isScopeDir(n):
			// A linked scope holds any number of packages; reading them
			// means walking the link's target, which a probe does not do
			// (D160's unit is one install candidate). Unread, not none.
			unresolved++
			img.NoteUnresolved(n, fmt.Sprintf("npm scope directory is a link to %q; the packages behind it are not read", l.Target))
		case path.Base(n) == "package.json":
			// Only an installed package's manifest is a candidate -- the
			// rule npminstalled.Catalog applies to regular files: a link at
			// a package's examples/package.json is nobody's install, and
			// its target is not this scan's to resolve (PR #271 review).
			if npminstalled.IsInstalledPackageJSON(n) {
				cands = append(cands, cand{logical: n, read: n, link: l.Target, linkLayer: l.DiffID})
			}
		case !l.Hard && isPackageDir(n):
			read := resolveLink(path.Dir(n), l.Target, links) + "/package.json"
			// A target that is itself an install this pass inventories is
			// that package, not a second copy: pnpm's
			// node_modules/x -> .pnpm/x@v/node_modules/x, whose manifest may
			// be a regular file or a hardlink into the store; a link from one
			// root into another; or a link to another package directory link.
			// Judged at the link's immediate target -- the first place it
			// lands -- and at the end of the chain. A package.json the probe
			// merely read -- inside another package's resources, say -- is no
			// install of its own, and the link is the only one this package
			// has (PR #271 review: lodash linked into a vendor package's
			// resources read 0 findings).
			if inventoried(resolveLinkTo(path.Dir(n), l.Target, links, false), files, links) || inventoried(strings.TrimSuffix(read, "/package.json"), files, links) {
				continue
			}
			cands = append(cands, cand{logical: n + "/package.json", read: read, link: l.Target, linkLayer: l.DiffID})
		}
	}
	if len(cands) == 0 {
		return unresolved, nil
	}
	want := make([]string, 0, len(cands))
	for _, c := range cands {
		want = append(want, c.read)
	}
	got, err := img.Files(ctx, want)
	if err != nil {
		return 0, fmt.Errorf("read the npm packages behind links: %w", err)
	}
	for _, c := range cands {
		f, ok := got[c.read]
		if !ok {
			unresolved++
			img.NoteUnresolved(c.logical, fmt.Sprintf("npm package link to %q does not resolve to a package.json the probe can read (missing, or behind a link outside the npm roots and the top-level layout links)", c.link))
			continue
		}
		files[c.logical] = f.Data
		// The logical path changed in whichever layer is later: the one the
		// bytes came from, or the one that made the link. An upper layer
		// that replaces an OS-owned manifest with a link to a file of its
		// own has put something new at that path, and the OS package's
		// record (D162's layer rule) no longer names it (PR #271 review).
		// A hardlink's bytes already come from the layer that made it (D130).
		layerOf[c.logical] = f.DiffID
		if layerIndex(c.linkLayer) > layerIndex(f.DiffID) {
			layerOf[c.logical] = c.linkLayer
		}
	}
	return unresolved, nil
}

// inventoried reports whether dir is a package directory this pass already
// inventories as an installed package: its manifest an installed
// package.json read as a file or recorded as a link candidate, or the
// directory itself a package-directory link under a root.
func inventoried(dir string, files map[string][]byte, links map[string]source.Link) bool {
	pj := dir + "/package.json"
	if !npminstalled.IsInstalledPackageJSON(pj) {
		return false
	}
	if _, ok := files[pj]; ok {
		return true
	}
	if _, ok := links[pj]; ok {
		return true
	}
	l, ok := links[dir]
	return ok && !l.Hard && underAny(dir, npminstalled.Roots) && isPackageDir(dir)
}

// aliasOfReadRoot reports whether t, a root link's resolved target, is
// another npm root (or a directory under one) that is not itself a link:
// everything there was read by this pass.
func aliasOfReadRoot(t string, links map[string]source.Link) bool {
	for _, r := range npminstalled.Roots {
		if t == r || strings.HasPrefix(t, r+"/") {
			_, linked := links[r]
			return !linked
		}
	}
	return false
}

// isNpmRoot reports whether name is one of the global node_modules roots
// itself.
func isNpmRoot(name string) bool {
	for _, r := range npminstalled.Roots {
		if name == r {
			return true
		}
	}
	return false
}

// resolveLink resolves a link's target the way the kernel walks a path:
// from dir (the link's own directory) for a relative target, from / for an
// absolute one, one component at a time, following any recorded symlink a
// component names BEFORE a later ".." is applied -- so /lib64/../qa-pkg
// through lib64 -> usr/lib is usr/qa-pkg, not qa-pkg (PR #271 review). The
// links known are the ones the pass recorded (the npm-root links and the
// top-level layout links); a component no recorded link names is taken as a
// directory. Bounded like the image's own resolver, so a cycle ends.
func resolveLink(dir, target string, links map[string]source.Link) string {
	return resolveLinkTo(dir, target, links, true)
}

// resolveLinkTo is resolveLink; with followFinal false, a link at the last
// component is left unfollowed -- the place the link first lands.
func resolveLinkTo(dir, target string, links map[string]source.Link, followFinal bool) string {
	var cur []string
	if !strings.HasPrefix(target, "/") {
		for _, c := range strings.Split(dir, "/") {
			if c != "" && c != "." {
				cur = append(cur, c)
			}
		}
	}
	queue := strings.Split(target, "/")
	for hops := 0; len(queue) > 0; {
		c := queue[0]
		queue = queue[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		cur = append(cur, c)
		if !followFinal && len(queue) == 0 {
			break
		}
		l, ok := links[strings.Join(cur, "/")]
		if !ok || l.Hard || l.Target == "" {
			continue
		}
		if hops++; hops > 40 {
			break
		}
		cur = cur[:len(cur)-1]
		if strings.HasPrefix(l.Target, "/") {
			cur = nil
		}
		queue = append(strings.Split(l.Target, "/"), queue...)
	}
	return strings.Join(cur, "/")
}

// minExecutableBytes is the smallest file the Go probe considers: no ELF
// with Go build info is shorter than a kilobyte, and the floor keeps wrapper
// scripts with the execute bit from being sniffed one by one.
const minExecutableBytes = 1024

func underAny(name string, roots []string) bool {
	for _, r := range roots {
		if strings.HasPrefix(name, r+"/") {
			return true
		}
	}
	return false
}

// scopeState is ScopeRead when a probe found something and ScopeNone when it
// ran and found nothing -- the D111 distinction catalogBitnami draws.
func scopeState(found bool) string {
	if found {
		return report.ScopeRead
	}
	return report.ScopeNone
}

// addStats folds one cataloger's counts into the image's.
func addStats(into *cyclonedx.Stats, s cyclonedx.Stats) {
	into.Components += s.Components
	into.Cataloged += s.Cataloged
	into.SkippedNoVersion += s.SkippedNoVersion
	into.SkippedNoPURL += s.SkippedNoPURL
	into.SkippedUnsupportedEcosystem += s.SkippedUnsupportedEcosystem
}

// applicationScopeNote is D141's stderr disclosure, rebuilt from the scope
// record (D160): what the probes read, where, and what is still not read,
// with the remedy for the latter. One function so the test that holds the
// wording holds the one that is printed.
func applicationScopeNote(w io.Writer, s *report.InventoryScopeRecord) {
	read, notRead := report.ApplicationScopeSentence(s)
	switch {
	case read == "":
		fmt.Fprintln(w, "note: an image scan reads OS packages (and Bitnami markers), not application "+
			"packages installed in the image -- npm, Python, Java and Go binaries were not checked")
	default:
		fmt.Fprintf(w, "note: an image scan reads OS packages (and Bitnami markers) plus %s; the other application "+
			"packages -- %s, node_modules elsewhere and Go binaries elsewhere -- were not checked\n", read, notRead)
	}
	fmt.Fprintln(w, "  scan the application's lockfile, directory or binary, or an SBOM of the image, "+
		"for those (D70, D160)")
}
