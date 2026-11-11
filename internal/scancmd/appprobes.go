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
	exact := append(append(append([]string{}, mergedUsrDirs...), npminstalled.Roots...), rootAncestors...)
	files, links, err := img.FilesProbedLinks(ctx, roots, exact, probeCandidate, probeSniff)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("application probes: %w", err)
	}
	// A root that lives elsewhere -- its own entry a link, or an ancestor's
	// (`/usr/local/lib -> /opt/new-global`, the release check of 2026-11-11:
	// the installs there read as npm `none`) -- is read where it physically
	// is: a second pass over the physical directories the chains end in,
	// outside every root the first pass covered, whose files and links are
	// then re-homed under the root's own name by the alias rules below. One
	// extra pass, only for an image that moves a root, and only over the
	// directories the fixed paths lead to: no wider search of the image.
	extra, err := readPhysicalRoots(ctx, img, files, links, owned.layerOf)
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
	unresolvedNpm, aliases, err := resolveNpmLinks(ctx, img, links, npmFiles, layerOf, owned.layerOf, extra)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, err
	}
	npmPkgs, npmStats := npminstalled.Catalog(npmFiles)
	for i := range npmPkgs {
		for j := range npmPkgs[i].Locations {
			npmPkgs[i].Locations[j].LayerDigest = layerOf[npmPkgs[i].Locations[j].Path]
		}
		// Several links to one install are one package with every name
		// the image gives it (PR #275 review: the other names were lost).
		for _, l := range npmPkgs[i].Locations {
			for _, a := range aliases[l.Path] {
				npmPkgs[i].Locations = append(npmPkgs[i].Locations, pkgmeta.Location{Path: a, LayerDigest: layerOf[a]})
			}
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
	return probeCandidateUnder(name, h, npminstalled.Roots)
}

// probeCandidateUnder is probeCandidate's npm and Go half with the npm
// roots given: the second pass over a moved root's physical directory
// (readPhysicalRoots) matches under that directory.
func probeCandidateUnder(name string, h *tar.Header, npmRoots []string) bool {
	if path.Base(name) == "package.json" {
		return underAny(name, npmRoots)
	}
	// Every symlink under an npm root is recorded for resolveNpmLinks;
	// nothing is read from it here. A package directory (usr/lib/
	// node_modules/x, a scoped @s/x) or a scope directory that is a link is
	// a candidate there; any other -- a link inside a package, one under a
	// directory another root is linked to (PR #275 review) -- is known so
	// it can be re-homed or followed, and costs a map entry.
	if h.Typeflag == tar.TypeSymlink && underAny(name, npmRoots) {
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
	base := path.Base(name)
	if strings.HasPrefix(base, ".") {
		// npm's own dot directories (.bin, a link to /usr/bin on some
		// images; pnpm's .pnpm): never a package, so never a candidate
		// whose package.json the gate would wait for (QA 2026-11-11).
		return false
	}
	parent := path.Dir(name)
	if path.Base(parent) == "node_modules" {
		return !strings.HasPrefix(base, "@")
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
func resolveNpmLinks(ctx context.Context, img *source.Image, links map[string]source.Link, files map[string][]byte, layerOf map[string]string, layerIndex func(string) int, extra map[string]bool) (unresolved int, aliases map[string][]string, err error) {
	aliases = map[string][]string{}
	// readRoot is aliasOfReadRoot plus the physical directories the second
	// pass read (readPhysicalRoots).
	underExtra := func(t string) bool {
		for d := range extra {
			if t == d || strings.HasPrefix(t, d+"/") {
				return true
			}
		}
		return false
	}
	readRoot := func(t string) bool {
		return aliasOfReadRoot(t, links) || underExtra(t)
	}
	type alias struct {
		logical, link string
		changed       []string
	}
	type cand struct {
		logical, read, link string
		// changed is every layer the logical path's meaning depends on:
		// the link's own and each link followed on the way; the file's own
		// layer joins it once the bytes are read.
		changed []string
		// aliases are the install's other names, each with the layers ITS
		// own chain changed in: an alias re-pointed in an upper layer is
		// located there, not in the representative's layer (release check
		// 2026-11-11: the representative's layer put the OS package's
		// ownership on a path the upper layer had re-pointed).
		aliases []alias
	}
	var cands []cand
	// A root the image replaced with a link has nothing under its name: a
	// lower layer's packages there are gone from the filesystem (a symlink
	// over a directory carries no whiteout, so the pass did not shadow
	// them), and so are the links it recorded there (PR #271 review).
	var linkedRoots []string
	for n, l := range links {
		if isNpmRoot(n) && !l.Hard {
			linkedRoots = append(linkedRoots, n)
		}
	}
	sort.Strings(linkedRoots)
	for _, r := range linkedRoots {
		for f := range files {
			if strings.HasPrefix(f, r+"/") {
				delete(files, f)
				delete(layerOf, f)
			}
		}
	}
	// A root linked to a directory UNDER another root is an alias of what
	// the pass already read there: its files are re-homed under the root's
	// own name (rehomeRoot), and so are its links -- a package directory or
	// manifest that is itself a link there is an install at the logical
	// path too, judged below by the same arms as any other link (PR #275
	// review: a linked install under the alias target was a silent miss).
	// A relative target is made absolute from its physical directory, and
	// a hardlink's logical twin points at the physical name, so the image's
	// resolver still follows it by inode (D130).
	rehomed := map[string]bool{} // synthesized logical links
	aliased := map[string]bool{} // roots handled here
	for _, r := range linkedRoots {
		l := links[r]
		final, followed, cyclic := resolveChain(path.Dir(r), l.Target, links)
		if cyclic || !readRoot(final) || final == rootOf(final) {
			continue
		}
		any := rehomeRoot(r, final, files, layerOf, layerIndex, append(followed, r), links, underExtra)
		for n, nl := range links {
			if !strings.HasPrefix(n, final+"/") {
				continue
			}
			logical := r + strings.TrimPrefix(n, final)
			if !(isPackageDir(logical) || isScopeDir(logical) || npminstalled.IsInstalledPackageJSON(logical)) {
				continue
			}
			any = true
			switch {
			case nl.Hard:
				nl = source.Link{Target: "/" + n, DiffID: nl.DiffID}
			case !strings.HasPrefix(nl.Target, "/"):
				// Spelled from the physical directory UNFOLDED: a ".." in
				// the target is applied by resolveChain after the link
				// before it, as the kernel applies it. path.Join had folded
				// `hop/../meta.json` to `meta.json` before `hop` (a link to
				// another directory) was followed, and read the wrong file
				// (release check 2026-11-11).
				nl.Target = "/" + path.Dir(n) + "/" + nl.Target
			}
			// The logical link's layer is the latest of the root link's
			// chain and the physical link's own: the root re-pointed in an
			// upper layer changed what the logical path means, and the OS
			// package that owned the physical manifest does not own that
			// (release check 2026-11-11: the owner had been kept).
			nl.DiffID = newestLayer(append(linkLayers(append(followed, r), links), nl.DiffID), layerIndex)
			links[logical] = nl
			rehomed[logical] = true
		}
		if any {
			aliased[r] = true
		}
	}
	names := make([]string, 0, len(links))
	for n := range links {
		names = append(names, n)
	}
	sort.Strings(names)
	// A package directory link points at an install; several may point at
	// one. Grouped by where the chain ends, so an install reached by two
	// links is one package, and a chain that leads nowhere -- a cycle, a
	// missing target -- leaves every link in it unread (QA 2026-11-11: two
	// links pointing at each other each took the other for an install
	// already made, and the strict gate saw nothing).
	type dirLink struct {
		n, link  string
		followed []string
		hops     int
	}
	groups := map[string][]dirLink{}
	var finals []string
	for _, n := range names {
		l := links[n]
		if underAny(n, linkedRoots) && !rehomed[n] {
			continue
		}
		switch {
		case isNpmRoot(n):
			// A global node_modules root that is itself a link. Its target
			// is enumerated when the pass already read it -- a directory
			// under another root, re-homed above (QA 2026-11-11: a root
			// linked to another root's vendor/assets read 0 of lodash's 4
			// findings, exit 0) -- and otherwise listed unread, so npm is
			// partial rather than none.
			if aliased[n] {
				continue
			}
			final, _, cyclic := resolveChain(path.Dir(n), l.Target, links)
			switch {
			case l.Hard || cyclic || !readRoot(final):
				unresolved++
				img.NoteUnresolved(n, fmt.Sprintf("npm root is a link to %q; the packages behind it are not enumerated", l.Target))
			case final == rootOf(final):
				// The whole of another root: every install there is
				// already inventoried at its own path.
			default:
				unresolved++
				img.NoteUnresolved(n, fmt.Sprintf("npm root is a link to %q, which holds nothing the probe read", l.Target))
			}
		case !underAny(n, npminstalled.Roots):
			// The statement of scope, and load-bearing since the release
			// check of main 5197df4: a link the second pass recorded under a
			// moved root's PHYSICAL directory is re-homed above and is no
			// install at its physical name (a package-directory link there
			// would otherwise be read twice, once at each name). The pass's
			// other links -- the layout names (bin, lib), the root
			// ancestors -- match no arm below either.
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
			if !npminstalled.IsInstalledPackageJSON(n) {
				continue
			}
			if l.Hard {
				// Read at its own name: the image's resolver follows a
				// hardlink to the inode of the layer that made it (D130).
				cands = append(cands, cand{logical: n, read: n, link: l.Target, changed: []string{l.DiffID}})
				continue
			}
			// A symlink's target is walked here through the links the pass
			// recorded, a component at a time, so a top-level layout link
			// (lib64 -> usr/lib) and a later ".." resolve as the kernel
			// resolves them (QA 2026-11-11: /lib64/../qa-pkg/package.json
			// read the wrong package, and /lib64/qa-package/package.json
			// read nothing); whatever link remains at the end -- one
			// outside the roots -- the image's resolver follows by name.
			final, followed, cyclic := resolveChain(path.Dir(n), l.Target, links)
			if cyclic {
				unresolved++
				img.NoteUnresolved(n, fmt.Sprintf("npm package link to %q is a symbolic link cycle; nothing was read", l.Target))
				continue
			}
			cands = append(cands, cand{logical: n, read: final, link: l.Target, changed: linkLayers(append(followed, n), links)})
		case !l.Hard && isPackageDir(n):
			final, followed, cyclic := resolveChain(path.Dir(n), l.Target, links)
			if cyclic {
				// Named by the install the link stands for, as a missing
				// target is, so one shape reads the same whatever failed.
				unresolved++
				img.NoteUnresolved(n+"/package.json", fmt.Sprintf("npm package link to %q is a symbolic link cycle; nothing was read", l.Target))
				continue
			}
			if _, ok := groups[final]; !ok {
				finals = append(finals, final)
			}
			groups[final] = append(groups[final], dirLink{n: n, link: l.Target, followed: followed, hops: len(followed)})
		}
	}
	sort.Strings(finals)
	for _, final := range finals {
		members := groups[final]
		// A target that is itself an install this pass inventories is that
		// package, not a second copy: pnpm's node_modules/x ->
		// .pnpm/x@v/node_modules/x, whose manifest may be a regular file or
		// a hardlink into the store, or a link from one root into another.
		// A package.json the probe merely read -- inside another package's
		// resources, say -- is no install of its own, and the link is the
		// only one this package has (PR #271 review).
		if inventoried(final, files, links) {
			continue
		}
		// Several links to one install are one package, at the name that
		// lands on it most directly; the rest are its other names.
		sort.Slice(members, func(i, j int) bool {
			if members[i].hops != members[j].hops {
				return members[i].hops < members[j].hops
			}
			return members[i].n < members[j].n
		})
		m := members[0]
		logical := m.n + "/package.json"
		c := cand{logical: logical, read: final + "/package.json", link: m.link, changed: linkLayers(append(m.followed, m.n), links)}
		for _, o := range members[1:] {
			c.aliases = append(c.aliases, alias{logical: o.n + "/package.json", link: o.link, changed: linkLayers(append(o.followed, o.n), links)})
		}
		// The manifest at the install may itself be a link the pass
		// recorded (it sits under a root): walked here like a manifest link
		// at the logical path, through the links the pass knows, so a
		// `/lib64/../x` target reads the same file either way (release
		// check 2026-11-11: a package directory linked to a directory whose
		// package.json was a link lost lodash's 4 findings -- the image's
		// resolver folded the ".." before following lib64). A hardlink is
		// read at its own name, by inode (D130).
		if ml, ok := links[c.read]; ok && !ml.Hard {
			mfinal, mfollowed, mcyclic := resolveChain(final, ml.Target, links)
			if mcyclic {
				unresolved += 1 + len(c.aliases)
				img.NoteUnresolved(logical, fmt.Sprintf("npm package link to %q leads to a manifest link to %q that is a symbolic link cycle; nothing was read", m.link, ml.Target))
				for _, a := range c.aliases {
					img.NoteUnresolved(a.logical, fmt.Sprintf("npm package link to %q leads to a manifest link to %q that is a symbolic link cycle; nothing was read", a.link, ml.Target))
				}
				continue
			}
			c.read = mfinal
			c.changed = append(c.changed, linkLayers(append(mfollowed, final+"/package.json"), links)...)
			for i := range c.aliases {
				c.aliases[i].changed = append(c.aliases[i].changed, linkLayers(append(mfollowed, final+"/package.json"), links)...)
			}
		}
		cands = append(cands, c)
	}
	// What the second pass read under a moved root's physical directory
	// was re-homed under the root's name: the physical names are not
	// installs of their own (release check 2026-11-11: the fixed path is
	// what the scan reads; the physical directory is where it led).
	for f := range files {
		if underExtra(f) {
			delete(files, f)
			delete(layerOf, f)
		}
	}
	if len(cands) == 0 {
		return unresolved, aliases, nil
	}
	want := make([]string, 0, len(cands))
	for _, c := range cands {
		want = append(want, c.read)
	}
	got, err := img.Files(ctx, want)
	if err != nil {
		return 0, nil, fmt.Errorf("read the npm packages behind links: %w", err)
	}
	for _, c := range cands {
		f, ok := got[c.read]
		if !ok {
			// Every name of the install is unread, not only the one the
			// probe would have read it under (release check 2026-11-11: two
			// links to one missing target reported one unread path).
			unresolved += 1 + len(c.aliases)
			img.NoteUnresolved(c.logical, fmt.Sprintf("npm package link to %q does not resolve to a package.json the probe can read (missing, or behind a link outside the npm roots and the top-level layout links)", c.link))
			for _, a := range c.aliases {
				img.NoteUnresolved(a.logical, fmt.Sprintf("npm package link to %q does not resolve to a package.json the probe can read (missing, or behind a link outside the npm roots and the top-level layout links)", a.link))
			}
			continue
		}
		files[c.logical] = f.Data
		for _, a := range c.aliases {
			aliases[c.logical] = append(aliases[c.logical], a.logical)
			layerOf[a.logical] = newestLayer(append(a.changed, f.DiffID, f.ViaDiffID), layerIndex)
		}
		// The logical path's meaning changed in whichever layer is latest:
		// the one the bytes came from, the one that made the link, or one
		// that made a link on the way (a middle link retargeted in an
		// upper layer, QA 2026-11-11). An upper layer that replaces an
		// OS-owned manifest with a link to a file of its own has put
		// something new at that path, and the OS package's record (D162's
		// layer rule) no longer names it. A hardlink's bytes already come
		// from the layer that made it (D130).
		layerOf[c.logical] = newestLayer(append(c.changed, f.DiffID, f.ViaDiffID), layerIndex)
	}
	return unresolved, aliases, nil
}

// readPhysicalRoots finds, for each npm root, the directory it physically is
// -- through the links the pass recorded at the root and at its ancestors --
// and reads, in one more pass, those that lie outside every root. A root
// moved by an ancestor's link gets a synthesized link entry of its own, so
// the alias rules (resolveNpmLinks) re-home what was read; its layer is the
// latest of the ancestor links', since those are what moved it. It returns
// the physical directories read. A chain that cycles is left to the alias
// rules, which report the root unread.
func readPhysicalRoots(ctx context.Context, img *source.Image, files map[string]source.FileFromLayer, links map[string]source.Link, layerIndex func(string) int) (map[string]bool, error) {
	var phys []string
	for _, r := range npminstalled.Roots {
		final, followed, cyclic := resolveChain("", "/"+r, links)
		if cyclic || final == r || final == "" {
			continue
		}
		if _, own := links[r]; !own {
			// Moved by an ancestor's link: a link of the root's own, so
			// resolveNpmLinks treats it as one (the lower tree under the
			// root's name is gone, the alias target is re-homed).
			links[r] = source.Link{Target: "/" + final, DiffID: newestLayer(linkLayers(followed, links), layerIndex)}
		}
		if rootOf(final) == "" && !strings.Contains("/"+final+"/", "/../") {
			phys = append(phys, final)
		}
	}
	extra := map[string]bool{}
	if len(phys) == 0 {
		return extra, nil
	}
	sort.Strings(phys)
	more, moreLinks, err := img.FilesProbedLinks(ctx, phys, nil, func(name string, h *tar.Header) bool {
		return probeCandidateUnder(name, h, phys)
	}, probeSniff)
	if err != nil {
		return nil, err
	}
	for n, f := range more {
		if path.Base(n) == "package.json" {
			files[n] = f
		}
	}
	for n, l := range moreLinks {
		if _, ok := links[n]; !ok {
			links[n] = l
		}
	}
	for _, d := range phys {
		extra[d] = true
	}
	return extra, nil
}

// rehomeRoot re-homes, under root (a link), every package.json the pass
// read under target, a directory beneath another root: the install shape
// (npminstalled.IsInstalledPackageJSON) is judged at the logical path, and
// one already an install at its physical path is left there, counted once.
// It reports whether anything at all was read under target.
func rehomeRoot(root, target string, files map[string][]byte, layerOf map[string]string, layerIndex func(string) int, followed []string, links map[string]source.Link, physical func(string) bool) bool {
	any := false
	for f := range files {
		if !strings.HasPrefix(f, target+"/") {
			continue
		}
		any = true
		logical := root + strings.TrimPrefix(f, target)
		if !npminstalled.IsInstalledPackageJSON(logical) || (npminstalled.IsInstalledPackageJSON(f) && !physical(f)) {
			continue
		}
		files[logical] = files[f]
		layerOf[logical] = newestLayer(append(linkLayers(followed, links), layerOf[f]), layerIndex)
	}
	return any
}

// rootOf is the npm root t sits under or is, "" for none.
func rootOf(t string) string {
	for _, r := range npminstalled.Roots {
		if t == r || strings.HasPrefix(t, r+"/") {
			return r
		}
	}
	return ""
}

// linkLayers is the layer of every link in names.
func linkLayers(names []string, links map[string]source.Link) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if l, ok := links[n]; ok {
			out = append(out, l.DiffID)
		}
	}
	return out
}

// newestLayer is the latest of diffIDs by index; "" entries are ignored.
func newestLayer(diffIDs []string, layerIndex func(string) int) string {
	best, bestIdx := "", -1
	for _, d := range diffIDs {
		if d == "" {
			continue
		}
		if i := layerIndex(d); best == "" || i > bestIdx {
			best, bestIdx = d, i
		}
	}
	return best
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
	_, ok := links[pj]
	return ok
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

// rootAncestors are the strict ancestors of the npm roots: recorded by the
// pass as exact names, so a root whose parent is a link (`/usr/local/lib ->
// /opt/new-global`) is known to live elsewhere (physicalRoots).
var rootAncestors = func() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range npminstalled.Roots {
		for p := path.Dir(r); p != "." && p != "/" && p != ""; p = path.Dir(p) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}()

// knownDir reports whether the pass can vouch for name being a directory
// when it recorded no link at it: a name under a root (every symlink there
// is recorded), a root, a root ancestor or a top-level layout name (recorded
// as exact names when links). Anything else may be a link the pass never
// saw.
func knownDir(name string) bool {
	if underAny(name, npminstalled.Roots) || isNpmRoot(name) {
		return true
	}
	for _, d := range mergedUsrDirs {
		if name == d {
			return true
		}
	}
	for _, d := range rootAncestors {
		if name == d {
			return true
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

// resolveChain is resolveLink that also reports the links it followed (in
// order) and whether it met one twice -- a cycle, which Linux refuses with
// ELOOP and this scan reports as unread rather than taking the last link
// seen for an install (QA 2026-11-11).
func resolveChain(dir, target string, links map[string]source.Link) (final string, followed []string, cyclic bool) {
	var cur []string
	if !strings.HasPrefix(target, "/") {
		for _, c := range strings.Split(dir, "/") {
			if c != "" && c != "." {
				cur = append(cur, c)
			}
		}
	}
	// A link met twice with the same path still to walk is a cycle; met
	// twice on different remainders it is one link crossed twice, which
	// "/lib64/../../lib64/qa" does and Linux resolves (PR #275 review).
	seen := map[string]string{}
	queue := strings.Split(target, "/")
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			// Applied only to a component the pass can vouch for as a
			// directory: one under a root (every link there is recorded),
			// a layout or root-ancestor name (recorded when a link), or a
			// recorded link's own parent. Any other component may be a link
			// the pass never saw, so the ".." stays in the path for the
			// image's resolver to apply once it has looked at the component
			// (source.Files, lazyDotDot; release check 2026-11-11:
			// `/opt/route/../qa-package` folded to `opt/qa-package` before
			// opt/route, a link to srv/nested/deep, was followed).
			switch {
			case len(cur) == 0:
				// The root's parent is the root.
			case cur[len(cur)-1] != ".." && knownDir(strings.Join(cur, "/")):
				cur = cur[:len(cur)-1]
			default:
				cur = append(cur, "..")
			}
			continue
		}
		cur = append(cur, c)
		name := strings.Join(cur, "/")
		l, ok := links[name]
		if !ok || l.Hard || l.Target == "" {
			continue
		}
		// A repeat is a cycle; the bound alone would also end it, so a
		// mutation dropping the repeat check survives -- the check only
		// spares the forty hops.
		rest := strings.Join(queue, "/")
		if prev, ok := seen[name]; (ok && prev == rest) || len(followed) >= 40 {
			return name, followed, true
		}
		seen[name] = rest
		followed = append(followed, name)
		cur = cur[:len(cur)-1]
		if strings.HasPrefix(l.Target, "/") {
			cur = nil
		}
		queue = append(strings.Split(l.Target, "/"), queue...)
	}
	return strings.Join(cur, "/"), followed, false
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
			switch {
			case len(cur) == 0:
				// The root's parent is the root.
			case cur[len(cur)-1] != ".." && knownDir(strings.Join(cur, "/")):
				cur = cur[:len(cur)-1]
			default:
				cur = append(cur, "..")
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
