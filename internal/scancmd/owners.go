package scancmd

import (
	"bytes"
	"path"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/pacmandb"
	"github.com/kun9497/assay/internal/cataloger/rpmdb"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/source"
)

// D162: which OS package owns a probed file. The D160 probes read an npm
// tree and the Go binaries in the bin directories without saying who put
// them there, and on the measured images most of what they find is the
// distro's own -- ubi8/nodejs-18's node_modules is the npm and
// nodejs-nodemon RPMs' bundled tree, archlinux's captree is libcap's binary
// -- so a reader could not tell the distro's bundled copy, whose advisory is
// the OS package's, from one the image author installed. Every OS package
// database records its files: rpm in three header tags, apk inline in
// `installed`, dpkg in one `.list` per package, pacman in the `files` beside
// each `desc`. The rpm and apk lists come with the database already read;
// the dpkg and pacman files ride the probes' own layer pass (one more root
// each, no extra pass).
//
// Two rules make a match an ownership claim rather than a path coincidence.
// Exact file: a package that owns a directory says nothing about the files
// under it, which is how an image author's globally installed module under
// the RPM-owned usr/lib/node_modules stays unowned. Layer order: a package
// manager writes a file and its database (or list) in the same layer, so a
// file in a LATER layer than the record that names it was put there by
// something else -- `npm install -g npm@latest` over the npm RPM's tree --
// and is unowned, whatever its path says.
//
// Ownership is additive information: a location without an owner is still
// located and still judged. So nothing here fails a scan or counts a skip --
// an unreadable list, a list for a package the inventory does not hold, a
// header whose file tags disagree, all own nothing.

// fileOwners resolves a probed location to the OS package whose file list
// names it. The rpm and apk sources are kept as the databases gave them and
// consulted per probed path; only the dpkg and pacman lists, which arrive
// one file at a time, are folded into a map.
type fileOwners struct {
	// layerIndex orders the image's diff ids, base first; a diff id not in
	// it (no image, or a test's synthetic layer) sorts as the base.
	layerIndex map[string]int

	rpm      *rpmdb.Result
	rpmLayer int

	apkFiles  map[string]string // path -> package name, as apk spells both
	apkByName map[string]pkgmeta.Package
	apkLayer  int

	lists map[string]listOwner // dpkg and pacman: path (no leading slash) -> owner

	// Built once, on the first list: the inventory by the names a list's
	// filename or location spells.
	debByName  map[string]pkgmeta.Package // "name" and "name:arch"
	alpmByDesc map[string]pkgmeta.Package // desc path -> package
}

type listOwner struct {
	owner pkgmeta.Owner
	layer int
}

func newFileOwners(img *source.Image) *fileOwners {
	o := &fileOwners{layerIndex: map[string]int{}, lists: map[string]listOwner{}}
	if img != nil {
		for i, l := range img.Layers {
			o.layerIndex[l.DiffID] = i
		}
	}
	return o
}

func (o *fileOwners) layerOf(diffID string) int { return o.layerIndex[diffID] }

// fromRPM takes the file lists an rpmdb read collected, with the layer the
// database came from.
func (o *fileOwners) fromRPM(res rpmdb.Result, diffID string) {
	r := res
	o.rpm, o.rpmLayer = &r, o.layerOf(diffID)
}

// fromAPK reads the F:/R: lines of the installed database the packages came
// from. A file whose record names a package Parse did not return (a record
// with no version, say) owns nothing.
func (o *fileOwners) fromAPK(installed []byte, pkgs []pkgmeta.Package, diffID string) error {
	files, err := apkdb.ParseFiles(bytes.NewReader(installed))
	if err != nil {
		return err
	}
	o.apkFiles, o.apkLayer = files, o.layerOf(diffID)
	o.apkByName = make(map[string]pkgmeta.Package, len(pkgs))
	for _, p := range pkgs {
		o.apkByName[p.Name] = p
	}
	return nil
}

// isOwnershipList says whether a probed path is a dpkg `.list` or a pacman
// `files`, the two ownership records that live as files under a fixed root
// rather than inside the package database.
func isOwnershipList(name string) bool {
	switch {
	case strings.HasPrefix(name, dpkgdb.InfoDir+"/"):
		return strings.HasSuffix(name, ".list")
	case strings.HasPrefix(name, pacmanLocalDir+"/"):
		return path.Base(name) == "files"
	}
	return false
}

// index builds the name lookups the lists resolve against, once.
func (o *fileOwners) index(osPkgs []pkgmeta.Package) {
	if o.debByName != nil {
		return
	}
	o.debByName, o.alpmByDesc = map[string]pkgmeta.Package{}, map[string]pkgmeta.Package{}
	for _, p := range osPkgs {
		switch p.Type {
		case "deb":
			if _, dup := o.debByName[p.Name]; !dup {
				o.debByName[p.Name] = p
			}
			if p.Arch != "" {
				o.debByName[p.Name+":"+p.Arch] = p
			}
		case "alpm":
			if len(p.Locations) > 0 {
				o.alpmByDesc[p.Locations[0].Path] = p
			}
		}
	}
}

// addList reads one ownership list the probe pass collected and records its
// files against the OS package it belongs to: a dpkg list by the name (and
// arch) its filename spells, a pacman files by the desc beside it. A list
// for a package the inventory does not hold (removed but not purged, a desc
// this build skipped), or one that does not read (a line past the scanner's
// bound), owns nothing -- additive information never fails the scan.
func (o *fileOwners) addList(name string, f source.FileFromLayer, osPkgs []pkgmeta.Package) {
	o.index(osPkgs)
	var (
		owner pkgmeta.Package
		ok    bool
		files []string
		err   error
	)
	switch {
	case strings.HasPrefix(name, dpkgdb.InfoDir+"/"):
		pkgName, arch := dpkgdb.ListOwner(path.Base(name))
		key := pkgName
		if arch != "" {
			key += ":" + arch
		}
		if owner, ok = o.debByName[key]; !ok {
			return
		}
		files, err = dpkgdb.ParseFileList(bytes.NewReader(f.Data))
	case strings.HasPrefix(name, pacmanLocalDir+"/"):
		if owner, ok = o.alpmByDesc[path.Dir(name)+"/desc"]; !ok {
			return
		}
		files, err = pacmandb.ParseFiles(bytes.NewReader(f.Data))
	default:
		return
	}
	// Both readers return nil files with an error, so falling through would
	// record nothing either; the return states the intent (an equivalent
	// mutation, verified 2026-11-09).
	if err != nil {
		return
	}
	lo := listOwner{owner: pkgmeta.Owner{Name: owner.Name, Version: owner.Version}, layer: o.layerOf(f.DiffID)}
	for _, p := range files {
		o.lists[strings.TrimPrefix(p, "/")] = lo
	}
}

// mergedUsrDirs are the directories a merged-/usr Debian or Ubuntu makes
// symlinks into usr/: a deb's list may say /bin/foo for the regular file
// the probe found at usr/bin/foo (rpm records the canonical usr/ path).
var mergedUsrDirs = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// spellings is the path as given plus its merged-/usr twin, without a
// leading slash.
func spellings(p string) []string {
	p = strings.TrimPrefix(p, "/")
	out := []string{p}
	for _, d := range mergedUsrDirs {
		switch {
		case strings.HasPrefix(p, "usr/"+d+"/"):
			out = append(out, strings.TrimPrefix(p, "usr/"))
		case strings.HasPrefix(p, d+"/"):
			out = append(out, "usr/"+p)
		}
	}
	return out
}

// lookup resolves one location: the owner whose record names the path (or
// its merged-/usr twin) and whose record is in the file's layer or a later
// one. A file in a layer after the record was put there by something other
// than the package manager that wrote the record.
func (o *fileOwners) lookup(p string, diffID string) (pkgmeta.Owner, bool) {
	fileLayer := o.layerOf(diffID)
	for _, s := range spellings(p) {
		if o.rpm != nil && o.rpmLayer >= fileLayer {
			if i, ok := o.rpm.Files["/"+s]; ok {
				pkg := o.rpm.Packages[i]
				return pkgmeta.Owner{Name: pkg.Name, Version: pkg.Version}, true
			}
		}
		if o.apkFiles != nil && o.apkLayer >= fileLayer {
			if name, ok := o.apkFiles[s]; ok {
				if pkg, ok := o.apkByName[name]; ok {
					return pkgmeta.Owner{Name: pkg.Name, Version: pkg.Version}, true
				}
			}
		}
		if lo, ok := o.lists[s]; ok && lo.layer >= fileLayer {
			return lo.owner, true
		}
	}
	return pkgmeta.Owner{}, false
}

// stamp sets OwnedBy on every location of pkgs an OS package owns.
func (o *fileOwners) stamp(pkgs []pkgmeta.Package) {
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			l := &pkgs[i].Locations[j]
			if owner, ok := o.lookup(l.Path, l.LayerDigest); ok {
				l.OwnedBy = &owner
			}
		}
	}
}
