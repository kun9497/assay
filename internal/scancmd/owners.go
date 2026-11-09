package scancmd

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/pacmandb"
	"github.com/kun9497/assay/internal/cataloger/rpmdb"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// D162: which OS package owns a probed file. The D160 probes read an npm
// tree and the Go binaries in the bin directories without saying who put
// them there, and on the measured images most of what they find is the
// distro's own -- ubi8/nodejs-18's node_modules is the npm and
// nodejs-nodemon RPMs' bundled tree, archlinux's captree is a pacman
// package's binary -- so a reader could not tell the distro's bundled copy,
// whose advisory is the OS package's, from one the image author installed.
// Every OS package database records its files: rpm in three header tags,
// apk inline in `installed`, dpkg in one `.list` per package, pacman in the
// `files` beside each `desc`. The rpm and apk lists come with the database
// already read; the dpkg and pacman files ride the probes' own layer pass
// (one more root each, no extra pass). Ownership is exact-file: a package
// that owns a directory says nothing about the files under it, which is
// how an image author's globally installed module under the RPM-owned
// usr/lib/node_modules stays unowned.

// fileOwners maps an image path, without its leading slash, to the OS
// package whose file list names it.
type fileOwners map[string]pkgmeta.Owner

func (o fileOwners) add(p string, pkg pkgmeta.Package) {
	o[strings.TrimPrefix(p, "/")] = pkgmeta.Owner{Name: pkg.Name, Version: pkg.Version}
}

// ownersFromRPM reads the file lists an rpmdb read collected.
func ownersFromRPM(res rpmdb.Result) fileOwners {
	o := fileOwners{}
	for p, i := range res.Files {
		o.add(p, res.Packages[i])
	}
	return o
}

// ownersFromAPK reads the F:/R: lines of the installed database the
// packages came from; a file whose record names a package Parse did not
// return (a record with no version, say) owns nothing.
func ownersFromAPK(installed []byte, pkgs []pkgmeta.Package) (fileOwners, error) {
	files, err := apkdb.ParseFiles(bytes.NewReader(installed))
	if err != nil {
		return nil, err
	}
	byName := map[string]pkgmeta.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	o := fileOwners{}
	for f, name := range files {
		if p, ok := byName[name]; ok {
			o.add(f, p)
		}
	}
	return o, nil
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

// addList reads one ownership list the probe pass collected and records its
// files against the OS package it belongs to: a dpkg list by the name (and
// arch) its filename spells, a pacman files by the desc beside it. A list
// for a package the inventory does not hold (removed but not purged, or a
// desc this build skipped) owns nothing. An unreadable list is an error:
// the file was read by the same pass as the package.json beside it.
func (o fileOwners) addList(name string, data []byte, osPkgs []pkgmeta.Package) error {
	switch {
	case strings.HasPrefix(name, dpkgdb.InfoDir+"/"):
		pkgName, arch := dpkgdb.ListOwner(path.Base(name))
		var owner *pkgmeta.Package
		for i := range osPkgs {
			p := &osPkgs[i]
			if p.Type == "deb" && p.Name == pkgName && (arch == "" || p.Arch == arch) {
				owner = p
				break
			}
		}
		if owner == nil {
			return nil
		}
		files, err := dpkgdb.ParseFileList(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}
		for _, f := range files {
			o.add(f, *owner)
		}
	case strings.HasPrefix(name, pacmanLocalDir+"/"):
		desc := path.Dir(name) + "/desc"
		var owner *pkgmeta.Package
		for i := range osPkgs {
			p := &osPkgs[i]
			if p.Type == "alpm" && len(p.Locations) > 0 && p.Locations[0].Path == desc {
				owner = p
				break
			}
		}
		if owner == nil {
			return nil
		}
		files, err := pacmandb.ParseFiles(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}
		for _, f := range files {
			o.add(f, *owner)
		}
	}
	return nil
}

// stamp sets OwnedBy on every location of pkgs whose path an OS package
// owns. Paths are compared without a leading slash on either side.
func (o fileOwners) stamp(pkgs []pkgmeta.Package) {
	if len(o) == 0 {
		return
	}
	for i := range pkgs {
		for j := range pkgs[i].Locations {
			if owner, ok := o[strings.TrimPrefix(pkgs[i].Locations[j].Path, "/")]; ok {
				owner := owner
				pkgs[i].Locations[j].OwnedBy = &owner
			}
		}
	}
}
