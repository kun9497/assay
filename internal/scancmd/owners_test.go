package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/source"
)

// D162, caller first: a probed package's location names the OS package
// whose file list holds it, through each of the four databases, and a
// location no OS package lists has no owner.

type ownedDoc struct {
	SchemaVersion int `json:"schemaVersion"`
	Findings      []struct {
		Package struct {
			Name      string `json:"name"`
			Locations []struct {
				Path    string `json:"path"`
				OwnedBy *struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"ownedBy"`
			} `json:"locations"`
		} `json:"package"`
	} `json:"findings"`
}

// ownersInJSON runs the image and returns, per finding path, the owner the
// JSON names ("" for none).
func ownersInJSON(t *testing.T, tarPath string) map[string]string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
	}
	var doc ownedDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out.String())
	}
	if doc.SchemaVersion != 19 {
		t.Errorf("schemaVersion = %d, want 19 (ownedBy is a schema change)", doc.SchemaVersion)
	}
	got := map[string]string{}
	for _, f := range doc.Findings {
		for _, l := range f.Package.Locations {
			if l.OwnedBy != nil {
				got[l.Path] = l.OwnedBy.Name + " " + l.OwnedBy.Version
			} else {
				got[l.Path] = ""
			}
		}
	}
	return got
}

const osReleaseDebianForOwners = "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"

// dpkg: the `.list` beside the status file names the files; the same
// package at a path no list names is unowned.
func TestRun_D162_DpkgListNamesTheOwnerOfTheNpmTree(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseDebianForOwners)},
		{name: dpkgDBPath, body: []byte("Package: npm\nStatus: install ok installed\nArchitecture: all\nVersion: 9.2.0~ds1-1\n\nPackage: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9\n\n")},
		{name: "var/lib/dpkg/info/npm.list", body: []byte("/.\n/usr\n/usr/lib\n/usr/lib/node_modules\n/usr/lib/node_modules/npm\n/usr/lib/node_modules/npm/node_modules/minimatch/package.json\n")},
		{name: "var/lib/dpkg/info/libc6:amd64.list", body: []byte("/.\n/usr/lib/x86_64-linux-gnu/libc.so.6\n")},
		// A sibling that is not a list is never read.
		{name: "var/lib/dpkg/info/npm.md5sums", body: []byte("not a list")},
		{name: "usr/lib/node_modules/npm/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
		// The image author's own global module: under the npm root, listed
		// by no package.
		{name: "usr/lib/node_modules/other/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
	})
	got := ownersInJSON(t, tarPath)
	if got["usr/lib/node_modules/npm/node_modules/minimatch/package.json"] != "npm 9.2.0~ds1-1" {
		t.Errorf("npm's bundled minimatch owner = %q, want npm 9.2.0~ds1-1 (all: %v)", got["usr/lib/node_modules/npm/node_modules/minimatch/package.json"], got)
	}
	if v, ok := got["usr/lib/node_modules/other/node_modules/minimatch/package.json"]; !ok || v != "" {
		t.Errorf("the unlisted copy: present=%v owner=%q, want present with no owner (all: %v)", ok, v, got)
	}
}

// apk: the installed database's own F:/R: lines.
func TestRun_D162_APKFileLinesNameTheOwnerOfTheGoBinary(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseAlpine319)},
		{name: apkDBPath, body: []byte("P:busybox-binsh\nV:1.36.1-r15\nA:x86_64\no:busybox\nF:bin\nR:sh\nF:usr/bin\nR:tool\n\n")},
		{name: "usr/bin/tool", body: bin, mode: 0o755},
		{name: "usr/bin/other", body: bin, mode: 0o755},
	})
	got := ownersInJSON(t, tarPath)
	if got["usr/bin/tool"] != "busybox-binsh 1.36.1-r15" {
		t.Errorf("usr/bin/tool owner = %q, want busybox-binsh 1.36.1-r15 (all: %v)", got["usr/bin/tool"], got)
	}
	if v, ok := got["usr/bin/other"]; !ok || v != "" {
		t.Errorf("usr/bin/other: present=%v owner=%q, want present with no owner", ok, v)
	}
}

// rpm: the BerkeleyDB fixture's passwd owns /usr/bin/passwd, and a Go
// binary put there is reported as its file.
func TestCatalogFromImage_D162_RPMHeaderFileListNamesTheOwner(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(bdbFixture)
	if err != nil {
		t.Fatal(err)
	}
	img := &source.Image{Layers: []source.Layer{layerWithModes(t, "sha256:rpm-owned", []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseRHEL8)},
		{name: "var/lib/rpm/Packages", body: db},
		{name: "usr/bin/passwd", body: bin, mode: 0o755},
		{name: "usr/bin/unlisted", body: bin, mode: 0o755},
	})}}
	target, _, _, err := catalogFromImage(context.Background(), "rpm-owned", img)
	if err != nil {
		t.Fatal(err)
	}
	assertOwners(t, target.Packages, map[string]*pkgmeta.Owner{
		"usr/bin/passwd":   {Name: "passwd", Version: "0.80-4.el8"},
		"usr/bin/unlisted": nil,
	})
}

// pacman: the `files` beside each desc.
func TestCatalogFromImage_D162_PacmanFilesNameTheOwner(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	img := &source.Image{Layers: []source.Layer{layerWithModes(t, "sha256:arch-owned", []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseArch)},
		{name: "var/lib/pacman/local/captree-0.3-1/desc", body: []byte(archDesc("captree", "0.3-1", "captree"))},
		{name: "var/lib/pacman/local/captree-0.3-1/files", body: []byte("%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n\n")},
		// A files whose desc this inventory does not hold owns nothing.
		{name: "var/lib/pacman/local/ghost-1-1/files", body: []byte("%FILES%\nusr/bin/other\n\n")},
		{name: "usr/bin/tool", body: bin, mode: 0o755},
		{name: "usr/bin/other", body: bin, mode: 0o755},
	})}}
	target, _, _, err := catalogFromImage(context.Background(), "arch-owned", img)
	if err != nil {
		t.Fatal(err)
	}
	assertOwners(t, target.Packages, map[string]*pkgmeta.Owner{
		"usr/bin/tool":  {Name: "captree", Version: "0.3-1"},
		"usr/bin/other": nil,
	})
}

// assertOwners checks every probed location at the given paths; a path with
// no package at all is a failure too (the probe must have found it).
func assertOwners(t *testing.T, pkgs []pkgmeta.Package, want map[string]*pkgmeta.Owner) {
	t.Helper()
	seen := map[string]bool{}
	for _, p := range pkgs {
		for _, l := range p.Locations {
			w, ok := want[l.Path]
			if !ok {
				continue
			}
			seen[l.Path] = true
			switch {
			case w == nil && l.OwnedBy != nil:
				t.Errorf("%s (%s): owned by %+v, want no owner", l.Path, p.Name, *l.OwnedBy)
			case w != nil && (l.OwnedBy == nil || *l.OwnedBy != *w):
				t.Errorf("%s (%s): owner = %+v, want %+v", l.Path, p.Name, l.OwnedBy, *w)
			}
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("no probed package is located at %s", path)
		}
	}
}

// The ownership roots join the probes' one pass: still six layer opens for
// the whole image (limits_test's count), and a list for a package the
// inventory does not hold, or an unreadable list name, owns nothing.
func TestFileOwners_UnknownOwnerAndLeadingSlash(t *testing.T) {
	o := fileOwners{}
	deb := []pkgmeta.Package{{Name: "npm", Version: "1", Type: "deb", Arch: "all"}, {Name: "libc6", Version: "2", Type: "deb", Arch: "amd64"}}
	if err := o.addList("var/lib/dpkg/info/ghost.list", []byte("/usr/bin/x\n"), deb); err != nil || len(o) != 0 {
		t.Errorf("a list for an uninventoried package: err=%v owners=%v", err, o)
	}
	if err := o.addList("var/lib/dpkg/info/libc6:i386.list", []byte("/usr/bin/x\n"), deb); err != nil || len(o) != 0 {
		t.Errorf("a list whose arch no package carries: err=%v owners=%v", err, o)
	}
	if err := o.addList("var/lib/dpkg/info/libc6:amd64.list", []byte("/usr/bin/x\n"), deb); err != nil || o["usr/bin/x"] != (pkgmeta.Owner{Name: "libc6", Version: "2"}) {
		t.Errorf("libc6:amd64.list: err=%v owners=%v", err, o)
	}
	pkgs := []pkgmeta.Package{{Name: "m", Locations: []pkgmeta.Location{{Path: "/usr/bin/x"}, {Path: "usr/bin/y"}}}}
	o.stamp(pkgs)
	if pkgs[0].Locations[0].OwnedBy == nil || pkgs[0].Locations[0].OwnedBy.Name != "libc6" {
		t.Errorf("a leading slash on the location must not hide the owner: %+v", pkgs[0].Locations[0])
	}
	if pkgs[0].Locations[1].OwnedBy != nil {
		t.Errorf("an unlisted path gained an owner: %+v", pkgs[0].Locations[1])
	}
}
