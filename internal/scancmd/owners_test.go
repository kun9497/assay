package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if doc.SchemaVersion != 21 {
		t.Errorf("schemaVersion = %d, want 21 (ownedBy is a schema change)", doc.SchemaVersion)
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

// Unit: a list for a package the inventory does not hold, or whose :arch no
// package carries, owns nothing; a list that does not read owns nothing and
// fails nothing; a location spelled with a leading slash still matches.
func TestFileOwners_UnknownOwnerUnreadableListAndLeadingSlash(t *testing.T) {
	o := newFileOwners(nil)
	deb := []pkgmeta.Package{{Name: "npm", Version: "1", Type: "deb", Arch: "all"}, {Name: "libc6", Version: "2", Type: "deb", Arch: "amd64"}}
	file := func(s string) source.FileFromLayer { return source.FileFromLayer{Data: []byte(s)} }
	o.addList("var/lib/dpkg/info/ghost.list", file("/usr/bin/x\n"), deb)
	o.addList("var/lib/dpkg/info/libc6:i386.list", file("/usr/bin/x\n"), deb)
	if len(o.lists) != 0 {
		t.Errorf("an uninventoried package or arch owns: %v", o.lists)
	}
	// A line past the scanner's bound: unreadable, and nothing before or
	// after it is kept either.
	o.addList("var/lib/dpkg/info/npm.list", file("/usr/bin/y\n/"+strings.Repeat("z", 70*1024)+"\n"), deb)
	if len(o.lists) != 0 {
		t.Errorf("an unreadable list owns: %d paths", len(o.lists))
	}
	o.addList("var/lib/dpkg/info/libc6:amd64.list", file("/usr/bin/x\n"), deb)
	pkgs := []pkgmeta.Package{{Name: "m", Locations: []pkgmeta.Location{{Path: "/usr/bin/x"}, {Path: "usr/bin/y"}}}}
	o.stamp(pkgs)
	if got := pkgs[0].Locations[0].OwnedBy; got == nil || *got != (pkgmeta.Owner{Name: "libc6", Version: "2"}) {
		t.Errorf("a leading slash on the location must not hide the owner: %+v", got)
	}
	if pkgs[0].Locations[1].OwnedBy != nil {
		t.Errorf("an unlisted path gained an owner: %+v", pkgs[0].Locations[1])
	}
}

// Layer order: the npm deb's list and its package.json share the image's
// first layer, so the file is npm's; the image author's later layer
// replaces that package.json (an `npm install -g` over the deb's tree),
// and the replacement is not the deb's file although its path is.
func TestRun_D162_AFileReplacedInALaterLayerIsNotTheOSPackages(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	deb := []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseDebianForOwners)},
		{name: dpkgDBPath, body: []byte("Package: npm\nStatus: install ok installed\nArchitecture: all\nVersion: 9.2.0~ds1-1\n\n")},
		{name: "var/lib/dpkg/info/npm.list", body: []byte("/usr/lib/node_modules/npm/node_modules/minimatch/package.json\n/usr/lib/node_modules/npm/node_modules/brace-expansion/package.json\n")},
		{name: "usr/lib/node_modules/npm/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
		{name: "usr/lib/node_modules/npm/node_modules/brace-expansion/package.json", body: []byte(`{"name":"brace-expansion","version":"1.1.11"}`)},
	}
	author := []probeLayerEntry{
		{name: "usr/lib/node_modules/npm/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
	}
	writeLayeredProbeImage(t, tarPath, deb, author)
	got := ownersInJSON(t, tarPath)
	if v, ok := got["usr/lib/node_modules/npm/node_modules/minimatch/package.json"]; !ok || v != "" {
		t.Errorf("the replaced file: present=%v owner=%q, want present and unowned (all: %v)", ok, v, got)
	}
}

// Merged /usr: a deb's list says /bin/tool for the regular file the probe
// finds at usr/bin/tool.
func TestCatalogFromImage_D162_MergedUsrListSpellingMatches(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	// A real merged-/usr image: bin is a symlink to usr/bin (QA 2026-11-10:
	// the twin spelling holds only where the image makes it true).
	img := &source.Image{Layers: []source.Layer{layerWithModes(t, "sha256:merged-usr", []probeLayerEntry{
		{name: "bin", link: "usr/bin"},
		{name: osReleasePath, body: []byte(osReleaseDebianForOwners)},
		{name: dpkgDBPath, body: []byte("Package: tool\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\n")},
		{name: "var/lib/dpkg/info/tool:amd64.list", body: []byte("/.\n/bin\n/bin/tool\n")},
		{name: "usr/bin/tool", body: bin, mode: 0o755},
	})}}
	target, _, _, err := catalogFromImage(context.Background(), "merged-usr", img)
	if err != nil {
		t.Fatal(err)
	}
	assertOwners(t, target.Packages, map[string]*pkgmeta.Owner{"usr/bin/tool": {Name: "tool", Version: "1.0-1"}})
}

// The layer rule holds for the rpm source too: the database in the base
// layer names /usr/bin/passwd, and a Go binary the author's later layer put
// at that path is not passwd's file.
func TestCatalogFromImage_D162_RPMOwnedPathReplacedLaterIsUnowned(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(bdbFixture)
	if err != nil {
		t.Fatal(err)
	}
	img := &source.Image{Layers: []source.Layer{
		layerWithModes(t, "sha256:rpm-base", []probeLayerEntry{
			{name: osReleasePath, body: []byte(osReleaseRHEL8)},
			{name: "var/lib/rpm/Packages", body: db},
		}),
		layerWithModes(t, "sha256:rpm-author", []probeLayerEntry{
			{name: "usr/bin/passwd", body: bin, mode: 0o755},
		}),
	}}
	target, _, _, err := catalogFromImage(context.Background(), "rpm-replaced", img)
	if err != nil {
		t.Fatal(err)
	}
	assertOwners(t, target.Packages, map[string]*pkgmeta.Owner{"usr/bin/passwd": nil})
}

func TestSpellings(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/usr/bin/tool", "usr/bin/tool|bin/tool"},
		{"bin/tool", "bin/tool|usr/bin/tool"},
		{"usr/lib64/x", "usr/lib64/x|lib64/x"},
		{"usr/lib/node_modules/npm/package.json", "usr/lib/node_modules/npm/package.json|lib/node_modules/npm/package.json"},
		{"opt/app/tool", "opt/app/tool"},
	} {
		if got := joinSpellings(spellings(tc.in, allMerged)); got != tc.want {
			t.Errorf("spellings(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// allMerged is a merged-/usr Debian's top-level links, for spellings' table.
var allMerged = map[string]topLink{"bin": {"usr/bin", 0}, "sbin": {"usr/sbin", 0}, "lib": {"usr/lib", 0}, "lib32": {"usr/lib32", 0}, "lib64": {"usr/lib64", 0}, "libx32": {"usr/libx32", 0}}

// joinSpellings renders spellings' paths for a table assertion.
func joinSpellings(ss []spelling) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.path
	}
	return strings.Join(out, "|")
}

// QA 2026-11-10: /lib and /usr/lib are two directories. The APK that owns
// lib/node_modules/minimatch/package.json does not own the independent copy at
// usr/lib/..., which the probe reads -- the twin spelling applies only when
// lib is a symlink to usr/lib. The same image with that link owns it.
func TestRun_QA1110_SplitUsrDoesNotLendTheOwner(t *testing.T) {
	apk := "P:qa-owner\nV:1.0-r0\nA:x86_64\nF:lib/node_modules/minimatch\nR:package.json\n\n"
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	for _, tc := range []struct {
		name  string
		link  bool
		owner string
	}{
		{"split /lib and /usr/lib", false, ""},
		{"lib -> usr/lib", true, "qa-owner 1.0-r0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := []probeLayerEntry{
				{name: osReleasePath, body: []byte(osReleaseAlpine319)},
				{name: apkDBPath, body: []byte(apk)},
				{name: "usr/lib/node_modules/minimatch/package.json", body: pkg},
			}
			if tc.link {
				entries = append([]probeLayerEntry{{name: "lib", link: "usr/lib"}}, entries...)
			} else {
				entries = append(entries, probeLayerEntry{name: "lib/node_modules/minimatch/package.json", body: pkg})
			}
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, entries)
			got := ownersInJSON(t, tarPath)
			if v, ok := got["usr/lib/node_modules/minimatch/package.json"]; !ok || v != tc.owner {
				t.Errorf("usr/lib minimatch: present=%v owner=%q, want %q (all: %v)", ok, v, tc.owner, got)
			}
		})
	}
}

// topLevelLinks resolves a link the way the kernel does at / and keeps only
// one that lands under usr/; spellings maps a path through those links in
// both directions, including Fedora's and Arch's sbin -> usr/bin.
func TestTopLevelLinks(t *testing.T) {
	got := topLevelLinks(map[string]source.Link{
		"bin":    {Target: "../usr/bin"},
		"sbin":   {Target: "usr/bin"}, // Fedora 42+ and Arch
		"lib":    {Target: "//usr/lib"},
		"lib64":  {Target: "./usr/lib"}, // Arch
		"lib32":  {Target: "usr/lib32", Hard: true},
		"libx32": {Target: "opt/libx32"}, // not under usr/: not a layout link
	}, func(string) int { return 0 })
	want := map[string]string{"bin": "usr/bin", "sbin": "usr/bin", "lib": "usr/lib", "lib64": "usr/lib"}
	if len(got) != len(want) {
		t.Fatalf("topLevelLinks = %v, want %v", got, want)
	}
	for d, w := range want {
		if got[d].target != w {
			t.Errorf("topLevelLinks[%s] = %q, want %q", d, got[d].target, w)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"sbin/tool", "sbin/tool|usr/bin/tool"},
		{"usr/bin/tool", "usr/bin/tool|bin/tool|sbin/tool"},
		{"lib64/ld.so", "lib64/ld.so|usr/lib/ld.so"},
		{"usr/sbin/tool", "usr/sbin/tool"},
		{"usr/lib32/x", "usr/lib32/x"},
	} {
		if s := joinSpellings(spellings(tc.in, got)); s != tc.want {
			t.Errorf("spellings(%q) = %q, want %q", tc.in, s, tc.want)
		}
	}
	if s := joinSpellings(spellings("usr/lib/x", nil)); s != "usr/lib/x" {
		t.Errorf("spellings with no link evidence = %q, want the exact path only", s)
	}
}

// PR #267 review: an upper layer that deletes a real lib64 directory and
// relinks lib64 -> usr/lib does not make the package that owned the old
// lib64/... files the owner of the independent usr/lib/... copy -- the record
// predates the link, so it was written through the directory the link
// replaced. The same link in the record's own layer (a merged-/usr install)
// still lends the owner, and a split layout lends nothing.
func TestRun_PR267_LinkNewerThanTheRecordDoesNotLendTheOwner(t *testing.T) {
	apk := "P:qa-owner\nV:1.0-r0\nA:x86_64\nF:lib64/node_modules/minimatch\nR:package.json\n\n"
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const probed = "usr/lib/node_modules/minimatch/package.json"
	base := []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseAlpine319)},
		{name: apkDBPath, body: []byte(apk)},
		{name: probed, body: pkg},
	}
	split := append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: "lib64/node_modules/minimatch/package.json", body: pkg})
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		owner  string
	}{
		{"split lib64 and usr/lib", [][]probeLayerEntry{split}, ""},
		{"lib64 relinked to usr/lib in a later layer", [][]probeLayerEntry{split, {{name: ".wh.lib64"}, {name: "lib64", link: "usr/lib"}}}, ""},
		{"lib64 -> usr/lib in the record's own layer", [][]probeLayerEntry{append([]probeLayerEntry{{name: "lib64", link: "usr/lib"}}, base...)}, "qa-owner 1.0-r0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			got := ownersInJSON(t, tarPath)
			if v, ok := got[probed]; !ok || v != tc.owner {
				t.Errorf("%s: present=%v owner=%q, want %q (all: %v)", probed, ok, v, tc.owner, got)
			}
		})
	}
}

// The same rule for a dpkg list: Debian's merged-/usr lists say /lib64/...,
// and a relink made after the list was written lends nothing.
func TestRun_PR267_DpkgListOlderThanTheLinkDoesNotLendTheOwner(t *testing.T) {
	db := "Package: libqa\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\n"
	list := "/.\n/lib64/node_modules/minimatch/package.json\n"
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const probed = "usr/lib/node_modules/minimatch/package.json"
	base := []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseDebianForOwners)},
		{name: dpkgDBPath, body: []byte(db)},
		{name: "var/lib/dpkg/info/libqa:amd64.list", body: []byte(list)},
		{name: probed, body: pkg},
	}
	split := append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: "lib64/node_modules/minimatch/package.json", body: pkg})
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		owner  string
	}{
		{"relinked in a later layer", [][]probeLayerEntry{split, {{name: ".wh.lib64"}, {name: "lib64", link: "usr/lib"}}}, ""},
		{"linked in the list's own layer", [][]probeLayerEntry{append([]probeLayerEntry{{name: "lib64", link: "usr/lib"}}, base...)}, "libqa 1.0-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			got := ownersInJSON(t, tarPath)
			if v, ok := got[probed]; !ok || v != tc.owner {
				t.Errorf("%s: present=%v owner=%q, want %q (all: %v)", probed, ok, v, tc.owner, got)
			}
		})
	}
}
