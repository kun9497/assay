package source

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

type entry struct {
	name, body string
	link       string // non-empty makes this a link entry, as tar carries it
	hardlink   bool   // a hardlink rather than a symlink; targets resolve differently
}

func sym(name, target string) entry { return entry{name: name, link: target} }

func hard(name, target string) entry {
	return entry{name: name, link: target, hardlink: true}
}

// layerOf builds a one-layer tar from path -> contents. Entry order is
// unspecified because Go map iteration is random; tests whose subject is
// ordering must use layerOfOrdered instead.
func layerOf(t *testing.T, diffID string, files map[string]string) Layer {
	t.Helper()
	es := make([]entry, 0, len(files))
	for n, b := range files {
		es = append(es, entry{name: n, body: b})
	}
	return layerOfOrdered(t, diffID, es...)
}

// layerOfOrdered writes entries in the given order. A whiteout's position
// within its own layer decides whether a correct reader ignores it, so a test
// of that property cannot leave the order to a map.
func layerOfOrdered(t *testing.T, diffID string, files ...entry) Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range files {
		if e.link != "" {
			// A symlink header carries no payload: reading it yields zero bytes,
			// which is exactly how a reader that ignores Typeflag goes wrong.
			kind := byte(tar.TypeSymlink)
			if e.hardlink {
				kind = tar.TypeLink
			}
			if err := tw.WriteHeader(&tar.Header{
				Name: e.name, Mode: 0o777, Typeflag: kind, Linkname: e.link,
			}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	return Layer{
		DiffID: diffID,
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil },
	}
}

func imageOf(ls ...Layer) *Image { return &Image{Layers: ls} }

// A later layer wins. Without this an image that upgrades a package still
// reports the base layer's version.
func TestFiles_TakesTheNewestLayerThatHasIt(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"etc/os-release": "old"}),
		layerOf(t, "sha256:top", map[string]string{"etc/os-release": "new"}),
	)
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got["etc/os-release"]
	if !ok {
		t.Fatal("etc/os-release not found")
	}
	if string(f.Data) != "new" {
		t.Errorf("Data = %q, want the upper layer's %q", f.Data, "new")
	}
	// Layer attribution is a reported field: it must name the layer the bytes
	// actually came from, not the one that happened to be read first.
	if f.DiffID != "sha256:top" {
		t.Errorf("DiffID = %q, want sha256:top", f.DiffID)
	}
}

// A file only in the base layer is still present: nothing deleted it.
func TestFiles_FallsThroughToLowerLayers(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"lib/apk/db/installed": "db"}),
		layerOf(t, "sha256:top", map[string]string{"usr/bin/thing": "x"}),
	)
	got, err := img.Files([]string{"lib/apk/db/installed"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["lib/apk/db/installed"]; !ok || string(f.Data) != "db" {
		t.Errorf("got %+v, want the base layer's copy", got)
	}
}

// The whiteout marker deletes the lower layer's copy. Without this a package
// removed by `apk del` in a later layer is reported as still installed —
// findings against software that is not there.
func TestFiles_WhiteoutHidesLowerLayer(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"lib/apk/db/installed": "db"}),
		layerOf(t, "sha256:top", map[string]string{"lib/apk/db/.wh.installed": ""}),
	)
	got, err := img.Files([]string{"lib/apk/db/installed"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["lib/apk/db/installed"]; ok {
		t.Errorf("found %q, but a whiteout deleted it", f.Data)
	}
}

// The opaque marker deletes every child of its directory, not only the ones
// named. Treating it as an ordinary whiteout would delete a file literally
// called ".wh..wh..opq" and keep the rest.
func TestFiles_OpaqueWhiteoutHidesEveryChild(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{
			"lib/apk/db/installed": "db",
			"lib/apk/db/scripts":   "s",
		}),
		layerOf(t, "sha256:top", map[string]string{"lib/apk/db/.wh..wh..opq": ""}),
	)
	got, err := img.Files([]string{"lib/apk/db/installed", "lib/apk/db/scripts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: an opaque whiteout clears the directory", got)
	}
}

// The opaque marker is recursive.
func TestFiles_OpaqueWhiteoutIsRecursive(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"a/b/c/deep": "x"}),
		layerOf(t, "sha256:top", map[string]string{"a/.wh..wh..opq": ""}),
	)
	got, err := img.Files([]string{"a/b/c/deep"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: opaque whiteouts cover descendants", got)
	}
}

// A whiteout is an instruction, never a result. Returning it would hand the
// apk parser the literal bytes of a marker file.
func TestFiles_WhiteoutEntriesAreNeverReturned(t *testing.T) {
	img := imageOf(layerOf(t, "sha256:top", map[string]string{"lib/apk/db/.wh.installed": ""}))
	got, err := img.Files([]string{"lib/apk/db/.wh.installed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: whiteouts are instructions", got)
	}
}

// Whiteouts apply downward only. One in the base layer must not hide a file
// a later layer installed — that would delete packages that are present.
func TestFiles_WhiteoutDoesNotApplyUpward(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"etc/.wh.os-release": ""}),
		layerOf(t, "sha256:top", map[string]string{"etc/os-release": "present"}),
	)
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["etc/os-release"]; !ok || string(f.Data) != "present" {
		t.Errorf("got %+v, want the upper layer's file: whiteouts only look down", got)
	}
}

// A whiteout in the same layer as the file it names does not delete it: the
// spec says whiteouts apply to lower layers only.
func TestFiles_WhiteoutDoesNotApplyWithinItsOwnLayer(t *testing.T) {
	// The whiteout is written FIRST, deliberately. If a reader records
	// whiteouts into the cross-layer set as it goes, this order is what makes
	// it delete a file in its own layer; the reverse order hides the bug. A map
	// would decide that at random, so this test passed for months of runs and
	// proved nothing.
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "etc/.wh.os-release", body: ""},
		entry{name: "etc/os-release", body: "present"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["etc/os-release"]; !ok {
		t.Error("a whiteout deleted a file in its own layer; it applies to lower layers only")
	}
}

// The same for an opaque marker written before the entries it would cover.
func TestFiles_OpaqueWhiteoutDoesNotApplyWithinItsOwnLayer(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "etc/.wh..wh..opq", body: ""},
		entry{name: "etc/os-release", body: "present"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["etc/os-release"]; !ok {
		t.Error("an opaque whiteout cleared its own layer; it applies to lower layers only")
	}
}

// Tar entries appear as "lib/apk/db/installed" from some builders and
// "./lib/apk/db/installed" from others. Comparing raw names makes the lookup
// miss depending on which tool built the image, and a miss here is an empty
// inventory rather than an error.
func TestFiles_NormalisesEntryNames(t *testing.T) {
	img := imageOf(layerOf(t, "sha256:one", map[string]string{"./etc/os-release": "x"}))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["etc/os-release"]; !ok {
		t.Errorf("got %+v; a leading ./ must not hide the file", got)
	}
}

// Wanting a file no layer carries is not an error — an image without an apk
// database is a real image, and the caller decides what that means.
func TestFiles_MissingIsNotAnError(t *testing.T) {
	img := imageOf(layerOf(t, "sha256:one", map[string]string{"a": "b"}))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
	}
}

// /etc/os-release is a regular file in alpine:3.19 and a SYMLINK to
// ../usr/lib/os-release in alpine:3.21, alpine:latest, debian:12 and
// ubuntu:24.04. A symlink's tar entry carries no payload, so a reader that
// treats it as a file returns zero bytes and marks the path resolved — "found
// it, here is nothing" for a path it never followed.
func TestFiles_FollowsRelativeSymlink(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		sym("etc/os-release", "../usr/lib/os-release"),
		entry{name: "usr/lib/os-release", body: "ID=alpine"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got["etc/os-release"]
	if !ok {
		t.Fatal("etc/os-release not resolved through its symlink")
	}
	if string(f.Data) != "ID=alpine" {
		t.Errorf("Data = %q, want the link target's contents", f.Data)
	}
}

// An absolute target is relative to the image root, not to the link.
func TestFiles_FollowsAbsoluteSymlink(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		sym("etc/os-release", "/usr/lib/os-release"),
		entry{name: "usr/lib/os-release", body: "ID=debian"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["etc/os-release"]; !ok || string(f.Data) != "ID=debian" {
		t.Errorf("got %+v, want the root-relative target's contents", got)
	}
}

// The target commonly lives in a lower layer than the link.
func TestFiles_FollowsSymlinkAcrossLayers(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"usr/lib/os-release": "ID=alpine"}),
		layerOfOrdered(t, "sha256:top", sym("etc/os-release", "../usr/lib/os-release")),
	)
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["etc/os-release"]; !ok || string(f.Data) != "ID=alpine" {
		t.Errorf("got %+v, want the base layer's target", got)
	}
}

// A cycle must terminate rather than spin.
func TestFiles_SymlinkCycleTerminates(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		sym("a", "b"),
		sym("b", "a"),
	))
	got, err := img.Files([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: a cycle resolves to no file", got)
	}
}

// A whiteout names a path, and that path can be a directory: `RUN rm -rf
// /lib/apk` emits lib/.wh.apk. Matching only exactly leaves the packages of a
// deleted apk database reported as installed.
func TestFiles_WhiteoutOnADirectoryRemovesItsContents(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"lib/apk/db/installed": "db"}),
		layerOf(t, "sha256:top", map[string]string{"lib/.wh.apk": ""}),
	)
	got, err := img.Files([]string{"lib/apk/db/installed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing: the whole directory was deleted", got)
	}
}

// ...but a whiteout must not delete a sibling whose name merely shares a
// prefix. lib/.wh.apk deletes lib/apk, never lib/apktool.
func TestFiles_DirectoryWhiteoutIsNotAPrefixMatch(t *testing.T) {
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{"lib/apktool/data": "keep"}),
		layerOf(t, "sha256:top", map[string]string{"lib/.wh.apk": ""}),
	)
	got, err := img.Files([]string{"lib/apktool/data"})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got["lib/apktool/data"]; !ok || string(f.Data) != "keep" {
		t.Errorf("got %+v, want lib/apktool/data: it is not under lib/apk", got)
	}
}

// A relative target with no ".." is where the two possible readings diverge.
// "../usr/lib/os-release" from etc/ resolves to usr/lib/os-release whether you
// join it to the link's directory or treat it as root-relative — the ".."
// cancels the "etc". "alpine-release" does not: joined it is etc/alpine-release,
// treated as root-relative it is alpine-release, and only one of those exists.
func TestFiles_RelativeSymlinkIsJoinedToTheLinksDirectory(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		sym("etc/os-release", "alpine-release"),
		entry{name: "etc/alpine-release", body: "3.19.9"},
		entry{name: "alpine-release", body: "WRONG: this is the root copy"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got["etc/os-release"]
	if !ok {
		t.Fatal("etc/os-release not resolved")
	}
	if string(f.Data) != "3.19.9" {
		t.Errorf("Data = %q, want etc/alpine-release; a relative target is "+
			"relative to the link, not to the image root", f.Data)
	}
}

// A hardlink's Linkname is relative to the archive root, not to the link's
// directory — the opposite of a symlink. Resolving one like the other turns
// "usr/lib/os-release" into "etc/usr/lib/os-release" and finds nothing.
func TestFiles_HardlinkTargetIsRootRelative(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		hard("etc/os-release", "usr/lib/os-release"),
		entry{name: "usr/lib/os-release", body: "ID=alpine"},
	))
	got, err := img.Files([]string{"etc/os-release"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got["etc/os-release"]
	if !ok {
		t.Fatal("etc/os-release not resolved through its hardlink")
	}
	if string(f.Data) != "ID=alpine" {
		t.Errorf("Data = %q, want the root-relative target's contents", f.Data)
	}
}
