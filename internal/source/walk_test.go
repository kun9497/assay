package source

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

type entry struct{ name, body string }

// layerOf builds a one-layer tar from path -> contents. Entry order is
// unspecified because Go map iteration is random; tests whose subject is
// ordering must use layerOfOrdered instead.
func layerOf(t *testing.T, diffID string, files map[string]string) Layer {
	t.Helper()
	es := make([]entry, 0, len(files))
	for n, b := range files {
		es = append(es, entry{n, b})
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
		name, body := e.name, e.body
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
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
		entry{"etc/.wh.os-release", ""},
		entry{"etc/os-release", "present"},
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
		entry{"etc/.wh..wh..opq", ""},
		entry{"etc/os-release", "present"},
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
