package source

import (
	"archive/tar"
	"context"
	"testing"
)

// Audit A10, per walker: something other than a regular file at a path in an
// upper layer shadows a lower layer's file at that path. The scan-level test
// (scancmd, TestCatalogFromImage_A10_*) holds Files and FilesUnder through the
// catalogers; these rows hold each shape on each walker, including the two
// walkers that test does not reach (FilesNamed for pacman, FilesMatching for
// Bitnami's markers).
func TestWalkers_A10_ANonFileShadowsTheLowerFile(t *testing.T) {
	const db = "lib/apk/db/installed"
	shapes := map[string][]entry{
		"directory":                  {node(db+"/", tar.TypeDir)},
		"directory with opaque":      {node(db+"/", tar.TypeDir), {name: db + "/.wh..wh..opq"}},
		"directory implied by child": {{name: db + "/x", body: "child"}},
		"character device":           {node(db, tar.TypeChar)},
		"block device":               {node(db, tar.TypeBlock)},
		"fifo":                       {node(db, tar.TypeFifo)},
	}
	for name, upper := range shapes {
		img := imageOf(layerOf(t, "sha256:base", map[string]string{db: "OLD-DB"}), layerOfOrdered(t, "sha256:top", upper...))
		got, err := img.Files(context.Background(), []string{db})
		if err != nil {
			t.Fatal(err)
		}
		if f, ok := got[db]; ok {
			t.Errorf("Files, %s: read %q from %s, which the upper layer replaced", name, f.Data, f.DiffID)
		}
	}

	walkers := []struct {
		name   string
		target string
		call   func(*Image) (map[string]FileFromLayer, int, error)
	}{
		{"FilesUnder", "var/lib/dpkg/status.d/libc6", func(img *Image) (map[string]FileFromLayer, int, error) {
			return img.FilesUnder(context.Background(), "var/lib/dpkg/status.d")
		}},
		{"FilesNamed", "var/lib/pacman/local/zlib-1.3-1/desc", func(img *Image) (map[string]FileFromLayer, int, error) {
			return img.FilesNamed(context.Background(), "var/lib/pacman/local", "desc")
		}},
		{"FilesMatching", "opt/bitnami/redis/.spdx-redis.spdx", func(img *Image) (map[string]FileFromLayer, int, error) {
			return img.FilesMatching(context.Background(), "opt/bitnami", ".spdx-", ".spdx")
		}},
	}
	for _, w := range walkers {
		for name, upper := range map[string][]entry{
			"directory":                  {node(w.target+"/", tar.TypeDir)},
			"directory with opaque":      {node(w.target+"/", tar.TypeDir), {name: w.target + "/.wh..wh..opq"}},
			"directory implied by child": {{name: w.target + "/x", body: "child"}},
			"fifo":                       {node(w.target, tar.TypeFifo)},
		} {
			img := imageOf(layerOf(t, "sha256:base", map[string]string{w.target: "OLD"}), layerOfOrdered(t, "sha256:top", upper...))
			got, _, err := w.call(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := got[w.target]; ok {
				t.Errorf("%s, %s: returned the lower layer's %s, which the upper layer replaced", w.name, name, w.target)
			}
		}
	}
}

// What the shadowing must not do: a directory at a sibling name (".../installed2/")
// or a prefix of the path's last segment ("instal/") is not the path; and a
// contiguous file ('7', which the walkers read like an old GNU sparse 'S')
// at the path is a file, read rather than shadowed.
func TestWalkers_A10_OnlyThePathItselfIsShadowed(t *testing.T) {
	const db = "lib/apk/db/installed"
	img := imageOf(
		layerOf(t, "sha256:base", map[string]string{db: "OLD-DB"}),
		layerOfOrdered(t, "sha256:top", node(db+"2/", tar.TypeDir), entry{name: db + "2/x", body: "x"}, node("lib/apk/db/instal/", tar.TypeDir)),
	)
	got, err := img.Files(context.Background(), []string{db})
	if err != nil {
		t.Fatal(err)
	}
	if string(got[db].Data) != "OLD-DB" {
		t.Errorf("Files = %q, want the base layer's OLD-DB: nothing replaced the path itself", got[db].Data)
	}

	img = imageOf(
		layerOf(t, "sha256:base", map[string]string{db: "OLD-DB"}),
		layerOfOrdered(t, "sha256:top", entry{name: db, body: "NEW-DB", typ: tar.TypeCont}),
	)
	got, err = img.Files(context.Background(), []string{db})
	if err != nil {
		t.Fatal(err)
	}
	if string(got[db].Data) != "NEW-DB" {
		t.Errorf("Files = %q, want the contiguous file's own NEW-DB", got[db].Data)
	}
}

// D130's ceiling holds for the shadow too: a hardlink made in a lower layer
// reads its target as of that layer, so a directory that replaced the target
// in a LATER layer does not shadow it for the hardlink.
func TestFiles_A10_AShadowAboveAHardlinksLayerDoesNotHideItsTarget(t *testing.T) {
	for name, upper := range map[string][]entry{
		"directory at the path":        {node("usr/lib/os-release/", tar.TypeDir)},
		"directory implied by a child": {{name: "usr/lib/os-release/x", body: "child"}},
	} {
		img := imageOf(
			layerOfOrdered(t, "sha256:base",
				entry{name: "usr/lib/os-release", body: "ID=alpine"},
				hard("etc/os-release", "usr/lib/os-release"),
			),
			layerOfOrdered(t, "sha256:top", upper...),
		)
		got, err := img.Files(context.Background(), []string{"etc/os-release"})
		if err != nil {
			t.Fatal(err)
		}
		if string(got["etc/os-release"].Data) != "ID=alpine" {
			t.Errorf("%s: Files(etc/os-release) = %q, want the hardlink's own ID=alpine", name, got["etc/os-release"].Data)
		}
	}
}
