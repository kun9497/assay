package source

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// labelled is a platform image whose digest differs by label.
func labelled(t *testing.T, label string) (v1.Image, string) {
	t.Helper()
	img, err := mutate.Config(platformImage(t, plat("linux/amd64")), v1.Config{Labels: map[string]string{"v": label}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return img, d.String()
}

func named(n string) layout.Option {
	return layout.WithAnnotations(map[string]string{refNameAnnotation: n})
}

// QA 2026-11-20. A layout directory written twice was scanned as its first
// image, and the newer one was never read.
func TestOpen_LayoutHoldingTwoImagesOfOnePlatform(t *testing.T) {
	setHostPlatform(t, "linux/amd64")
	dir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	one, oneDigest := labelled(t, "1")
	two, twoDigest := labelled(t, "2")
	for n, img := range map[string]v1.Image{"1.0": one, "2.0": two} {
		if err := lp.AppendImage(img, layout.WithPlatform(plat("linux/amd64")), named(n)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = Open(context.Background(), "oci-dir:"+dir, "")
	if err == nil {
		t.Fatal("a layout holding two linux/amd64 images was scanned; want a refusal")
	}
	for _, want := range []string{"holds 2 different linux/amd64 images", "1.0 (" + oneDigest + ")", "2.0 (" + twoDigest + ")", "@<ref name or digest>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	for which, want := range map[string]string{"1.0": oneDigest, "2.0": twoDigest, oneDigest: oneDigest, twoDigest: twoDigest} {
		img, err := Open(context.Background(), "oci-dir:"+dir+"@"+which, "")
		if err != nil {
			t.Errorf("@%s: %v", which, err)
			continue
		}
		if img.Platform.ManifestDigest != want {
			t.Errorf("@%s scanned %s, want %s", which, img.Platform.ManifestDigest, want)
		}
	}
	if _, err := Open(context.Background(), "oci-dir:"+dir+"@3.0", ""); err == nil || !strings.Contains(err.Error(), `no entry named "3.0"`) {
		t.Errorf("@3.0: err = %v, want it refused", err)
	}
}

// What is not a tie: one image under two names, and a multi-platform layout.
// A name two images share is settled by digest only.
func TestOpen_LayoutThatIsNotATie(t *testing.T) {
	setHostPlatform(t, "linux/amd64")
	dir := filepath.Join(t.TempDir(), "lay@out") // an "@" in a real path is the path's
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	one, oneDigest := labelled(t, "1")
	for _, n := range []string{"1.0", "latest"} {
		if err := lp.AppendImage(one, layout.WithPlatform(plat("linux/amd64")), named(n)); err != nil {
			t.Fatal(err)
		}
	}
	arm := platformImage(t, plat("linux/arm64"))
	if err := lp.AppendImage(arm, layout.WithPlatform(plat("linux/arm64")), named("latest")); err != nil {
		t.Fatal(err)
	}
	img, err := Open(context.Background(), "oci-dir:"+dir, "")
	if err != nil || img.Platform.ManifestDigest != oneDigest {
		t.Fatalf("Open = %v, %v; want the one amd64 image", img, err)
	}
	if img, err := Open(context.Background(), "oci-dir:"+dir+"@"+oneDigest, ""); err != nil || img.Platform.ManifestDigest != oneDigest {
		t.Errorf("one image listed twice, by digest: %v", err)
	}
	if _, err := Open(context.Background(), "oci-dir:"+dir+"@latest", ""); err == nil || !strings.Contains(err.Error(), "select one by digest") {
		t.Errorf("@latest names two entries: err = %v, want a refusal", err)
	}
}

// The entry of the layout is the unit of the tie: two different images inside
// one index are that index's own order, the same image inside two indexes is
// one image, and a registry index is not a layout.
func TestOpen_LayoutTieIsBetweenTopLevelEntries(t *testing.T) {
	setHostPlatform(t, "linux/amd64")
	one, oneDigest := labelled(t, "1")
	two, _ := labelled(t, "2")
	index := func(imgs ...v1.Image) v1.ImageIndex {
		var idx v1.ImageIndex = empty.Index
		for _, img := range imgs {
			p := plat("linux/amd64")
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
		}
		return idx
	}
	for name, tc := range map[string]struct {
		roots []v1.ImageIndex
		tie   bool
	}{
		"two images in one index":                {[]v1.ImageIndex{index(one, two)}, false},
		"one image in two indexes":               {[]v1.ImageIndex{index(one), index(one, one)}, false},
		"different images in two indexes":        {[]v1.ImageIndex{index(one), index(two)}, true},
		"three indexes, two of them one image's": {[]v1.ImageIndex{index(one), index(two), index(two, two)}, true},
	} {
		dir := filepath.Join(t.TempDir(), "layout")
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range tc.roots {
			if err := lp.AppendIndex(r); err != nil {
				t.Fatal(err)
			}
		}
		img, err := Open(context.Background(), "oci-dir:"+dir, "")
		if tc.tie {
			if err == nil || !strings.Contains(err.Error(), "holds 2 different linux/amd64 images") {
				t.Errorf("%s: err = %v, want a tie between two images", name, err)
				continue
			}
			// What the refusal names is what the selector takes.
			d, _ := tc.roots[0].Digest()
			if !strings.Contains(err.Error(), d.String()) {
				t.Errorf("%s: %q does not name %s", name, err, d)
			}
			if img, err := Open(context.Background(), "oci-dir:"+dir+"@"+d.String(), ""); err != nil || img.Platform.ManifestDigest != oneDigest {
				t.Errorf("%s: selecting %s: %v", name, d, err)
			}
			continue
		}
		if err != nil || img.Platform.ManifestDigest != oneDigest {
			t.Errorf("%s: err = %v, want the first image", name, err)
		}
	}

	parent, _ := index(one, two).Digest()
	if _, choice, err := imageFromIndex(context.Background(), v1Index{idx: index(one, two)}, "registry", parent, plat("linux/amd64"), false); err != nil || choice.ManifestDigest != oneDigest {
		t.Errorf("a registry index: %v, %v; want its first image", choice, err)
	}
}
