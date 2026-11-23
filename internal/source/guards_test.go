package source

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// QA 2026-11-20: two guards nothing held.

func TestConfigDiffIDs_TheCountMustMatchTheLayers(t *testing.T) {
	img := platformImage(t, plat("linux/amd64"))
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	n := len(cf.RootFS.DiffIDs)
	for layers, ok := range map[int]bool{n: true, n + 1: false, n - 1: false} {
		if _, err := configDiffIDs(img, layers); (err == nil) != ok {
			t.Errorf("%d layers against %d diff ids: err = %v", layers, n, err)
		}
	}
}

func TestImageFromIndex_DepthIsBounded(t *testing.T) {
	nest := func(depth int) v1.ImageIndex {
		p := plat("linux/amd64")
		var idx v1.ImageIndex = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: platformImage(t, p), Descriptor: v1.Descriptor{Platform: &p}})
		for i := 1; i < depth; i++ {
			idx = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: idx})
		}
		return idx
	}
	for depth, ok := range map[int]bool{maxIndexDepth: true, maxIndexDepth + 1: false} {
		idx := nest(depth)
		parent, err := idx.Digest()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = imageFromIndex(context.Background(), v1Index{idx: idx}, "x", parent, plat("linux/amd64"), false)
		if (err == nil) != ok || (!ok && !strings.Contains(err.Error(), "nests indexes more than")) {
			t.Errorf("depth %d: err = %v", depth, err)
		}
	}
}
