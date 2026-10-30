package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/source"
)

// rawLayer is a layer of tar headers written exactly as given, for the shapes
// buildTar's regular files cannot express: a directory, a device, a FIFO, an
// opaque marker.
func rawLayer(t *testing.T, diffID string, hs ...tar.Header) source.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hs {
		h := h
		if h.Mode == 0 {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	return source.Layer{DiffID: diffID, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}
}

// 2026-10-22 audit A10: an upper layer that put something other than a
// regular file at a path the scan reads -- a directory, a device, a FIFO --
// neither answered the read nor ended it, so the lower layer's deleted copy
// was read: a package database the running image does not have, reported as
// its inventory, with no symptom. A file turned into a directory carries no
// ".wh.<name>" (only "<name>/" and, when the build replaced it outright, an
// opaque marker inside it), so the whiteout rules never fired either. The
// runtime filesystem shows the directory, so the scan must see no file there.
func TestCatalogFromImage_A10_ANonFileInAnUpperLayerShadowsTheLowerFile(t *testing.T) {
	apkDB := "P:busybox\nV:1.36.1-r15\nA:x86_64\no:busybox\n\n"
	stanza := "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\nSource: glibc\n\n"
	for _, tc := range []struct {
		name  string
		base  map[string]string
		upper []tar.Header
		gone  string
	}{
		{"apk database replaced by a directory, opaque", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkDB},
			[]tar.Header{{Name: apkDBPath + "/", Typeflag: tar.TypeDir}, {Name: apkDBPath + "/.wh..wh..opq", Typeflag: tar.TypeReg}}, "busybox"},
		{"apk database replaced by a directory implied by a child", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkDB},
			[]tar.Header{{Name: apkDBPath + "/x", Typeflag: tar.TypeReg}}, "busybox"},
		{"apk database replaced by a FIFO", map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkDB},
			[]tar.Header{{Name: apkDBPath, Typeflag: tar.TypeFifo}}, "busybox"},
		{"status.d stanza replaced by a directory", map[string]string{osReleasePath: osReleaseDebian12, dpkgStatusDir + "/libc6": stanza},
			[]tar.Header{{Name: dpkgStatusDir + "/libc6/", Typeflag: tar.TypeDir}}, "libc6"},
		{"status.d stanza replaced by a character device", map[string]string{osReleasePath: osReleaseDebian12, dpkgStatusDir + "/libc6": stanza},
			[]tar.Header{{Name: dpkgStatusDir + "/libc6", Typeflag: tar.TypeChar}}, "libc6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := &source.Image{Layers: []source.Layer{
				imageLayer(t, "sha256:base", tc.base),
				rawLayer(t, "sha256:upper", tc.upper...),
			}}
			// With the only database shadowed the image has none, and the scan
			// says so (exit 2) rather than reading the deleted one.
			target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
			if err != nil {
				if !strings.Contains(err.Error(), "no supported package database found") {
					t.Fatalf("catalogFromImage: %v", err)
				}
				return
			}
			for _, p := range target.Packages {
				if p.Name == tc.gone {
					t.Errorf("%s is cataloged from the lower layer's file, which the upper layer replaced", tc.gone)
				}
			}
		})
	}
}
