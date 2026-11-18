package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Open is the boundary used by a scan. A descriptor must bound the read,
// even if its blob is valid JSON with a matching digest and lots of padding.
func TestOpen_LayoutMetadataMustFitDescriptor(t *testing.T) {
	for _, kind := range []string{"manifest", "nested index"} {
		for _, tc := range []struct {
			name    string
			size    func(int64) int64
			padding int
			// want is everything after the digest, or nil for a layout that
			// opens. The whole message is compared, target included: "100
			// MiB limit" alone is in two of these rows, and a nested index's
			// refusal once reached the user naming no target at all.
			want func(n int64) string
		}{
			{"exact size", func(n int64) int64 { return n }, 0, nil},
			{"negative", func(int64) int64 { return -1 }, 0, func(int64) string {
				return " declares -1 bytes, outside the 0 to 100 MiB limit (D112)"
			}},
			{"over limit", func(int64) int64 { return maxArchiveManifestBytes + 1 }, 0, func(int64) string {
				return " declares 104857601 bytes, outside the 0 to 100 MiB limit (D112)"
			}},
			{"shorter than declared", func(n int64) int64 { return n + 1 }, 0, func(n int64) string {
				return fmt.Sprintf(" contains %d bytes, descriptor declares %d", n, n+1)
			}},
			{"understated padded blob", func(int64) int64 { return 1 }, 20 << 20, func(int64) string {
				return " is longer than its descriptor declares (size 1)"
			}},
			// A descriptor that omits size decodes to this one. The blob is
			// refused because the descriptor is what bounds the read, and the
			// message must not present 0 bytes as a limit of the scanner's.
			{"size zero or omitted", func(int64) int64 { return 0 }, 0, func(int64) string {
				return " is longer than its descriptor declares (size 0)"
			}},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				lp, err := layout.Write(dir, empty.Index)
				if err != nil {
					t.Fatal(err)
				}
				img := platformImage(t, plat("linux/amd64"))
				if err := lp.WriteImage(img); err != nil {
					t.Fatal(err)
				}
				raw, err := img.RawManifest()
				if err != nil {
					t.Fatal(err)
				}
				desc := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, raw), Size: int64(len(raw))}
				if kind == "nested index" {
					raw, err = json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{desc}})
					if err != nil {
						t.Fatal(err)
					}
					desc.MediaType = types.OCIImageIndex
				}
				raw = append(raw, bytes.Repeat([]byte{' '}, tc.padding)...)
				desc.Digest = writeBlob(t, lp, raw)
				desc.Size = tc.size(int64(len(raw)))
				if err := lp.AppendDescriptor(desc); err != nil {
					t.Fatal(err)
				}
				_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
				if tc.want == nil {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				want := "read oci layout oci-dir:" + dir + ": layout metadata " + desc.Digest.String() + tc.want(int64(len(raw)))
				if err == nil || err.Error() != want {
					t.Fatalf("Open = %v\nwant   %s", err, want)
				}
			})
		}
	}
}

// The image an index walk settles on is read after the walk, on a return of
// its own. A refusal there is this file's too, and names the layout like the
// others.
func TestOpen_LayoutChosenImageRefusalNamesTheLayout(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	var bad v1.Hash
	for _, p := range []string{"linux/amd64", "linux/arm64"} {
		img := platformImage(t, plat(p))
		if err := lp.WriteImage(img); err != nil {
			t.Fatal(err)
		}
		raw, err := img.RawManifest()
		if err != nil {
			t.Fatal(err)
		}
		pl := plat(p)
		d := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, raw), Size: int64(len(raw)), Platform: &pl}
		if p == "linux/amd64" {
			d.Size, bad = 0, d.Digest
		}
		if err := lp.AppendDescriptor(d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(t.Context(), "oci-dir:"+dir, "linux/arm64"); err != nil {
		t.Fatalf("the sound image of the same layout: %v", err)
	}
	_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
	want := "read oci layout oci-dir:" + dir + ": layout metadata " + bad.String() + " is longer than its descriptor declares (size 0)"
	if err == nil || err.Error() != want {
		t.Fatalf("Open = %v\nwant   %s", err, want)
	}
	// The other half of the same rule: a walk error that named the target
	// itself is passed through as it came. Wrapping it too would print the
	// layout twice, and a substring check could not tell.
	_, err = Open(t.Context(), "oci-dir:"+dir, "linux/riscv64")
	if err == nil || strings.HasPrefix(err.Error(), "read oci layout ") || strings.Count(err.Error(), "oci-dir:"+dir) != 1 {
		t.Fatalf("platform miss = %v\nwant the target named once, by the walk", err)
	}
}

func TestOpen_LayoutRootIndexIsBounded(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(platformImage(t, plat("linux/amd64"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "index.json"), maxArchiveManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
	want := "read oci layout oci-dir:" + dir + ": layout index.json exceeds the 100 MiB limit (D112)"
	if err == nil || err.Error() != want {
		t.Fatalf("Open = %v\nwant   %s", err, want)
	}
}

func TestOpen_LayoutMetadataHonorsCanceledContext(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(platformImage(t, plat("linux/amd64"))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Open(ctx, "oci-dir:"+dir, "linux/amd64")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open = %v, want context.Canceled", err)
	}
}

func TestOpen_LayoutRootIndexMustBeRegular(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "index.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
	want := "read oci layout oci-dir:" + dir + ": layout index.json is a directory, not a regular file"
	if err == nil || err.Error() != want {
		t.Fatalf("Open = %v\nwant   %s", err, want)
	}
}

// layoutSymlink links, or skips where this account may not: creating a
// symbolic link on Windows needs a privilege most accounts lack. Nothing else
// skips -- a link that cannot be made for any other reason fails the test, and
// Linux and macOS, where CI runs it, never take the branch.
func layoutSymlink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	const privilegeNotHeld = syscall.Errno(1314) // ERROR_PRIVILEGE_NOT_HELD
	if runtime.GOOS == "windows" && errors.Is(err, privilegeNotHeld) {
		t.Skipf("this Windows account may not create symbolic links: %v", err)
	}
	t.Fatal(err)
}

// An index.json that is a link to a regular file is a layout: a symlink tree
// (Bazel runfiles, a linked store) is laid out that way, blob reads follow
// links, and so did this read before it was bounded. The link is followed and
// every rule then applies to what it reaches.
func TestOpen_LayoutRootIndexLinkIsFollowed(t *testing.T) {
	newLayout := func(t *testing.T) (dir, moved string) {
		dir = t.TempDir()
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AppendImage(platformImage(t, plat("linux/amd64"))); err != nil {
			t.Fatal(err)
		}
		// Outside the layout, so nothing but the link can find it.
		moved = filepath.Join(t.TempDir(), "the-real-index")
		if err := os.Rename(filepath.Join(dir, "index.json"), moved); err != nil {
			t.Fatal(err)
		}
		return dir, moved
	}
	refusal := func(dir, what string) string {
		return "read oci layout oci-dir:" + dir + ": layout index.json " + what
	}

	t.Run("to a regular file: the layout opens", func(t *testing.T) {
		dir, moved := newLayout(t)
		layoutSymlink(t, moved, filepath.Join(dir, "index.json"))
		img, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
		if err != nil {
			t.Fatal(err)
		}
		if len(img.Layers) != 1 {
			t.Fatalf("opened %d layers through the link, want the image's 1", len(img.Layers))
		}
	})
	t.Run("to a file past the limit: still bounded", func(t *testing.T) {
		dir, moved := newLayout(t)
		if err := os.Truncate(moved, maxArchiveManifestBytes+1); err != nil {
			t.Fatal(err)
		}
		layoutSymlink(t, moved, filepath.Join(dir, "index.json"))
		_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
		if want := refusal(dir, "exceeds the 100 MiB limit (D112)"); err == nil || err.Error() != want {
			t.Fatalf("Open = %v\nwant   %s", err, want)
		}
	})
	t.Run("to a directory: refused as that", func(t *testing.T) {
		dir, _ := newLayout(t)
		layoutSymlink(t, t.TempDir(), filepath.Join(dir, "index.json"))
		_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
		if want := refusal(dir, "is a symbolic link to a directory, not a regular file"); err == nil || err.Error() != want {
			t.Fatalf("Open = %v\nwant   %s", err, want)
		}
	})
	t.Run("to nothing: refused as a dangling link", func(t *testing.T) {
		dir, moved := newLayout(t)
		if err := os.Remove(moved); err != nil {
			t.Fatal(err)
		}
		layoutSymlink(t, moved, filepath.Join(dir, "index.json"))
		_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
		want := refusal(dir, "is a symbolic link whose target cannot be read: ")
		if err == nil || !strings.HasPrefix(err.Error(), want) || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Open = %v\nwant   %s<the missing target>", err, want)
		}
	})
	t.Run("to a device: refused as that", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("NUL is not a path a link can name")
		}
		dir, _ := newLayout(t)
		layoutSymlink(t, os.DevNull, filepath.Join(dir, "index.json"))
		_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
		if want := refusal(dir, "is a symbolic link to a device, not a regular file"); err == nil || err.Error() != want {
			t.Fatalf("Open = %v\nwant   %s", err, want)
		}
	})
}

func TestLayoutMetadataReadBound(t *testing.T) {
	for _, n := range []int{7, 8, 9, 1024} {
		r := strings.NewReader(strings.Repeat(" ", n))
		raw, err := readLayoutMetadata(t.Context(), r, 8)
		if n <= 8 {
			if err != nil || len(raw) != n {
				t.Fatalf("read %d: raw %d, err %v", n, len(raw), err)
			}
		} else if !errors.Is(err, errLayoutMetadataTooLong) {
			t.Fatalf("read %d = %v, want the over-read refusal", n, err)
		}
		if read := n - r.Len(); read > 9 {
			t.Fatalf("read %d bytes, bound 9", read)
		}
	}
}

func TestLayoutMetadataChecksContextDuringRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	r := &metadataCancelReader{cancel: cancel}
	_, err := readLayoutMetadata(ctx, r, 1024)
	if !errors.Is(err, context.Canceled) || r.calls != 1 {
		t.Fatalf("err %v, reads %d; want canceled after one read", err, r.calls)
	}
}

type metadataCancelReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *metadataCancelReader) Read(p []byte) (int, error) {
	r.calls++
	r.cancel()
	p[0] = ' '
	return 1, nil
}

func TestLayoutDescriptorIsRefusedBeforeBlobOpen(t *testing.T) {
	for _, n := range []int64{-1, maxArchiveManifestBytes + 1} {
		for _, mt := range []types.MediaType{types.OCIManifestSchema1, types.OCIImageIndex} {
			d := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: mt, Size: n}
			idx := &boundedLayoutIndex{ctx: t.Context(), manifest: v1.IndexManifest{Manifests: []v1.Descriptor{d}}, openBlob: func(v1.Hash) (io.ReadCloser, error) {
				t.Fatal("opened a descriptor already known to exceed the bound")
				return nil, nil
			}}
			var err error
			if mt.IsIndex() {
				_, err = idx.ImageIndex(d.Digest)
			} else {
				_, err = idx.Image(d.Digest)
			}
			if err == nil {
				t.Fatalf("accepted %s size %d", mt, n)
			}
		}
	}
}

func TestLayoutImageAndIndexBoundTheirBlobReads(t *testing.T) {
	for _, mt := range []types.MediaType{types.OCIManifestSchema1, types.OCIImageIndex} {
		r := strings.NewReader(strings.Repeat(" ", 1024))
		d := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: mt, Size: 1}
		idx := &boundedLayoutIndex{ctx: t.Context(), manifest: v1.IndexManifest{Manifests: []v1.Descriptor{d}}, openBlob: func(v1.Hash) (io.ReadCloser, error) { return io.NopCloser(r), nil }}
		var err error
		if mt.IsIndex() {
			_, err = idx.ImageIndex(d.Digest)
		} else {
			_, err = idx.Image(d.Digest)
		}
		if err == nil || 1024-r.Len() != 2 {
			t.Fatalf("%s: err=%v bytesRead=%d, want rejection after 2 bytes", mt, err, 1024-r.Len())
		}
	}
}

func TestLayoutImageUsesCheckedManifestSnapshot(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	original := platformImage(t, plat("linux/amd64"))
	if err := lp.AppendImage(original); err != nil {
		t.Fatal(err)
	}
	idx, err := openLayoutIndex(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	d := idx.manifest.Manifests[0]
	img, err := idx.Image(d.Digest)
	if err != nil {
		t.Fatal(err)
	}
	want, err := original.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", d.Digest.Algorithm, d.Digest.Hex), []byte("replaced"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := img.RawManifest()
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("manifest was reopened: %q, %v", raw, err)
	}
	if _, err := img.ConfigFile(); err != nil {
		t.Fatal(err)
	}
	if _, err := img.Layers(); err != nil {
		t.Fatal(err)
	}
}

func TestOpen_LayoutDuplicateDescriptorsAgree(t *testing.T) {
	for _, shape := range []string{"images", "indexes", "different branches"} {
		for _, conflict := range []string{"size", "media type", "none"} {
			for _, reversed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reversed=%t", shape, conflict, reversed), func(t *testing.T) {
					dir := t.TempDir()
					lp, err := layout.Write(dir, empty.Index)
					if err != nil {
						t.Fatal(err)
					}
					img := platformImage(t, plat("linux/amd64"))
					if err := lp.WriteImage(img); err != nil {
						t.Fatal(err)
					}
					raw, err := img.RawManifest()
					if err != nil {
						t.Fatal(err)
					}
					first := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, raw), Size: int64(len(raw))}
					wrap := func(d v1.Descriptor) v1.Descriptor {
						b, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{d}})
						if err != nil {
							t.Fatal(err)
						}
						return v1.Descriptor{MediaType: types.OCIImageIndex, Digest: writeBlob(t, lp, b), Size: int64(len(b))}
					}
					if shape != "images" {
						first = wrap(first)
					}
					second := first
					first.Platform = &v1.Platform{OS: "linux", Architecture: "arm64"}
					second.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
					first.Annotations = map[string]string{"test": "first"}
					second.Annotations = map[string]string{"test": "second"}
					switch conflict {
					case "size":
						second.Size = 1
					case "media type":
						second.MediaType = types.DockerManifestSchema2
						if shape != "images" {
							second.MediaType = types.DockerManifestList
						}
					}
					// The pair that disagrees, in the order the walk meets it.
					met := [2]v1.Descriptor{first, second}
					if shape == "different branches" {
						first, second = wrap(first), wrap(second)
					}
					if reversed {
						first, second = second, first
						met[0], met[1] = met[1], met[0]
					}
					if err := lp.AppendDescriptor(first); err != nil {
						t.Fatal(err)
					}
					if err := lp.AppendDescriptor(second); err != nil {
						t.Fatal(err)
					}
					_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
					if conflict == "none" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					// Digest and both declarations, so the two entries can be
					// found in a layout that may list thousands; and the whole
					// message, because the branch case is raised from a nested
					// index, which once named no layout.
					want := fmt.Sprintf("read oci layout oci-dir:%s: layout indexes declare %s twice and disagree: "+
						"size %d, media type %q against size %d, media type %q",
						dir, met[0].Digest, met[0].Size, met[0].MediaType, met[1].Size, met[1].MediaType)
					// A smaller bad descriptor met first is rejected on its
					// own read before the other branch is reached.
					if shape == "different branches" && conflict == "size" && reversed {
						want = fmt.Sprintf("read oci layout oci-dir:%s: layout metadata %s is longer than its descriptor declares (size 1)",
							dir, met[0].Digest)
					}
					if err == nil || err.Error() != want {
						t.Fatalf("Open = %v\nwant   %s", err, want)
					}
				})
			}
		}
	}
}
