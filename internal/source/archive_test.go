package source

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type archiveTestEntry struct {
	header tar.Header
	data   []byte
}

func archiveTestFile(name string, data []byte) archiveTestEntry {
	return archiveTestEntry{header: tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}, data: data}
}

func archiveTestBytes(t *testing.T, entries ...archiveTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, entry := range entries {
		if err := w.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func archiveTestOpener(data []byte) tarball.Opener {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
}

func TestArchiveMetadataRejectsSizeBeforeReadingPayload(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
	}{{"config.json", MaxConfigBytes}, {"manifest.json", maxArchiveManifestBytes}} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tar.NewWriter(&buf)
			if err := w.WriteHeader(&tar.Header{Name: tc.name, Size: tc.limit + 1}); err != nil {
				t.Fatal(err)
			}
			trap := &archiveReadTrap{}
			_, _, err := findArchiveMetadata(io.MultiReader(&buf, trap), tc.name, tc.limit)
			if err == nil || !strings.Contains(err.Error(), "past the") || trap.reads != 0 {
				t.Fatalf("error=%v, payload reads=%d", err, trap.reads)
			}
		})
	}
}

type archiveReadTrap struct{ reads int }

func (r *archiveReadTrap) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected payload read")
}

func TestArchiveMetadataBoundariesAndTruncation(t *testing.T) {
	for _, n := range []int{15, 16, 17} {
		data := archiveTestBytes(t, archiveTestFile("config", bytes.Repeat([]byte("x"), n)))
		body, err := readArchiveMetadata(context.Background(), archiveTestOpener(data), "config", 16)
		if n <= 16 {
			if err != nil || len(body) != n {
				t.Fatalf("size %d: body=%q error=%v", n, body, err)
			}
		} else if err == nil {
			t.Fatal("accepted an oversized entry")
		}
	}
	data := archiveTestBytes(t, archiveTestFile("config", []byte("truncated")))
	_, err := readArchiveMetadata(context.Background(), archiveTestOpener(data[:514]), "config", MaxConfigBytes)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated config: %v", err)
	}
}

func TestArchiveMetadataLinksFirstMatchAndLongNames(t *testing.T) {
	long := strings.Repeat("a/", 80) + "config.json"
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink} {
		data := archiveTestBytes(t,
			archiveTestEntry{header: tar.Header{Name: "dir/config", Typeflag: kind, Linkname: "../" + long}},
			archiveTestFile("./"+long, []byte("first")),
			archiveTestFile(long, []byte("second")),
		)
		body, err := readArchiveMetadata(context.Background(), archiveTestOpener(data), "dir/config", MaxConfigBytes)
		if err != nil || string(body) != "first" {
			t.Fatalf("link %c: body=%q error=%v", kind, body, err)
		}
	}
	for _, hops := range []int{maxSymlinks, maxSymlinks + 1} {
		var entries []archiveTestEntry
		for i := 0; i < hops; i++ {
			entries = append(entries, archiveTestEntry{header: tar.Header{
				Name: fmt.Sprint(i), Typeflag: tar.TypeSymlink, Linkname: fmt.Sprint(i + 1),
			}})
		}
		entries = append(entries, archiveTestFile(fmt.Sprint(hops), []byte("config")))
		body, err := readArchiveMetadata(context.Background(), archiveTestOpener(archiveTestBytes(t, entries...)), "0", 16)
		if hops == maxSymlinks && (err != nil || string(body) != "config") {
			t.Fatalf("40 hops: %q, %v", body, err)
		}
		if hops > maxSymlinks && err == nil {
			t.Fatal("accepted 41 link hops")
		}
	}
	cycle := archiveTestBytes(t, archiveTestEntry{header: tar.Header{
		Name: "config", Typeflag: tar.TypeSymlink, Linkname: "./config",
	}})
	_, err := readArchiveMetadata(context.Background(), archiveTestOpener(cycle), "config", 16)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
}

func TestDockerArchiveSnapshotSurvivesMetadataReplacement(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	manifest := []byte(`[{"Config":"dir/config","Layers":[]}]`)
	original := archiveTestBytes(t,
		archiveTestFile("data", config),
		archiveTestEntry{header: tar.Header{Name: "dir/config", Typeflag: tar.TypeSymlink, Linkname: "../data"}},
		archiveTestFile("manifest.json", manifest),
	)
	base, err := tarball.Image(archiveTestOpener(original), nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	current := original
	opener, err := dockerArchiveOpener(context.Background(), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(current)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// If the underlying metadata is consulted again, this header alone
	// makes config loading fail, before a potentially unbounded payload.
	var changed bytes.Buffer
	w := tar.NewWriter(&changed)
	if err := w.WriteHeader(&tar.Header{Name: "manifest.json", Size: maxArchiveManifestBytes + 1}); err != nil {
		t.Fatal(err)
	}
	current = changed.Bytes()
	img, err := tarball.Image(opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := img.Digest()
	if err != nil || got != want {
		t.Fatalf("digest=%s, want=%s, error=%v", got, want, err)
	}
	raw, err := img.RawConfigFile()
	if err != nil || !bytes.Equal(raw, config) {
		t.Fatalf("config=%q, error=%v", raw, err)
	}
}

func TestOpenDockerArchiveRejectsInconsistentLayerCounts(t *testing.T) {
	for _, counts := range [][2]int{{0, 1}, {1, 0}, {1, 2}, {2, 1}} {
		config := v1.ConfigFile{OS: "linux", Architecture: "amd64"}
		config.RootFS.DiffIDs = make([]v1.Hash, counts[0])
		for i := range config.RootFS.DiffIDs {
			config.RootFS.DiffIDs[i] = v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}
		}
		cf, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := json.Marshal(tarball.Manifest{{Config: "config", Layers: make([]string, counts[1])}})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "image.tar")
		if err := os.WriteFile(file, archiveTestBytes(t, archiveTestFile("manifest.json", manifest), archiveTestFile("config", cf)), 0600); err != nil {
			t.Fatal(err)
		}
		_, err = Open(context.Background(), "docker-archive:"+file, "linux/amd64")
		if err == nil || !strings.Contains(err.Error(), "diff ids for") {
			t.Fatalf("counts %v: %v", counts, err)
		}
	}
}

type archiveCancelReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *archiveCancelReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.cancel()
	return n, err
}

func TestArchiveMetadataCancellationWhileSkippingLayer(t *testing.T) {
	data := archiveTestBytes(t, archiveTestFile("layer.tar", bytes.Repeat([]byte("x"), 4096)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(&archiveCancelReader{Reader: bytes.NewReader(data), cancel: cancel}), nil
	}
	_, err := readArchiveMetadata(ctx, opener, "config", MaxConfigBytes)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("metadata scan cancellation: %v", err)
	}
}
