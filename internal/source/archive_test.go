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

// The test above holds that the reader refuses on the header; this one holds
// which limit Open hands it for each file, at the scan's own entry point. Each
// archive ends at the header that declares one byte too many, so there is no
// body: a reader given any larger limit goes on to read it and reports a
// truncated archive instead, which is how the refusal is known to come first.
func TestOpen_DockerArchiveMetadataLimitsAreTheDeclaredOnes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []archiveTestEntry
		over    tar.Header
		want    string
	}{
		{"manifest.json", nil,
			tar.Header{Name: "manifest.json", Mode: 0600, Size: maxArchiveManifestBytes + 1},
			"archive metadata manifest.json declares 104857601 bytes, past the 100 MiB limit (D112)"},
		{"config", []archiveTestEntry{archiveTestFile("manifest.json", []byte(`[{"Config":"the-config.json","Layers":[]}]`))},
			tar.Header{Name: "the-config.json", Mode: 0600, Size: MaxConfigBytes + 1},
			"archive metadata the-config.json declares 16777217 bytes, past the 16 MiB limit (D112)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tar.NewWriter(&buf)
			for _, entry := range tc.entries {
				if err := w.WriteHeader(&entry.header); err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(entry.data); err != nil {
					t.Fatal(err)
				}
			}
			// Never closed: Close would refuse the missing body, and the
			// header is flushed, with the padding before it, as it is written.
			if err := w.WriteHeader(&tc.over); err != nil {
				t.Fatal(err)
			}
			// The manifest is looked for to the end of the archive, so an
			// over-long config needs its body for the manifest to be read.
			if len(tc.entries) > 0 {
				buf.Write(make([]byte, (tc.over.Size+511)/512*512+1024))
			}
			file := filepath.Join(t.TempDir(), "image.tar")
			if err := os.WriteFile(file, buf.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Open(context.Background(), "docker-archive:"+file, "linux/amd64")
			want := "read docker archive docker-archive:" + file + ": " + tc.want
			if err == nil || err.Error() != want {
				t.Fatalf("Open = %v\nwant   %s", err, want)
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

func TestArchiveMetadataLinksAndLongNames(t *testing.T) {
	long := strings.Repeat("a/", 80) + "config.json"
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink} {
		data := archiveTestBytes(t,
			archiveTestEntry{header: tar.Header{Name: "dir/config", Typeflag: kind, Linkname: "../" + long}},
			archiveTestFile("./"+long, []byte("first")),
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

type archiveCountingFile struct {
	*bytes.Reader
	readBytes int
	seeks     int
}

func (r *archiveCountingFile) Close() error { return nil }

func (r *archiveCountingFile) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.readBytes += n
	return n, err
}

func (r *archiveCountingFile) Seek(offset int64, whence int) (int64, error) {
	r.seeks++
	return r.Reader.Seek(offset, whence)
}

func TestDockerArchiveSkipsLargePrecedingEntries(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	data := archiveTestBytes(t,
		archiveTestFile("unrelated-layer", make([]byte, 4<<20)),
		archiveTestFile("manifest.json", []byte(`[{"Config":"config","Layers":[]}]`)),
		archiveTestFile("config", config),
		archiveTestFile("after", []byte("found")),
	)
	var opens []*archiveCountingFile
	open := func() (io.ReadCloser, error) {
		file := &archiveCountingFile{Reader: bytes.NewReader(data)}
		opens = append(opens, file)
		return file, nil
	}
	guarded, err := dockerArchiveOpener(context.Background(), open)
	if err != nil {
		t.Fatal(err)
	}
	// This lookup passes both the synthetic prefix and the large entry in
	// the original tar, just as looking up a later layer does.
	body, err := readArchiveMetadata(context.Background(), guarded, "after", 16)
	if err != nil || string(body) != "found" {
		t.Fatalf("body=%q error=%v", body, err)
	}
	for _, file := range opens {
		if file.readBytes > 32<<10 || file.seeks == 0 {
			t.Fatalf("read %d bytes, %d seeks while skipping 4 MiB", file.readBytes, file.seeks)
		}
	}
	// tar's seek optimization must still detect a truncated unwanted entry.
	truncated := data[:1024]
	_, err = readArchiveMetadata(context.Background(), func() (io.ReadCloser, error) {
		return &archiveCountingFile{Reader: bytes.NewReader(truncated)}, nil
	}, "config", MaxConfigBytes)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated preceding layer: %v", err)
	}
}

func TestArchivePrefixSeeksAcrossBoundary(t *testing.T) {
	file := &archiveCountingFile{Reader: bytes.NewReader([]byte("ghi"))}
	r := &archivePrefixReader{file: file, prefix: [][]byte{[]byte("abc"), []byte("def")}}
	for _, tc := range []struct {
		offset int64
		whence int
		want   string
	}{{1, io.SeekStart, "bcdef"}, {1, io.SeekCurrent, "hi"}, {-6, io.SeekEnd, "defghi"}, {0, io.SeekStart, "abcdefghi"}} {
		if _, err := r.Seek(tc.offset, tc.whence); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(tc.want))
		if _, err := io.ReadFull(r, buf); err != nil || string(buf) != tc.want {
			t.Fatalf("seek %+v: read %q, error=%v", tc, buf, err)
		}
	}
	if _, err := r.Seek(-10, io.SeekEnd); err == nil {
		t.Fatal("accepted a negative logical offset")
	}
	if r.pos != 9 {
		t.Fatalf("failed seek changed position to %d", r.pos)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	guarded := &archiveContextReader{ctx: ctx, Reader: r, Closer: file}
	if _, err := guarded.Seek(0, io.SeekStart); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled seek: %v", err)
	}
}

// QA 2026-11-20. Readers disagree on which of two same-named members is the
// image: one tarball scanned as A and loaded as B.
func TestOpen_DockerArchiveWithTwoMetadataMembersIsRefused(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	manifest := []byte(`[{"Config":"c.json","Layers":[]}]`)
	for name, entries := range map[string][]archiveTestEntry{
		"two manifests":         {archiveTestFile("manifest.json", manifest), archiveTestFile("c.json", config), archiveTestFile("manifest.json", manifest)},
		"two configs":           {archiveTestFile("manifest.json", manifest), archiveTestFile("c.json", config), archiveTestFile("./c.json", config)},
		"a link and a file":     {archiveTestFile("manifest.json", manifest), {header: tar.Header{Name: "c.json", Typeflag: tar.TypeSymlink, Linkname: "d.json"}}, archiveTestFile("d.json", config), archiveTestFile("c.json", config)},
		"two of what is linked": {archiveTestFile("manifest.json", manifest), {header: tar.Header{Name: "c.json", Typeflag: tar.TypeSymlink, Linkname: "d.json"}}, archiveTestFile("d.json", config), archiveTestFile("d.json", config)},
	} {
		p := filepath.Join(t.TempDir(), "x.tar")
		if err := os.WriteFile(p, archiveTestBytes(t, entries...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), "docker-archive:"+p, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "more than one member named") {
			t.Errorf("%s: err = %v, want it refused", name, err)
		}
	}
}
