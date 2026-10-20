package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// D123 at the source boundary: Open then Files, the same calls scancmd makes,
// against layers whose bytes are not the ones their digests name.
// internal/scancmd's layerdigest_test.go holds the whole scan; these hold the
// same paths where they can be run one mutation at a time.

const (
	d123Path   = "lib/apk/db/installed"
	d123Honest = "P:busybox\nV:1.36.1-r05\n\n"
	d123Forged = "P:busybox\nV:1.36.1-r15\n\n"
)

func d123Tar(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: d123Path, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func d123Gzip(t *testing.T, raw []byte, extra int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Extra = make([]byte, extra)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// d123Blobs returns honest and forged blobs of equal length, and the honest
// uncompressed tar.
func d123Blobs(t *testing.T, compression string) (honest, forged, honestTar []byte, mt types.MediaType) {
	t.Helper()
	h, f := d123Tar(t, d123Honest), d123Tar(t, d123Forged)
	if compression == "none" {
		return h, f, h, types.OCIUncompressedLayer
	}
	const base = 8
	hz, fz := d123Gzip(t, h, base), d123Gzip(t, f, base)
	if d := len(hz) - len(fz); d > 0 {
		fz = d123Gzip(t, f, base+d)
	} else if d < 0 {
		hz = d123Gzip(t, h, base-d)
	}
	if len(hz) != len(fz) {
		t.Fatalf("fixture: %d vs %d bytes", len(hz), len(fz))
	}
	return hz, fz, h, types.DockerLayer
}

func d123Image(t *testing.T, blob, honestTar []byte, mt types.MediaType) (img v1.Image, layerDigest, diffID v1.Hash) {
	t.Helper()
	layer := static.NewLayer(blob, mt)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	diffID, _, err = v1.SHA256(bytes.NewReader(honestTar))
	if err != nil {
		t.Fatal(err)
	}
	if img, err = mutate.ConfigFile(img, &v1.ConfigFile{
		OS: "linux", Architecture: runtime.GOARCH,
		RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
	}); err != nil {
		t.Fatal(err)
	}
	if layerDigest, err = layer.Digest(); err != nil {
		t.Fatal(err)
	}
	return img, layerDigest, diffID
}

// readInstalled is the caller's whole read: Open, then Files.
func readInstalled(t *testing.T, ref string) (string, error) {
	t.Helper()
	img, err := Open(context.Background(), ref, "")
	if err != nil {
		return "", err
	}
	got, err := img.Files(context.Background(), []string{d123Path})
	if err != nil {
		return "", err
	}
	return string(got[d123Path].Data), nil
}

func wantHonest(t *testing.T, ref string) {
	t.Helper()
	got, err := readInstalled(t, ref)
	if err != nil {
		t.Fatalf("honest image: %v", err)
	}
	if got != d123Honest {
		t.Fatalf("honest image read %q, want %q", got, d123Honest)
	}
}

func TestFiles_RegistryLayerNotMatchingItsDigestFails(t *testing.T) {
	for _, compression := range []string{"none", "gzip"} {
		t.Run(compression, func(t *testing.T) {
			isolateEnv(t)
			honest, forged, honestTar, mt := d123Blobs(t, compression)
			img, ld, _ := d123Image(t, honest, honestTar, mt)

			var serveForged bool
			reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveForged && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+ld.String()) {
					w.Header().Set("Content-Length", strconv.Itoa(len(forged)))
					w.Write(forged)
					return
				}
				reg.ServeHTTP(w, r)
			}))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "http://")
			tagged, err := name.ParseReference(host + "/forge/app:1")
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(tagged, img); err != nil {
				t.Fatal(err)
			}
			md, err := img.Digest()
			if err != nil {
				t.Fatal(err)
			}
			ref := host + "/forge/app@" + md.String()
			wantHonest(t, ref)

			serveForged = true
			got, err := readInstalled(t, ref)
			if err == nil {
				t.Fatalf("a forged layer under a pinned digest was read without error: %q", got)
			}
			if !strings.Contains(err.Error(), "read layer ") {
				t.Errorf("error does not name the layer: %v", err)
			}
		})
	}
}

// oci-dir and docker-archive: the library verifies nothing on these paths, so
// only D123's diff id check can stop the forged bytes -- and only if the diff
// id is the config's, since the library's own DiffID() for such a layer is
// computed from the bytes themselves.
func TestFiles_LocalLayerNotMatchingItsDiffIDFails(t *testing.T) {
	honest, forged, honestTar, mt := d123Blobs(t, "gzip")
	img, ld, diffID := d123Image(t, honest, honestTar, mt)

	writeLayout := func(t *testing.T) string {
		dir := filepath.Join(t.TempDir(), "layout")
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AppendImage(img); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	wantLayerDigestError := func(t *testing.T, err error) {
		t.Helper()
		var lde *LayerDigestError
		if !errors.As(err, &lde) {
			t.Fatalf("err = %v, want a *LayerDigestError", err)
		}
		if lde.DiffID != diffID.String() {
			t.Errorf("LayerDigestError.DiffID = %s, want the config's %s", lde.DiffID, diffID)
		}
	}

	t.Run("oci-dir", func(t *testing.T) {
		dir := writeLayout(t)
		wantHonest(t, "oci-dir:"+dir)
		if err := os.WriteFile(filepath.Join(dir, "blobs", ld.Algorithm, ld.Hex), forged, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := readInstalled(t, "oci-dir:"+dir)
		wantLayerDigestError(t, err)
	})

	t.Run("oci-dir with its config forged to match", func(t *testing.T) {
		dir := writeLayout(t)
		if err := os.WriteFile(filepath.Join(dir, "blobs", ld.Algorithm, ld.Hex), forged, 0o644); err != nil {
			t.Fatal(err)
		}
		forgedDiff, _, err := v1.SHA256(bytes.NewReader(d123Tar(t, d123Forged)))
		if err != nil {
			t.Fatal(err)
		}
		cfgName, err := img.ConfigName()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := img.RawConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		forgedCfg := bytes.Replace(raw, []byte(diffID.String()), []byte(forgedDiff.String()), 1)
		if bytes.Equal(forgedCfg, raw) {
			t.Fatal("fixture: the config's diff id was not rewritten")
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", cfgName.Algorithm, cfgName.Hex), forgedCfg, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = readInstalled(t, "oci-dir:"+dir)
		var cde *ConfigDigestError
		if !errors.As(err, &cde) {
			t.Fatalf("err = %v, want a *ConfigDigestError", err)
		}
		if cde.Want != cfgName.String() {
			t.Errorf("ConfigDigestError.Want = %s, want the manifest's %s", cde.Want, cfgName)
		}
	})

	t.Run("docker-archive", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "image.tar")
		tagged, err := name.ParseReference("forge:latest")
		if err != nil {
			t.Fatal(err)
		}
		if err := tarball.WriteToFile(path, tagged, img); err != nil {
			t.Fatal(err)
		}
		wantHonest(t, "docker-archive:"+path)
		in, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(in, honest) != 1 {
			t.Fatal("fixture: the layer blob is not in the archive exactly once")
		}
		if err := os.WriteFile(path, bytes.Replace(in, honest, forged, 1), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = readInstalled(t, "docker-archive:"+path)
		wantLayerDigestError(t, err)
	})
}

// The bytes after the archive's end marker are part of the layer too: a
// stream whose tar ends early and whose tail differs must still be rejected,
// which only a read to EOF can see.
func TestFiles_TailAfterTheArchiveEndIsVerified(t *testing.T) {
	raw := d123Tar(t, d123Honest)
	tail := append(append([]byte{}, raw...), make([]byte, 4096)...)
	forgedTail := append(append([]byte{}, raw...), bytes.Repeat([]byte{1}, 4096)...)
	diff, _, err := v1.SHA256(bytes.NewReader(tail))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"honest": tail, "forged": forgedTail} {
		t.Run(name, func(t *testing.T) {
			img, err := fromV1(fakeImage{layers: []fakeLayer{{diff: diff.String(), body: string(body)}}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := img.Files(context.Background(), []string{d123Path})
			if name == "honest" {
				if err != nil || string(got[d123Path].Data) != d123Honest {
					t.Fatalf("honest = %q, %v", got[d123Path].Data, err)
				}
				return
			}
			var lde *LayerDigestError
			if !errors.As(err, &lde) {
				t.Fatalf("err = %v, want a *LayerDigestError for a forged tail", err)
			}
		})
	}
}

func TestVerifyDiffID_RefusesAnAlgorithmItCannotCheck(t *testing.T) {
	_, err := verifyDiffID(io.NopCloser(strings.NewReader("x")), v1.Hash{Algorithm: "md5", Hex: "00"})
	if err == nil || !strings.Contains(err.Error(), `diff id algorithm "md5" cannot be verified`) {
		t.Fatalf("err = %v, want the unverifiable algorithm refused", err)
	}
}

func TestDrainLayer_StopsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := drainLayer(ctx, strings.NewReader(strings.Repeat("x", 1<<20)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("drainLayer = %v, want context.Canceled", err)
	}
}
