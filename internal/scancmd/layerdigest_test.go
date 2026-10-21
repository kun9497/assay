package scancmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
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
	"github.com/klauspost/compress/zstd"

	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// D123's caller tests. A layer whose bytes are not the bytes its digest names
// must fail the scan, on every image path, before any verdict is printed.
//
// The forged layer is the honest one with busybox's release changed from r05
// (below d111DB's r10 fix: one critical finding, exit 1) to r15 (clean): the
// same length, a valid tar, and a valid compressed stream, so nothing about it
// is malformed — only its digest is wrong. Before D123 the forged scan printed
// a clean exit 0 under the honest image's manifest digest, with no padding or
// unusual layout needed (2026-10-20 external review, re-measured across
// uncompressed, gzip and zstd).
const (
	apkVulnerable = "P:busybox-binsh\nV:1.36.1-r05\nA:x86_64\no:busybox\n\n"
	apkForged     = "P:busybox-binsh\nV:1.36.1-r15\nA:x86_64\no:busybox\n\n"
)

// orderedTar writes the entries in the order given. buildTar ranges over a
// map, and two of its calls can order the same files differently -- fatal here,
// where the honest and forged layers must differ in the package record only.
func orderedTar(t *testing.T, entries ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// layerPair returns the honest and forged blobs for one compression, the same
// length as each other, and the honest uncompressed tar the config's diff id
// is computed from.
func layerPair(t *testing.T, compression string) (honest, forged []byte, mt types.MediaType) {
	t.Helper()
	h := orderedTar(t, [2]string{osReleasePath, osReleaseAlpine319}, [2]string{apkDBPath, apkVulnerable})
	f := orderedTar(t, [2]string{osReleasePath, osReleaseAlpine319}, [2]string{apkDBPath, apkForged})
	switch compression {
	case "none":
		return h, f, types.OCIUncompressedLayer
	case "gzip":
		// The gzip header's Extra field evens the lengths out, so the forged
		// blob is a complete, valid stream with nothing trailing it. Both
		// start with one, because the first Extra byte also costs the two-byte
		// XLEN header and would skew the difference.
		const base = 8
		hz, fz := gzipped(t, h, base), gzipped(t, f, base)
		if d := len(hz) - len(fz); d > 0 {
			fz = gzipped(t, f, base+d)
		} else if d < 0 {
			hz = gzipped(t, h, base-d)
		}
		return hz, fz, types.DockerLayer
	case "zstd":
		// A trailing skippable frame (RFC 8878 3.1.2) evens the lengths: part
		// of the format, so the forged blob is still one valid stream.
		hz, fz := zstded(t, h, 0), zstded(t, f, 0)
		const base = 16
		if d := len(hz) - len(fz); d >= 0 {
			hz, fz = zstded(t, h, base), zstded(t, f, base+d)
		} else {
			hz, fz = zstded(t, h, base-d), zstded(t, f, base)
		}
		return hz, fz, types.OCILayerZStd
	}
	t.Fatalf("compression %q", compression)
	return nil, nil, ""
}

func zstded(t *testing.T, raw []byte, skip int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if skip > 0 {
		var h [8]byte
		binary.LittleEndian.PutUint32(h[:4], 0x184D2A50)
		binary.LittleEndian.PutUint32(h[4:], uint32(skip))
		b.Write(h[:])
		b.Write(make([]byte, skip))
	}
	return b.Bytes()
}

func gzipped(t *testing.T, raw []byte, extra int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if extra > 0 {
		zw.Extra = make([]byte, extra)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// pinnedImage builds a linux/<host arch> image over blob. static.NewLayer
// takes the blob as given, so the diff id has to be set explicitly from the
// honest tar.
func pinnedImage(t *testing.T, blob []byte, mt types.MediaType, honestTar []byte) (img v1.Image, layerDigest, diffID v1.Hash) {
	t.Helper()
	layer := static.NewLayer(blob, mt)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	diff, _, err := v1.SHA256(bytes.NewReader(honestTar))
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{
		OS: "linux", Architecture: runtime.GOARCH,
		RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diff}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ld, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return img, ld, diff
}

func layerDigestDB(t *testing.T) string {
	t.Helper()
	return d111DB(t, map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19"}}})
}

func scanFailOnLow(t *testing.T, db, target string) (stdout, stderr string, code int) {
	t.Helper()
	low := severity.Low
	var out, errOut bytes.Buffer
	code = Run(context.Background(), db, target, Options{FailOn: &low}, &out, &errOut)
	return out.String(), errOut.String(), code
}

// wantRejected is the one outcome a forged layer may produce: exit 2, the
// layer named on stderr, and no verdict on stdout -- a report under the honest
// image's digest is exactly what must not be printed.
func wantRejected(t *testing.T, stdout, stderr string, code int, diffID v1.Hash) {
	t.Helper()
	if code != 2 {
		t.Fatalf("Run = %d, want 2 for a layer that is not the bytes its digest names\nstdout: %s\nstderr: %s",
			code, stdout, stderr)
	}
	// Which check speaks first depends on the path: on the registry the
	// library's blob-digest check fires on the drain's first read past the
	// archive end, before the diff id is compared; on oci-dir and
	// docker-archive only the diff id check exists. Either is a rejection of
	// THIS layer, so the assertion pins the layer's own "read layer <id>:"
	// prefix together with a digest-mismatch phrase, not either half alone.
	prefix := "read layer " + diffID.String() + ": "
	i := strings.Index(stderr, prefix)
	if i < 0 {
		t.Fatalf("stderr does not name the layer %s:\n%s", diffID, stderr)
	}
	rest := stderr[i+len(prefix):]
	if !strings.HasPrefix(rest, "layer "+diffID.String()+" content does not match") &&
		!strings.HasPrefix(rest, "error verifying sha256 checksum") {
		t.Errorf("the layer was not rejected for its digest:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want no report for an untrusted image", stdout)
	}
}

func TestRun_RegistryLayerNotMatchingItsDigestIsExit2(t *testing.T) {
	for _, compression := range []string{"none", "gzip", "zstd"} {
		t.Run(compression, func(t *testing.T) {
			isolateCredentials(t)
			honest, forged, mt := layerPair(t, compression)
			if len(honest) != len(forged) || bytes.Equal(honest, forged) {
				t.Fatalf("fixture: honest %d bytes, forged %d -- they must differ at equal length",
					len(honest), len(forged))
			}
			rawHonest, _ := uncompressedTar(t, honest, compression)
			img, ld, diff := pinnedImage(t, honest, mt, rawHonest)

			var serveForged bool
			reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveForged && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+ld.String()) {
					w.Header().Set("Content-Length", strconv.Itoa(len(forged)))
					w.Header().Set("Docker-Content-Digest", ld.String())
					w.Write(forged)
					return
				}
				reg.ServeHTTP(w, r)
			}))
			t.Cleanup(s.Close)
			host := strings.TrimPrefix(s.URL, "http://")
			tagged, err := name.ParseReference(host + "/forge/alpine:3.19")
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(tagged, img); err != nil {
				t.Fatalf("push: %v", err)
			}
			md, err := img.Digest()
			if err != nil {
				t.Fatal(err)
			}
			pinned := host + "/forge/alpine@" + md.String()
			db := layerDigestDB(t)

			// Control: the honest bytes scan and find the r05 busybox.
			out, errOut, code := scanFailOnLow(t, db, pinned)
			if code != 1 {
				t.Fatalf("honest layer: Run = %d, want 1 (one finding)\nstderr: %s", code, errOut)
			}
			if !strings.Contains(out, "ALPINE-2024-0001") {
				t.Fatalf("honest layer: the finding is missing from the report:\n%s", out)
			}

			serveForged = true
			out, errOut, code = scanFailOnLow(t, db, pinned)
			wantRejected(t, out, errOut, code, diff)
		})
	}
}

// oci-dir and docker-archive have no verifying reader underneath at all --
// go-containerregistry checks a blob's digest only on the registry path -- so
// draining the stream would not catch these; the diff id check does.
func TestRun_LocalLayerNotMatchingItsDigestIsExit2(t *testing.T) {
	isolateCredentials(t)
	honest, forged, mt := layerPair(t, "gzip")
	rawHonest, _ := uncompressedTar(t, honest, "gzip")
	img, ld, diff := pinnedImage(t, honest, mt, rawHonest)
	db := layerDigestDB(t)

	t.Run("oci-dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "layout")
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AppendImage(img); err != nil {
			t.Fatal(err)
		}
		if _, _, code := scanFailOnLow(t, db, "oci-dir:"+dir); code != 1 {
			t.Fatalf("honest layout: Run = %d, want 1", code)
		}
		blob := filepath.Join(dir, "blobs", ld.Algorithm, ld.Hex)
		if err := os.WriteFile(blob, forged, 0o644); err != nil {
			t.Fatal(err)
		}
		out, errOut, code := scanFailOnLow(t, db, "oci-dir:"+dir)
		wantRejected(t, out, errOut, code, diff)
	})

	// Forging the config too -- diff ids rewritten to the forged layer's --
	// moves the mismatch up one link: the manifest still names the honest
	// config's digest, so the chain breaks there instead.
	t.Run("oci-dir with its config forged to match", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "layout")
		lp, err := layout.Write(dir, empty.Index)
		if err != nil {
			t.Fatal(err)
		}
		if err := lp.AppendImage(img); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", ld.Algorithm, ld.Hex), forged, 0o644); err != nil {
			t.Fatal(err)
		}
		rawForged, _ := uncompressedTar(t, forged, "gzip")
		forgedDiff, _, err := v1.SHA256(bytes.NewReader(rawForged))
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
		forgedCfg := bytes.Replace(raw, []byte(diff.String()), []byte(forgedDiff.String()), 1)
		if bytes.Equal(forgedCfg, raw) || len(forgedCfg) != len(raw) {
			t.Fatal("fixture: the config's diff id was not rewritten in place")
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", cfgName.Algorithm, cfgName.Hex), forgedCfg, 0o644); err != nil {
			t.Fatal(err)
		}
		out, errOut, code := scanFailOnLow(t, db, "oci-dir:"+dir)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		if want := "image config does not match the manifest: the manifest names " + cfgName.String(); !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
		if out != "" {
			t.Errorf("stdout = %q, want no report", out)
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
		if _, _, code := scanFailOnLow(t, db, "docker-archive:"+path); code != 1 {
			t.Fatalf("honest archive: Run = %d, want 1", code)
		}
		replaceArchiveEntry(t, path, honest, forged)
		out, errOut, code := scanFailOnLow(t, db, "docker-archive:"+path)
		wantRejected(t, out, errOut, code, diff)
	})
}

// replaceArchiveEntry rewrites a docker-archive tarball with the one entry
// whose content is old replaced by new (same length).
func replaceArchiveEntry(t *testing.T, path string, old, new []byte) {
	t.Helper()
	in, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	tr := tar.NewReader(bytes.NewReader(in))
	tw := tar.NewWriter(&out)
	replaced := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, old) {
			b = new
			replaced++
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if replaced != 1 {
		t.Fatalf("replaced %d archive entries, want exactly the one layer", replaced)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func uncompressedTar(t *testing.T, blob []byte, compression string) ([]byte, error) {
	t.Helper()
	if compression == "none" {
		return blob, nil
	}
	if compression == "zstd" {
		zr, err := zstd.NewReader(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		b, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b, nil
}
