package source

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// P4 of the 2026-11-20 audit. The config of an index child chosen by its
// descriptor's platform is read only when the layers are, past the pull's own
// error path, and a registry that refuses it there is still an AuthError.
func TestOpen_AnIndexChildsRefusedConfigIsAnAuthError(t *testing.T) {
	isolateEnv(t)
	p := plat("linux/amd64")
	img := platformImage(t, p)
	config, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	var locked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if locked.Load() && strings.HasSuffix(r.URL.Path, "/blobs/"+config.String()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"denied"}]}`)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ref, err := name.ParseReference(host + "/private/app:1")
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	locked.Store(true)
	_, err = Open(context.Background(), ref.String(), "linux/amd64")
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want an *AuthError", err)
	}
	if ae.Status != http.StatusForbidden || ae.Registry != host {
		t.Errorf("AuthError = {%d, %q}", ae.Status, ae.Registry)
	}
}

// sparseTar is one entry in GNU's sparse format. The writer does not write
// that type, so an ordinary header's fields are set to say it: one data
// segment, at offset 0, holding the whole file.
func sparseTar(t *testing.T, file, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: file, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	b[156] = tar.TypeGNUSparse
	copy(b[386:], fmt.Sprintf("%011o ", 0))
	copy(b[398:], fmt.Sprintf("%011o ", len(body)))
	copy(b[483:], fmt.Sprintf("%011o ", len(body)))
	copy(b[148:156], "        ")
	sum := 0
	for _, c := range b[:512] {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

// A sparse or contiguous entry is a file with content, not a node that shadows
// the lower layer's copy.
func TestFilesUnder_SparseAndContiguousEntriesAreFiles(t *testing.T) {
	const file = "var/lib/dpkg/status.d/libc6"
	raw := sparseTar(t, file, "NEW")
	h, err := tar.NewReader(bytes.NewReader(raw)).Next()
	if err != nil || h.Typeflag != tar.TypeGNUSparse {
		t.Fatalf("the fixture is not a sparse entry: %+v, %v", h, err)
	}
	sparse := layerOfOrdered(t, "sha256:top")
	sparse.Open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	for kind, top := range map[string]Layer{
		"sparse":     sparse,
		"contiguous": layerOfOrdered(t, "sha256:top", entry{name: file, body: "NEW", typ: tar.TypeCont}),
	} {
		img := imageOf(layerOfOrdered(t, "sha256:base", entry{name: file, body: "OLD"}), top)
		got, _, err := img.FilesUnder(context.Background(), "var/lib/dpkg/status.d")
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if b := bodiesOf(t, got); len(b) != 1 || b[file] != "NEW" {
			t.Errorf("%s: %v, want the top layer's content", kind, b)
		}
	}
}
