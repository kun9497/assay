package dbcmd

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust"
	"github.com/kun9497/assay/internal/store"
)

// The signature's payload blob, not its manifest, failing to download: the
// pull is refused with or without --allow-unsigned (nothing says the
// artifact is unsigned), the registry's error is shown, and the operator is
// not told the signature is wrong -- "does not verify under any key" would
// send them looking for a rotated key over a 403 (2026-10-27 review, item 3).
func TestPull_AnUnreadableSignatureBlobIsNeitherUnsignedNorInvalid(t *testing.T) {
	var armed atomic.Bool
	var blobPath atomic.Value
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, _ := blobPath.Load().(string); armed.Load() && r.Method == http.MethodGet && r.URL.Path == p {
				http.Error(w, "signature blob unavailable", http.StatusForbidden)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, wrap)
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(parsed)
	if err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := remote.Image(parsed.Context().Tag(trust.SigTag(d)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := sig.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	blobPath.Store("/v2/" + parsed.Context().RepositoryStr() + "/blobs/" + m.Layers[0].Digest.String())
	armed.Store(true)

	for _, allow := range []bool{false, true} {
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		var out, errOut bytes.Buffer
		if code := Pull(context.Background(), dst, ref, allow, &out, &errOut); code != 2 {
			t.Fatalf("allowUnsigned=%v: Pull = %d, want 2 (stderr: %s)", allow, code, errOut.String())
		}
		e := errOut.String()
		if !strings.Contains(e, "signature blob unavailable") {
			t.Errorf("allowUnsigned=%v: stderr does not carry the registry's reason:\n%s", allow, e)
		}
		if strings.Contains(e, "does not verify") || strings.Contains(e, "is not signed") || strings.Contains(e, "UNVERIFIED") {
			t.Errorf("allowUnsigned=%v: an unreadable signature was reported as invalid or absent:\n%s", allow, e)
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Errorf("allowUnsigned=%v: a pull whose signature could not be read installed a database", allow)
		}
	}
}
