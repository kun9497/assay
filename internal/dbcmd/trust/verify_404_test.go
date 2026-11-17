package trust

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// A registry that answers a missing tag with a 404 whose body is not the
// distribution spec's MANIFEST_UNKNOWN -- Harbor's NOT_FOUND, a reverse
// proxy's HTML page, an empty body -- is still saying the tag is not there.
// The repository is known to exist (the artifact's own manifest was just
// fetched from it), so a 404 on its .sig tag is "not signed", never a
// transport failure: read as transport, --allow-unsigned could not reach it
// and the operator would be told to retry or fix auth for an artifact that
// is simply unsigned (D137 PR 2 review).
func TestVerify_A404WithoutTheSpecCodeIsNotSigned(t *testing.T) {
	for _, body := range []string{
		``,
		`<html><body>404 Not Found</body></html>`,
		`{"errors":[{"code":"NOT_FOUND","message":"artifact not found"}]}`,
	} {
		host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/manifests/sha256-") {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(body))
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
		_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
		if !errors.Is(err, ErrNotSigned) {
			t.Errorf("404 with body %q: err = %v, want ErrNotSigned", body, err)
		}
	}
}

func TestVerify_MissingIndexChildIsNotAnAbsentSignatureTag(t *testing.T) {
	child := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				w.Header().Set("Content-Type", string(types.OCIImageIndex))
				_ = json.NewEncoder(w).Encode(v1.IndexManifest{
					SchemaVersion: 2,
					MediaType:     types.OCIImageIndex,
					Manifests:     []v1.Descriptor{{MediaType: types.OCIManifestSchema1, Digest: child}},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	var terr *transport.Error
	if errors.Is(err, ErrNotSigned) || !errors.As(err, &terr) || terr.StatusCode != http.StatusNotFound ||
		!strings.HasSuffix(terr.Request.URL.Path, "/manifests/"+child.String()) {
		t.Fatalf("Verify = %v, want the missing child manifest's HTTP 404", err)
	}
}
