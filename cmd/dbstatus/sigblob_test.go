package main

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust"
	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// A signature whose payload blob cannot be read says nothing about whether
// the artifact is signed, exactly like a signature manifest that cannot be
// read (TestRun_ATransientSignatureFetchKeepsThePreviousDescription). The
// 2026-10-27 review found the blob case filed as "no key verifies": status
// replaced a signed observation with signed:false and a fresh time, the
// outage signal, and dropped the error. 403, 404 (a manifest naming a blob
// the registry no longer serves) and 503 (after the client's retries).
func TestRun_AnUnreadableSignatureBlobKeepsThePreviousDescription(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			key := trusttest.NewKey(t)
			trustKey(t, key)
			fixedNow(t, t0)
			var block atomic.Bool
			var blobPath atomic.Value
			host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if p, _ := blobPath.Load().(string); block.Load() && r.Method == http.MethodGet && r.URL.Path == p {
						http.Error(w, "signature blob unavailable", status)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			ref := host + "/assay-db:v9"
			pushTo(t, ref, key)

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
			blobPath.Store("/v2/assay-db/blobs/" + m.Layers[0].Digest.String())
			block.Store(true)

			old := &Artifact{Reference: ref, Digest: "sha256:prev", Signed: true, SignedBy: "k", ObservedAt: t0.Add(-time.Hour)}
			prev := writePrev(t, Status{SchemaVersion: 1, Published: old})
			s, stderr := runStatus(t, "-ref", ref, "-prev", prev, "-workflow", "db-publish", "-result", "success", "-run-url", "u")
			if s.Published == nil || s.Published.Digest != "sha256:prev" || !s.Published.Signed || !s.Published.ObservedAt.Equal(old.ObservedAt) {
				t.Errorf("published = %+v, want the previous signed description kept", s.Published)
			}
			if !strings.Contains(s.PublishedError, "signature blob unavailable") {
				t.Errorf("publishedError = %q, want the blob read failure recorded", s.PublishedError)
			}
			if !strings.Contains(stderr, "keeping the previous description") {
				t.Errorf("stderr does not say the previous description was kept:\n%s", stderr)
			}
		})
	}
}
