package trust

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// blobBlocker serves a registry whose GET of one blob path fails with
// status once armed. The path is set after the .sig image is written,
// when its layer digests are known.
type blobBlocker struct {
	armed  atomic.Bool
	path   atomic.Value
	status int
}

func (b *blobBlocker) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, _ := b.path.Load().(string); b.armed.Load() && r.Method == http.MethodGet && r.URL.Path == p {
			http.Error(w, "payload unavailable", b.status)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sigLayerDigests reads the .sig manifest for d and returns its layer
// digests in order.
func sigLayerDigests(t *testing.T, repo name.Repository, d v1.Hash) []v1.Hash {
	t.Helper()
	img, err := remote.Image(repo.Tag(SigTag(d)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	var out []v1.Hash
	for _, l := range m.Layers {
		out = append(out, l.Digest)
	}
	return out
}

// A layer whose payload cannot be fetched is not a signature that failed to
// verify: nothing was checked. With no other layer to decide, Verify says
// it could not read the signature (ErrSignatureUnreadable), never
// ErrNoKeyVerifies, so a status page does not publish signed:false over a
// registry hiccup (2026-10-27 review, item 3).
func TestVerify_AnUnreadablePayloadIsNotAnInvalidSignature(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			b := &blobBlocker{status: status}
			host := trusttest.NewRegistry(t, b.wrap)
			ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
			key := trusttest.NewKey(t)
			trusttest.SignArtifact(t, key, ref, d)
			b.path.Store("/v2/assay-db/blobs/" + sigLayerDigests(t, ref.Context(), d)[0].String())
			b.armed.Store(true)

			_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
			if !errors.Is(err, ErrSignatureUnreadable) || errors.Is(err, ErrNoKeyVerifies) || errors.Is(err, ErrNotSigned) {
				t.Fatalf("err = %v, want ErrSignatureUnreadable and neither ErrNoKeyVerifies nor ErrNotSigned", err)
			}
			if !strings.Contains(err.Error(), "payload unavailable") {
				t.Errorf("err = %v, want the registry's reason kept", err)
			}
		})
	}
}

// One unreadable layer does not stop the others: a genuine layer after it
// still accepts, and so does one before it.
func TestVerify_AnUnreadableLayerDoesNotHideAGenuineOne(t *testing.T) {
	for _, blocked := range []int{0, 1} {
		b := &blobBlocker{status: http.StatusServiceUnavailable}
		host := trusttest.NewRegistry(t, b.wrap)
		ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
		key := trusttest.NewKey(t)
		p := trusttest.Payload(t, ref.Context().Name(), d)
		// Two layers with different payload bytes, so they are two blobs.
		p2 := append(append([]byte{}, p...), ' ')
		trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{
			{Payload: p, Signature: trusttest.Sign(t, key, p)},
			{Payload: p2, Signature: trusttest.Sign(t, key, p2)},
		})
		b.path.Store("/v2/assay-db/blobs/" + sigLayerDigests(t, ref.Context(), d)[blocked].String())
		b.armed.Store(true)
		if _, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)}); err != nil {
			t.Errorf("layer %d unreadable: Verify = %v, want the other genuine layer to accept", blocked, err)
		}
	}
}

// A readable layer that fails to verify and an unreadable one: no signature
// verified, but the unreadable one might have, so the answer is "could not
// read", with both reasons named.
func TestVerify_AnInvalidLayerBesideAnUnreadableOneIsUnreadable(t *testing.T) {
	b := &blobBlocker{status: http.StatusForbidden}
	host := trusttest.NewRegistry(t, b.wrap)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	p := trusttest.Payload(t, ref.Context().Name(), d)
	p2 := append(append([]byte{}, p...), ' ')
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{
		{Payload: p, Signature: trusttest.Sign(t, trusttest.NewKey(t), p)}, // readable, wrong key
		{Payload: p2, Signature: trusttest.Sign(t, key, p2)},               // genuine, unreadable
	})
	b.path.Store("/v2/assay-db/blobs/" + sigLayerDigests(t, ref.Context(), d)[1].String())
	b.armed.Store(true)
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrSignatureUnreadable) || errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrSignatureUnreadable", err)
	}
	if !strings.Contains(err.Error(), "layer 0") || !strings.Contains(err.Error(), "layer 1") {
		t.Errorf("err = %v, want both layers' reasons", err)
	}
}

// A blob the registry serves but whose bytes do not match the manifest's
// digest was read: it is wrong, not unknown, and stays ErrNoKeyVerifies.
func TestVerify_ABlobThatDoesNotMatchItsDigestIsInvalid(t *testing.T) {
	var served atomic.Value
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, _ := served.Load().(string); r.Method == http.MethodGet && r.URL.Path == p {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte(`{"critical":{"type":"tampered"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)
	served.Store("/v2/assay-db/blobs/" + sigLayerDigests(t, ref.Context(), d)[0].String())
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrNoKeyVerifies) || errors.Is(err, ErrSignatureUnreadable) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies", err)
	}
}

// A payload stream cut short -- the registry promised more bytes than it
// sent -- was not read either: unreadable, not invalid.
func TestVerify_APayloadStreamCutShortIsUnreadable(t *testing.T) {
	var cut, cutSize atomic.Value
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, _ := cut.Load().(string); r.Method == http.MethodGet && r.URL.Path == p {
				// The descriptor's own size, so the client's size check
				// passes and the cut lands mid-body.
				w.Header().Set("Content-Length", cutSize.Load().(string))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"critical":`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)
	img, err := remote.Image(ref.Context().Tag(SigTag(d)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	cutSize.Store(strconv.FormatInt(m.Layers[0].Size, 10))
	cut.Store("/v2/assay-db/blobs/" + m.Layers[0].Digest.String())
	_, err = Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrSignatureUnreadable) || errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrSignatureUnreadable", err)
	}
}

// The caller's context ends while a payload is being fetched (dbstatus's
// own deadline, say): nothing was checked, so unreadable.
func TestVerify_AContextEndedMidFetchIsUnreadable(t *testing.T) {
	var path atomic.Value
	reached := make(chan struct{}, 1)
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, _ := path.Load().(string); r.Method == http.MethodGet && r.URL.Path == p {
				reached <- struct{}{}
				<-r.Context().Done()
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)
	path.Store("/v2/assay-db/blobs/" + sigLayerDigests(t, ref.Context(), d)[0].String())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-reached; cancel() }()
	_, err := Verify(ctx, ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrSignatureUnreadable) || errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrSignatureUnreadable", err)
	}
}
