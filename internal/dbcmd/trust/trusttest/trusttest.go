// Package trusttest mints cosign-shaped signatures in-test and serves them
// from an in-process registry, so trust.Verify and its callers can be
// tested without the cosign CLI (D137). The payload and tag layout follow
// cosign's key-based mode exactly: a simple-signing JSON payload as a layer
// of the image at tag sha256-<hex>.sig, with the base64 DER ECDSA signature
// in the layer's dev.cosignproject.cosign/signature annotation.
package trusttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// SignatureAnnotation and PayloadType are cosign's spellings, duplicated
// here rather than imported so a drift in the production constants shows up
// as a test failure instead of a test that drifted with them.
const (
	SignatureAnnotation = "dev.cosignproject.cosign/signature"
	PayloadType         = "cosign container image signature"
	payloadMediaType    = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// NewRegistry serves an in-memory OCI registry and returns its host:port.
// wrap, when non-nil, decorates the handler (a test can fail one path).
func NewRegistry(t testing.TB, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	var h http.Handler = registry.New()
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// PushArtifact writes a small random image to host/repo:tag and returns the
// reference and its manifest digest.
func PushArtifact(t testing.TB, host, repo, tag string) (name.Reference, v1.Hash) {
	t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(host + "/" + repo + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return ref, d
}

// NewKey is a fresh ECDSA P-256 signing key.
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Payload is cosign's simple-signing document for digest, as bytes.
func Payload(t testing.TB, repoName string, digest v1.Hash) []byte {
	t.Helper()
	doc := map[string]any{
		"critical": map[string]any{
			"identity": map[string]any{"docker-reference": repoName},
			"image":    map[string]any{"docker-manifest-digest": digest.String()},
			"type":     PayloadType,
		},
		"optional": nil,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Sign returns the base64 DER ECDSA signature cosign would write for
// payload: ECDSA-P256-SHA256 over the raw bytes.
func Sign(t testing.TB, key *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// SigLayer is one layer of a .sig image. NoAnnotation omits the signature
// annotation entirely.
type SigLayer struct {
	Payload      []byte
	Signature    string
	NoAnnotation bool
}

// WriteSig writes the .sig image for digest under repo with the given
// layers, replacing any existing one.
func WriteSig(t testing.TB, repo name.Repository, digest v1.Hash, layers []SigLayer) {
	t.Helper()
	img := v1.Image(empty.Image)
	for _, l := range layers {
		add := mutate.Addendum{Layer: static.NewLayer(l.Payload, types.MediaType(payloadMediaType))}
		if !l.NoAnnotation {
			add.Annotations = map[string]string{SignatureAnnotation: l.Signature}
		}
		var err error
		img, err = mutate.Append(img, add)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := remote.Write(repo.Tag(SigTag(digest)), img); err != nil {
		t.Fatal(err)
	}
}

// SigTag is cosign's tag for a digest's signature: sha256-<hex>.sig.
func SigTag(digest v1.Hash) string {
	return strings.Replace(digest.String(), ":", "-", 1) + ".sig"
}

// SignArtifact is the common case: one genuine layer signed by key.
func SignArtifact(t testing.TB, key *ecdsa.PrivateKey, ref name.Reference, digest v1.Hash) {
	t.Helper()
	p := Payload(t, ref.Context().Name(), digest)
	WriteSig(t, ref.Context(), digest, []SigLayer{{Payload: p, Signature: Sign(t, key, p)}})
}
