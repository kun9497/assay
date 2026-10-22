package dbcmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust"
	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// testSigningKey signs every artifact this package's tests publish, and is
// trusted through the TrustedKeys seam for the whole test binary (D137).
// Registered once, in init, rather than swapped per test: the seam is a
// package variable, and a per-test swap would race any test that runs in
// parallel. The embedded production key stays trusted beside it, so a
// test that wants an UNTRUSTED signer mints a fresh key of its own.
var testSigningKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

func init() {
	TrustedKeys = func() []trust.PublicKey {
		return append(trust.TrustedKeys(), testSigningPublicKey())
	}
}

func testSigningPublicKey() trust.PublicKey {
	pub := &testSigningKey.PublicKey
	return trust.PublicKey{ID: trust.KeyID(pub), Key: pub}
}

// signPublished writes the .sig tag for whatever ref currently points at,
// signed by testSigningKey: what the publish workflow's cosign step does
// after `db push`, so a test's pull meets a signed artifact as a user's
// would.
func signPublished(t *testing.T, ref string) {
	t.Helper()
	r, d := hashOf(t, ref)
	trusttest.SignArtifact(t, testSigningKey, r, d)
}

// hashOf resolves ref at the registry and returns it with its manifest
// digest, the pair a signature is written against.
func hashOf(t *testing.T, ref string) (name.Reference, v1.Hash) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r, remote.WithContext(context.Background()))
	if err != nil {
		t.Fatalf("resolve %s: %v", ref, err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return r, d
}
