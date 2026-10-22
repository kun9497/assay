package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/dbcmd/trust"
	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// The artifacts this package's routing tests publish to an in-process
// registry are signed by this key, trusted through dbcmd.TrustedKeys for
// the whole test binary (D137) -- registered once in init, never swapped per
// test, for the same reason internal/dbcmd's own seam file gives: the seam
// is a package variable and the tests may run in parallel.
var testSigningKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

func init() {
	dbcmd.TrustedKeys = func() []trust.PublicKey {
		pub := &testSigningKey.PublicKey
		return append(trust.TrustedKeys(), trust.PublicKey{ID: trust.KeyID(pub), Key: pub})
	}
}

// signPublished writes the .sig tag for what ref points at, as the publish
// workflow's cosign step does after `db push`.
func signPublished(t *testing.T, ref string) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(r)
	if err != nil {
		t.Fatalf("resolve %s: %v", ref, err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	trusttest.SignArtifact(t, testSigningKey, r, d)
}
