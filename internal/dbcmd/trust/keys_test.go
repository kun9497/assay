package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"testing"
)

// D137: the binary trusts the keys committed under keys/ and nothing else.
// A key's id is what cosign prints and what db status and error messages
// name, so it is pinned to one derivation here.

func TestTrustedKeys_EmbedsAtLeastOneP256Key(t *testing.T) {
	keys := TrustedKeys()
	if len(keys) < 1 {
		t.Fatal("TrustedKeys() is empty: nothing could ever verify a published artifact")
	}
	id := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for _, k := range keys {
		if k.Key == nil || k.Key.Curve != elliptic.P256() {
			t.Errorf("key %q is not an ECDSA P-256 key: %+v", k.ID, k.Key)
		}
		if !id.MatchString(k.ID) {
			t.Errorf("key id %q is not 16 lowercase hex characters", k.ID)
		}
	}
}

func TestKeyID_IsSHA256OfPKIXDER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])[:16]
	if got := KeyID(&priv.PublicKey); got != want {
		t.Errorf("KeyID = %q, want %q (first 16 hex of sha256 over the PKIX DER)", got, want)
	}
}

func TestParsePublicKeyPEM_RejectsRSAAndGarbage(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := ParsePublicKeyPEM(rsaPEM); err == nil {
		t.Error("an RSA key was accepted; only ECDSA P-256 keys sign the artifact")
	}
	if _, err := ParsePublicKeyPEM([]byte("nope")); err == nil {
		t.Error("garbage was accepted as a public key")
	}
}

// A parsed key round-trips to the same id the file is named by, so a
// mis-named file is caught at build time rather than at a customer's pull.
func TestTrustedKeys_IDsMatchTheirFileNames(t *testing.T) {
	for _, k := range TrustedKeys() {
		if KeyID(k.Key) != k.ID {
			t.Errorf("key file %s.pub parses to id %s", k.ID, KeyID(k.Key))
		}
	}
}
