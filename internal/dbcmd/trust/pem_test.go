package trust

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// trusttestPEM renders a test key's public half the way cosign.pub is
// written, so the tests go through ParsePublicKeyPEM like production does.
func trusttestPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
