// Package trust holds the public keys a binary trusts to have signed the
// published database artifact, and verifies cosign's signature of a pulled
// artifact against them (D137).
//
// The keys are embedded, not fetched: a key fetched from the same place as
// the artifact verifies nothing that a compromise of that place cannot
// forge. Rotation is a release that adds the next key before it signs
// anything and a later release that drops the old one; the binary trusts
// every key under keys/, in file order.
package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed keys/*.pub
var keyFiles embed.FS

// PublicKey is one trusted signing key. ID is what cosign prints for it,
// what error messages name, and what db status records as `signed: key`.
type PublicKey struct {
	ID  string
	Key *ecdsa.PublicKey
}

// KeyID is the first 16 hex characters of SHA-256 over the key's PKIX DER
// encoding -- the file name under keys/ and cosign's own spelling.
func KeyID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// A P-256 key always marshals; a nil or exotic curve is a defect
		// in the caller, and an empty id is visibly wrong everywhere it is
		// printed.
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16]
}

// ParsePublicKeyPEM reads one PEM-encoded PKIX public key and requires an
// ECDSA P-256 key, the only kind the signing workflow produces (cosign
// generate-key-pair). Anything else is refused rather than trusted.
func ParsePublicKeyPEM(data []byte) (PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return PublicKey{}, errors.New("not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return PublicKey{}, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return PublicKey{}, fmt.Errorf("public key is %T, want an ECDSA P-256 key", parsed)
	}
	return PublicKey{ID: KeyID(pub), Key: pub}, nil
}

// trusted is parsed once at init. A malformed committed key, or one whose
// file name is not its id, panics here: that is a defect in the repository,
// caught by the package's own tests before it could ship, and a binary
// that silently trusted fewer keys than it was built with is the quieter
// failure.
var trusted = func() []PublicKey {
	entries, err := fs.ReadDir(keyFiles, "keys")
	if err != nil {
		panic("trust: " + err.Error())
	}
	var keys []PublicKey
	for _, e := range entries {
		data, err := keyFiles.ReadFile("keys/" + e.Name())
		if err != nil {
			panic("trust: " + err.Error())
		}
		k, err := ParsePublicKeyPEM(data)
		if err != nil {
			panic("trust: keys/" + e.Name() + ": " + err.Error())
		}
		if want := strings.TrimSuffix(e.Name(), ".pub"); want != k.ID {
			panic(fmt.Sprintf("trust: keys/%s holds the key %s", e.Name(), k.ID))
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	return keys
}()

// TrustedKeys returns the embedded keys, in id order. Callers must not
// modify the returned slice's keys; the slice itself is a copy.
func TrustedKeys() []PublicKey {
	out := make([]PublicKey, len(trusted))
	copy(out, trusted)
	return out
}
