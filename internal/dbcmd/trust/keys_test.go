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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	// The curve clause itself (D137's review): an ECDSA key that is not
	// P-256 passes the type assertion and must still be refused.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384})); err == nil {
		t.Error("a P-384 key was accepted; the signing key is P-256")
	}
	// Two keys in one file (the rotation mistake) and a non-PUBLIC KEY block.
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der256, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	one := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der256})
	if _, err := ParsePublicKeyPEM(append(append([]byte{}, one...), one...)); err == nil {
		t.Error("a file holding two PEM blocks was accepted; install.sh would trust both and the binary one")
	}
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der256})); err == nil {
		t.Error("a CERTIFICATE block was accepted as a public key")
	}
}

// Every file under keys/ is named by the id of the key it holds, read from
// the embedded FS by name -- so db status, error messages and the file
// cannot drift apart. (The first draft compared KeyID(k.Key) with k.ID,
// which ParsePublicKeyPEM had set from the same key: a tautology, D137's
// review.)
func TestTrustedKeys_FileNamesAreTheirKeyIDs(t *testing.T) {
	entries, err := fs.ReadDir(keyFiles, "keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no files under keys/")
	}
	for _, e := range entries {
		data, err := keyFiles.ReadFile("keys/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		k, err := ParsePublicKeyPEM(data)
		if err != nil {
			t.Fatalf("keys/%s: %v", e.Name(), err)
		}
		if want := strings.TrimSuffix(e.Name(), ".pub"); k.ID != want {
			t.Errorf("keys/%s holds the key %s", e.Name(), k.ID)
		}
	}
}

// install.sh carries the same keys as a PEM literal between its BEGIN/END
// TRUSTED KEYS markers; nothing else ties the two trust roots together, so
// this does (D137's review): the set of ids in the script equals the set
// the binary embeds.
func TestInstallScript_EmbedsExactlyTheTrustedKeys(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	start := strings.Index(s, "# BEGIN TRUSTED KEYS")
	end := strings.Index(s, "# END TRUSTED KEYS")
	if start < 0 || end < 0 || end < start {
		t.Fatal("install.sh lacks the TRUSTED KEYS markers")
	}
	block := s[start:end]
	got := map[string]bool{}
	rest := []byte(block)
	for {
		var p *pem.Block
		p, rest = pem.Decode(rest)
		if p == nil {
			break
		}
		k, err := ParsePublicKeyPEM(pem.EncodeToMemory(p))
		if err != nil {
			t.Fatalf("install.sh key block: %v", err)
		}
		got[k.ID] = true
	}
	want := map[string]bool{}
	for _, k := range TrustedKeys() {
		want[k.ID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("install.sh embeds %d key(s) %v, the binary trusts %d %v", len(got), got, len(want), want)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("install.sh does not embed key %s, which the binary trusts", id)
		}
	}
}
