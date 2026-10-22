package trust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// The Go verifier against a signature the REAL cosign CLI wrote (D137's
// review): every other test mints signatures in trusttest's reading of
// cosign's layout, which cannot catch a mis-reading. testdata/cosign/ holds
// one .sig image captured from cosign v2.4.3 over a known digest, with the
// test key it was signed by; the test below serves it from an in-process
// registry under the same digest and requires Verify to accept it.
//
// Regenerate (after a cosign upgrade) with the real CLI on PATH or named:
//
//	ASSAY_COSIGN=/path/to/cosign go test ./internal/dbcmd/trust -run TestCosignFixture_Regenerate -count=1
//
// which rewrites testdata/cosign/*. The committed files are what CI runs.

const cosignFixtureDir = "testdata/cosign"

type cosignFixture struct {
	CosignVersion string `json:"cosignVersion"`
	Digest        string `json:"digest"`
	Layers        []struct {
		Payload   string `json:"payload"`   // base64 of the raw layer bytes
		Signature string `json:"signature"` // the annotation, verbatim
	} `json:"layers"`
}

func TestVerify_AcceptsARealCosignSignature(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(cosignFixtureDir, "signature.json"))
	if err != nil {
		t.Fatalf("fixture missing (regenerate with ASSAY_COSIGN): %v", err)
	}
	var fx cosignFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(cosignFixtureDir, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := v1.NewHash(fx.Digest)
	if err != nil {
		t.Fatal(err)
	}
	host := trusttest.NewRegistry(t, nil)
	repo, err := name.NewRepository(host + "/assay-db")
	if err != nil {
		t.Fatal(err)
	}
	var layers []trusttest.SigLayer
	for _, l := range fx.Layers {
		p, err := base64.StdEncoding.DecodeString(l.Payload)
		if err != nil {
			t.Fatal(err)
		}
		layers = append(layers, trusttest.SigLayer{Payload: p, Signature: l.Signature})
	}
	trusttest.WriteSig(t, repo, digest, layers)

	id, err := Verify(context.Background(), repo, digest, []PublicKey{pub})
	if err != nil {
		t.Fatalf("Verify refused cosign %s's own signature: %v", fx.CosignVersion, err)
	}
	if id != pub.ID {
		t.Errorf("key id = %s, want the fixture key's %s", id, pub.ID)
	}
	// And the payload cosign wrote names the digest the way the verifier
	// reads it -- the layout assumption trusttest encodes, pinned here.
	if !strings.Contains(string(mustDecode(t, fx.Layers[0].Payload)), `"docker-manifest-digest":"`+fx.Digest+`"`) {
		t.Errorf("cosign's payload does not spell the digest where the verifier reads it:\n%s", mustDecode(t, fx.Layers[0].Payload))
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCosignFixture_Regenerate signs an artifact in an in-process registry
// with the real cosign named by ASSAY_COSIGN and writes the fixture. Skipped
// without the variable, loudly, so a CI run says the fixture was not
// regenerated rather than passing in silence.
func TestCosignFixture_Regenerate(t *testing.T) {
	cosign := os.Getenv("ASSAY_COSIGN")
	if cosign == "" {
		t.Skip("ASSAY_COSIGN not set: not regenerating testdata/cosign (the committed fixture is what TestVerify_AcceptsARealCosignSignature uses)")
	}
	dir := t.TempDir()
	// cosign's own key pair, so the fixture is cosign's reading of a key too.
	gen := exec.Command(cosign, "generate-key-pair")
	gen.Dir = dir
	gen.Env = append(os.Environ(), "COSIGN_PASSWORD=fixture")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate-key-pair: %v\n%s", err, out)
	}
	host := trusttest.NewRegistry(t, nil)
	ref, digest := trusttest.PushArtifact(t, host, "assay-db", "v14")
	sign := exec.Command(cosign, "sign", "--key", filepath.Join(dir, "cosign.key"), "--tlog-upload=false", "--yes",
		"--allow-http-registry", "--allow-insecure-registry", ref.Context().Name()+"@"+digest.String())
	sign.Env = append(os.Environ(), "COSIGN_PASSWORD=fixture")
	if out, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("cosign sign: %v\n%s", err, out)
	}
	ver, _ := exec.Command(cosign, "version", "--json").Output()
	var vj struct {
		GitVersion string `json:"gitVersion"`
	}
	_ = json.Unmarshal(ver, &vj)

	img, err := remote.Image(ref.Context().Tag(SigTag(digest)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	fx := cosignFixture{CosignVersion: vj.GitVersion, Digest: digest.String()}
	for i, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		buf := make([]byte, 1<<16)
		for {
			n, err := rc.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		rc.Close()
		fx.Layers = append(fx.Layers, struct {
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}{Payload: base64.StdEncoding.EncodeToString([]byte(sb.String())), Signature: manifest.Layers[i].Annotations[SignatureAnnotation]})
	}
	if err := os.MkdirAll(cosignFixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ := json.MarshalIndent(fx, "", "  ")
	if err := os.WriteFile(filepath.Join(cosignFixtureDir, "signature.json"), append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cosignFixtureDir, "cosign.pub"), pub, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture written from cosign %s: %d layer(s), digest %s", vj.GitVersion, len(fx.Layers), digest)
}
