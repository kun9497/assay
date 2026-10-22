package trust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// D137's verifier, against an in-process registry and signatures minted
// in-test in cosign's shape. Every negative row is executed; the rows are
// the attacks the design names plus the review-focus shapes.

func keyOf(t *testing.T, k *ecdsa.PrivateKey) PublicKey {
	t.Helper()
	pk, err := ParsePublicKeyPEM(trusttestPEM(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestVerify_AcceptsAGenuineSignatureAndReportsTheKey(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)

	id, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id != KeyID(&key.PublicKey) {
		t.Errorf("key id = %q, want %q", id, KeyID(&key.PublicKey))
	}
}

func TestVerify_WrongKeyIsRefused(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	trusttest.SignArtifact(t, trusttest.NewKey(t), ref, d)

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if !errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies", err)
	}
}

// The payload is re-serialised (still valid JSON, still names the right
// digest) while the original signature stays: the raw bytes no longer
// verify, and that must be checked BEFORE the JSON is believed.
func TestVerify_TamperedPayloadIsRefusedBeforeParsing(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	genuine := trusttest.Payload(t, ref.Context().Name(), d)
	sig := trusttest.Sign(t, key, genuine)
	tampered := bytes.Replace(genuine, []byte(`"optional":null`), []byte(`"optional":{"x":1}`), 1)
	if bytes.Equal(tampered, genuine) {
		t.Fatal("fixture: tampering did not change the payload")
	}
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: tampered, Signature: sig}})

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies", err)
	}
}

func TestVerify_UnsignedArtifactIsNotSigned(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if !errors.Is(err, ErrNotSigned) {
		t.Fatalf("err = %v, want ErrNotSigned", err)
	}
	if !strings.Contains(err.Error(), SigTag(d)) {
		t.Errorf("err = %q, want it to name the missing tag %s", err, SigTag(d))
	}
}

// A genuine signature for another artifact copied onto this one's tag: the
// ECDSA check passes, the digest binding must refuse it.
func TestVerify_ForeignGenuineSignatureIsRefusedOnDigest(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	refA, dA := trusttest.PushArtifact(t, host, "assay-db", "a")
	_, dB := trusttest.PushArtifact(t, host, "assay-db", "b")
	key := trusttest.NewKey(t)
	payloadB := trusttest.Payload(t, refA.Context().Name(), dB)
	trusttest.WriteSig(t, refA.Context(), dA, []trusttest.SigLayer{{Payload: payloadB, Signature: trusttest.Sign(t, key, payloadB)}})

	_, err := Verify(context.Background(), refA.Context(), dA, []PublicKey{keyOf(t, key)})
	if err == nil || errors.Is(err, ErrNotSigned) {
		t.Fatalf("err = %v, want a digest refusal", err)
	}
	if !strings.Contains(err.Error(), dA.String()) || !strings.Contains(err.Error(), dB.String()) {
		t.Errorf("err = %q, want both digests named", err)
	}
}

func TestVerify_MissingAnnotationIsRefused(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	p := trusttest.Payload(t, ref.Context().Name(), d)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: p, NoAnnotation: true}})

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrNoKeyVerifies) || !strings.Contains(err.Error(), SignatureAnnotation) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies naming %s", err, SignatureAnnotation)
	}
}

// cosign appends a layer on re-sign: any one valid layer accepts, and a
// total failure names every layer.
func TestVerify_SecondLayerAloneCanAccept(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	p := trusttest.Payload(t, ref.Context().Name(), d)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{
		{Payload: p, Signature: trusttest.Sign(t, trusttest.NewKey(t), p)}, // wrong key
		{Payload: p, Signature: trusttest.Sign(t, key, p)},                 // genuine
	})
	if _, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)}); err != nil {
		t.Fatalf("Verify: %v, want the second layer to accept", err)
	}
}

func TestVerify_AllLayersNamedOnFailure(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	p := trusttest.Payload(t, ref.Context().Name(), d)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{
		{Payload: p, Signature: trusttest.Sign(t, trusttest.NewKey(t), p)},
		{Payload: p, NoAnnotation: true},
	})
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if err == nil || !strings.Contains(err.Error(), "layer 0") || !strings.Contains(err.Error(), "layer 1") {
		t.Fatalf("err = %v, want every layer's reason named", err)
	}
}

func TestVerify_PayloadOverCapIsRefusedWithoutReading(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	big := append(trusttest.Payload(t, ref.Context().Name(), d), bytes.Repeat([]byte(" "), MaxPayloadBytes+1024)...)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: big, Signature: trusttest.Sign(t, key, big)}})

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if !errors.Is(err, ErrNoKeyVerifies) || !strings.Contains(err.Error(), "65536") {
		t.Fatalf("err = %v, want a refusal naming the %d-byte cap", err, MaxPayloadBytes)
	}
}

func TestVerify_TwoTrustedKeysSecondSigns(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	a, b := trusttest.NewKey(t), trusttest.NewKey(t)
	trusttest.SignArtifact(t, b, ref, d)

	id, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, a), keyOf(t, b)})
	if err != nil || id != KeyID(&b.PublicKey) {
		t.Fatalf("id=%q err=%v, want key b's id", id, err)
	}
}

func TestVerify_WrongPayloadTypeIsRefused(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	var doc map[string]any
	if err := json.Unmarshal(trusttest.Payload(t, ref.Context().Name(), d), &doc); err != nil {
		t.Fatal(err)
	}
	doc["critical"].(map[string]any)["type"] = "something else"
	p, _ := json.Marshal(doc)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: p, Signature: trusttest.Sign(t, key, p)}})

	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("err = %v, want a refusal on the payload type", err)
	}
}

// A registry that refuses the signature manifest with 403 is a transport
// failure, not "not signed": a mirror whose auth did not reach the second
// fetch must not read as an unsigned artifact.
func TestVerify_TransportFailureIsNotNotSigned(t *testing.T) {
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/manifests/sha256-") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if err == nil || errors.Is(err, ErrNotSigned) || errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want a transport error that is neither sentinel", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %q, want the status named", err)
	}
}

func TestVerify_EmptyKeyListRefuses(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	trusttest.SignArtifact(t, trusttest.NewKey(t), ref, d)
	_, err := Verify(context.Background(), ref.Context(), d, nil)
	if !errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies with no trusted keys", err)
	}
}

// The remote options reach the signature fetch: an option that fails every
// request fails Verify, which is how a test knows auth travels with it.
func TestVerify_UsesTheCallersRemoteOptions(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Verify(ctx, ref.Context(), d, []PublicKey{keyOf(t, key)}, remote.WithContext(ctx))
	if err == nil || errors.Is(err, ErrNotSigned) {
		t.Fatalf("err = %v, want the cancelled context's failure through the options", err)
	}
}

// SigTag spells cosign's tag.
func TestSigTag(t *testing.T) {
	d := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("ab", 32)}
	if got, want := SigTag(d), "sha256-"+strings.Repeat("ab", 32)+".sig"; got != want {
		t.Errorf("SigTag = %q, want %q", got, want)
	}
}
