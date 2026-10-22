package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Where cosign's key-based mode puts a signature (D137): the image at tag
// sha256-<hex>.sig in the artifact's own repository, one layer per
// signature, each layer a simple-signing JSON payload with the base64 DER
// ECDSA signature over the raw payload bytes in this annotation.
const (
	SignatureAnnotation = "dev.cosignproject.cosign/signature"
	PayloadType         = "cosign container image signature"
	// MaxPayloadBytes bounds one payload read. The .sig tag is writable by
	// whoever can write the repository -- the attacker in this design's
	// threat model -- so a layer is never read whole before it is judged;
	// a genuine payload is a few hundred bytes.
	MaxPayloadBytes = 65536
)

var (
	// ErrNotSigned: the repository carries no signature tag for the digest.
	// Distinct from a transport failure so a mirror that did not copy the
	// tag is told what to copy, and from ErrNoKeyVerifies so a present but
	// foreign signature is never mistaken for an absent one.
	ErrNotSigned = errors.New("artifact is not signed")
	// ErrNoKeyVerifies: a signature tag exists and no layer of it verifies
	// under any trusted key with a payload that binds the pulled digest.
	ErrNoKeyVerifies = errors.New("no signature verified under a trusted key")
)

// SigTag is cosign's tag for a digest's signature.
func SigTag(digest v1.Hash) string {
	return strings.Replace(digest.String(), ":", "-", 1) + ".sig"
}

// Verify fetches the signature image for digest under repo with opts (the
// same options the pull used, so auth and context travel with it) and
// returns the id of the trusted key that verified it. The rules, in order
// per layer: the annotation is present; some key verifies ECDSA-P256-SHA256
// over the RAW payload bytes; only then the payload parses as JSON, names
// PayloadType, and names digest as the signed manifest. The first layer to
// pass accepts; on total failure the error lists every layer's reason,
// because cosign appends a layer on re-sign and a diagnostic that stopped at
// the first would hide the one that mattered.
func Verify(ctx context.Context, repo name.Repository, digest v1.Hash, keys []PublicKey, opts ...remote.Option) (string, error) {
	tag := repo.Tag(SigTag(digest))
	img, err := remote.Image(tag, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			for _, e := range terr.Errors {
				if e.Code == transport.ManifestUnknownErrorCode {
					return "", fmt.Errorf("%w: no %s in %s", ErrNotSigned, SigTag(digest), repo)
				}
			}
		}
		return "", fmt.Errorf("signature %s: fetch: %w", tag, err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return "", fmt.Errorf("signature %s: read manifest: %w", tag, err)
	}
	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("signature %s: read layers: %w", tag, err)
	}
	if len(layers) != len(manifest.Layers) {
		return "", fmt.Errorf("signature %s: %d layers but %d descriptors", tag, len(layers), len(manifest.Layers))
	}

	var reasons []string
	for i, layer := range layers {
		id, err := verifyLayer(layer, manifest.Layers[i].Annotations, digest, keys)
		if err == nil {
			return id, nil
		}
		reasons = append(reasons, fmt.Sprintf("layer %d: %v", i, err))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no layers")
	}
	return "", fmt.Errorf("%w (%s): %s", ErrNoKeyVerifies, tag, strings.Join(reasons, "; "))
}

// payload is the part of cosign's simple-signing document this verifier
// reads. Everything else (identity, optional) is ignored: the reference a
// mirror serves differs from the one signed, by design.
type payload struct {
	Critical struct {
		Image struct {
			Digest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func verifyLayer(layer v1.Layer, annotations map[string]string, digest v1.Hash, keys []PublicKey) (string, error) {
	sigB64, ok := annotations[SignatureAnnotation]
	if !ok || sigB64 == "" {
		return "", fmt.Errorf("no %s annotation", SignatureAnnotation)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", fmt.Errorf("signature annotation is not base64: %w", err)
	}
	rc, err := layer.Compressed()
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, MaxPayloadBytes+1))
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}
	if len(raw) > MaxPayloadBytes {
		return "", fmt.Errorf("payload exceeds the %d-byte cap", MaxPayloadBytes)
	}
	// The signature is over the raw bytes and is checked before the bytes
	// are believed: a re-serialised payload that still names the right
	// digest must fail here, not be read for its digest.
	sum := sha256.Sum256(raw)
	keyID := ""
	for _, k := range keys {
		if ecdsa.VerifyASN1(k.Key, sum[:], sig) {
			keyID = k.ID
			break
		}
	}
	if keyID == "" {
		return "", errors.New("ECDSA signature does not verify under any trusted key")
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("signed payload is not JSON: %w", err)
	}
	if p.Critical.Type != PayloadType {
		return "", fmt.Errorf("signed payload type is %q, want %q", p.Critical.Type, PayloadType)
	}
	if p.Critical.Image.Digest != digest.String() {
		return "", fmt.Errorf("signed digest %s is not the pulled digest %s", p.Critical.Image.Digest, digest)
	}
	return keyID, nil
}
