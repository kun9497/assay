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
	"net/http"
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
	// MaxLayers bounds how many layers a .sig manifest may carry before it
	// is refused unread: cosign appends one per re-sign, so a handful is
	// the honest maximum, and each layer costs a blob request.
	MaxLayers = 16
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
	// ErrSignatureUnreadable: a signature tag exists, no layer verified,
	// and at least one layer's payload could not be fetched -- so whether
	// the artifact is validly signed is not known. Neither ErrNotSigned
	// (the tag is there) nor ErrNoKeyVerifies (an unread layer was never
	// checked): a caller treats it as the transport failure it is, which
	// keeps --allow-unsigned out of reach and a status page from
	// publishing signed:false over a registry hiccup.
	ErrSignatureUnreadable = errors.New("signature could not be read")

	// errPayloadUnread marks a verifyLayer failure that happened before
	// anything was checked: the payload never arrived.
	errPayloadUnread = errors.New("payload not read")
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
// the first would hide the one that mattered. That failure is
// ErrSignatureUnreadable when some layer's payload could not be fetched
// (that layer might have verified), else ErrNoKeyVerifies.
func Verify(ctx context.Context, repo name.Repository, digest v1.Hash, keys []PublicKey, opts ...remote.Option) (string, error) {
	tag := repo.Tag(SigTag(digest))
	// ctx reaches the registry through the options; appended last so a
	// caller's own WithContext is the same one, and a caller that passed
	// none still gets cancellation.
	opts = append(opts, remote.WithContext(ctx))
	img, err := remote.Image(tag, opts...)
	if err != nil {
		// Any 404 is "not signed", whatever its body says: the repository
		// exists (the caller just fetched the artifact's manifest from it),
		// and registries spell a missing tag differently -- MANIFEST_UNKNOWN
		// per the spec, NOT_FOUND on Harbor, an HTML page or nothing behind a
		// proxy. Read as a transport failure, --allow-unsigned could not reach
		// it. 401, 403 and 5xx stay transport failures.
		var terr *transport.Error
		if errors.As(err, &terr) {
			if terr.StatusCode == http.StatusNotFound {
				return "", fmt.Errorf("%w: no %s in %s", ErrNotSigned, SigTag(digest), repo)
			}
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
	if len(layers) > MaxLayers {
		return "", fmt.Errorf("%w (%s): %d layers, more than the %d a re-signed artifact can carry; refusing to read them",
			ErrNoKeyVerifies, tag, len(layers), MaxLayers)
	}

	var reasons []string
	unread := false
	for i, layer := range layers {
		id, err := verifyLayer(layer, manifest.Layers[i].Annotations, digest, keys)
		if err == nil {
			return id, nil
		}
		if errors.Is(err, errPayloadUnread) {
			unread = true
		}
		reasons = append(reasons, fmt.Sprintf("layer %d: %v", i, err))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no layers")
	}
	if unread {
		return "", fmt.Errorf("%w (%s): %s", ErrSignatureUnreadable, tag, strings.Join(reasons, "; "))
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
		return "", readFailure(err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, MaxPayloadBytes+1))
	if err != nil {
		return "", readFailure(err)
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

// readFailure classifies a payload read error. The layer is invalid only
// when ggcr checked bytes the registry did send and they were wrong: a blob
// that does not hash to its digest, or a size that is not the descriptor's.
// Every other read error -- the registry refusing or erroring (after the
// client's retries), the network, a stream cut short over HTTP/1 or reset
// over HTTP/2, a cancelled context, or a failure of a kind not listed --
// leaves the layer unchecked (errPayloadUnread). Defaulting to unread is
// the safe side: an unread layer still refuses the install, and only keeps
// a status page from announcing a signature outage it did not observe.
//
// A typed transport error is decided first, so a registry whose error body
// happens to contain ggcr's wording is still a transport failure. ggcr's
// checks are recognised by their messages because their types are in its
// internal package; TestVerify_ABlobThatDoesNotMatchItsDigestIsInvalid
// fails if an upgrade changes the wording.
func readFailure(err error) error {
	var terr *transport.Error
	if errors.As(err, &terr) || !contentMismatch(err) {
		return fmt.Errorf("read payload: %w: %w", errPayloadUnread, err)
	}
	return fmt.Errorf("read payload: %w", err)
}

// contentMismatch reports whether err is one of ggcr's checks of received
// bytes (internal/verify: "error verifying Digest|Size|size|<algo> checksum";
// remote/fetcher.go: a Content-Length that "does not match expected size").
func contentMismatch(err error) bool {
	s := err.Error()
	return strings.Contains(s, "error verifying ") || strings.Contains(s, "does not match expected size")
}
