package trust

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

// Rows added by D137's review: guards the first draft described in comments
// but held by nothing.

// The cap is on bytes READ, not merely on bytes counted after a full read:
// a registry that streams megabytes under the payload blob must see the
// client stop near the cap. Asserted on what the server managed to write.
func TestVerify_PayloadCapStopsReadingNearTheCap(t *testing.T) {
	huge := bytes.Repeat([]byte(" "), 8<<20) // 8 MiB
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: huge, Signature: trusttest.Sign(t, key, huge)}})

	// Count the bytes the client actually pulls through its transport.
	counting := &countingTransport{RoundTripper: http.DefaultTransport}
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)}, remoteWithTransport(counting))
	if !errors.Is(err, ErrNoKeyVerifies) {
		t.Fatalf("err = %v, want ErrNoKeyVerifies", err)
	}
	if n := counting.bodyBytes.Load(); n > 2*MaxPayloadBytes {
		t.Errorf("the client read %d bytes of an 8 MiB payload; the cap is %d and reading must stop near it", n, MaxPayloadBytes)
	}
}

// A .sig manifest with more layers than any re-signed artifact carries is
// refused before a single blob is fetched.
func TestVerify_TooManyLayersIsRefusedUnread(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	p := trusttest.Payload(t, ref.Context().Name(), d)
	var layers []trusttest.SigLayer
	for i := 0; i <= MaxLayers; i++ {
		layers = append(layers, trusttest.SigLayer{Payload: append([]byte{}, p...), Signature: trusttest.Sign(t, key, p)})
	}
	trusttest.WriteSig(t, ref.Context(), d, layers)
	counting := &countingTransport{RoundTripper: http.DefaultTransport}
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)}, remoteWithTransport(counting))
	if !errors.Is(err, ErrNoKeyVerifies) || !strings.Contains(err.Error(), "17 layers") {
		t.Fatalf("err = %v, want a refusal naming the layer count", err)
	}
	if n := counting.blobGets.Load(); n != 0 {
		t.Errorf("%d blob requests were made for a manifest refused on its layer count", n)
	}
	// And exactly the maximum is still read and accepted.
	trusttest.WriteSig(t, ref.Context(), d, layers[:MaxLayers])
	if _, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)}); err != nil {
		t.Errorf("%d layers refused: %v", MaxLayers, err)
	}
}

// ctx is honoured even when the caller passed no remote.WithContext.
func TestVerify_CancelledContextFailsWithoutAnOption(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	key := trusttest.NewKey(t)
	trusttest.SignArtifact(t, key, ref, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, ref.Context(), d, []PublicKey{keyOf(t, key)}); err == nil || errors.Is(err, ErrNotSigned) {
		t.Fatalf("err = %v, want the cancelled context's failure", err)
	}
}

// The signature is checked before the payload is parsed: a payload that is
// not JSON, under a key that is not trusted, is reported as a signature
// failure -- parse-first would report "not JSON" and would have believed
// the bytes before any key vouched for them.
func TestVerify_SignatureIsCheckedBeforeThePayloadIsParsed(t *testing.T) {
	host := trusttest.NewRegistry(t, nil)
	ref, d := trusttest.PushArtifact(t, host, "assay-db", "v14")
	notJSON := []byte("not json at all")
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: notJSON, Signature: trusttest.Sign(t, trusttest.NewKey(t), notJSON)}})
	_, err := Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if err == nil || !strings.Contains(err.Error(), "ECDSA signature does not verify") || strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("err = %v, want the signature refusal, not a parse error", err)
	}
	// And under a trusted key, the parse error is what remains.
	key := trusttest.NewKey(t)
	trusttest.WriteSig(t, ref.Context(), d, []trusttest.SigLayer{{Payload: notJSON, Signature: trusttest.Sign(t, key, notJSON)}})
	_, err = Verify(context.Background(), ref.Context(), d, []PublicKey{keyOf(t, key)})
	if err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("err = %v, want the parse error once the signature verified", err)
	}
}
