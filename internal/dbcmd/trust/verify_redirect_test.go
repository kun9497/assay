package trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kun9497/assay/internal/dbcmd/trust/trusttest"
)

func TestVerify_RedirectedSignatureTag404IsNotUnsigned(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".sig") {
			reached.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer target.Close()
	host := trusttest.NewRegistry(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".sig") {
				// Keep the path identical: only the authority distinguishes a
				// missing signature here from a redirect destination's 404.
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ref, digest := trusttest.PushArtifact(t, host, "assay-db", "v14")
	_, err := Verify(context.Background(), ref.Context(), digest, []PublicKey{keyOf(t, trusttest.NewKey(t))})
	if reached.Load() == 0 {
		t.Fatal("redirect destination was never reached")
	}
	if err == nil || errors.Is(err, ErrNotSigned) {
		t.Fatalf("Verify = %v, want a transport failure, not ErrNotSigned", err)
	}
}
