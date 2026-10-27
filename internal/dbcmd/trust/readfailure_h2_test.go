package trust

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A payload GET over HTTP/2 -- what a TLS registry negotiates, ggcr's
// transport forcing it -- whose stream the server resets after the headers.
// The body read fails with net/http's unexported http2 stream error, which
// is no net.Error: before, it was filed as a readable invalid signature
// (branch review wf_724fb3e1-bb3). Anything but ggcr's own checks of the
// bytes it was sent is unread.
func TestReadFailure_AnHTTP2StreamResetIsUnread(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"critical":`))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/v2/x/blobs/sha256:00")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("proto %s, want HTTP/2.0", resp.Proto)
	}
	_, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := readFailure(rerr)
	if !errors.Is(got, errPayloadUnread) {
		t.Errorf("an HTTP/2 stream reset mid-payload is classified as a readable invalid signature: %v", got)
	}
}
