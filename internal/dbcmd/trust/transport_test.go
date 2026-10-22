package trust

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// countingTransport counts blob requests and the body bytes the client
// actually read, so a test can assert on what the verifier pulled rather
// than on what the server offered.
type countingTransport struct {
	http.RoundTripper
	blobGets  atomic.Int64
	bodyBytes atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.RoundTripper.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
		c.blobGets.Add(1)
	}
	resp.Body = &countingBody{ReadCloser: resp.Body, n: &c.bodyBytes}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func remoteWithTransport(t http.RoundTripper) remote.Option { return remote.WithTransport(t) }
