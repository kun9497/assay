package dbcmd

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// cutBlob wraps a registry so the first `cuts` GETs of the database layer's
// blob send half of it and drop the connection -- a download interrupted
// mid-stream, after go-containerregistry's own request retry has already
// succeeded (it retries the request, not the body). Every other request,
// and every later GET of the blob, is served whole.
type cutBlob struct {
	layer  atomic.Value // string: "/blobs/sha256:..."
	cuts   atomic.Int32
	served atomic.Int32
}

func (c *cutBlob) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, _ := c.layer.Load().(string)
		if r.Method != http.MethodGet || path == "" || !strings.HasSuffix(r.URL.Path, path) {
			h.ServeHTTP(w, r)
			return
		}
		c.served.Add(1)
		if c.cuts.Add(-1) < 0 {
			h.ServeHTTP(w, r)
			return
		}
		rec := &bufferedResponse{header: http.Header{}}
		h.ServeHTTP(rec, r)
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(rec.body.Len()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rec.body.Bytes()[:rec.body.Len()/2])
		// Returning with fewer bytes than Content-Length makes net/http
		// close the connection; the client reads io.ErrUnexpectedEOF.
	})
}

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) WriteHeader(s int)           { b.status = s }

// publishWithCuts publishes a signed, valid database behind a registry that
// cuts its layer `cuts` times, and returns the reference and the cutter.
func publishWithCuts(t *testing.T, cuts int32) (string, *cutBlob) {
	t.Helper()
	c := &cutBlob{}
	ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, c.wrap)
	img, err := remote.Image(mustRef(t, ref))
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		mt, _ := l.MediaType()
		if string(mt) == dbartifact.MediaTypeLayer {
			d, _ := l.Digest()
			c.layer.Store("/blobs/" + d.String())
		}
	}
	c.cuts.Store(cuts)
	return ref, c
}

func noPause(t *testing.T) {
	t.Helper()
	old := transferRetryPause
	transferRetryPause = func(int) {}
	t.Cleanup(func() { transferRetryPause = old })
}

// D140: a download cut mid-stream is retried, and the retry is said on
// stderr. The caller's test, written before the retry existed: it drives
// Pull end to end and asserts the database landed after the layer was
// fetched twice.
func TestPull_RetriesADownloadCutMidStream(t *testing.T) {
	noPause(t)
	ref, c := publishWithCuts(t, 1)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 0 {
		t.Fatalf("Pull with one interrupted download = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if got := c.served.Load(); got != 2 {
		t.Errorf("layer fetched %d times, want 2 (one cut, one whole)", got)
	}
	if !strings.Contains(errOut.String(), "retrying (2/3)") {
		t.Errorf("stderr does not say the download was retried:\n%s", errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatalf("the retried pull did not install a usable database: %v", err)
	}
	db.Close()
}

// Three attempts, then the pull fails as it always did: a link that cuts
// every download is not hidden behind an endless loop.
func TestPull_GivesUpAfterThreeInterruptedDownloads(t *testing.T) {
	noPause(t)
	ref, c := publishWithCuts(t, 3)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("Pull with every download interrupted = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if got := c.served.Load(); got != 3 {
		t.Errorf("layer fetched %d times, want exactly 3", got)
	}
	if !strings.Contains(errOut.String(), "after 3 attempts") {
		t.Errorf("stderr does not say how many attempts were made:\n%s", errOut.String())
	}
}

// The nightly's seed pull gets the same retry: an interrupted seed download
// fails the whole publish, and that is the run D140 exists for.
func TestPullSeed_RetriesADownloadCutMidStream(t *testing.T) {
	noPause(t)
	ref, c := publishWithCuts(t, 1)
	dst := filepath.Join(t.TempDir(), "seed.db")

	var out, errOut bytes.Buffer
	if code := PullSeed(context.Background(), dst, ref, &out, &errOut); code != 0 {
		t.Fatalf("PullSeed with one interrupted download = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if got := c.served.Load(); got != 2 {
		t.Errorf("layer fetched %d times, want 2", got)
	}
}

// garbleBlob serves the database layer whole but with every byte replaced,
// so it is not gzip: a property of the artifact, not of the link.
type garbleBlob struct {
	layer  string
	served atomic.Int32
}

func (g *garbleBlob) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || g.layer == "" || !strings.HasSuffix(r.URL.Path, g.layer) {
			h.ServeHTTP(w, r)
			return
		}
		g.served.Add(1)
		rec := &bufferedResponse{header: http.Header{}}
		h.ServeHTTP(rec, r)
		junk := bytes.Repeat([]byte{'x'}, rec.body.Len())
		w.Header().Set("Content-Length", strconv.Itoa(len(junk)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(junk)
	})
}

// A layer that arrives whole and is not a database layer fails at once:
// retrying an artifact's own defect repeats the same answer three times
// and triples the download for nothing.
func TestPull_ABrokenArtifactIsNotRetried(t *testing.T) {
	noPause(t)
	g := &garbleBlob{}
	ref := publishedFrom(t, pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), store.SchemaVersion, g.wrap)
	img, err := remote.Image(mustRef(t, ref))
	if err != nil {
		t.Fatal(err)
	}
	layers, _ := img.Layers()
	for _, l := range layers {
		if mt, _ := l.MediaType(); string(mt) == dbartifact.MediaTypeLayer {
			d, _ := l.Digest()
			g.layer = "/blobs/" + d.String()
		}
	}
	dst := filepath.Join(t.TempDir(), "vulnerability.db")

	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("Pull of a non-gzip layer = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if got := g.served.Load(); got != 1 {
		t.Errorf("a broken layer was fetched %d times, want 1", got)
	}
	if strings.Contains(errOut.String(), "retrying") {
		t.Errorf("a broken artifact was retried:\n%s", errOut.String())
	}
}
