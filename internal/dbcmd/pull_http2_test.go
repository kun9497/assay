package dbcmd

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// httpsOnly sends every request over the TLS test server's own client.
// go-containerregistry speaks plain HTTP to 127.0.0.1, which the HTTP/2 test
// server does not.
type httpsOnly struct{ next http.RoundTripper }

func (h httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.URL.Scheme = "https"
	return h.next.RoundTrip(c)
}

// h2Blob is how an HTTP/2 registry serves the database layer's blob, per GET.
type h2Blob int

const (
	h2Whole   h2Blob = iota
	h2Reset          // half the body, then RST_STREAM INTERNAL_ERROR
	h2Corrupt        // the whole body with one byte changed
	h2Stall          // half the body, then nothing until the client gives up
)

// publishHTTP2 publishes a signed database behind an HTTP/2 TLS registry.
// plan says how each GET of the layer is served, in order; GETs past the end
// of plan are served whole. It returns the reference, the GET counter, and
// a channel closed when a GET starts stalling.
func publishHTTP2(t *testing.T, plan ...h2Blob) (string, *atomic.Int32, chan struct{}) {
	t.Helper()
	var (
		layer   atomic.Value
		gets    atomic.Int32
		stalled = make(chan struct{})
	)
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, _ := layer.Load().(string)
		if r.Method != http.MethodGet || path == "" || !strings.HasSuffix(r.URL.Path, path) {
			reg.ServeHTTP(w, r)
			return
		}
		if r.ProtoMajor != 2 {
			t.Errorf("layer fetched over HTTP/%d.%d, want HTTP/2", r.ProtoMajor, r.ProtoMinor)
		}
		n := int(gets.Add(1)) - 1
		mode := h2Whole
		if n < len(plan) {
			mode = plan[n]
		}
		if mode == h2Whole {
			reg.ServeHTTP(w, r)
			return
		}
		rec := &bufferedResponse{header: http.Header{}}
		reg.ServeHTTP(rec, r)
		body := rec.body.Bytes()
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		switch mode {
		case h2Corrupt:
			bad := append([]byte(nil), body...)
			bad[len(bad)/2] ^= 0xff
			_, _ = w.Write(bad)
		case h2Reset:
			_, _ = w.Write(body[:len(body)/2])
			w.(http.Flusher).Flush()
			// An HTTP/2 server answers an aborted handler with RST_STREAM
			// INTERNAL_ERROR: the client reads "stream error: ...;
			// INTERNAL_ERROR; received from peer", which is not
			// io.ErrUnexpectedEOF and matched nothing D140 retried.
			panic(http.ErrAbortHandler)
		case h2Stall:
			_, _ = w.Write(body[:len(body)/2])
			w.(http.Flusher).Flush()
			close(stalled)
			<-r.Context().Done()
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	old := remote.DefaultTransport
	remote.DefaultTransport = httpsOnly{srv.Client().Transport}
	t.Cleanup(func() { remote.DefaultTransport = old })

	ref := strings.TrimPrefix(srv.URL, "https://") + "/assay-db:v" + itoa(store.SchemaVersion)
	img, err := dbartifact.Pack(pushable(t, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)), dbartifact.Meta{
		SchemaVersion: store.SchemaVersion,
		BuiltAt:       time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC),
		DataAsOf:      time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(parsed, img); err != nil {
		t.Fatal(err)
	}
	signPublished(t, ref)
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		if mt, _ := l.MediaType(); string(mt) == dbartifact.MediaTypeLayer {
			d, _ := l.Digest()
			layer.Store("/blobs/" + d.String())
		}
	}
	return ref, &gets, stalled
}

// previousDB installs a database at dst for a pull to replace and returns
// its bytes, so a failed pull can be held to leaving it alone.
func previousDB(t *testing.T, dst string) []byte {
	t.Helper()
	if err := copyFile(pushable(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)), dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertUntouched(t *testing.T, dst string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("a failed pull changed the previous database (read error %v)", err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a failed pull left %s.tmp behind (stat: %v)", filepath.Base(dst), err)
	}
}

// QA 2026-10-30: an HTTP/2 registry that resets the stream mid-body was not
// retried. D140 recognised a cut HTTP/1 body (io.ErrUnexpectedEOF), a reset
// or a failed socket read; HTTP/2's stream error is none of those, so Pull
// and PullSeed failed on the first GET. A read error from a response body is
// now a transfer failure whatever the protocol says it is.
func TestPull_QA1030_AnHTTP2StreamResetIsRetried(t *testing.T) {
	for _, seed := range []bool{false, true} {
		t.Run(map[bool]string{false: "Pull", true: "PullSeed"}[seed], func(t *testing.T) {
			noPause(t)
			ref, gets, _ := publishHTTP2(t, h2Reset)
			dst := filepath.Join(t.TempDir(), "vulnerability.db")
			previousDB(t, dst)
			var out, errOut bytes.Buffer
			code := 0
			if seed {
				code = PullSeed(context.Background(), dst, ref, &out, &errOut)
			} else {
				code = Pull(context.Background(), dst, ref, false, &out, &errOut)
			}
			if code != 0 {
				t.Fatalf("exit %d, want 0 after one reset stream (stderr: %s)", code, errOut.String())
			}
			if got := gets.Load(); got != 2 {
				t.Errorf("layer fetched %d times, want 2", got)
			}
			if !strings.Contains(errOut.String(), "retrying (2/3)") {
				t.Errorf("stderr does not say the download was retried:\n%s", errOut.String())
			}
			db, err := store.Open(dst)
			if err != nil {
				t.Fatalf("the retried pull did not install a usable database: %v", err)
			}
			db.Close()
		})
	}
}

// The bound holds for HTTP/2 too, and the database already installed
// survives every failed attempt.
func TestPull_QA1030_GivesUpAfterThreeResetStreams(t *testing.T) {
	noPause(t)
	ref, gets, _ := publishHTTP2(t, h2Reset, h2Reset, h2Reset)
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	before := previousDB(t, dst)
	var out, errOut bytes.Buffer
	if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if got := gets.Load(); got != 3 {
		t.Errorf("layer fetched %d times, want exactly 3", got)
	}
	assertUntouched(t, dst, before)
}

// The controls. A body that arrives whole with a byte changed -- gzip or
// the digest check refuses it -- is the artifact's defect, not the link's: it fails once. A pull the caller
// cancelled mid-body stops: the retry must not outlive the context.
func TestPull_QA1030_PermanentFailuresAreNotRetried(t *testing.T) {
	t.Run("corrupt layer", func(t *testing.T) {
		noPause(t)
		ref, gets, _ := publishHTTP2(t, h2Corrupt, h2Corrupt, h2Corrupt)
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		before := previousDB(t, dst)
		var out, errOut bytes.Buffer
		if code := Pull(context.Background(), dst, ref, false, &out, &errOut); code != 2 {
			t.Fatalf("exit %d, want 2 (stderr: %s)", code, errOut.String())
		}
		if got := gets.Load(); got != 1 {
			t.Errorf("a corrupt layer was fetched %d times, want 1", got)
		}
		if strings.Contains(errOut.String(), "retrying") {
			t.Errorf("a corrupt layer was retried:\n%s", errOut.String())
		}
		assertUntouched(t, dst, before)
	})
	t.Run("cancelled", func(t *testing.T) {
		noPause(t)
		ref, gets, stalled := publishHTTP2(t, h2Stall, h2Stall, h2Stall)
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		before := previousDB(t, dst)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-stalled
			cancel()
		}()
		var out, errOut bytes.Buffer
		if code := Pull(ctx, dst, ref, false, &out, &errOut); code != 2 {
			t.Fatalf("exit %d, want 2 (stderr: %s)", code, errOut.String())
		}
		if got := gets.Load(); got != 1 {
			t.Errorf("a cancelled pull fetched the layer %d times, want 1", got)
		}
		if strings.Contains(errOut.String(), "retrying") {
			t.Errorf("a cancelled pull was retried:\n%s", errOut.String())
		}
		assertUntouched(t, dst, before)
	})
	// --timeout's deadline: its error reports Timeout() like a stalled
	// socket's, which D140 retries, but no attempt can succeed past it.
	t.Run("past the deadline", func(t *testing.T) {
		noPause(t)
		ref, gets, _ := publishHTTP2(t, h2Stall, h2Stall, h2Stall)
		dst := filepath.Join(t.TempDir(), "vulnerability.db")
		before := previousDB(t, dst)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var out, errOut bytes.Buffer
		if code := Pull(ctx, dst, ref, false, &out, &errOut); code != 2 {
			t.Fatalf("exit %d, want 2 (stderr: %s)", code, errOut.String())
		}
		if got := gets.Load(); got != 1 {
			t.Errorf("a pull past its deadline fetched the layer %d times, want 1", got)
		}
		if strings.Contains(errOut.String(), "retrying") {
			t.Errorf("a pull past its deadline was retried:\n%s", errOut.String())
		}
		assertUntouched(t, dst, before)
	})
}
