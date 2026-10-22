package suse

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// These tests drive Fetch, not the spooling helper directly, mirroring
// redhat's identical choice (see redhat/spool_test.go's own doc comment):
// the failure this guards against is a live-streamed archive holding a
// connection open for as long as the whole parse-and-store pass takes,
// which is the shape D64 exists to close on both feeds.
//
// Unlike Red Hat's server, this one must carry a Last-Modified on the
// archive response: since D135 the GET that downloads the bytes is the only
// statement of their age (the pre-flight HEAD is gone). A HEAD is still
// answered harmlessly below, in case one is ever sent again.

// resettingServer serves the archive but severs the connection partway
// through the first N GET attempts, mirroring redhat's resettingServer.
type resettingServer struct {
	body           []byte
	archiveModTime time.Time
	failFirst      int32
	attempts       atomic.Int32
	ranged         atomic.Bool
	ignoreRange    bool
	shortChunkedOn int32
	// regenerateAfter, when set, makes every GET from that attempt number
	// on report a Last-Modified one hour later than archiveModTime: the
	// archive rebuilt in place while a download was in flight (D135).
	regenerateAfter int32
	// restarts counts GETs with no Range header after the first attempt --
	// a client that chose to start over rather than resume.
	restarts atomic.Int32
}

func (s *resettingServer) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "csaf-vex/"+changesFile {
			// An empty changes.csv, so the delta step is a no-op and these
			// tests are about the archive alone.
			return
		}
		if p != archiveName {
			http.NotFound(w, r)
			return
		}
		modTime := s.archiveModTime
		if s.regenerateAfter > 0 && s.attempts.Load()+1 >= s.regenerateAfter {
			modTime = modTime.Add(time.Hour)
		}
		if !modTime.IsZero() {
			w.Header().Set("Last-Modified", modTime.Format(http.TimeFormat))
		}
		if r.Method == http.MethodGet && r.Header.Get("Range") == "" && s.attempts.Load() > 0 {
			s.restarts.Add(1)
		}
		if r.Method == http.MethodHead {
			// The pre-flight request archiveLastModified makes. It carries no
			// body and must not be subject to the reset simulation below, or
			// every test would need a spare successful attempt just to get
			// past it.
			w.WriteHeader(http.StatusOK)
			return
		}

		start := 0
		if rng := r.Header.Get("Range"); rng != "" {
			s.ranged.Store(true)
			var end int
			if n, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); n < 1 || err != nil {
				if _, err := fmt.Sscanf(rng, "bytes=%d-", &start); err != nil {
					t.Errorf("unparseable Range header %q", rng)
				}
			}
			if start > len(s.body) {
				http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
				return
			}
		}

		n := s.attempts.Add(1)
		if s.ignoreRange {
			start = 0
		}
		rest := s.body[start:]

		if n == s.shortChunkedOn {
			if start > 0 {
				w.Header().Set("Content-Range",
					fmt.Sprintf("bytes %d-%d/%d", start, len(s.body)-1, len(s.body)))
				w.WriteHeader(http.StatusPartialContent)
			}
			cut := 1
			if len(rest) < cut {
				cut = len(rest)
			}
			_, _ = w.Write(rest[:cut])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}

		if n <= s.failFirst {
			w.Header().Set("Content-Length", strconv.Itoa(len(rest)))
			w.WriteHeader(http.StatusOK)
			cut := len(rest) / 3
			if cut == 0 {
				cut = 1
			}
			_, _ = w.Write(rest[:cut])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler)
		}

		if start > 0 {
			w.Header().Set("Content-Range",
				fmt.Sprintf("bytes %d-%d/%d", start, len(s.body)-1, len(s.body)))
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(rest)
	})
}

// fetchSpooled runs a whole Fetch against srv and returns what it emitted.
func fetchSpooled(t *testing.T, srv *httptest.Server) ([]advisory.Advisory, error) {
	t.Helper()
	p := New(Options{BaseURL: srv.URL})
	var got []advisory.Advisory
	_, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	return got, err
}

func newResettingServer(t *testing.T, s *resettingServer) (*resettingServer, *httptest.Server) {
	t.Helper()
	if s.archiveModTime.IsZero() {
		s.archiveModTime = archiveBuilt2026
	}
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	return s, srv
}

// A reset partway through the archive must not fail the build.
func TestFetch_ArchiveResetIsRetried(t *testing.T) {
	s, srv := newResettingServer(t, &resettingServer{body: fixture(t, "archive.tar.bz2"), failFirst: 1})

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v — a reset mid-archive must be retried, not fatal", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d (%+v), want both documents", len(got), got)
	}
	if s.attempts.Load() < 2 {
		t.Errorf("GET attempts = %d, want more than one — nothing retried", s.attempts.Load())
	}
}

// The retry resumes from where it stopped rather than starting over.
func TestFetch_ArchiveRetryResumes(t *testing.T) {
	s, srv := newResettingServer(t, &resettingServer{body: fixture(t, "archive.tar.bz2"), failFirst: 1})

	if _, err := fetchSpooled(t, srv); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !s.ranged.Load() {
		t.Error("no Range header was sent; the retry restarted the whole download")
	}
}

// A download that ends short of the length the server promised is an ERROR,
// never a successfully-parsed short archive.
func TestFetch_TruncatedArchiveIsNotSilentlyAccepted(t *testing.T) {
	_, srv := newResettingServer(t, &resettingServer{body: fixture(t, "archive.tar.bz2"), failFirst: 99})

	_, err := fetchSpooled(t, srv)
	if err == nil {
		t.Fatal("err = nil; a truncated archive must fail rather than parse as a short one")
	}
	if !strings.Contains(err.Error(), archiveName) {
		t.Errorf("err = %v, want it to name the archive", err)
	}
}

// A body that ends cleanly but short of the promised length must be
// retried, not parsed.
func TestFetch_ShortCleanBodyIsRetriedNotParsed(t *testing.T) {
	s, srv := newResettingServer(t, &resettingServer{
		body: fixture(t, "archive.tar.bz2"), failFirst: 1, shortChunkedOn: 2,
	})

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d (%+v), want both — a short body was accepted as the whole archive", len(got), got)
	}
	if s.attempts.Load() < 3 {
		t.Errorf("GET attempts = %d, want 3: the short clean body must count as a failure", s.attempts.Load())
	}
}

// A server that ignores Range answers 200 with the whole file. Appending
// that to what is already on disk would corrupt the spool.
func TestFetch_ServerIgnoringRangeDoesNotCorruptTheSpool(t *testing.T) {
	_, srv := newResettingServer(t, &resettingServer{
		body: fixture(t, "archive.tar.bz2"), failFirst: 1, ignoreRange: true,
	})

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v — a 200 answer to a Range request must restart, not append", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d, want both", len(got))
	}
}

// D135: a resumed response that names a different Last-Modified than the
// bytes already on disk is the archive rebuilt under the download. The
// partial file is discarded and the transfer restarts from byte 0, and the
// provenance names the generation actually downloaded -- never a splice of
// two generations bzip2 may or may not notice.
func TestFetch_ArchiveRegeneratedMidDownloadRestartsFromZero(t *testing.T) {
	s, srv := newResettingServer(t, &resettingServer{
		body: fixture(t, "archive.tar.bz2"), failFirst: 1, regenerateAfter: 2,
	})
	p := New(Options{BaseURL: srv.URL})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v -- a regenerated archive must be re-downloaded, not fatal", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d, want both", len(got))
	}
	if !s.ranged.Load() {
		t.Error("no Range request was made; the regeneration case was never reached")
	}
	if s.restarts.Load() == 0 {
		t.Error("the download resumed onto a different generation instead of restarting from byte 0")
	}
	if want := archiveBuilt2026.Add(time.Hour); !prov.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %s, want the regenerated archive's %s", prov.DataAsOf, want)
	}
}

// The spool file must not survive Fetch, whether it succeeded or failed.
func TestFetch_SpoolIsRemoved(t *testing.T) {
	count := func() int {
		matches, err := filepath.Glob(filepath.Join(os.TempDir(), "assay-suse-*.tar.bz2"))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		return len(matches)
	}

	body := fixture(t, "archive.tar.bz2")
	before := count()

	_, okSrv := newResettingServer(t, &resettingServer{body: body})
	if _, err := fetchSpooled(t, okSrv); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if after := count(); after != before {
		t.Errorf("spool files: %d before, %d after a successful fetch", before, after)
	}

	_, failSrv := newResettingServer(t, &resettingServer{body: body, failFirst: 99})
	if _, err := fetchSpooled(t, failSrv); err == nil {
		t.Fatal("Fetch succeeded against a server that never completes")
	}
	if after := count(); after != before {
		t.Errorf("spool files: %d before, %d after a failed fetch", before, after)
	}
}
