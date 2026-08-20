package redhat

import (
	"bytes"
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

	"github.com/kun9497/assay/internal/advisory"
)

// These tests drive Fetch, not the spooling helper. The failure they exist for
// is the one that took the 2026-08-13 publish run down at 1h3m: the archive was
// read as a live stream while every record was being stored, so the connection
// stayed open four times longer than the download needed, and a reset 8 minutes
// in cost the whole build. D58's retry did not help because it covers the delta
// documents, a different code path entirely.

// vexDoc renders a minimal CSAF VEX document naming one fixed package, so a
// test can assert which documents survived a resumed download.
func vexDoc(cve string) string {
	return fmt.Sprintf(`{
	  "document": {"tracking": {"id": %q}},
	  "vulnerabilities": [{
	    "cve": %q,
	    "product_status": {"fixed": ["red_hat_enterprise_linux_9:spooltest-0:1.0-1.el9"]}
	  }],
	  "product_tree": {"branches": [{"category": "vendor", "name": "Red Hat", "branches": [
	    {"category": "product_family", "name": "Red Hat Enterprise Linux",
	     "branches": [{"category": "product_name", "name": "Red Hat Enterprise Linux 9",
	       "product": {"name": "Red Hat Enterprise Linux 9",
	         "product_id": "red_hat_enterprise_linux_9",
	         "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}}]}]}]}
	}`, cve, cve)
}

// resettingServer serves the archive but severs the connection partway through
// the first N attempts, the way a real reset arrives: bytes delivered, then the
// socket dies with no trailer and no error status.
type resettingServer struct {
	body      []byte
	failFirst int32
	attempts  atomic.Int32
	// ranged records whether the client asked to resume rather than restart.
	ranged atomic.Bool
	// ignoreRange answers every request with 200 and the whole file, the way a
	// proxy or CDN that does not implement Range does. A client that appends
	// such a response to what it already has corrupts the archive.
	ignoreRange bool
	// shortChunkedOn ends that attempt cleanly after a few bytes with NO
	// Content-Length. This is the one shape where a truncated body reaches the
	// caller with a nil error: net/http enforces Content-Length itself, so
	// without this the short-read check can never fire and cannot be tested.
	shortChunkedOn int32
}

func (s *resettingServer) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "archive_latest.txt") {
			_, _ = w.Write([]byte("csaf_vex_2026-08-09.tar.zst"))
			return
		}
		// An empty changes.csv, so the delta step is a no-op and these tests
		// are about the archive alone. Without it the archive body is served
		// here too and the CSV reader fails on compressed bytes - which is a
		// real failure, just not the one under test.
		if strings.HasSuffix(r.URL.Path, ".csv") {
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
			// No Content-Length written, so the response is chunked and ending
			// it is legal. The client sees a clean EOF on a body that is short
			// of the archive it was promised on the first attempt.
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
			// Flushed on purpose. Without this Go buffers the small body and
			// sets Content-Length itself, so the response is not chunked and
			// the client rejects the short read before the code under test
			// ever sees it - the test would then pass for the wrong reason.
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}

		if n <= s.failFirst {
			// Announce the full length, deliver a third of it, then hang up.
			// A reader that trusts the stream ending sees a truncated archive;
			// one that checks the length it was promised does not.
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
			// Panicking out of a handler with ErrAbortHandler is httptest's way
			// of dropping the connection without a clean EOF.
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

// A reset partway through the archive must not fail the build. This is the
// 2026-08-13 failure, reproduced.
func TestFetch_ArchiveResetIsRetried(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
		"vex/2026/CVE-2026-1001.json": vexDoc("CVE-2026-1001"),
	})
	s := &resettingServer{body: body, failFirst: 1}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v — a reset mid-archive must be retried, not fatal", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d (%+v), want both documents", len(got), got)
	}
	if s.attempts.Load() < 2 {
		t.Errorf("attempts = %d, want more than one — nothing retried", s.attempts.Load())
	}
}

// The retry resumes from where it stopped rather than starting over. On the
// real archive that is 261 MB not re-downloaded, and it is observable: the
// second request carries a Range header.
func TestFetch_ArchiveRetryResumes(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
	})
	s := &resettingServer{body: body, failFirst: 1}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	if _, err := fetchSpooled(t, srv); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !s.ranged.Load() {
		t.Error("no Range header was sent; the retry restarted the whole download")
	}
}

// TestFetch_ReportsTheRetryItMade is the caller-side proof for the D58
// retry counters: retry_loop_test.go and this file's own
// TestFetch_ArchiveResetIsRetried/TestFetch_ArchiveRetryResumes hold that
// p.retried and p.rescued increment correctly, but nothing holds Fetch's own
// copy of them into stats (st.DeltaRetried = int(p.retried.Load()) etc.,
// redhat.go) and on into the disclosed "N retried, M rescued" progress
// line -- the exact "helper covered, caller unheld" shape CLAUDE.md
// documents for D56's reportTimings, one provider over. Hardcoding either
// field to 0 there leaves every existing retry test green, because none of
// them reads the progress line's own numbers: the disclosure exists because
// "the build finished" was not evidence the retry saved it, and a build
// that silently always reports "0 retried, 0 rescued" removes exactly that
// evidence.
func TestFetch_ReportsTheRetryItMade(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
	})
	s := &resettingServer{body: body, failFirst: 1}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	var progress bytes.Buffer
	p := New(Options{BaseURL: srv.URL, Progress: &progress})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(progress.String(), "1 retried, 1 rescued by a retry") {
		t.Errorf("progress does not disclose the retry Fetch actually made "+
			"(exactly one archive-download attempt failed and was rescued):\n%s",
			progress.String())
	}
}

// A download that ends short of the length the server promised is an ERROR,
// never a successfully-parsed short archive. This is the direction that fails
// silently: zstd and tar both stop at a truncation without complaining, so a
// build would publish an artifact missing however many advisories were in the
// tail, and nothing would say so.
func TestFetch_TruncatedArchiveIsNotSilentlyAccepted(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
	})
	// Every attempt truncates, so the retries are exhausted.
	s := &resettingServer{body: body, failFirst: 99}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	_, err := fetchSpooled(t, srv)
	if err == nil {
		t.Fatal("err = nil; a truncated archive must fail rather than parse as a short one")
	}
	if !strings.Contains(err.Error(), "csaf_vex_2026-08-09.tar.zst") {
		t.Errorf("err = %v, want it to name the archive", err)
	}
}

// A body that ends cleanly but short of the length the server promised must be
// retried, not parsed. net/http enforces Content-Length itself, so the only way
// this reaches the caller with a nil error is a response with no length at all
// — a chunked one, which a proxy in front of the archive can produce.
//
// The consequence of getting it wrong is the quiet kind: zstd and tar both stop
// at a truncation without complaining, so the build would publish an artifact
// missing whatever was in the tail and say nothing.
func TestFetch_ShortCleanBodyIsRetriedNotParsed(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
		"vex/2026/CVE-2026-1001.json": vexDoc("CVE-2026-1001"),
	})
	// Attempt 1 announces the full length and aborts, so the whole size is
	// known. Attempt 2 returns a clean but tiny chunked body. Attempt 3 serves
	// the rest.
	s := &resettingServer{body: body, failFirst: 1, shortChunkedOn: 2}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d (%+v), want both — a short body was accepted as the whole archive", len(got), got)
	}
	if s.attempts.Load() < 3 {
		t.Errorf("attempts = %d, want 3: the short clean body must count as a failure", s.attempts.Load())
	}
}

// A server that ignores Range answers 200 with the whole file. Appending that
// to what is already on disk produces a file that is one and a third copies of
// the archive, which zstd rejects minutes later and nowhere near the cause.
func TestFetch_ServerIgnoringRangeDoesNotCorruptTheSpool(t *testing.T) {
	body := archiveOf(t, map[string]string{
		"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000"),
		"vex/2026/CVE-2026-1001.json": vexDoc("CVE-2026-1001"),
	})
	s := &resettingServer{body: body, failFirst: 1, ignoreRange: true}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()

	got, err := fetchSpooled(t, srv)
	if err != nil {
		t.Fatalf("Fetch: %v — a 200 answer to a Range request must restart, not append", err)
	}
	if len(got) != 2 {
		t.Fatalf("advisories = %d, want both", len(got))
	}
}

// The spool is 261 MB in production. Leaving one behind per run fills a CI
// runner, and leaving one per FAILED attempt does it faster — so both paths are
// checked here rather than trusting the defer to be right.
func TestFetch_SpoolIsRemoved(t *testing.T) {
	count := func() int {
		matches, err := filepath.Glob(filepath.Join(os.TempDir(), "assay-redhat-*.tar.zst"))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		return len(matches)
	}

	body := archiveOf(t, map[string]string{"vex/2026/CVE-2026-1000.json": vexDoc("CVE-2026-1000")})

	before := count()

	okSrv := httptest.NewServer((&resettingServer{body: body}).handler(t))
	defer okSrv.Close()
	if _, err := fetchSpooled(t, okSrv); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if after := count(); after != before {
		t.Errorf("spool files: %d before, %d after a successful fetch", before, after)
	}

	failSrv := httptest.NewServer((&resettingServer{body: body, failFirst: 99}).handler(t))
	defer failSrv.Close()
	if _, err := fetchSpooled(t, failSrv); err == nil {
		t.Fatal("Fetch succeeded against a server that never completes")
	}
	if after := count(); after != before {
		t.Errorf("spool files: %d before, %d after a failed fetch", before, after)
	}
}
