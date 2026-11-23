package suse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// QA 2026-11-20. A status the download does not accept was formatted into a
// plain error, so the retry loop saw status 0 -- "no response at all", not
// retried -- and one 503 from the CDN failed the night's build on the first
// request, under a message that claimed four attempts.

// statusFirst answers the first n archive GETs with code, then serves.
func statusFirst(t *testing.T, code, n int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	prev := archiveBackoff
	archiveBackoff = []time.Duration{time.Millisecond}
	t.Cleanup(func() { archiveBackoff = prev })

	body := fixture(t, "archive.tar.bz2")
	s := &resettingServer{body: body, archiveModTime: archiveBuilt2026}
	inner := s.handler(t)
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".tar.bz2") {
			if int(gets.Add(1)) <= n {
				http.Error(w, "try later", code)
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &gets
}

func TestFetch_AServerErrorOnTheArchiveIsRetried(t *testing.T) {
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusTooManyRequests} {
		srv, gets := statusFirst(t, code, 1)
		got, err := fetchSpooled(t, srv)
		if err != nil {
			t.Fatalf("%d once: Fetch: %v -- a server error on the archive must be retried", code, err)
		}
		if len(got) != 2 {
			t.Errorf("%d once: %d advisories, want 2", code, len(got))
		}
		if gets.Load() != 2 {
			t.Errorf("%d once: %d archive requests, want 2", code, gets.Load())
		}
	}
}

// A status that will not get better is not retried, and the message says how
// many requests were really made.
func TestFetch_AClientErrorOnTheArchiveIsNotRetried(t *testing.T) {
	srv, gets := statusFirst(t, http.StatusNotFound, 99)
	_, err := fetchSpooled(t, srv)
	if err == nil {
		t.Fatal("Fetch succeeded against an archive that answers 404")
	}
	if gets.Load() != 1 {
		t.Errorf("%d archive requests, want 1: a 404 is wrong again on the next try", gets.Load())
	}
	if !strings.Contains(err.Error(), "1 attempt(s)") || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want it to say one attempt and the status", err)
	}
}

// Four server errors in a row use every attempt and say so.
func TestFetch_ServerErrorsOnTheArchiveExhaustTheAttempts(t *testing.T) {
	srv, gets := statusFirst(t, http.StatusServiceUnavailable, 99)
	_, err := fetchSpooled(t, srv)
	if err == nil || int(gets.Load()) != archiveAttempts || !strings.Contains(err.Error(), "4 attempt(s)") {
		t.Errorf("err = %v after %d requests, want an error after all %d attempts", err, gets.Load(), archiveAttempts)
	}
}
