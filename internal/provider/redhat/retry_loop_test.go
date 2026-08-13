package redhat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDocument_RetriesATransientFailure is the behaviour D58 exists for, and
// nothing else held it: a mutation collapsing the retry loop to a single
// attempt left retryable() and sleepOrDone() green, because both are correct in
// isolation and neither is what fetches a document.
//
// This is the fifth time in this project that a helper was covered and the
// wiring that calls it was not.
func TestDocument_RetriesATransientFailure(t *testing.T) {
	var hits int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail once the way the real feed did — hang up before answering — then
		// serve. A retry that never happens leaves the caller with the first
		// error and never reaches the body below.
		if atomic.AddInt32(&hits, 1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support hijacking; cannot simulate a closed connection")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		}
		w.Write([]byte(`{"document":{"tracking":{"id":"CVE-2026-1"}},` +
			`"vulnerabilities":[{"cve":"CVE-2026-1"}]}`))
	}))
	defer s.Close()

	d, err := New(Options{BaseURL: s.URL}).document(context.Background(), "2026/cve-2026-1.json")
	if err != nil {
		t.Fatalf("document: %v — a transient failure was not retried", err)
	}
	if d == nil {
		t.Fatal("document returned nil for a document the server served")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("server saw %d requests, want 2 (one failure, one retry)", got)
	}
	if d.Vulnerabilities[0].CVE != "CVE-2026-1" {
		t.Errorf("parsed %q, want CVE-2026-1 — the retry returned the wrong body",
			d.Vulnerabilities[0].CVE)
	}
}

// TestDocument_GivesUpAfterDeltaAttempts. The retry must be bounded, or a feed
// that has genuinely gone away turns 20,000 documents into a hang instead of a
// loud failure — and the error has to name the document, or the operator is
// left guessing which one ended the build.
func TestDocument_GivesUpAfterDeltaAttempts(t *testing.T) {
	var hits int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()

	_, err := New(Options{BaseURL: s.URL}).document(context.Background(), "2026/cve-2026-2.json")
	if err == nil {
		t.Fatal("document = nil error against a server that always 503s")
	}
	if got := atomic.LoadInt32(&hits); got != deltaAttempts {
		t.Errorf("server saw %d requests, want %d — the retry is unbounded or does not run",
			got, deltaAttempts)
	}
	if !strings.Contains(err.Error(), "cve-2026-2.json") {
		t.Errorf("err = %q, want it to name the document that ended the build", err)
	}
}

// TestDocument_DoesNotRetryAPermanentFailure. Retrying a 403 delays a real
// signal and triples the log noise around it, and a 404 must reach the caller
// as a withdrawal (D49) rather than being tried again.
func TestDocument_DoesNotRetryAPermanentFailure(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
	}{
		{"404 is a withdrawal, not a failure", http.StatusNotFound},
		{"403 will be 403 again", http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var hits int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(tt.status)
			}))
			defer s.Close()

			d, err := New(Options{BaseURL: s.URL}).document(
				context.Background(), "2026/cve-2026-3.json")
			if got := atomic.LoadInt32(&hits); got != 1 {
				t.Errorf("server saw %d requests, want 1 — a permanent failure was retried", got)
			}
			if tt.status == http.StatusNotFound {
				if err != nil || d != nil {
					t.Errorf("404 gave (%v, %v), want (nil, nil) — D49 reads it as a withdrawal",
						d, err)
				}
				return
			}
			if err == nil {
				t.Error("a 403 returned no error")
			}
		})
	}
}

// TestDocument_StopsOnCancellation. A cancelled pass must not spend a backoff
// per remaining document before noticing, which is the difference between
// stopping and appearing to hang.
func TestDocument_StopsOnCancellation(t *testing.T) {
	var hits int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(Options{BaseURL: s.URL}).document(ctx, "2026/cve-2026-4.json"); err == nil {
		t.Fatal("document = nil error with a cancelled context")
	}
	if got := atomic.LoadInt32(&hits); got > 1 {
		t.Errorf("server saw %d requests after cancellation, want at most 1", got)
	}
}
