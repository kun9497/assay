package fedora

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestRetryable pins the narrowed policy this package's own doc comment
// describes: 429/5xx only, cancellation checked first. Unlike
// redhat.retryable, a network-level failure (status 0) and a decode error
// are NOT retried -- "honest retry ONLY on 429/5xx" was the design brief,
// not the fuller transient-transport-error set D58 built for Red Hat's
// 20,000-document delta pass.
func TestRetryable(t *testing.T) {
	// Run 43123419307. http.Client wraps its request deadline in a url.Error.
	const bodhiURL = "https://bodhi.fedoraproject.org/updates/?page=1&releases=F43&rows_per_page=100&status=stable&type=security"
	timeout := &url.Error{Op: "Get", URL: bodhiURL, Err: fmt.Errorf("%w (Client.Timeout exceeded while awaiting headers)", context.DeadlineExceeded)}
	for _, tt := range []struct {
		name   string
		err    error
		status int
		want   bool
	}{
		{"429", nil, http.StatusTooManyRequests, true},
		{"500", nil, http.StatusInternalServerError, true},
		{"503", nil, http.StatusServiceUnavailable, true},

		{"404", nil, http.StatusNotFound, false},
		{"403", nil, http.StatusForbidden, false},
		{"400", nil, http.StatusBadRequest, false},
		{"200", nil, http.StatusOK, false},

		// Unlike redhat.retryable, a bare network failure (no status at
		// all) is NOT retried here -- the narrower policy this package's
		// own doc comment names.
		{"network failure with no status", errors.New("connection reset"), 0, false},
		// Flipped 2026-08-25: three consecutive nightly publishes died on
		// mid-body transport failures (retry.go's own comment has the dates).
		// A truncated read and a peer reset are transport, not an Anubis
		// challenge -- the challenge case is the syntax-error row below, and
		// it stays non-retryable.
		{"truncated body with a 200", io.ErrUnexpectedEOF, http.StatusOK, true},
		{"connection reset mid-body", syscall.ECONNRESET, http.StatusOK, true},
		{"wrapped connection reset", fmt.Errorf("decode page: %w", syscall.ECONNRESET), http.StatusOK, true},
		{"anubis challenge: HTML body decodes as a JSON syntax error", &json.SyntaxError{}, http.StatusOK, false},
		{"no error at all", nil, 0, false},

		// Cancellation outranks everything, checked before the status --
		// mirroring redhat.retryable's own ordering.
		{"context cancelled", context.Canceled, 0, false},
		{"page timeout while waiting for headers", fmt.Errorf("fedora: fetch %s: %w", bodhiURL, timeout), 0, true},
		// Cancellation wins even alongside a status that would otherwise
		// retry, proving the check really does run first.
		{"cancelled with a 503 status", context.Canceled, http.StatusServiceUnavailable, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryable(tt.err, tt.status); got != tt.want {
				t.Errorf("retryable(%v, %d) = %v, want %v", tt.err, tt.status, got, tt.want)
			}
		})
	}
}

func TestPageTimeoutRetriesOnlyWhileBuildIsLive(t *testing.T) {
	for _, tc := range []struct {
		name          string
		stall         int32
		parentTimeout bool
		wantCalls     int32
	}{
		{"one slow response", 1, false, 2},
		{"every response times out", pageAttempts, false, pageAttempts},
		{"build deadline", 1, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) <= tc.stall {
					<-r.Context().Done()
					return
				}
				_, _ = io.WriteString(w, `{"page":1,"pages":1,"updates":[]}`)
			}))
			defer srv.Close()
			p := Provider{client: srv.Client(), baseURL: srv.URL}
			ctx := context.Background()
			p.client.Timeout = 300 * time.Millisecond
			if tc.parentTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
				p.client.Timeout = 0
			}
			var st stats
			_, err := p.fetchPageRetrying(ctx, "F43", 1, &st)
			if calls.Load() != tc.wantCalls || st.Retried != int(tc.wantCalls-1) {
				t.Fatalf("observed %d calls and %d retries, want %d calls", calls.Load(), st.Retried, tc.wantCalls)
			}
			if tc.wantCalls > tc.stall {
				if err != nil || st.Rescued != 1 {
					t.Fatalf("rescued=%d error=%v", st.Rescued, err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("want deadline error, got %v", err)
			}
		})
	}
}

// TestPageBackoff pins the shape and scale, identical to redhat's own
// TestDeltaBackoff: short on purpose, because this exists for a bot-front
// answering 429/5xx a moment ago, not a service under sustained load.
func TestPageBackoff(t *testing.T) {
	for _, tt := range []struct {
		attempt int
		want    time.Duration
	}{
		{1, 500 * time.Millisecond},
		{2, time.Second},
	} {
		if got := pageBackoff(tt.attempt); got != tt.want {
			t.Errorf("pageBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
	var total time.Duration
	for i := 1; i < pageAttempts; i++ {
		total += pageBackoff(i)
	}
	if total > 2*time.Second {
		t.Errorf("a fully failing page waits %v before giving up; that is a hang, not a loud failure", total)
	}
}

// TestSleepOrDone_ReturnsEarlyOnCancellation mirrors
// redhat.TestSleepOrDone_ReturnsEarlyOnCancellation exactly.
func TestSleepOrDone_ReturnsEarlyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepOrDone(ctx, 10*time.Second); err == nil {
		t.Error("sleepOrDone returned nil for a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepOrDone waited %v on a cancelled context; it must return at once", elapsed)
	}
}

// TestSleepOrDone_WaitsWhenNotCancelled is the other half: a sleep that
// never sleeps would make the backoff decorative.
func TestSleepOrDone_WaitsWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := sleepOrDone(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("sleepOrDone: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("sleepOrDone returned after %v, want it to have waited ~50ms", elapsed)
	}
}
