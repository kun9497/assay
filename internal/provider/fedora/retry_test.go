package fedora

import (
	"context"
	"errors"
	"io"
	"net/http"
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
		{"truncated body with a 200", io.ErrUnexpectedEOF, http.StatusOK, false},
		{"no error at all", nil, 0, false},

		// Cancellation outranks everything, checked before the status --
		// mirroring redhat.retryable's own ordering.
		{"context cancelled", context.Canceled, 0, false},
		{"deadline exceeded", context.DeadlineExceeded, 0, false},
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
