package suse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestRetryable mirrors redhat's TestRetryable exactly: retryable is generic
// HTTP transport classification, not specific to either feed's shape (see
// retry.go's doc comment).
func TestRetryable(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		want   bool
	}{
		{"the failure this exists for", &url.Error{
			Op: "Get", URL: "https://example.test/x.json", Err: io.EOF}, 0, true},
		{"body truncated mid-document", fmt.Errorf("parse: %w", io.ErrUnexpectedEOF), 0, true},
		{"truncated body with a 200", fmt.Errorf("parse: %w", io.ErrUnexpectedEOF),
			http.StatusOK, true},
		{"a net.Error", &net.OpError{Op: "dial", Err: errors.New("refused")}, 0, true},

		{"503", nil, http.StatusServiceUnavailable, true},
		{"500", nil, http.StatusInternalServerError, true},
		{"429", nil, http.StatusTooManyRequests, true},

		{"404", nil, http.StatusNotFound, false},
		{"403", nil, http.StatusForbidden, false},
		{"400", nil, http.StatusBadRequest, false},
		{"200", nil, http.StatusOK, false},

		{"a genuine parse error", errors.New("invalid character 'x'"), 0, false},
		{"no error at all", nil, 0, false},

		{"context cancelled", context.Canceled, 0, false},
		{"deadline exceeded", context.DeadlineExceeded, 0, false},
		{"cancellation wrapped in a url.Error", &url.Error{
			Op: "Get", URL: "https://example.test/x.json", Err: context.Canceled}, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryable(tt.err, tt.status); got != tt.want {
				t.Errorf("retryable(%v, %d) = %v, want %v", tt.err, tt.status, got, tt.want)
			}
		})
	}
}

func TestRetryable_StatusWinsOverError(t *testing.T) {
	if retryable(io.EOF, http.StatusNotFound) {
		t.Error("a 404 was retried because the error looked transient; the status is the more specific fact")
	}
	if !retryable(nil, http.StatusBadGateway) {
		t.Error("a 502 was not retried")
	}
}

func TestDeltaBackoff(t *testing.T) {
	for _, tt := range []struct {
		attempt int
		want    time.Duration
	}{
		{1, 500 * time.Millisecond},
		{2, time.Second},
	} {
		if got := deltaBackoff(tt.attempt); got != tt.want {
			t.Errorf("deltaBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
	var total time.Duration
	for i := 1; i < deltaAttempts; i++ {
		total += deltaBackoff(i)
	}
	if total > 2*time.Second {
		t.Errorf("a fully failing document waits %v before giving up; at up to %d documents "+
			"that is a hang rather than a loud failure", total, maxDelta)
	}
}

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

func TestSleepOrDone_WaitsWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := sleepOrDone(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("sleepOrDone: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("sleepOrDone returned after %v, want it to have waited ~50ms", elapsed)
	}
}
