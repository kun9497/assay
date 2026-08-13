package redhat

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

// TestRetryable is the whole of D58, so the table is written around what each
// mistake costs rather than around coverage.
//
// Retrying a PERMANENT error turns "the feed changed shape" into a slow build
// that fails anyway and buries which document broke under three identical
// failures. Not retrying a TRANSIENT one is the bug this fixes: one closed
// connection killed a 42-minute build.
func TestRetryable(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		want   bool
	}{
		// The observed failure, verbatim in shape: url.Error wrapping a bare
		// EOF from a server that hung up before answering.
		{"the failure this exists for", &url.Error{
			Op: "Get", URL: "https://example.test/x.json", Err: io.EOF}, 0, true},
		{"body truncated mid-document", fmt.Errorf("parse: %w", io.ErrUnexpectedEOF), 0, true},
		// The SAME failure as it actually arrives: the response was fine, so
		// the status is 200, and the truncation only shows when the decoder
		// runs out of body. An earlier version returned on the status before
		// looking at the error, which made this case unreachable.
		{"truncated body with a 200", fmt.Errorf("parse: %w", io.ErrUnexpectedEOF),
			http.StatusOK, true},
		{"a net.Error", &net.OpError{Op: "dial", Err: errors.New("refused")}, 0, true},

		// Status-carrying cases. The server answered and said try later.
		{"503", nil, http.StatusServiceUnavailable, true},
		{"500", nil, http.StatusInternalServerError, true},
		{"429", nil, http.StatusTooManyRequests, true},

		// Permanent. A 404 never reaches here (D49 reads it as a withdrawal),
		// but the rest of 4xx must not be retried: the request is wrong and
		// will be wrong again.
		{"404", nil, http.StatusNotFound, false},
		{"403", nil, http.StatusForbidden, false},
		{"400", nil, http.StatusBadRequest, false},
		{"200", nil, http.StatusOK, false},

		// A document that is not JSON will not become JSON, and retrying it
		// delays a real signal that the feed changed shape.
		{"a genuine parse error", errors.New("invalid character 'x'"), 0, false},
		{"no error at all", nil, 0, false},

		// Cancellation outranks everything. It arrives looking like a
		// transport error, and retrying through it would spend three backoffs
		// per remaining document against a deadline already passed.
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

// TestRetryable_StatusWinsOverError. documentOnce returns both, and a 404 with
// a non-nil error must not be retried on the strength of the error: the status
// is the more specific fact and the one D49 already acts on.
func TestRetryable_StatusWinsOverError(t *testing.T) {
	if retryable(io.EOF, http.StatusNotFound) {
		t.Error("a 404 was retried because the error looked transient; the status is the "+
			"more specific fact", nil)
	}
	if !retryable(nil, http.StatusBadGateway) {
		t.Error("a 502 was not retried")
	}
}

// TestDeltaBackoff pins the shape and, more importantly, the SCALE. This is for
// a connection closed mid-handshake, not for a service under load: an assay
// build is one client, and minutes of politeness to a feed already answering
// everyone else is waiting for nothing. A total outage costs each document
// about a second and a half before it gives up.
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
		t.Errorf("a fully failing document waits %v before giving up; at up to 20,000 "+
			"documents that is a hang rather than a loud failure", total)
	}
}

// TestSleepOrDone_ReturnsEarlyOnCancellation. Without this a cancelled pass
// spends deltaAttempts backoffs per remaining document before noticing, which
// is the difference between stopping and appearing to hang.
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

// TestSleepOrDone_WaitsWhenNotCancelled is the other half: a sleep that never
// sleeps would make the backoff decorative, and the retry would hammer a server
// that just asked it not to.
func TestSleepOrDone_WaitsWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := sleepOrDone(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("sleepOrDone: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("sleepOrDone returned after %v, want it to have waited ~50ms", elapsed)
	}
}
