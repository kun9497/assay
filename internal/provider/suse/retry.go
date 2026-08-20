package suse

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// deltaAttempts is how many times one document fetch is tried before the
// build fails (D58), matching redhat.deltaAttempts.
const deltaAttempts = 3

// deltaBackoff is the pause before attempt n (1-indexed), matching
// redhat.deltaBackoff: 0.5s then 1s, short on purpose -- this is for a
// connection closed mid-handshake, not for a service under sustained load.
func deltaBackoff(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
}

// retryable reports whether an error is worth another attempt. Identical
// classification to redhat.retryable -- the reasoning is generic HTTP
// transport behaviour, not anything specific to either feed's shape. See
// redhat.retryable's doc comment for the full breakdown of what is and is
// not retried.
func retryable(err error, status int) bool {
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return false
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	if status >= 400 {
		return false
	}
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return false
}

// sleepOrDone waits for d, or returns the context's error if it ends first.
// Identical to redhat.sleepOrDone.
func sleepOrDone(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
