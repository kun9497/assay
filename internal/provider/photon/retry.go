package photon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"syscall"
	"time"
)

// fetchAttempts is how many times one major's file is fetched before the
// build fails. Three, the same figure fedora.pageAttempts and D58's redhat
// document fetch chose, for the same reason: a file that has genuinely gone
// away must fail loudly rather than be retried forever against a feed that
// is not coming back. Until 2026-10-17 this provider made exactly one
// request per major and failed the whole nightly publish on any non-200;
// that night the Photon CDN answered 404 for one of the three fixed URLs
// and served it again the next night.
const fetchAttempts = 3

// fetchBackoff is the pause before attempt n (1-indexed), so 0.5s then 1s
// -- fedora.pageBackoff's exact schedule, reused rather than reinvented:
// short on purpose, because this exists for "the CDN front answered wrongly
// a moment ago", not for a service under sustained load. A package variable
// rather than a plain function so a test can shrink it (eol.fetchBackoff
// and its epss/kev twins take the same shape, for the same reason).
var fetchBackoff = func(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
}

// retryable reports whether an error is worth another attempt.
//
// fedora.retryable's policy, with ONE addition: 404 is retried here. That
// is a deliberate deviation, not an oversight. Bodhi's 404 means "no such
// release", which asking again cannot change; here the three URLs are
// fixed, known-good files (DefaultMajors, verified live 2026-08-26), so a
// 404 for one of them can only be the file's actual removal or a CDN front
// momentarily not having it -- and the second was observed once
// (2026-10-17, the nightly publish; the file was back the next night). A
// file that is really gone still fails after fetchAttempts requests, now
// with the attempt count in the error, so the cost of the deviation is two
// extra requests and 1.5 seconds on a real removal.
//
// What is kept from fedora: the CLASSIFICATION ORDER. Cancellation is
// checked before anything else, including the status, because retrying
// through the caller's own "stop" would ignore the one instruction that
// outranks this.
//
// Retried: 429 and 5xx (the server could not answer this time), 404 (above),
// and a TRANSPORT failure mid-body -- connection reset or an unexpectedly
// truncated read, the io.ErrUnexpectedEOF the JSON decoder surfaces when a
// 31 MB body is cut short.
//
// Not retried: any other 4xx (the request is wrong and will be wrong
// again), a connection that never got a status at all (status 0 without a
// reset), a decode error on a body that arrived intact (the feed's shape
// changed, which is a finding, not a blip), and context cancellation or
// deadline.
func retryable(err error, status int) bool {
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return false
	}
	if err != nil && (errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return true
	}
	return status == http.StatusTooManyRequests || status == http.StatusNotFound || status >= 500
}

// sleepOrDone waits for d, or returns the context's error if it ends first
// -- redhat.sleepOrDone's own doc comment explains why this matters:
// without it a cancelled build spends fetchAttempts backoffs per remaining
// major before noticing.
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
